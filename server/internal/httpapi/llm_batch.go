package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/janus-cbom/janus/server/internal/llm"
	"github.com/janus-cbom/janus/server/internal/store"
)

// maxBatchFindings caps a single batch so an "all" scope cannot fan out into an
// unbounded number of LLM calls.
const maxBatchFindings = 500

// batchState tracks an admin-initiated batch analysis. The grouping is in-memory
// (jobs and verdicts themselves are persisted in the DB); a server restart loses
// the batch summary but not the analysis results. Documented in LLM-022.
type batchState struct {
	BatchID   string            `json:"batch_id"`
	CreatedBy string            `json:"created_by"`
	CreatedAt time.Time         `json:"created_at"`
	Total     int               `json:"total"`
	Queued    int               `json:"queued"`
	Running   int               `json:"running"`
	Completed int               `json:"completed"`
	Failed    int               `json:"failed"`
	Skipped   int               `json:"skipped"`
	Jobs      map[string]string `json:"jobs"` // finding_id -> job_id
	mu        sync.Mutex        `json:"-"`
}

// llmBatches holds active/recent batch summaries keyed by batch_id.
var llmBatches sync.Map // batch_id -> *batchState

type batchAnalyzeRequest struct {
	FindingIDs []string `json:"finding_ids"`
	Filter     *struct {
		SeverityGte int32  `json:"severity_gte"`
		Status      string `json:"status"`
		Algorithm   string `json:"algorithm"`
		HostUUID    string `json:"host_uuid"`
		Scope       string `json:"scope"` // all | all_critical
	} `json:"filter"`
	JobType string `json:"job_type"`
	Force   bool   `json:"force"`
}

// POST /api/llm/analyze/batch — admin-initiated batch analysis of selected findings.
// Accepts an explicit finding_ids list OR a filter; resolves the set, dedupes
// against existing fresh verdicts (unless force), creates one job per finding, and
// processes them asynchronously with bounded concurrency. The agent never calls
// this — analysis is always admin-initiated (LLM-022).
func (a *API) llmAnalyzeBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	svc := a.llmService()
	if !svc.IsEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "LLM capability is disabled. Set JANUS_LLM_BASE_URL and JANUS_LLM_API_KEY_FILE to enable.",
		})
		return
	}
	var req batchAnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	jobType := req.JobType
	if jobType == "" {
		jobType = llm.JobTypeFalsePositiveTriage
	}
	username, _ := r.Context().Value(UserContextKey).(string)
	if username == "" {
		username = "admin"
	}

	// Resolve the candidate finding set from the full findings list (in-memory
	// filter keeps the store interface small; capped read).
	all, err := a.store.Findings(r.Context(), 5000)
	if err != nil {
		writeError(w, err)
		return
	}
	selected := selectFindings(all, req)
	if len(selected) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no findings matched the selection"})
		return
	}
	if len(selected) > maxBatchFindings {
		selected = selected[:maxBatchFindings]
	}

	bs := &batchState{
		BatchID:   uuid.NewString(),
		CreatedBy: username,
		CreatedAt: time.Now(),
		Jobs:      make(map[string]string),
	}

	type jobUnit struct {
		findingID string
		jobID     string
		evidence  []byte
	}
	var units []jobUnit
	for _, f := range selected {
		// Dedup: skip findings that already have a verdict unless force.
		if !req.Force {
			if v, err := a.store.GetVerdictByFinding(r.Context(), f.FindingID); err == nil && v != nil && v.Verdict != "" {
				bs.Skipped++
				continue
			}
		}
		jobID, err := svc.SubmitAnalysisJob(r.Context(), f.FindingID, jobType, username)
		if err != nil {
			bs.Failed++
			continue
		}
		bs.Jobs[f.FindingID] = jobID
		units = append(units, jobUnit{findingID: f.FindingID, jobID: jobID, evidence: buildFindingEvidence(f)})
	}
	bs.Total = len(units)
	bs.Queued = len(units)
	llmBatches.Store(bs.BatchID, bs)

	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: username,
		Action:   "LLM_ANALYZE_BATCH",
		Details:  "batch_id=" + bs.BatchID + " jobs=" + intStr(int64(bs.Total)) + " skipped=" + intStr(int64(bs.Skipped)),
	})

	// Process asynchronously with bounded concurrency. Detached context so work
	// survives the request; per-call timeout comes from the LLM service config.
	maxConc := a.cfg.LLM.MaxConcurrent
	if maxConc <= 0 {
		maxConc = 4
	}
	go func() {
		sem := make(chan struct{}, maxConc)
		var wg sync.WaitGroup
		for _, u := range units {
			wg.Add(1)
			sem <- struct{}{}
			go func(u jobUnit) {
				defer wg.Done()
				defer func() { <-sem }()
				bs.mu.Lock()
				bs.Queued--
				bs.Running++
				bs.mu.Unlock()
				_, err := svc.AnalyzeFinding(context.Background(), u.jobID, u.evidence, "false-positive-triage")
				bs.mu.Lock()
				bs.Running--
				if err != nil {
					bs.Failed++
				} else {
					bs.Completed++
				}
				bs.mu.Unlock()
			}(u)
		}
		wg.Wait()
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"batch_id": bs.BatchID,
		"total":    bs.Total,
		"skipped":  bs.Skipped,
		"jobs":     bs.Jobs,
		"message":  "batch queued; poll GET /api/llm/batches/" + bs.BatchID,
	})
}

// GET /api/llm/batches/{id} — batch progress summary.
func (a *API) llmBatchStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	batchID := strings.TrimPrefix(r.URL.Path, "/api/llm/batches/")
	if batchID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "batch_id is required"})
		return
	}
	v, ok := llmBatches.Load(batchID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown batch_id"})
		return
	}
	bs := v.(*batchState)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"batch_id":  bs.BatchID,
		"total":     bs.Total,
		"queued":    bs.Queued,
		"running":   bs.Running,
		"completed": bs.Completed,
		"failed":    bs.Failed,
		"skipped":   bs.Skipped,
		"done":      bs.Queued == 0 && bs.Running == 0,
		"jobs":      bs.Jobs,
	})
}

// selectFindings resolves the batch target set from an explicit id list or a filter.
func selectFindings(all []store.Finding, req batchAnalyzeRequest) []store.Finding {
	if len(req.FindingIDs) > 0 {
		want := make(map[string]bool, len(req.FindingIDs))
		for _, id := range req.FindingIDs {
			want[id] = true
		}
		var out []store.Finding
		for _, f := range all {
			if want[f.FindingID] {
				out = append(out, f)
			}
		}
		return out
	}
	if req.Filter == nil {
		return nil
	}
	f := req.Filter
	sevGte := f.SeverityGte
	statusFilter := f.Status
	switch f.Scope {
	case "all_critical":
		sevGte = 5
	case "all":
		// no severity floor; default to open findings unless an explicit status given
		if statusFilter == "" {
			statusFilter = "open"
		}
	}
	algo := strings.ToLower(strings.TrimSpace(f.Algorithm))
	var out []store.Finding
	for _, fn := range all {
		if sevGte > 0 && fn.Severity < sevGte {
			continue
		}
		if statusFilter != "" && fn.Status != statusFilter {
			continue
		}
		if f.HostUUID != "" && fn.HostUUID != f.HostUUID {
			continue
		}
		if algo != "" && !strings.Contains(strings.ToLower(fn.Algorithm), algo) {
			continue
		}
		out = append(out, fn)
	}
	return out
}

// buildFindingEvidence assembles a privacy-safe evidence object SERVER-SIDE from a
// stored finding's metadata. Control flow never trusts client- or agent-supplied
// evidence for the batch path (LLM-022 acceptance criterion).
func buildFindingEvidence(f store.Finding) []byte {
	ev := map[string]any{
		"finding_id":           f.FindingID,
		"algorithm":            f.Algorithm,
		"title":                f.Title,
		"description":          f.Description,
		"asset_ref":            f.AssetRef,
		"severity":             f.Severity,
		"detection_confidence": f.Confidence,
		"status":               f.Status,
		"policy_rule_id":       f.PolicyRuleID,
		"sensitivity":          "metadata-only",
	}
	b, _ := json.Marshal(ev)
	return b
}
