package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/janus-cbom/janus/server/internal/llm"
	"github.com/janus-cbom/janus/server/internal/store"
)

// initLLMService creates the LLM service lazily. Returns nil when disabled.
func (a *API) llmService() *llm.Service {
	if a.llmSvc != nil {
		return a.llmSvc
	}
	a.llmSvc = llm.NewService(a.store, a.cfg)
	return a.llmSvc
}

// POST /api/llm/analyze - Submit a finding for LLM analysis.
// Body: { "finding_id": "...", "job_type": "false_positive_triage|intent_classification|...", "evidence": {...} }
func (a *API) llmAnalyze(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		FindingID string          `json:"finding_id"`
		JobType   string          `json:"job_type"`
		Evidence  json.RawMessage `json:"evidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.FindingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "finding_id is required"})
		return
	}
	if req.JobType == "" {
		req.JobType = llm.JobTypeFalsePositiveTriage
	}
	username, _ := r.Context().Value(UserContextKey).(string)
	if username == "" {
		username = "admin"
	}
	jobID, err := svc.SubmitAnalysisJob(r.Context(), req.FindingID, req.JobType, username)
	if err != nil {
		writeError(w, err)
		return
	}

	// Evidence is assembled SERVER-SIDE from the stored finding (LLM-022: control flow
	// never requires client-supplied evidence). A client may still pass an explicit
	// evidence object for ad-hoc analysis; when absent we build it from the finding so
	// a UI submit (finding_id only) runs to completion instead of queuing indefinitely.
	evidence := []byte(req.Evidence)
	if len(evidence) == 0 {
		if f, ok := a.findFindingByID(r.Context(), req.FindingID); ok {
			evidence = buildFindingEvidence(f)
		}
	}
	if len(evidence) > 0 {
		a.respondWithAnalysis(w, r, svc, jobID, req.FindingID, req.JobType, username, evidence)
		return
	}

	// No evidence and the finding could not be resolved — leave the job queued.
	writeJSON(w, http.StatusAccepted, map[string]string{
		"job_id":  jobID,
		"status":  llm.JobStatusQueued,
		"message": "analysis job queued; poll GET /api/llm/jobs/" + jobID + " for results",
	})
}

// findFindingByID resolves a finding from the store by id (capped read, mirroring the
// batch path). ok is false if no finding matches.
func (a *API) findFindingByID(ctx context.Context, findingID string) (store.Finding, bool) {
	all, err := a.store.Findings(ctx, 5000, TenantFromContext(ctx))
	if err != nil {
		return store.Finding{}, false
	}
	for _, f := range all {
		if f.FindingID == findingID {
			return f, true
		}
	}
	return store.Finding{}, false
}

// respondWithAnalysis runs the job to completion and writes the result. Remediation
// jobs run the generate→validate→persist pipeline (LLM-011/013); all other job types
// produce a verdict.
func (a *API) respondWithAnalysis(w http.ResponseWriter, r *http.Request, svc *llm.Service, jobID, findingID, jobType, username string, evidence []byte) {
	if jobType == llm.JobTypeRemediationSuggestion {
		suggestion, err := svc.GenerateRemediation(r.Context(), jobID, evidence)
		if err != nil {
			writeError(w, err)
			return
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "LLM_SUGGEST_REMEDIATION",
			Details:  "finding_id=" + findingID + " job_id=" + jobID + " validation=" + suggestion.ValidationStatus,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"job_id":     jobID,
			"status":     llm.JobStatusCompleted,
			"suggestion": suggestion,
		})
		return
	}
	verdict, err := svc.AnalyzeFinding(r.Context(), jobID, evidence, "false-positive-triage")
	if err != nil {
		writeError(w, err)
		return
	}
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: username,
		Action:   "LLM_ANALYZE",
		Details:  "finding_id=" + findingID + " job_id=" + jobID + " verdict=" + verdict.Verdict,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"job_id":  jobID,
		"status":  llm.JobStatusCompleted,
		"verdict": verdict,
	})
}

// GET /api/llm/jobs - List LLM analysis jobs.
// GET /api/llm/jobs/{id} - Get a specific job and its verdict.
func (a *API) llmJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Check for /api/llm/jobs/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/llm/jobs"), "/")
	if len(parts) >= 2 && parts[1] != "" {
		jobID := parts[1]
		job, err := a.store.GetAnalysisJob(r.Context(), jobID)
		if err != nil {
			writeError(w, err)
			return
		}
		result := map[string]any{"job": job}
		if job.Status == llm.JobStatusCompleted {
			if job.JobType == llm.JobTypeRemediationSuggestion {
				if s, err := a.store.GetSuggestionByJob(r.Context(), jobID); err == nil {
					result["suggestion"] = s
				}
			} else if verdict, err := a.store.GetVerdictByJob(r.Context(), jobID); err == nil {
				result["verdict"] = verdict
			}
		}
		writeJSON(w, http.StatusOK, result)
		return
	}

	params := store.QueryParams{
		Limit:  intParam(r, "limit", 50),
		Offset: intParam(r, "offset", 0),
		Search: r.URL.Query().Get("finding_id"),
	}
	jobs, total, err := a.store.ListAnalysisJobs(r.Context(), params)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("X-Total-Count", intStr(total))
	writeJSON(w, http.StatusOK, jobs)
}

// GET /api/llm/verdicts/{finding_id} - Get the latest LLM verdict for a finding.
func (a *API) llmVerdict(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/llm/verdicts/")
	// POST /api/llm/verdicts/{verdict_id}/review — human approve/reject (LLM-022).
	if strings.HasSuffix(rest, "/review") {
		a.reviewVerdict(w, r, strings.TrimSuffix(rest, "/review"))
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	findingID := rest
	if findingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "finding_id is required"})
		return
	}
	verdict, err := a.store.GetVerdictByFinding(r.Context(), findingID)
	if errors.Is(err, pgx.ErrNoRows) {
		// No verdict yet for this finding is the normal case (most findings are
		// never LLM-analyzed). Return 404, not a 500 — the dashboard polls this
		// per-finding, so a 500 here floods the error log (BUGFIX).
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no verdict for this finding"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verdict)
}

func validReviewDecision(d string) bool { return d == "approved" || d == "rejected" }

// reviewVerdict records an operator/admin approve-or-reject decision on an LLM verdict
// (LLM-022). The decision is an audit record only: per the authority-inversion invariant
// it does not change the finding's status or inventory — the operator applies any
// resulting change through the normal finding-status path.
func (a *API) reviewVerdict(w http.ResponseWriter, r *http.Request, verdictID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// The /api/llm/verdicts/ route is not RequireRole-wrapped (GET is read-only for any
	// user); gate the mutating review action to operator/admin here.
	if role, _ := r.Context().Value(RoleContextKey).(string); role != "operator" && role != "admin" {
		http.Error(w, "forbidden: operator or admin role required", http.StatusForbidden)
		return
	}
	if verdictID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "verdict_id is required"})
		return
	}
	var body struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if !validReviewDecision(body.Decision) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decision must be 'approved' or 'rejected'"})
		return
	}
	reviewer, _ := r.Context().Value(UserContextKey).(string)
	verdict, err := a.store.SetVerdictReview(r.Context(), verdictID, body.Decision, reviewer, body.Note)
	if errors.Is(err, store.ErrVerdictNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "verdict not found"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: reviewer,
		Action:   "LLM_VERDICT_REVIEW",
		Details:  fmt.Sprintf("verdict %s %s", verdictID, body.Decision),
	})
	writeJSON(w, http.StatusOK, verdict)
}

// GET /api/llm/provenance/{finding_id} - List all LLM provenance records for a finding.
func (a *API) llmProvenance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	findingID := strings.TrimPrefix(r.URL.Path, "/api/llm/provenance/")
	if findingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "finding_id is required"})
		return
	}
	provenance, err := a.store.ListProvenance(r.Context(), findingID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, provenance)
}

// GET /api/llm/status - Returns LLM capability status and configuration summary.
func (a *API) llmStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	svc := a.llmService()
	writeJSON(w, http.StatusOK, map[string]any{
		"capability_mode":     string(svc.Mode()),
		"enabled":             svc.IsEnabled(),
		"suggest_remediation": svc.CanSuggestRemediation(),
		"model_analysis":      a.cfg.LLM.ModelAnalysis,
		"model_remediation":   a.cfg.LLM.ModelRemediation,
		"base_url_configured": a.cfg.LLM.BaseURL != "",
		"api_key_configured":  a.cfg.LLM.APIKey() != "",
		// LLM-021: the env config (JANUS_LLM_*) is the single authoritative source for
		// live provider calls. The fleet_configs/config_profiles llm_api_key/llm_api_url
		// columns are legacy and intentionally NOT used for outbound calls (using a
		// DB-stored URL would re-open the SSRF hole closed in LLM-20).
		"config_source": "env",
	})
}

// llmModelCostPer1K maps a model id to [inputPer1K, outputPer1K] USD (LLM-023). These
// are public list-price estimates; unknown models contribute 0 and are flagged.
var llmModelCostPer1K = map[string][2]float64{
	"gpt-4o":       {0.0025, 0.01},
	"gpt-4o-mini":  {0.00015, 0.0006},
	"gpt-4.1":      {0.002, 0.008},
	"gpt-4.1-mini": {0.0004, 0.0016},
	"o4-mini":      {0.0011, 0.0044},
}

// llmUsage returns a token/cost/latency rollup plus job success rate (LLM-023).
// Read-only; available to any authenticated user.
func (a *API) llmUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	usage, err := a.store.GetLLMUsage(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}

	type modelOut struct {
		store.LLMModelUsage
		EstCostUSD float64 `json:"estimated_cost_usd"`
		Priced     bool    `json:"priced"`
	}
	var (
		byModel     []modelOut
		totalCalls  int
		totalIn     int
		totalOut    int
		totalCost   float64
		anyUnpriced bool
	)
	for _, m := range usage.ByModel {
		cost, priced := 0.0, false
		if rate, ok := llmModelCostPer1K[m.Model]; ok {
			cost = float64(m.TokensIn)/1000*rate[0] + float64(m.TokensOut)/1000*rate[1]
			priced = true
		} else {
			anyUnpriced = true
		}
		totalCalls += m.Calls
		totalIn += m.TokensIn
		totalOut += m.TokensOut
		totalCost += cost
		byModel = append(byModel, modelOut{LLMModelUsage: m, EstCostUSD: cost, Priced: priced})
	}

	completed, failed := usage.JobsByStatus["completed"], usage.JobsByStatus["failed"]
	successRate := 0.0
	if completed+failed > 0 {
		successRate = float64(completed) / float64(completed+failed)
	}
	note := "Costs are list-price estimates for the models in use."
	if anyUnpriced {
		note = "Costs are list-price estimates for known models; unknown models show $0."
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"by_model":                 byModel,
		"total_calls":              totalCalls,
		"total_tokens_input":       totalIn,
		"total_tokens_output":      totalOut,
		"total_estimated_cost_usd": totalCost,
		"jobs_by_status":           usage.JobsByStatus,
		"job_success_rate":         successRate,
		"pricing_note":             note,
	})
}

func intStr(n int64) string {
	return fmt.Sprintf("%d", n)
}
