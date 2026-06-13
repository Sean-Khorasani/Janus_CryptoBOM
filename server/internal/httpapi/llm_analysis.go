package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

	// If evidence is provided, run synchronously; otherwise queue for background processing.
	if len(req.Evidence) > 0 {
		verdict, err := svc.AnalyzeFinding(r.Context(), jobID, req.Evidence, "false-positive-triage")
		if err != nil {
			writeError(w, err)
			return
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "LLM_ANALYZE",
			Details:  "finding_id=" + req.FindingID + " job_id=" + jobID + " verdict=" + verdict.Verdict,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"job_id":  jobID,
			"status":  llm.JobStatusCompleted,
			"verdict": verdict,
		})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"job_id":  jobID,
		"status":  llm.JobStatusQueued,
		"message": "analysis job queued; poll GET /api/llm/jobs/" + jobID + " for results",
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
			if verdict, err := a.store.GetVerdictByJob(r.Context(), jobID); err == nil {
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
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	findingID := strings.TrimPrefix(r.URL.Path, "/api/llm/verdicts/")
	if findingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "finding_id is required"})
		return
	}
	verdict, err := a.store.GetVerdictByFinding(r.Context(), findingID)
	if err != nil {
		writeError(w, err)
		return
	}
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
	})
}

func intStr(n int64) string {
	return fmt.Sprintf("%d", n)
}
