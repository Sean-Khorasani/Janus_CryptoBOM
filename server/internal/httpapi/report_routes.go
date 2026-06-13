package httpapi

import (
	"net/http"
	"strings"

	"github.com/janus-cbom/janus/server/internal/scanconfig"
	"github.com/janus-cbom/janus/server/internal/store"
)

// GET /api/reports/{scanId}/findings — findings for a specific scan run.
// The fleet UI ("Findings JSON" downloads and the agent-detail drawer) calls this;
// it was previously unregistered, so those flows 404'd (UX-003).
func (a *API) reportFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Path: /api/reports/{scanId}/findings
	rest := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] != "findings" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected /api/reports/{scan_id}/findings"})
		return
	}
	scanID := parts[0]
	params := store.QueryParams{
		Limit:  intParam(r, "limit", 200),
		Offset: intParam(r, "offset", 0),
		Search: r.URL.Query().Get("search"),
	}
	findings, total, err := a.store.ReportFindings(r.Context(), scanID, params)
	if err != nil {
		writeError(w, err)
		return
	}
	if findings == nil {
		findings = []store.Finding{}
	}
	w.Header().Set("X-Total-Count", intStr(total))
	writeJSON(w, http.StatusOK, findings)
}

// GET /api/scan-config/schema — canonical scan-parameter schema (defaults + limits).
// The per-agent Configure modal needs this to validate input; without it the modal's
// Apply button stayed permanently disabled (UX-004).
func (a *API) scanConfigSchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, scanconfig.CurrentSchema())
}
