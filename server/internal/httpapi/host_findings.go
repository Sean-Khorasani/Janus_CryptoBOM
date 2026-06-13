package httpapi

import (
	"net/http"
	"strings"

	"github.com/janus-cbom/janus/server/internal/store"
)

// hostFindings handles GET /api/hosts/{uuid}/findings.
// It returns all findings recorded for the given host UUID.
func (a *API) hostFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Parse /api/hosts/{uuid}/findings — expect exactly two segments after /api/hosts/
	path := strings.TrimPrefix(r.URL.Path, "/api/hosts/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[1] != "findings" {
		http.NotFound(w, r)
		return
	}

	hostUUID := parts[0]
	if hostUUID == "" || strings.Contains(hostUUID, "..") || strings.Contains(hostUUID, "/") {
		http.NotFound(w, r)
		return
	}

	findings, err := a.store.FindingsByHost(r.Context(), hostUUID)
	if err != nil {
		writeError(w, err)
		return
	}
	if findings == nil {
		findings = []store.Finding{}
	}
	writeJSON(w, http.StatusOK, findings)
}
