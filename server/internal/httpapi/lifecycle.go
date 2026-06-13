package httpapi

import (
	"net/http"
	"strings"

	"github.com/janus-cbom/janus/server/internal/store"
)

// findingsDispatch routes /api/findings/{id}/timeline to findingTimeline and
// all other /api/findings/ paths to findingStatus.
// Registered as: mux.HandleFunc("/api/findings/", api.findingsDispatch)
func (a *API) findingsDispatch(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/timeline") {
		a.findingTimeline(w, r)
		return
	}
	a.findingStatus(w, r)
}

// findingTimeline handles GET /api/findings/{id}/timeline.
// It returns the ordered lifecycle event history for a single finding.
func (a *API) findingTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Path: /api/findings/{id}/timeline
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	if !strings.HasSuffix(trimmed, "/timeline") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	findingID := strings.TrimSuffix(trimmed, "/timeline")
	if findingID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	events, err := a.store.ListLifecycleEvents(r.Context(), findingID)
	if err != nil {
		writeError(w, err)
		return
	}
	if events == nil {
		events = []store.FindingLifecycleEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}
