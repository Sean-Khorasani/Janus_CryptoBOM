package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/janus-cbom/janus/server/internal/agility"
	"github.com/janus-cbom/janus/server/internal/store"
	"github.com/janus-cbom/janus/server/internal/waveplan"
)

// GET /api/agility/scorecard
// Query params: host_uuid (optional) — omit for fleet-wide view.
func (a *API) agilityScorecard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hostUUID := r.URL.Query().Get("host_uuid")

	// Fetch findings from DB.
	params := store.QueryParams{Limit: 5000, HostUUID: hostUUID}
	findings, _, err := a.store.FindingsPaginated(r.Context(), params)
	if err != nil {
		writeError(w, err)
		return
	}

	if hostUUID != "" {
		// Per-host scorecard.
		sc := agility.ComputeScorecard(hostUUID, findings, 0, 0, nil)
		writeJSON(w, http.StatusOK, sc)
		return
	}

	// Fleet-wide: group by host_uuid, compute per-host, then aggregate.
	hostFindings := map[string][]store.Finding{}
	for _, f := range findings {
		hostFindings[f.HostUUID] = append(hostFindings[f.HostUUID], f)
	}
	scorecards := make([]agility.Scorecard, 0, len(hostFindings))
	for host, hf := range hostFindings {
		scorecards = append(scorecards, agility.ComputeScorecard(host, hf, 0, 0, nil))
	}
	fleet := agility.ComputeFleetScorecard(scorecards)
	writeJSON(w, http.StatusOK, map[string]any{
		"fleet":   fleet,
		"hosts":   scorecards,
		"top_blast_radius": agility.TopBlastRadiusAlgorithms(fleet, 5),
	})
}

// GET  /api/waves        — list all wave plans
// POST /api/waves        — create a wave plan
func (a *API) wavePlans(w http.ResponseWriter, r *http.Request) {
	planner := waveplan.New(a.store)
	switch r.Method {
	case http.MethodGet:
		plans, err := planner.List(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"plans":     plans,
			"checklist": waveplan.ReadinessChecklist(),
		})
	case http.MethodPost:
		var plan store.WavePlan
		if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		username, _ := r.Context().Value(UserContextKey).(string)
		if username == "" {
			username = "admin"
		}
		if err := planner.Create(r.Context(), &plan, username); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "WAVE_PLAN_CREATE",
			Details:  "plan_id=" + plan.PlanID + " name=" + plan.Name,
		})
		writeJSON(w, http.StatusCreated, plan)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// PUT    /api/waves/{id}  — update wave plan status
// DELETE /api/waves/{id}  — delete a wave plan
func (a *API) wavePlanByID(w http.ResponseWriter, r *http.Request) {
	planID := strings.TrimPrefix(r.URL.Path, "/api/waves/")
	if planID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "plan_id is required"})
		return
	}
	planner := waveplan.New(a.store)
	username, _ := r.Context().Value(UserContextKey).(string)
	if username == "" {
		username = "admin"
	}

	switch r.Method {
	case http.MethodPut:
		var body struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := planner.UpdateStatus(r.Context(), planID, body.Status); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "WAVE_PLAN_STATUS",
			Details:  "plan_id=" + planID + " status=" + body.Status,
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": body.Status, "plan_id": planID})
	case http.MethodDelete:
		if err := planner.Delete(r.Context(), planID); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "WAVE_PLAN_DELETE",
			Details:  "plan_id=" + planID,
		})
		writeJSON(w, http.StatusNoContent, nil)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
