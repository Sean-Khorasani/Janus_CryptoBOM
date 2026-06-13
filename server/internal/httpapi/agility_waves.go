package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/janus-cbom/janus/server/internal/agility"
	"github.com/janus-cbom/janus/server/internal/store"
	"github.com/janus-cbom/janus/server/internal/waveplan"
)

// POST /api/agility/exercise — dry-run agility exercise (WP-023).
// Computes scorecards for all hosts and runs RunExercise against them.
// Requires operator or admin role (enforced at route registration).
func (a *API) agilityExercise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Fetch findings for all hosts, same as the scorecard endpoint.
	params := store.QueryParams{Limit: 5000}
	findings, _, err := a.store.FindingsPaginated(r.Context(), params)
	if err != nil {
		writeError(w, err)
		return
	}

	// Group by host_uuid and compute per-host scorecards.
	hostFindings := map[string][]store.Finding{}
	for _, f := range findings {
		hostFindings[f.HostUUID] = append(hostFindings[f.HostUUID], f)
	}
	scorecards := make([]agility.Scorecard, 0, len(hostFindings))
	for host, hf := range hostFindings {
		scorecards = append(scorecards, agility.ComputeScorecard(host, hf, 0, 0, nil))
	}

	report := agility.RunExercise(scorecards)

	// Per-adapter negotiation harness (WP-023): evaluate the migration adapters
	// against the active profile's PQC targets. Targets may be overridden via
	// ?targets=a,b,c; otherwise they come from the active policy profile.
	targets := parseTargets(r.URL.Query().Get("targets"))
	if len(targets) == 0 && a.engine != nil {
		prof := a.engine.GetActiveProfile()
		if prof.PreferredKEM != "" {
			targets = append(targets, prof.PreferredKEM)
		}
		if prof.PreferredSignature != "" {
			targets = append(targets, prof.PreferredSignature)
		}
	}
	negotiation := agility.RunNegotiationHarness(targets)

	// Persist per-host agility metric snapshots so the agility_metrics table
	// reflects each exercise run (it was previously never written). host_uuid
	// carries a foreign key to assets, so we record one row per real host.
	fleet := agility.ComputeFleetScorecard(scorecards)
	fleetTTSA := agility.EstimateTTSADays(fleet, negotiation)
	for _, sc := range scorecards {
		hostTTSA := agility.EstimateTTSADays(sc, negotiation)
		_ = a.store.UpsertAgilityMetrics(r.Context(), &store.AgilityMetrics{
			HostUUID:            sc.HostUUID,
			MeasurementDate:     report.RunAt,
			TTSADays:            &hostTTSA,
			HardcodeIndex:       sc.HardcodeIndex,
			NegotiationCoverage: sc.NegotiationCoverage,
			BlastRadiusScore:    sc.BlastRadiusScore,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"exercise":            report,
		"negotiation":         negotiation,
		"estimated_ttsa_days": fleetTTSA,
	})
}

// parseTargets splits a comma-separated target list, trimming blanks.
func parseTargets(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

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
		"fleet":            fleet,
		"hosts":            scorecards,
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

	// GET /api/waves/graph — dependency graph + budget rollup (WP-022).
	if planID == "graph" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		graph, err := planner.Graph(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		budget, err := planner.Budget(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"graph":  graph,
			"budget": budget,
		})
		return
	}

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
