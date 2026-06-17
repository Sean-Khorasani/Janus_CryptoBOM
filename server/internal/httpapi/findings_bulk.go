package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/janus-cbom/janus/server/internal/store"
)

// bulkFindingUpdate is one item in a POST /api/findings/bulk-update request (UX-002).
type bulkFindingUpdate struct {
	FindingID string `json:"finding_id"`
	Status    string `json:"status"`
}

type bulkUpdateResult struct {
	FindingID string `json:"finding_id"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

const bulkUpdateMax = 100

// bulkUpdateFindings applies a status change to many findings in one request
// (UX-002). It reuses UpdateFindingStatus per item so each finding gets the
// exact same transactional lifecycle-event + auto-reopen behavior as a single
// update, and returns per-item success/failure rather than aborting the whole
// batch on the first error. Operator/admin only (enforced at route registration).
func (a *API) bulkUpdateFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Accept both a bare array and {"updates":[...]}.
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, err)
		return
	}
	var updates []bulkFindingUpdate
	var wrapper struct {
		Updates []bulkFindingUpdate `json:"updates"`
	}
	if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Updates) > 0 {
		updates = wrapper.Updates
	} else if err := json.Unmarshal(body, &updates); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": `body must be an array of {finding_id,status} or {"updates":[...]}`,
		})
		return
	}

	if len(updates) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no updates provided"})
		return
	}
	if len(updates) > bulkUpdateMax {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "too many findings in one request",
			"max":   bulkUpdateMax,
			"given": len(updates),
		})
		return
	}

	// Actor identity from the JWT context (falls back to "operator").
	actor, _ := r.Context().Value(UserContextKey).(string)
	if actor == "" {
		actor = "operator"
	}
	tenant := TenantFromContext(r.Context())

	results := make([]bulkUpdateResult, 0, len(updates))
	updated, failed := 0, 0
	for _, u := range updates {
		if u.FindingID == "" || u.Status == "" {
			results = append(results, bulkUpdateResult{FindingID: u.FindingID, OK: false, Error: "finding_id and status are required"})
			failed++
			continue
		}
		if err := a.store.UpdateFindingStatus(r.Context(), u.FindingID, u.Status, actor); err != nil {
			results = append(results, bulkUpdateResult{FindingID: u.FindingID, OK: false, Error: err.Error()})
			failed++
			continue
		}
		results = append(results, bulkUpdateResult{FindingID: u.FindingID, OK: true})
		updated++
		a.wsHub.BroadcastTenant(tenant, "finding_status", map[string]string{
			"finding_id": u.FindingID,
			"status":     u.Status,
			"updated_by": actor,
		})
	}

	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: actor,
		Action:   "FINDINGS_BULK_UPDATE",
		Details:  fmt.Sprintf("updated=%d failed=%d", updated, failed),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"updated": updated,
		"failed":  failed,
		"results": results,
	})
}
