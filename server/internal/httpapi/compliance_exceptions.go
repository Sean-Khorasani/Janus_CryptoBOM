package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/store"
)

// complianceExceptions handles GET (list) and POST (create) on /api/compliance/exceptions.
// An exception is an operator/admin-approved, optionally time-bounded waiver that excludes a
// rule (optionally scoped to one asset) from compliance failure — without deleting findings
// (WP-017). Writes are role-gated at registration and audit-logged.
func (a *API) complianceExceptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := a.store.ListComplianceExceptions(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		if list == nil {
			list = []store.ComplianceException{}
		}
		writeJSON(w, http.StatusOK, list)
	case http.MethodPost:
		var req struct {
			RuleID   string `json:"rule_id"`
			AssetRef string `json:"asset_ref"`
			Reason   string `json:"reason"`
			TTLHours int    `json:"ttl_hours"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if strings.TrimSpace(req.RuleID) == "" || strings.TrimSpace(req.Reason) == "" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "rule_id and reason are required"})
			return
		}
		username, _ := r.Context().Value(UserContextKey).(string)
		if username == "" {
			username = "operator"
		}
		exc := &store.ComplianceException{
			ExceptionID: uuid.NewString(),
			RuleID:      strings.TrimSpace(req.RuleID),
			AssetRef:    strings.TrimSpace(req.AssetRef),
			Reason:      strings.TrimSpace(req.Reason),
			RequestedBy: username,
			ApprovedBy:  username,
			Status:      "active",
		}
		if req.TTLHours > 0 {
			exp := time.Now().Add(time.Duration(req.TTLHours) * time.Hour)
			exc.ExpiresAt = &exp
		}
		if err := a.store.CreateComplianceException(r.Context(), exc); err != nil {
			writeError(w, err)
			return
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "COMPLIANCE_EXCEPTION_CREATE",
			Details:  "exception_id=" + exc.ExceptionID + " rule_id=" + exc.RuleID + " asset_ref=" + exc.AssetRef,
		})
		writeJSON(w, http.StatusCreated, exc)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// complianceExceptionByID handles DELETE /api/compliance/exceptions/{id} — revoke an exception
// (it immediately stops suppressing compliance). Role-gated + audit-logged.
func (a *API) complianceExceptionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/compliance/exceptions/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "exception_id is required"})
		return
	}
	if err := a.store.RevokeComplianceException(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	username, _ := r.Context().Value(UserContextKey).(string)
	if username == "" {
		username = "operator"
	}
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: username,
		Action:   "COMPLIANCE_EXCEPTION_REVOKE",
		Details:  "exception_id=" + id,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "exception_id": id})
}
