package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/janus-cbom/janus/server/internal/store"
)

// tenantIDPattern restricts tenant IDs to a safe slug (used in JWT claims, row filters, and
// config keys) — lowercase alphanumerics, dash, underscore.
var tenantIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// tenants handles GET (list) and POST (create) on /api/tenants (admin-only, WP-020).
// Tenants are the isolation boundaries that scope fleet/finding data per login.
func (a *API) tenants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := a.store.ListTenants(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		if list == nil {
			list = []store.Tenant{}
		}
		writeJSON(w, http.StatusOK, list)
	case http.MethodPost:
		var req struct {
			TenantID string `json:"tenant_id"`
			Name     string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		id := strings.TrimSpace(req.TenantID)
		if !tenantIDPattern.MatchString(id) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "tenant_id must match ^[a-z0-9][a-z0-9_-]{0,62}$"})
			return
		}
		t := &store.Tenant{TenantID: id, Name: strings.TrimSpace(req.Name), Status: "active"}
		if err := a.store.CreateTenant(r.Context(), t); err != nil {
			writeError(w, err)
			return
		}
		username, _ := r.Context().Value(UserContextKey).(string)
		if username == "" {
			username = "admin"
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "TENANT_CREATE",
			Details:  "tenant_id=" + t.TenantID + " name=" + t.Name,
		})
		writeJSON(w, http.StatusCreated, t)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
