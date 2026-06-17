package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
	"gopkg.in/yaml.v3"
)

// UX-006: policy update / delete / export / import. Create already exists
// (createPolicy). These handlers write to the policies/ directory and update
// the in-memory engine so changes take effect immediately, and broadcast
// policy_switched so the dashboard refreshes.

// writePolicyFile persists a profile as canonical YAML under policies/.
func writePolicyFile(safeVersion string, p policy.Profile) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll("policies", 0700); err != nil {
		return err
	}
	return os.WriteFile(fmt.Sprintf("policies/%s.yaml", safeVersion), data, 0600)
}

func policyVersionValid(version string) bool {
	if version == "" || strings.Contains(version, "..") {
		return false
	}
	return sanitizePolicyFilename(strings.ToLower(version)) == strings.ToLower(version)
}

// policyByVersion handles /api/policies/{version} (PUT update, DELETE) and
// /api/policies/{version}/export (GET). Operator/admin gate is at registration;
// DELETE additionally requires admin.
func (a *API) policyByVersion(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/policies/")
	parts := strings.Split(rest, "/")
	version := parts[0]
	if !policyVersionValid(version) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid policy version"})
		return
	}
	safe := sanitizePolicyFilename(strings.ToLower(version))
	actor, _ := r.Context().Value(UserContextKey).(string)
	if actor == "" {
		actor = "operator"
	}

	// GET /api/policies/{version}/export → YAML download.
	if len(parts) == 2 && parts[1] == "export" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		p, ok := a.engine.GetProfile(version)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		data, err := yaml.Marshal(p)
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.yaml", safe))
		_, _ = w.Write(data)
		return
	}

	switch r.Method {
	case http.MethodPut: // update existing profile
		var p policy.Profile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		p.Version = version // path is authoritative
		a.engine.AddProfile(p)
		if err := writePolicyFile(safe, p); err != nil {
			writeError(w, err)
			return
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{Username: actor, Action: "UPDATE_POLICY_PROFILE", Details: "version=" + version})
		a.wsHub.Broadcast("policy_switched", map[string]string{"version": version, "action": "updated"})
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "profile": p})

	case http.MethodDelete: // admin only
		if role, _ := r.Context().Value(RoleContextKey).(string); role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "deleting a policy requires admin role"})
			return
		}
		if err := a.engine.RemoveProfile(version); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		_ = os.Remove(fmt.Sprintf("policies/%s.yaml", safe))
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{Username: actor, Action: "DELETE_POLICY_PROFILE", Details: "version=" + version})
		a.wsHub.Broadcast("policy_switched", map[string]string{"version": version, "action": "deleted"})
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "version": version})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// importPolicy handles POST /api/policies/import — accepts a YAML profile,
// validates it, saves it as a new/updated version, and loads it into the engine.
func (a *API) importPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		writeError(w, err)
		return
	}
	var p policy.Profile
	if err := yaml.Unmarshal(body, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid YAML: " + err.Error()})
		return
	}
	if !policyVersionValid(p.Version) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy 'version' is required and must contain only [a-z0-9._-]"})
		return
	}
	safe := sanitizePolicyFilename(strings.ToLower(p.Version))
	a.engine.AddProfile(p)
	if err := writePolicyFile(safe, p); err != nil {
		writeError(w, err)
		return
	}
	actor, _ := r.Context().Value(UserContextKey).(string)
	if actor == "" {
		actor = "operator"
	}
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{Username: actor, Action: "IMPORT_POLICY_PROFILE", Details: "version=" + p.Version})
	a.wsHub.Broadcast("policy_switched", map[string]string{"version": p.Version, "action": "imported"})
	writeJSON(w, http.StatusCreated, map[string]any{"status": "ok", "profile": p})
}
