package httpapi

// Route registration lines to add to server.go (inside the New() function):
//
//	mux.HandleFunc("/api/policy/rules", api.complianceRules)
//	mux.HandleFunc("/api/policy/rules/", api.complianceRuleByID)
//
// To make these routes public (no JWT required), add them to the allowlist in
// AuthMiddleware (auth.go), for example:
//
//	if r.URL.Path == "/api/policy/rules" || strings.HasPrefix(r.URL.Path, "/api/policy/rules/") {
//	    next.ServeHTTP(w, r)
//	    return
//	}
//
// Without that addition, these routes require a valid Bearer token like all other
// authenticated endpoints.

import (
	"net/http"
	"strings"

	"github.com/janus-cbom/janus/server/internal/policy"
)

// complianceRules handles GET /api/policy/rules.
// Returns the full built-in control pack as JSON.
func (a *API) complianceRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, policy.BuiltinControlPack())
}

// complianceRuleByID handles GET /api/policy/rules/{id}.
// Returns a single control rule by its rule ID.
func (a *API) complianceRuleByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ruleID := strings.TrimPrefix(r.URL.Path, "/api/policy/rules/")
	if ruleID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rule, ok := policy.GetRule(ruleID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found", "rule_id": ruleID})
		return
	}
	writeJSON(w, http.StatusOK, rule)
}
