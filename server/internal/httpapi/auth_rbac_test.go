package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// AUTH-004: privileged endpoints (e.g. HSM sign/verify) are wrapped with
// RequireRole(operator, admin). Verify the guard blocks lower roles and the
// missing-context case, and admits operator/admin.
func TestRequireRoleGuardsPrivilegedEndpoints(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	guarded := RequireRole([]string{"operator", "admin"})(next)

	cases := []struct {
		role       string
		setRole    bool
		wantStatus int
		wantReach  bool
	}{
		{"admin", true, http.StatusOK, true},
		{"operator", true, http.StatusOK, true},
		{"viewer", true, http.StatusForbidden, false},
		{"", false, http.StatusForbidden, false}, // no role in context
	}
	for _, c := range cases {
		reached = false
		r := httptest.NewRequest(http.MethodPost, "/api/hsm/sign", nil)
		if c.setRole {
			r = r.WithContext(context.WithValue(r.Context(), RoleContextKey, c.role))
		}
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		if w.Code != c.wantStatus {
			t.Errorf("role=%q: status got %d want %d", c.role, w.Code, c.wantStatus)
		}
		if reached != c.wantReach {
			t.Errorf("role=%q: handler reached=%v want %v", c.role, reached, c.wantReach)
		}
	}
}
