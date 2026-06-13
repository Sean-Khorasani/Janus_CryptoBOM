package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AUTH-003: /api/certificates/csr must require authentication and an
// operator/admin role. Previously it was in the public allowlist, letting any
// network client mint PQC CSRs without credentials.

// The endpoint must no longer be reachable without a JWT. AuthMiddleware should
// reject an unauthenticated request before it ever reaches the handler.
func TestCSREndpointRequiresAuth(t *testing.T) {
	secret := []byte("test-signing-key-aaaaaaaaaaaaaaaa")
	reached := false
	guarded := AuthMiddleware(secret, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/certificates/csr",
		strings.NewReader(`{"common_name":"example.com"}`))
	rr := httptest.NewRecorder()
	guarded.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated CSR request status = %d, want 401", rr.Code)
	}
	if reached {
		t.Fatal("handler was reached without authentication")
	}
}

// With a JWT present, the role guard must still reject viewers and admit
// operators/admins. We assert the access-control contract: viewer → 403,
// operator → passes the guard (not 401/403).
func TestCSREndpointRoleGuard(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	wrapped := RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.createCSR))

	t.Run("viewer_forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/certificates/csr",
			strings.NewReader(`{"common_name":"example.com"}`))
		req = req.WithContext(context.WithValue(req.Context(), RoleContextKey, "viewer"))
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("viewer CSR request status = %d, want 403", rr.Code)
		}
	})

	t.Run("operator_passes_guard", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/certificates/csr",
			strings.NewReader(`{"common_name":"example.com","target_signature":"ML-DSA-65"}`))
		req = req.WithContext(context.WithValue(req.Context(), RoleContextKey, "operator"))
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		// The operator clears the role guard; the handler then runs. Whatever the
		// CSR-generation outcome, it must not be an auth/role rejection.
		if rr.Code == http.StatusForbidden || rr.Code == http.StatusUnauthorized {
			t.Fatalf("operator CSR request rejected by access control: status = %d", rr.Code)
		}
	})
}
