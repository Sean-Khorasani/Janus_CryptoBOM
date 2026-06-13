package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OPS-001: while draining, /api/health must report "draining" with 503 and new
// non-health requests must be rejected with 503 so load balancers stop routing.

func TestHealthReportsDraining(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})

	// Before draining: healthy.
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rr := httptest.NewRecorder()
	api.health(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("pre-drain health = %d, want 200", rr.Code)
	}

	// After BeginDraining: 503 with status "draining".
	api.BeginDraining()
	rr = httptest.NewRecorder()
	api.health(rr, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining health = %d, want 503", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "draining") {
		t.Fatalf("draining health body = %q, want it to contain \"draining\"", body)
	}
}

func TestDrainGuardRejectsNewRequests(t *testing.T) {
	api := newTestAPI(&handlerMockStore{})
	reached := false
	guarded := drainGuard(api, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// Not draining: request passes through.
	rr := httptest.NewRecorder()
	guarded.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	if !reached || rr.Code != http.StatusOK {
		t.Fatalf("pre-drain request blocked unexpectedly: reached=%v code=%d", reached, rr.Code)
	}

	// Draining: non-health request rejected with 503; handler not reached.
	api.BeginDraining()
	reached = false
	rr = httptest.NewRecorder()
	guarded.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	if reached {
		t.Fatal("handler reached while draining")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining request = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on drain rejection")
	}

	// Health endpoint stays reachable while draining so probes can observe state.
	reached = false
	rr = httptest.NewRecorder()
	guarded.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if !reached {
		t.Fatal("health endpoint blocked while draining; probes cannot observe state")
	}
}
