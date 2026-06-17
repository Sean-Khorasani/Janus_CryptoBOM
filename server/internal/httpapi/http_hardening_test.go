package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// RateLimit returns 429 once a client IP exceeds the per-minute budget, and keys by
// IP (not ip:port) so varying the source port does not reset the count (HTTP-01).
func TestRateLimitByIP(t *testing.T) {
	h := RateLimit(2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	call := func(remote string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	// Same IP, different ephemeral ports — must share the window.
	if code := call("10.0.0.1:5001"); code != http.StatusOK {
		t.Fatalf("req 1: want 200, got %d", code)
	}
	if code := call("10.0.0.1:5002"); code != http.StatusOK {
		t.Fatalf("req 2: want 200, got %d", code)
	}
	if code := call("10.0.0.1:5003"); code != http.StatusTooManyRequests {
		t.Fatalf("req 3 over limit: want 429, got %d", code)
	}

	// A different IP is unaffected.
	if code := call("10.0.0.2:6000"); code != http.StatusOK {
		t.Fatalf("other IP: want 200, got %d", code)
	}
}

// bodyLimit caps request bodies; reading past the cap returns an error to the
// handler. Small bodies pass through unchanged; /api/ws is exempt.
func TestBodyLimit(t *testing.T) {
	var readErr error
	h := bodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))

	// Oversized body on a normal route -> read fails (MaxBytesReader).
	big := strings.NewReader(strings.Repeat("a", maxRequestBodyBytes+1024))
	req := httptest.NewRequest(http.MethodPost, "/api/policies", big)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if readErr == nil {
		t.Fatal("expected an error reading a body over the cap")
	}

	// Small body passes through.
	readErr = nil
	small := strings.NewReader(`{"ok":true}`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/policies", small)
	h.ServeHTTP(httptest.NewRecorder(), req2)
	if readErr != nil {
		t.Fatalf("small body should read cleanly, got %v", readErr)
	}
}
