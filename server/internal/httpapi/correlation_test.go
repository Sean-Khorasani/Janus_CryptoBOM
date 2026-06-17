package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// correlationMiddleware reuses a well-formed inbound ID, replaces a malformed one,
// generates one when absent, and always echoes it on the response + into context (OPS-004).
func TestCorrelationMiddleware(t *testing.T) {
	var ctxID string
	h := correlationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = correlationID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Well-formed inbound ID is reused on both the response header and context.
	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set(CorrelationHeader, "abc-123_OK.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if got := w.Header().Get(CorrelationHeader); got != "abc-123_OK.1" {
		t.Fatalf("valid inbound id should be reused, got %q", got)
	}
	if ctxID != "abc-123_OK.1" {
		t.Fatalf("context id mismatch: %q", ctxID)
	}

	// Malformed inbound ID (spaces/newline) is rejected and replaced.
	req = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set(CorrelationHeader, "bad id\nwith newline")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if got := w.Header().Get(CorrelationHeader); got == "" || got == "bad id\nwith newline" {
		t.Fatalf("malformed id should be replaced, got %q", got)
	}

	// Absent ID is generated.
	req = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Header().Get(CorrelationHeader) == "" || ctxID == "" {
		t.Fatal("missing id should be generated and propagated")
	}
}
