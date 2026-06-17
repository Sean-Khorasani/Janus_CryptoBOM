package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// writeError must never echo the internal error to the client (HTTP-03): a leaked
// pgx/SQL/config string would aid an attacker. The body is a fixed generic message.
func TestWriteErrorSanitizesInternalDetail(t *testing.T) {
	w := httptest.NewRecorder()
	secret := "pg: password=hunter2 host=10.0.0.5 SELECT * FROM users"
	writeError(w, errors.New(secret))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "password") || strings.Contains(body, "SELECT") || strings.Contains(body, "10.0.0.5") {
		t.Fatalf("internal error detail leaked to client: %s", body)
	}
	if !strings.Contains(body, "internal server error") {
		t.Fatalf("expected a generic error body, got %s", body)
	}
}

// requestLogger must capture the downstream status (default 200 when the handler
// never calls WriteHeader) and pass the request through unchanged.
func TestRequestLoggerCapturesStatus(t *testing.T) {
	// Default 200 (handler writes a body, no explicit WriteHeader).
	h := requestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/overview", nil))
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("passthrough failed: code=%d body=%q", w.Code, w.Body.String())
	}

	// Explicit error status is preserved.
	h2 := requestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	w2 := httptest.NewRecorder()
	h2.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	if w2.Code != http.StatusTeapot {
		t.Fatalf("status not preserved: got %d", w2.Code)
	}
}
