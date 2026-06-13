package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/janus-cbom/janus/server/internal/config"
)

func loginReq(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// LoginHandler must accept only configured, bcrypt-hashed credentials and reject
// everything else — no compiled-in passwords (S1 regression).
func TestLoginHandlerConfiguredCredentials(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret-pw"), bcrypt.DefaultCost)
	creds := []config.Credential{{Username: "admin", Role: "admin", Hash: hash}}
	h := LoginHandler([]byte("0123456789abcdef0123456789abcdef"), false, creds)

	// Valid credential -> 200 with a token + role.
	w := httptest.NewRecorder()
	h(w, loginReq(`{"username":"admin","password":"s3cret-pw"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("valid login: got %d, body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"role":"admin"`) || !strings.Contains(w.Body.String(), `"token":`) {
		t.Fatalf("expected token+role, got %s", w.Body.String())
	}

	// Wrong password -> 401.
	w = httptest.NewRecorder()
	h(w, loginReq(`{"username":"admin","password":"wrong"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d", w.Code)
	}

	// The old hardcoded password must NOT work.
	w = httptest.NewRecorder()
	h(w, loginReq(`{"username":"admin","password":"janus-admin-pass"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("legacy hardcoded password must be rejected: got %d", w.Code)
	}

	// Unknown user -> 401.
	w = httptest.NewRecorder()
	h(w, loginReq(`{"username":"ghost","password":"s3cret-pw"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown user: got %d", w.Code)
	}
}

// With no credentials configured and auth enabled, login fails closed.
func TestLoginHandlerNoCredentialsFailsClosed(t *testing.T) {
	h := LoginHandler([]byte("0123456789abcdef0123456789abcdef"), false, nil)
	w := httptest.NewRecorder()
	h(w, loginReq(`{"username":"admin","password":"anything"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no creds should reject all logins: got %d", w.Code)
	}
}
