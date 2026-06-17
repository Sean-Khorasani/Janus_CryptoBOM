package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// validateNewPassword enforces the length floor and rejects reuse (AUTH-002).
func TestValidateNewPassword(t *testing.T) {
	if err := validateNewPassword("short", "old-password-123"); err == nil {
		t.Fatal("expected too-short password to be rejected")
	}
	if err := validateNewPassword("same-password-1", "same-password-1"); err == nil {
		t.Fatal("expected reuse of current password to be rejected")
	}
	if err := validateNewPassword("a-fresh-strong-passphrase", "old-password-123"); err != nil {
		t.Fatalf("valid new password rejected: %v", err)
	}
}

// The revocation cache reports a cutoff only for users that changed their password.
func TestRevocationCache(t *testing.T) {
	c := newRevocationCache()
	if got := c.before("nobody"); got != 0 {
		t.Fatalf("unknown user should have cutoff 0, got %d", got)
	}
	c.set("alice", 1000)
	if got := c.before("alice"); got != 1000 {
		t.Fatalf("alice cutoff: want 1000, got %d", got)
	}
	c.seedFromTimes(map[string]time.Time{"bob": time.Unix(2000, 0)})
	if got := c.before("bob"); got != 2000 {
		t.Fatalf("bob cutoff after seed: want 2000, got %d", got)
	}
}

// AuthMiddleware rejects a token whose iat predates the user's revocation cutoff
// (i.e. a password change since the token was issued), and admits one issued after.
func TestAuthMiddlewareSessionRevocation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cache := newRevocationCache()

	// A token issued "now"; set a cutoff far in the future to simulate a later change.
	tok, err := GenerateToken("admin", "admin", "default", secret)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cache.set("admin", time.Now().Add(1*time.Hour).Unix())

	handler := AuthMiddleware(secret, secret, false, cache.before, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("token minted before the revocation cutoff must be rejected, got %d", w.Code)
	}

	// No cutoff for the user -> the same token is accepted.
	cache2 := newRevocationCache()
	handler2 := AuthMiddleware(secret, secret, false, cache2.before, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	handler2.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("token should be accepted with no revocation cutoff, got %d", w2.Code)
	}
}
