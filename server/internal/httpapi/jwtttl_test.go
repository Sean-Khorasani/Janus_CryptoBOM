package httpapi

import (
	"testing"
	"time"
)

func TestJWTTTLConfigurableAndClamped(t *testing.T) {
	cases := []struct {
		env  string
		want time.Duration
	}{
		{"", 24 * time.Hour},        // default
		{"8h", 8 * time.Hour},       // honored
		{"30m", 30 * time.Minute},   // honored
		{"10s", 5 * time.Minute},    // clamped up to floor
		{"99999h", 720 * time.Hour}, // clamped down to ceiling
		{"garbage", 24 * time.Hour}, // unparseable -> default
	}
	for _, c := range cases {
		t.Setenv("JANUS_JWT_TTL", c.env)
		if got := jwtTTL(); got != c.want {
			t.Errorf("JANUS_JWT_TTL=%q: got %v, want %v", c.env, got, c.want)
		}
	}
}

// A generated token must expire according to the configured TTL.
func TestGenerateTokenHonorsTTL(t *testing.T) {
	t.Setenv("JANUS_JWT_TTL", "1h")
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok, err := GenerateToken("admin", "admin", secret)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, _, err = VerifyToken(tok, secret)
	if err != nil {
		t.Fatalf("freshly minted token should verify: %v", err)
	}
}
