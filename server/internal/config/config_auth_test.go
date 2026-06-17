package config

import (
	"bytes"
	"testing"
)

// AUTH-03: JANUS_JWT_SECRET defaults to the command key but can be set independently.
// AUTH-01: JANUS_REQUIRE_MTLS implies JANUS_REQUIRE_TLS; neither is required by default.
func TestFromEnvJWTSecretAndTLSFlags(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	t.Setenv("JANUS_COMMAND_SIGNING_KEY", key)

	cfg := FromEnv()
	if !bytes.Equal(cfg.JWTSecret, []byte(key)) {
		t.Fatalf("JWTSecret should default to the command key when JANUS_JWT_SECRET is unset")
	}
	if cfg.RequireTLS || cfg.RequireMTLS {
		t.Fatalf("TLS/mTLS must not be required by default")
	}

	t.Setenv("JANUS_JWT_SECRET", "fedcba9876543210fedcba9876543210")
	cfg = FromEnv()
	if bytes.Equal(cfg.JWTSecret, cfg.CommandSigningKey) {
		t.Fatalf("JWTSecret should be the distinct JANUS_JWT_SECRET, not the command key")
	}

	t.Setenv("JANUS_REQUIRE_MTLS", "true")
	cfg = FromEnv()
	if !cfg.RequireMTLS || !cfg.RequireTLS {
		t.Fatalf("RequireMTLS must imply RequireTLS; got mtls=%v tls=%v", cfg.RequireMTLS, cfg.RequireTLS)
	}
}
