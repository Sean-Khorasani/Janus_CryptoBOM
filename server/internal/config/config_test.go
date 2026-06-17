package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommandSigningKeyFileOverridesEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command-signing-key")
	if err := os.WriteFile(path, []byte("file-based-command-signing-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JANUS_COMMAND_SIGNING_KEY", "environment-command-signing-key")
	t.Setenv("JANUS_COMMAND_SIGNING_KEY_FILE", path)

	cfg := FromEnv()

	if got, want := string(cfg.CommandSigningKey), "file-based-command-signing-key"; got != want {
		t.Fatalf("CommandSigningKey = %q, want %q", got, want)
	}
}

func TestMissingCommandSigningKeyFileFailsClosed(t *testing.T) {
	t.Setenv("JANUS_COMMAND_SIGNING_KEY", "environment-command-signing-key")
	t.Setenv("JANUS_COMMAND_SIGNING_KEY_FILE", filepath.Join(t.TempDir(), "missing"))

	defer func() {
		if recover() == nil {
			t.Fatal("FromEnv did not panic for missing signing key file")
		}
	}()
	FromEnv()
}

func TestGRPCMaxRecvBytesIsBoundedAndConfigurable(t *testing.T) {
	t.Setenv("JANUS_COMMAND_SIGNING_KEY", "environment-command-signing-key")
	t.Setenv("JANUS_COMMAND_SIGNING_KEY_FILE", "")
	t.Setenv("JANUS_GRPC_MAX_RECV_BYTES", "33554432")

	cfg := FromEnv()

	if cfg.GRPCMaxRecvBytes != 32*1024*1024 {
		t.Fatalf("GRPCMaxRecvBytes = %d", cfg.GRPCMaxRecvBytes)
	}
}

// OPS-002: the global API rate limit defaults sensibly, honors an explicit value, and
// treats negatives as "disabled" (0).
func TestAPIRateLimitConfig(t *testing.T) {
	t.Setenv("JANUS_COMMAND_SIGNING_KEY", "environment-command-signing-key")
	t.Setenv("JANUS_COMMAND_SIGNING_KEY_FILE", "")

	t.Setenv("JANUS_API_RATE_LIMIT_PER_MIN", "")
	if got := FromEnv().APIRateLimitPerMin; got != DefaultAPIRateLimitPerMin {
		t.Fatalf("default APIRateLimitPerMin = %d, want %d", got, DefaultAPIRateLimitPerMin)
	}

	t.Setenv("JANUS_API_RATE_LIMIT_PER_MIN", "120")
	if got := FromEnv().APIRateLimitPerMin; got != 120 {
		t.Fatalf("explicit APIRateLimitPerMin = %d, want 120", got)
	}

	t.Setenv("JANUS_API_RATE_LIMIT_PER_MIN", "0")
	if got := FromEnv().APIRateLimitPerMin; got != 0 {
		t.Fatalf("disabled APIRateLimitPerMin = %d, want 0", got)
	}

	t.Setenv("JANUS_API_RATE_LIMIT_PER_MIN", "-5")
	if got := FromEnv().APIRateLimitPerMin; got != 0 {
		t.Fatalf("negative APIRateLimitPerMin = %d, want clamped to 0", got)
	}
}
