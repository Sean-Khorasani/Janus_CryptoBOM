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
