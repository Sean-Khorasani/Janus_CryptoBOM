package hsm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/janus-cbom/janus/server/internal/config"
)

// HSM settings must resolve from the optional server config file (JANUS_CONFIG_FILE), not only
// from environment variables — i.e. LoadConfigFromEnv goes through the config resolver.
func TestLoadConfigFromEnvHonorsConfigFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "janus.env")
	body := "JANUS_HSM_MODE=disabled\n" +
		"JANUS_HSM_COMMAND_KEY_LABEL=from-file-label\n" +
		"JANUS_HSM_SIGN_COMMANDS=true\n" +
		"JANUS_HSM_MODULE_PATH=/opt/from-file.so\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JANUS_CONFIG_FILE", p)
	// Ensure the env layer is empty so the file layer is what's exercised.
	t.Setenv("JANUS_HSM_MODE", "")
	t.Setenv("JANUS_HSM_COMMAND_KEY_LABEL", "")
	t.Setenv("JANUS_HSM_SIGN_COMMANDS", "")
	t.Setenv("JANUS_HSM_MODULE_PATH", "")
	config.ReloadFile()
	t.Cleanup(func() {
		_ = os.Unsetenv("JANUS_CONFIG_FILE")
		config.ReloadFile()
	})

	cfg := LoadConfigFromEnv()
	if cfg.Mode != ModeDisabled {
		t.Errorf("Mode = %q, want disabled (from file)", cfg.Mode)
	}
	if cfg.CommandKeyLabel != "from-file-label" {
		t.Errorf("CommandKeyLabel = %q, want from-file-label", cfg.CommandKeyLabel)
	}
	if !cfg.SignCommands {
		t.Error("SignCommands should be true (from file)")
	}
	if cfg.ModulePath != "/opt/from-file.so" {
		t.Errorf("ModulePath = %q, want /opt/from-file.so", cfg.ModulePath)
	}
}

// An env var still overrides the config file.
func TestEnvOverridesConfigFileForHSM(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "janus.env")
	if err := os.WriteFile(p, []byte("JANUS_HSM_MODE=disabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JANUS_CONFIG_FILE", p)
	t.Setenv("JANUS_HSM_MODE", "software")
	config.ReloadFile()
	t.Cleanup(func() {
		_ = os.Unsetenv("JANUS_CONFIG_FILE")
		config.ReloadFile()
	})

	if cfg := LoadConfigFromEnv(); cfg.Mode != ModeSoftware {
		t.Errorf("Mode = %q, want software (env overrides file)", cfg.Mode)
	}
}
