package hsm

import (
	"os"
	"strconv"
	"strings"

	"github.com/janus-cbom/janus/server/internal/config"
)

// DefaultCommandKeyLabel is the HSM object label for the command-signing key when
// JANUS_HSM_COMMAND_KEY_LABEL is unset.
const DefaultCommandKeyLabel = "janus-command-signing"

// Mode selects which HSM backend the server uses (configurable; see LoadConfigFromEnv).
type Mode string

const (
	// ModeDisabled wires no HSM: /api/hsm/* return 501 and command signing stays in-process.
	ModeDisabled Mode = "disabled"
	// ModeSoftware uses the in-process software keystore (real ML-DSA via circl; no hardware).
	ModeSoftware Mode = "software"
	// ModePKCS11 uses a real PKCS#11 token (SoftHSM2 or hardware). Fail-closed: if the
	// module/token cannot be opened the server refuses to start.
	ModePKCS11 Mode = "pkcs11"
)

// HSMConfig holds configuration for the HSM backend: how a PKCS#11 token is reached and
// whether migration-command signing is routed through an HSM-resident key.
type HSMConfig struct {
	Mode Mode `json:"mode"`
	// ModulePath is the filesystem path to the PKCS#11 module (.so/.dll). PKCS#11 mode only.
	ModulePath string `json:"module_path"`
	// Pin is the user PIN for the token session. PKCS#11 mode only. Never serialized.
	Pin string `json:"-"`
	// SlotID identifies the slot by its (possibly very large) PKCS#11 slot id.
	SlotID int `json:"slot_id"`
	// SlotIndex selects the slot by its 0-based position in C_GetSlotList (token-present),
	// which is far more practical than a large slot id. -1 means "unset". Preferred over
	// SlotID; Label (when set) wins over both.
	SlotIndex int `json:"slot_index"`
	// Label is the token label used to locate the slot (highest priority).
	Label string `json:"label"`
	// SignCommands routes migration-command HMAC signing through an HSM-resident key.
	SignCommands bool `json:"sign_commands"`
	// CommandKeyLabel is the HSM object label under which the command-signing key lives.
	CommandKeyLabel string `json:"command_key_label"`
}

// LoadConfigFromEnv builds the HSM config from JANUS_HSM_* settings, resolved with precedence
// environment variable > config file (JANUS_CONFIG_FILE) > default — so the optional server
// config file covers HSM settings too. The default mode is "software" so existing deployments
// keep working with no new config.
func LoadConfigFromEnv() HSMConfig {
	mode := Mode(strings.ToLower(strings.TrimSpace(config.Value("JANUS_HSM_MODE"))))
	switch mode {
	case ModeDisabled, ModeSoftware, ModePKCS11:
		// valid
	default:
		mode = ModeSoftware
	}
	slot := 0
	if v := config.Value("JANUS_HSM_SLOT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			slot = n
		}
	}
	slotIndex := -1
	if v := config.Value("JANUS_HSM_SLOT_INDEX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			slotIndex = n
		}
	}
	pin := config.Value("JANUS_HSM_PIN")
	if f := config.Value("JANUS_HSM_PIN_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			pin = strings.TrimRight(string(b), "\r\n")
		}
	}
	return HSMConfig{
		Mode:            mode,
		ModulePath:      config.Value("JANUS_HSM_MODULE_PATH"),
		Pin:             pin,
		SlotID:          slot,
		SlotIndex:       slotIndex,
		Label:           config.Value("JANUS_HSM_TOKEN_LABEL"),
		SignCommands:    config.BoolValue("JANUS_HSM_SIGN_COMMANDS"),
		CommandKeyLabel: config.ValueOr("JANUS_HSM_COMMAND_KEY_LABEL", DefaultCommandKeyLabel),
	}
}
