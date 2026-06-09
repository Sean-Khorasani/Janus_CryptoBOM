package hsm

// HSMConfig holds configuration for connecting to a PKCS#11-compatible HSM.
type HSMConfig struct {
	// ModulePath is the filesystem path to the PKCS#11 module (.dll or .so).
	ModulePath string `json:"module_path"`
	// PIN is the security officer or user PIN for the HSM session.
	Pin string `json:"pin"`
	// SlotID identifies the slot to use on the HSM.
	SlotID int `json:"slot_id"`
	// Label is an optional label to identify the token.
	Label string `json:"label"`
}
