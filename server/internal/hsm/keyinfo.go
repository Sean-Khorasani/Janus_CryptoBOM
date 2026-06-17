package hsm

import "time"

// SlotDetail describes one PKCS#11 slot for the `hsm info` CLI: the practical 0-based
// index, the (possibly huge) slot id, and token metadata from C_GetTokenInfo.
type SlotDetail struct {
	Index        int    `json:"index"`
	SlotID       uint   `json:"slot_id"`
	TokenPresent bool   `json:"token_present"`
	Label        string `json:"label"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
}

// KeyInfo holds metadata about a cryptographic key stored in the HSM.
type KeyInfo struct {
	KeyID     string    `json:"key_id"`
	Label     string    `json:"label"`
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
	IsPQC     bool      `json:"is_pqc"`
	CreatedAt time.Time `json:"created_at"`
}
