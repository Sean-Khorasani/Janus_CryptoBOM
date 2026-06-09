package hsm

import "time"

// KeyInfo holds metadata about a cryptographic key stored in the HSM.
type KeyInfo struct {
	KeyID     string    `json:"key_id"`
	Label     string    `json:"label"`
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
	IsPQC     bool      `json:"is_pqc"`
	CreatedAt time.Time `json:"created_at"`
}
