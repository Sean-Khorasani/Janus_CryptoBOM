package hsm

// HSM defines the interface for Hardware Security Module operations.
// Implementations can use PKCS#11 (via SoftHSM2 or a real HSM) or a software fallback.
type HSM interface {
	// ListKeys returns all keys stored in the HSM.
	ListKeys() ([]KeyInfo, error)

	// Sign signs the given data with the specified key and returns the signature.
	Sign(keyID string, data []byte) ([]byte, error)

	// Verify checks that the signature is valid for the given data and key.
	Verify(keyID string, data, signature []byte) (bool, error)

	// GenerateKeyPair creates a new asymmetric key pair with the given algorithm.
	GenerateKeyPair(algorithm string) (string, error)

	// GetKeyInfo returns metadata for a specific key.
	GetKeyInfo(keyID string) (*KeyInfo, error)

	// Close releases all HSM resources and sessions.
	Close() error
}
