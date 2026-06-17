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

// MACSigner is an optional HSM capability: compute a keyed MAC (HMAC-SHA256) over data
// using an HSM-resident secret key identified by a stable label. This backs HSM-resident
// migration-command signing. HMAC-SHA256 is a SYMMETRIC MAC and is quantum-resistant
// (CNSA 2.0 accepts SHA-256), so it is PQC-safe — it is deliberately NOT an asymmetric
// digital signature (those must be ML-DSA/SLH-DSA; RSA/ECDSA are never used).
type MACSigner interface {
	// EnsureMACKey imports keyMaterial under label if no key with that label exists.
	EnsureMACKey(label string, keyMaterial []byte) error
	// MAC returns the HMAC-SHA256 of data using the labelled key.
	MAC(label string, data []byte) ([]byte, error)
}

// CommandKeyManager is the optional HSM capability for HSM-resident ML-DSA migration-
// command signing: ensure a stable-labelled ML-DSA key exists (so the public key is
// persistent across restarts) and export its public key for agents to verify with. The
// returned keyID is the label, usable with Sign/Verify.
type CommandKeyManager interface {
	// EnsureMLDSAKey returns the keyID of an existing ML-DSA key with the label, or
	// generates one (with that label) and returns it.
	EnsureMLDSAKey(label, algorithm string) (keyID string, err error)
	// PublicKey returns the FIPS 204 standard encoding of the key's verification key.
	PublicKey(keyID string) ([]byte, error)
}

// acceptedPQCSignatureAlgs are the ONLY asymmetric digital-signature algorithms Janus will
// produce. RSA and ECDSA are excluded on purpose — Shor's algorithm breaks them, which is
// the reason this platform exists. Any asymmetric-signing request for another algorithm
// must fail closed (never silently downgrade to a classical signature).
var acceptedPQCSignatureAlgs = map[string]bool{
	"ML-DSA-44": true, "ML-DSA-65": true, "ML-DSA-87": true,
	"SLH-DSA-SHA2-128S": true, "SLH-DSA-SHA2-128F": true,
	"SLH-DSA-SHA2-192S": true, "SLH-DSA-SHA2-256S": true,
}

// IsAcceptedPQCSignatureAlg reports whether alg is a NIST PQC signature standard Janus
// will sign with (FIPS 204 ML-DSA / FIPS 205 SLH-DSA).
func IsAcceptedPQCSignatureAlg(alg string) bool { return acceptedPQCSignatureAlgs[alg] }
