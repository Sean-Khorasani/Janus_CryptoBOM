package orchestrator

import (
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// MLDSACommandSigner signs migration commands with ML-DSA (FIPS 204) instead of HMAC, so
// agents VERIFY with the server's public key (asymmetric) — a leaked agent can no longer
// forge commands the way a shared HMAC key allows. Used when JANUS_COMMAND_SIG_SCHEME=
// ml-dsa with the software backend. (HSM-resident ML-DSA command keys delegate to
// hsm.HSM.Sign via Orchestrator.UseAsymSigner instead.)
type MLDSACommandSigner struct {
	algorithm string
	scheme    sign.Scheme
	priv      sign.PrivateKey
	pub       sign.PublicKey
}

// NewMLDSACommandSigner generates a fresh ML-DSA key pair for command signing.
func NewMLDSACommandSigner(algorithm string) (*MLDSACommandSigner, error) {
	scheme := schemes.ByName(algorithm)
	if scheme == nil {
		return nil, fmt.Errorf("unknown ML-DSA algorithm %q", algorithm)
	}
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate %s command key: %w", algorithm, err)
	}
	return &MLDSACommandSigner{algorithm: algorithm, scheme: scheme, priv: priv, pub: pub}, nil
}

// NewMLDSACommandSignerFromSeed derives a deterministic key pair from a 32+ byte seed.
// Used for reproducible cross-language test vectors and for operators who want a stable
// command public key without an HSM (seed supplied via secret storage).
func NewMLDSACommandSignerFromSeed(algorithm string, seed []byte) (*MLDSACommandSigner, error) {
	scheme := schemes.ByName(algorithm)
	if scheme == nil {
		return nil, fmt.Errorf("unknown ML-DSA algorithm %q", algorithm)
	}
	if len(seed) < scheme.SeedSize() {
		return nil, fmt.Errorf("seed too short for %s: need %d bytes", algorithm, scheme.SeedSize())
	}
	pub, priv := scheme.DeriveKey(seed[:scheme.SeedSize()])
	return &MLDSACommandSigner{algorithm: algorithm, scheme: scheme, priv: priv, pub: pub}, nil
}

// NewMLDSACommandSignerFromKey loads a software ML-DSA command signer from a private key's
// standard binary encoding (as produced by certmanager.IssueMLDSAChain / `pki command-ca`).
// Used for the CA-chained (janus-sig-v2) command path so the signing key corresponds to a
// persistent leaf certificate the agents trust via the bundled root.
func NewMLDSACommandSignerFromKey(algorithm string, keyBytes []byte) (*MLDSACommandSigner, error) {
	scheme := schemes.ByName(algorithm)
	if scheme == nil {
		return nil, fmt.Errorf("unknown ML-DSA algorithm %q", algorithm)
	}
	priv, err := scheme.UnmarshalBinaryPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("load %s command key: %w", algorithm, err)
	}
	pub, ok := priv.Public().(sign.PublicKey)
	if !ok {
		return nil, fmt.Errorf("loaded %s key has no usable public key", algorithm)
	}
	return &MLDSACommandSigner{algorithm: algorithm, scheme: scheme, priv: priv, pub: pub}, nil
}

// Sign returns the ML-DSA signature over the canonical command bytes.
func (m *MLDSACommandSigner) Sign(canonical []byte) ([]byte, error) {
	return m.scheme.Sign(m.priv, canonical, nil), nil
}

// PublicKey returns the standard FIPS 204 encoding of the verification key, which the
// agent loads to verify commands.
func (m *MLDSACommandSigner) PublicKey() ([]byte, error) {
	return m.pub.MarshalBinary()
}

// Algorithm reports the ML-DSA parameter set (e.g. "ML-DSA-65").
func (m *MLDSACommandSigner) Algorithm() string { return m.algorithm }
