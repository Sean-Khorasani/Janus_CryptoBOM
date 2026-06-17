package hsm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
	"github.com/google/uuid"
)

// SoftHSM2 is the in-process software keystore used when no hardware HSM is configured
// (dev/eval). It is PQC-correct: asymmetric Sign/Verify use real NIST ML-DSA (FIPS 204)
// via cloudflare/circl — never RSA or ECDSA, which Shor's algorithm breaks. It also
// implements MACSigner (HMAC-SHA256) so it can back HSM-resident migration-command
// signing in software mode. Keys are process-local and lost on restart.
type SoftHSM2 struct {
	mu      sync.Mutex
	keys    map[string]*softKey // keyID -> asymmetric PQC key
	byLabel map[string]string   // label -> keyID (for stable command keys)
	macKeys map[string][]byte   // label  -> HMAC secret (command signing)
}

type softKey struct {
	info   KeyInfo
	scheme sign.Scheme
	priv   sign.PrivateKey
	pub    sign.PublicKey
}

// NewSoftHSM2 creates a new software keystore instance.
func NewSoftHSM2() *SoftHSM2 {
	return &SoftHSM2{
		keys:    make(map[string]*softKey),
		byLabel: make(map[string]string),
		macKeys: make(map[string][]byte),
	}
}

// ListKeys returns metadata for all asymmetric keys in the keystore.
func (s *SoftHSM2) ListKeys() ([]KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]KeyInfo, 0, len(s.keys))
	for _, k := range s.keys {
		result = append(result, k.info)
	}
	return result, nil
}

// GenerateKeyPair creates a real PQC signing key pair. Non-PQC algorithms (RSA/ECDSA)
// are refused — Janus only produces quantum-resistant signatures.
func (s *SoftHSM2) GenerateKeyPair(algorithm string) (string, error) {
	if !IsAcceptedPQCSignatureAlg(algorithm) {
		return "", fmt.Errorf("softhsm: refusing to generate a non-PQC signing key %q; Janus signs only with ML-DSA/SLH-DSA (FIPS 204/205)", algorithm)
	}
	scheme := schemes.ByName(algorithm)
	if scheme == nil {
		return "", fmt.Errorf("softhsm: PQC algorithm %q is not available in this build", algorithm)
	}
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("softhsm: generate %s key: %w", algorithm, err)
	}
	keyID := uuid.NewString()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[keyID] = &softKey{
		info: KeyInfo{
			KeyID:     keyID,
			Label:     fmt.Sprintf("janus-soft-%s-%d", algorithm, time.Now().Unix()),
			Algorithm: algorithm,
			KeySize:   scheme.PublicKeySize() * 8,
			IsPQC:     true,
			CreatedAt: time.Now(),
		},
		scheme: scheme,
		priv:   priv,
		pub:    pub,
	}
	return keyID, nil
}

// Sign produces a real ML-DSA/SLH-DSA signature over data using the named key.
func (s *SoftHSM2) Sign(keyID string, data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	return k.scheme.Sign(k.priv, data, nil), nil
}

// Verify checks a PQC signature for the named key. Returns false (never an unconditional
// true) for a tampered signature or unknown key.
func (s *SoftHSM2) Verify(keyID string, data, signature []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return false, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	return k.scheme.Verify(k.pub, data, signature, nil), nil
}

// GetKeyInfo returns metadata for a specific key.
func (s *SoftHSM2) GetKeyInfo(keyID string) (*KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	info := k.info
	return &info, nil
}

// EnsureMACKey stores keyMaterial under label if no MAC key with that label exists
// (MACSigner). This is how the command-signing key is held in the software keystore.
func (s *SoftHSM2) EnsureMACKey(label string, keyMaterial []byte) error {
	if len(keyMaterial) == 0 {
		return fmt.Errorf("softhsm: MAC key material is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.macKeys[label]; !ok {
		s.macKeys[label] = append([]byte(nil), keyMaterial...)
	}
	return nil
}

// MAC returns the HMAC-SHA256 of data under the labelled key (MACSigner).
func (s *SoftHSM2) MAC(label string, data []byte) ([]byte, error) {
	s.mu.Lock()
	secret, ok := s.macKeys[label]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("softhsm: MAC key %q not found", label)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// EnsureMLDSAKey returns the keyID for the labelled ML-DSA key, generating one if absent
// (CommandKeyManager). Software keys are process-local: the public key is stable for the
// process lifetime but changes on restart (use pkcs11 mode for a persistent command key).
func (s *SoftHSM2) EnsureMLDSAKey(label, algorithm string) (string, error) {
	s.mu.Lock()
	if id, ok := s.byLabel[label]; ok {
		s.mu.Unlock()
		return id, nil
	}
	s.mu.Unlock()
	keyID, err := s.GenerateKeyPair(algorithm)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.byLabel[label] = keyID
	if k := s.keys[keyID]; k != nil {
		k.info.Label = label
	}
	s.mu.Unlock()
	return keyID, nil
}

// PublicKey returns the FIPS 204 encoding of the key's verification key (CommandKeyManager).
func (s *SoftHSM2) PublicKey(keyID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	return k.pub.MarshalBinary()
}

// Close clears all key material.
func (s *SoftHSM2) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = nil
	s.byLabel = nil
	s.macKeys = nil
	return nil
}

// randomMACKey is a helper for callers that need to mint a fresh command MAC key.
func randomMACKey() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}
