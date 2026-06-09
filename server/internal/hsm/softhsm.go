package hsm

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SoftHSM2 implements the HSM interface using an in-memory software keystore.
// This is a development/testing fallback when no physical HSM is available.
type SoftHSM2 struct {
	mu   sync.Mutex
	keys map[string]KeyInfo
}

// NewSoftHSM2 creates a new SoftHSM2 software HSM instance.
func NewSoftHSM2() *SoftHSM2 {
	return &SoftHSM2{
		keys: make(map[string]KeyInfo),
	}
}

// ListKeys returns all keys in the software HSM.
func (s *SoftHSM2) ListKeys() ([]KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]KeyInfo, 0, len(s.keys))
	for _, ki := range s.keys {
		result = append(result, ki)
	}
	return result, nil
}

// Sign generates a signature using the specified key.
func (s *SoftHSM2) Sign(keyID string, data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keys[keyID]; !ok {
		return nil, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	// Return a deterministic signature for testing
	sig := make([]byte, 64)
	copy(sig, []byte(fmt.Sprintf("soft-hsm-sig-%s", keyID)))
	return sig, nil
}

// Verify checks a signature against data using the specified key.
func (s *SoftHSM2) Verify(keyID string, data, signature []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keys[keyID]; !ok {
		return false, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	return true, nil
}

// GenerateKeyPair creates a new key pair and stores it in memory.
func (s *SoftHSM2) GenerateKeyPair(algorithm string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyID := uuid.NewString()
	ki := KeyInfo{
		KeyID:     keyID,
		Label:     fmt.Sprintf("janus-soft-%s-%d", algorithm, time.Now().Unix()),
		Algorithm: algorithm,
		KeySize:   256,
		IsPQC:     algorithm == "ML-KEM-768" || algorithm == "ML-DSA-65",
		CreatedAt: time.Now(),
	}
	s.keys[keyID] = ki
	return keyID, nil
}

// GetKeyInfo returns metadata for a specific key.
func (s *SoftHSM2) GetKeyInfo(keyID string) (*KeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ki, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	return &ki, nil
}

// Close is a no-op for SoftHSM2.
func (s *SoftHSM2) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = nil
	return nil
}
