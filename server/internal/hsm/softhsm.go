package hsm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SoftHSM2 implements the HSM interface using an in-memory software keystore.
// This is a development/testing fallback when no physical HSM is available.
//
// Sign/Verify use real HMAC-SHA256 over a per-key random secret, so signatures
// are unforgeable and Verify actually validates them (S5). The previous stub
// returned a fixed byte pattern and Verify returned true for ANY signature —
// a forgery hole if this fallback were ever reachable in production.
type SoftHSM2 struct {
	mu      sync.Mutex
	keys    map[string]KeyInfo
	secrets map[string][]byte // keyID -> HMAC secret
}

// NewSoftHSM2 creates a new SoftHSM2 software HSM instance.
func NewSoftHSM2() *SoftHSM2 {
	return &SoftHSM2{
		keys:    make(map[string]KeyInfo),
		secrets: make(map[string][]byte),
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

	secret, ok := s.secrets[keyID]
	if !ok {
		return nil, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// Verify recomputes the HMAC over data and constant-time compares it to the
// supplied signature. Returns false for a tampered signature or unknown key —
// never an unconditional true.
func (s *SoftHSM2) Verify(keyID string, data, signature []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	secret, ok := s.secrets[keyID]
	if !ok {
		return false, fmt.Errorf("softhsm: key %s not found", keyID)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), signature), nil
}

// GenerateKeyPair creates a new key pair and stores it in memory.
func (s *SoftHSM2) GenerateKeyPair(algorithm string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyID := uuid.NewString()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("softhsm: generate key secret: %w", err)
	}
	ki := KeyInfo{
		KeyID:     keyID,
		Label:     fmt.Sprintf("janus-soft-%s-%d", algorithm, time.Now().Unix()),
		Algorithm: algorithm,
		KeySize:   256,
		IsPQC:     algorithm == "ML-KEM-768" || algorithm == "ML-DSA-65",
		CreatedAt: time.Now(),
	}
	s.keys[keyID] = ki
	s.secrets[keyID] = secret
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
