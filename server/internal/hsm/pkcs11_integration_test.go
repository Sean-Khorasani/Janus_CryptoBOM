//go:build !windows && cgo

package hsm

import (
	"os"
	"testing"
)

// These tests exercise the REAL PKCS#11 client against a live SoftHSM2 token. They are
// skipped unless JANUS_HSM_TEST_MODULE points at a PKCS#11 module and a token has been
// initialized (SOFTHSM2_CONF + JANUS_HSM_TEST_LABEL/PIN). scripts/hsm-softhsm-init.sh
// sets all of these up, so `make` on a box without SoftHSM still passes by skipping.
func testPKCS11Config(t *testing.T) HSMConfig {
	t.Helper()
	module := os.Getenv("JANUS_HSM_TEST_MODULE")
	if module == "" {
		t.Skip("set JANUS_HSM_TEST_MODULE (+ SOFTHSM2_CONF, JANUS_HSM_TEST_LABEL, JANUS_HSM_TEST_PIN) to run live SoftHSM tests")
	}
	label := os.Getenv("JANUS_HSM_TEST_LABEL")
	if label == "" {
		label = "JanusTestToken"
	}
	pin := os.Getenv("JANUS_HSM_TEST_PIN")
	if pin == "" {
		pin = "1234"
	}
	return HSMConfig{Mode: ModePKCS11, ModulePath: module, Label: label, Pin: pin}
}

// Command signing via the HSM: HMAC-SHA256 over a token-resident generic-secret key.
// This is the platform's PQC-safe signing capability (symmetric MAC) on real hardware.
func TestPKCS11_HMACCommandSigning(t *testing.T) {
	h, err := newPKCS11(testPKCS11Config(t))
	if err != nil {
		t.Fatalf("open token: %v", err)
	}
	defer h.Close()
	ms, ok := h.(MACSigner)
	if !ok {
		t.Fatal("pkcs11 client must implement MACSigner")
	}
	key := []byte("0123456789abcdef0123456789abcdef") // 32-byte command key
	const label = "janus-test-cmdkey"
	if err := ms.EnsureMACKey(label, key); err != nil {
		t.Fatalf("EnsureMACKey: %v", err)
	}
	if err := ms.EnsureMACKey(label, key); err != nil {
		t.Fatalf("EnsureMACKey must be idempotent: %v", err)
	}
	a, err := ms.MAC(label, []byte("canonical-command"))
	if err != nil || len(a) != 32 {
		t.Fatalf("MAC: len=%d err=%v", len(a), err)
	}
	b, _ := ms.MAC(label, []byte("canonical-command"))
	if string(a) != string(b) {
		t.Fatal("HMAC must be deterministic")
	}
	if c, _ := ms.MAC(label, []byte("tampered")); string(a) == string(c) {
		t.Fatal("HMAC must change with data")
	}
}

// Real ML-DSA (FIPS 204) asymmetric signing on the token — PQC, never RSA/ECDSA.
func TestPKCS11_MLDSASignVerify(t *testing.T) {
	h, err := newPKCS11(testPKCS11Config(t))
	if err != nil {
		t.Fatalf("open token: %v", err)
	}
	defer h.Close()

	keyID, err := h.GenerateKeyPair("ML-DSA-65")
	if err != nil {
		t.Skipf("token lacks ML-DSA (need the PQC SoftHSM build): %v", err)
	}
	msg := []byte("migration attestation payload")
	sig, err := h.Sign(keyID, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := h.Verify(keyID, msg, sig)
	if err != nil || !ok {
		t.Fatalf("valid ML-DSA signature must verify: ok=%v err=%v", ok, err)
	}
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xFF
	if ok, _ := h.Verify(keyID, msg, tampered); ok {
		t.Fatal("tampered ML-DSA signature must not verify")
	}
	if ok, _ := h.Verify(keyID, []byte("different"), sig); ok {
		t.Fatal("signature over different data must not verify")
	}
}

// The PQC mandate holds on the token too: RSA/ECDSA key generation is refused.
func TestPKCS11_RefusesNonPQC(t *testing.T) {
	h, err := newPKCS11(testPKCS11Config(t))
	if err != nil {
		t.Fatalf("open token: %v", err)
	}
	defer h.Close()
	for _, alg := range []string{"RSA-2048", "ECDSA-P384"} {
		if _, err := h.GenerateKeyPair(alg); err == nil {
			t.Errorf("GenerateKeyPair(%q) must be refused on the HSM (non-PQC)", alg)
		}
	}
}
