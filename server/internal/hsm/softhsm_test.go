package hsm

import "testing"

// SoftHSM2 must do real HMAC crypto: a genuine signature verifies, a tampered
// one does not, and an unknown key never returns a blanket true (S5 regression).
func TestSoftHSM2SignVerifyRoundTrip(t *testing.T) {
	h := NewSoftHSM2()
	keyID, err := h.GenerateKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data := []byte("attestation payload")
	sig, err := h.Sign(keyID, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := h.Verify(keyID, data, sig)
	if err != nil || !ok {
		t.Fatalf("valid signature should verify: ok=%v err=%v", ok, err)
	}

	// Tampered signature must fail.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xFF
	if ok, _ := h.Verify(keyID, data, bad); ok {
		t.Fatal("tampered signature must not verify")
	}
	// Tampered data must fail.
	if ok, _ := h.Verify(keyID, []byte("different payload"), sig); ok {
		t.Fatal("signature over different data must not verify")
	}
	// Unknown key must error, not return true.
	if ok, err := h.Verify("no-such-key", data, sig); ok || err == nil {
		t.Fatalf("unknown key must fail: ok=%v err=%v", ok, err)
	}
	// Two keys must not share secrets.
	other, _ := h.GenerateKeyPair("ML-DSA-65")
	if ok, _ := h.Verify(other, data, sig); ok {
		t.Fatal("signature must not verify under a different key")
	}
}
