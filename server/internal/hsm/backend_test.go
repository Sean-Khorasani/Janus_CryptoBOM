package hsm

import "testing"

// The software backend must REFUSE classical signature algorithms — Janus is a PQC
// platform and never signs with RSA or ECDSA.
func TestSoftHSMRefusesNonPQC(t *testing.T) {
	h := NewSoftHSM2()
	for _, alg := range []string{"RSA-2048", "RSA-3072", "ECDSA-P256", "ECDSA-P384", "Ed25519"} {
		if _, err := h.GenerateKeyPair(alg); err == nil {
			t.Errorf("GenerateKeyPair(%q) must be refused (non-PQC)", alg)
		}
	}
	if !IsAcceptedPQCSignatureAlg("ML-DSA-65") || IsAcceptedPQCSignatureAlg("ECDSA-P384") {
		t.Fatal("accepted-PQC set is wrong")
	}
}

// The software backend implements MACSigner for HSM-resident command signing.
func TestSoftHSMMAC(t *testing.T) {
	h := NewSoftHSM2()
	var ms MACSigner = h // compile-time: software backend is a MACSigner
	if err := ms.EnsureMACKey("cmd", []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	a, err := ms.MAC("cmd", []byte("payload"))
	if err != nil || len(a) != 32 {
		t.Fatalf("MAC: len=%d err=%v", len(a), err)
	}
	b, _ := ms.MAC("cmd", []byte("payload"))
	if string(a) != string(b) {
		t.Fatal("HMAC must be deterministic for the same key+data")
	}
	c, _ := ms.MAC("cmd", []byte("different"))
	if string(a) == string(c) {
		t.Fatal("HMAC must differ for different data")
	}
	if _, err := ms.MAC("missing", []byte("x")); err == nil {
		t.Fatal("MAC with unknown label must error")
	}
}

func TestNewBackendModes(t *testing.T) {
	// disabled -> no backend (endpoints stay 501)
	if b, err := NewBackend(HSMConfig{Mode: ModeDisabled}); err != nil || b != nil {
		t.Fatalf("disabled: want (nil,nil), got (%v,%v)", b, err)
	}
	// software / empty -> a working keystore
	for _, m := range []Mode{ModeSoftware, ""} {
		b, err := NewBackend(HSMConfig{Mode: m})
		if err != nil || b == nil {
			t.Fatalf("mode %q: want backend, got err=%v", m, err)
		}
	}
	// unknown -> error
	if _, err := NewBackend(HSMConfig{Mode: "bogus"}); err == nil {
		t.Fatal("unknown mode must error")
	}
	// pkcs11 with no module path -> error (fail-closed), regardless of cgo/stub.
	if _, err := NewBackend(HSMConfig{Mode: ModePKCS11}); err == nil {
		t.Fatal("pkcs11 mode without a module must fail closed")
	}
}

func TestLoadConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("JANUS_HSM_MODE", "")
	t.Setenv("JANUS_HSM_SIGN_COMMANDS", "")
	cfg := LoadConfigFromEnv()
	if cfg.Mode != ModeSoftware {
		t.Fatalf("default mode must be software, got %q", cfg.Mode)
	}
	if cfg.SignCommands {
		t.Fatal("command signing via HSM must be off by default")
	}
	if cfg.CommandKeyLabel == "" {
		t.Fatal("command key label must have a default")
	}
	t.Setenv("JANUS_HSM_MODE", "PKCS11")
	if LoadConfigFromEnv().Mode != ModePKCS11 {
		t.Fatal("mode parsing must be case-insensitive")
	}
}
