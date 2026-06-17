package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// WP-018: the agent-upgrade advisory is a signed update manifest — an agent (using the same
// HMAC primitive as plugin-signature verification) must be able to authenticate it under the
// command-signing key, and any tampering or a wrong key must fail.
func TestSignedUpdateManifest(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	manifest, sig := signedUpdateManifest(key, 1_700_000_000)
	if manifest == "" || sig == "" {
		t.Fatal("manifest and signature must be non-empty")
	}

	// Verify exactly as the agent would (HMAC-SHA256 hex over the manifest bytes).
	verify := func(k []byte, m, s string) bool {
		mac := hmac.New(sha256.New, k)
		mac.Write([]byte(m))
		return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(s))
	}
	if !verify(key, manifest, sig) {
		t.Fatal("signature must verify under the command key")
	}
	if verify([]byte("wrong-key-wrong-key-wrong-key-32"), manifest, sig) {
		t.Fatal("signature must not verify under a different key")
	}
	if verify(key, manifest+" ", sig) {
		t.Fatal("a tampered manifest must not verify")
	}
	// Deterministic for a fixed timestamp.
	m2, s2 := signedUpdateManifest(key, 1_700_000_000)
	if m2 != manifest || s2 != sig {
		t.Fatal("manifest/signature must be deterministic for a fixed timestamp")
	}
}
