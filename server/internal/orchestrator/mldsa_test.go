package orchestrator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/schemes"
	"github.com/janus-cbom/janus/server/internal/pb"
)

// A dual-signed command carries an envelope with BOTH the HMAC and the ML-DSA signature.
// The HMAC must verify with the shared key; the ML-DSA signature must verify under the
// embedded public key; tampering either signature or a command field must fail.
func TestMLDSACommandDualSign(t *testing.T) {
	signer, err := NewMLDSACommandSigner("ML-DSA-65")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	pubBytes, _ := signer.PublicKey()
	o := New(key)
	o.AddMLDSASigner(signer.Sign, pubBytes)
	cmd := o.BuildCommand("host-1", "nginx", "cnsa-2.0", "/etc/nginx/nginx.conf", "patch", "csum", true, "ML-KEM-1024", "ML-DSA-87")
	canonical := []byte(canonicalCommand(cmd))

	// Parse the envelope: marker, hmac-hex, base64 sig, base64 pub.
	parts := strings.Split(string(cmd.SignedDirective), "\n")
	if len(parts) != 4 || parts[0] != commandSigEnvelopeV1 {
		t.Fatalf("expected a dual-sign envelope, got %d parts (%q)", len(parts), parts[0])
	}
	// HMAC part verifies with the shared key.
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	if parts[1] != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("HMAC part of the envelope must verify with the shared key")
	}
	// ML-DSA part verifies with the embedded public key.
	sig, _ := base64.StdEncoding.DecodeString(parts[2])
	pubRaw, _ := base64.StdEncoding.DecodeString(parts[3])
	scheme := schemes.ByName("ML-DSA-65")
	pub, err := scheme.UnmarshalBinaryPublicKey(pubRaw)
	if err != nil {
		t.Fatalf("unmarshal pub: %v", err)
	}
	if !scheme.Verify(pub, canonical, sig, nil) {
		t.Fatal("valid ML-DSA command signature must verify")
	}
	// The embedded pubkey must match the signer's published key (what agents pin).
	if base64.StdEncoding.EncodeToString(pubBytes) != parts[3] {
		t.Fatal("embedded public key must equal the signer's public key")
	}
	// Tamper the signature.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xFF
	if scheme.Verify(pub, canonical, bad, nil) {
		t.Fatal("tampered ML-DSA signature must not verify")
	}
	// Tamper a command field → canonical changes → verify fails.
	cmd.DryRun = !cmd.DryRun
	if scheme.Verify(pub, []byte(canonicalCommand(cmd)), sig, nil) {
		t.Fatal("modified command must not verify against the original signature")
	}
}

// TestWriteMLDSAFixture emits a deterministic (pubkey, canonical-message, signature)
// triple the Rust agent test consumes to prove cross-language interop (circl signs ↔
// fips204 verifies). Run with JANUS_WRITE_MLDSA_FIXTURE=1 to regenerate the committed file.
func TestWriteMLDSAFixture(t *testing.T) {
	if os.Getenv("JANUS_WRITE_MLDSA_FIXTURE") == "" {
		t.Skip("set JANUS_WRITE_MLDSA_FIXTURE=1 to (re)write the cross-language fixture")
	}
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	signer, err := NewMLDSACommandSignerFromSeed("ML-DSA-65", seed)
	if err != nil {
		t.Fatalf("seed signer: %v", err)
	}
	// A fixed command so the canonical message is stable.
	cmd := &pb.MigrationCommand{
		CommandId: "fixed-cmd-id", HostUuid: "fixed-host", TargetService: "nginx",
		MigrationProfile: "cnsa-2.0", TargetKem: "ML-KEM-1024", TargetSignature: "ML-DSA-87",
		ConfigPath: "/etc/nginx/nginx.conf", ValidationChecklist: []string{"config-syntax"},
		RollbackWindowSeconds: 300, PatchUnifiedDiff: "--- a\n+++ b\n", IssuedAtUnix: 1750000000, DryRun: true,
	}
	canonical := []byte(canonicalCommand(cmd))
	sig, _ := signer.Sign(canonical)
	pub, _ := signer.PublicKey()

	out := map[string]string{
		"algorithm":      "ML-DSA-65",
		"public_key_b64": base64.StdEncoding.EncodeToString(pub),
		"message_b64":    base64.StdEncoding.EncodeToString(canonical),
		"signature_b64":  base64.StdEncoding.EncodeToString(sig),
	}
	blob, _ := json.MarshalIndent(out, "", "  ")
	path := filepath.Join("..", "..", "..", "agent", "tests", "fixtures", "mldsa_command_vector.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(blob, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}
