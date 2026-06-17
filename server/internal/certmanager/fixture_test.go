package certmanager

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWriteMLDSACertChainFixture emits a committed cross-language fixture for WP-029 P3: an
// ML-DSA Root CA cert, a leaf command cert chained to it, and a (message, signature) pair the
// leaf key produced. The Rust agent test (command_cert::verifies_server_produced_cert_chain)
// consumes it to prove circl-issued chains verify under fips204 + x509-parser. A long validity
// window keeps the committed fixture from expiring. Run with JANUS_WRITE_MLDSA_FIXTURE=1 to
// regenerate.
func TestWriteMLDSACertChainFixture(t *testing.T) {
	if os.Getenv("JANUS_WRITE_MLDSA_FIXTURE") == "" {
		t.Skip("set JANUS_WRITE_MLDSA_FIXTURE=1 to (re)write the cross-language cert-chain fixture")
	}
	// ~100-year leaf validity so the committed fixture does not expire.
	chain, err := IssueMLDSAChain("ML-DSA-65", "Janus Command Root", "janus-command", 36500)
	if err != nil {
		t.Fatalf("issue chain: %v", err)
	}
	message := []byte("janus-command-canonical-v2-fixture")
	sig := chain.RootScheme.Sign(chain.LeafPriv, message, nil)

	// Also mint an EXPIRED leaf under the same root (NotAfter in the past) so the agent test
	// can prove revocation-by-expiry: a chained-but-expired leaf must be rejected (WP-029 P4
	// short-lived-cert revocation strategy).
	expiredPub, _, err := chain.RootScheme.GenerateKey()
	if err != nil {
		t.Fatalf("expired leaf key: %v", err)
	}
	expiredSerial, _ := randSerial()
	rootName := pkix.Name{CommonName: "Janus Command Root", Organization: []string{"Janus CryptoBOM"}}
	expiredDER, err := IssueMLDSACert(MLDSACertParams{
		Scheme:     "ML-DSA-65",
		Serial:     expiredSerial,
		Subject:    pkix.Name{CommonName: "expired-command", Organization: []string{"Janus CryptoBOM"}},
		Issuer:     rootName,
		NotBefore:  time.Unix(1_600_000_000, 0), // 2020
		NotAfter:   time.Unix(1_600_086_400, 0), // 2020 + 1 day — firmly in the past
		SubjectPub: expiredPub,
		IsCA:       false,
		signScheme: chain.RootScheme,
		signPriv:   chain.RootPriv,
	})
	if err != nil {
		t.Fatalf("issue expired leaf: %v", err)
	}

	b64 := base64.StdEncoding
	out := map[string]string{
		"algorithm":                 "ML-DSA-65",
		"root_cert_der_b64":         b64.EncodeToString(chain.RootCertDER),
		"leaf_cert_der_b64":         b64.EncodeToString(chain.LeafCertDER),
		"expired_leaf_cert_der_b64": b64.EncodeToString(expiredDER),
		"message_b64":               b64.EncodeToString(message),
		"signature_b64":             b64.EncodeToString(sig),
	}
	blob, _ := json.MarshalIndent(out, "", "  ")
	path := filepath.Join("..", "..", "..", "agent", "tests", "fixtures", "mldsa_cert_chain_vector.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(blob, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}
