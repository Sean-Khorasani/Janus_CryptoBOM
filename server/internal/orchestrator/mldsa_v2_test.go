package orchestrator

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/janus-cbom/janus/server/internal/certmanager"
)

// A janus-sig-v2 command carries the leaf command cert (chained to the bundled ML-DSA root)
// instead of a bare public key. This proves the full server-side trust path: HMAC verifies,
// the embedded cert is the leaf, the leaf chains to the root, and the command signature
// verifies under the public key EXTRACTED FROM the cert (not a separately-trusted pin).
func TestMLDSACommandV2CertChain(t *testing.T) {
	chain, err := certmanager.IssueMLDSAChain("ML-DSA-65", "Janus Command Root", "janus-command", 30)
	if err != nil {
		t.Fatalf("issue chain: %v", err)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	o := New(key)
	leafPub, err := chain.LeafPub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal leaf pub: %v", err)
	}
	// Sign with the LEAF key (the key whose cert is in the envelope).
	o.AddMLDSASigner(func(b []byte) ([]byte, error) {
		return chain.RootScheme.Sign(chain.LeafPriv, b, nil), nil
	}, leafPub)
	o.SetMLDSACommandCert(chain.LeafCertDER)

	cmd := o.BuildCommand("host-1", "nginx", "cnsa-2.0", "/etc/nginx/nginx.conf", "patch", "csum", true, "ML-KEM-1024", "ML-DSA-87")
	canonical := []byte(canonicalCommand(cmd))

	parts := strings.Split(string(cmd.SignedDirective), "\n")
	if len(parts) != 4 || parts[0] != commandSigEnvelopeV2 {
		t.Fatalf("expected a v2 envelope, got %d parts (%q)", len(parts), parts[0])
	}

	// HMAC baseline verifies with the shared key.
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	if parts[1] != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("HMAC part of the envelope must verify with the shared key")
	}

	// Line 3 is the leaf cert DER.
	certDER, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	if !bytes.Equal(certDER, chain.LeafCertDER) {
		t.Fatal("embedded cert must equal the configured leaf command cert")
	}

	// The leaf cert chains to the root: the root key verifies the leaf's TBS.
	leafTBS, leafSig, err := certmanager.MLDSATBSAndSig(certDER)
	if err != nil {
		t.Fatalf("extract leaf tbs/sig: %v", err)
	}
	if !chain.RootScheme.Verify(chain.RootPub, leafTBS, leafSig, nil) {
		t.Fatal("embedded leaf cert does not chain to the root")
	}

	// The command signature verifies under the public key extracted FROM the cert.
	pubFromCert, name, err := certmanager.MLDSAPublicKeyFromCert(certDER)
	if err != nil {
		t.Fatalf("extract pub from cert: %v", err)
	}
	if name != "ML-DSA-65" {
		t.Fatalf("cert scheme = %q, want ML-DSA-65", name)
	}
	cmdSig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !chain.RootScheme.Verify(pubFromCert, canonical, cmdSig, nil) {
		t.Fatal("command signature must verify under the cert's public key")
	}

	// Tamper a command field → canonical changes → command sig no longer verifies.
	cmd.DryRun = !cmd.DryRun
	if chain.RootScheme.Verify(pubFromCert, []byte(canonicalCommand(cmd)), cmdSig, nil) {
		t.Fatal("modified command must not verify against the original signature")
	}
}

// A signer loaded from the leaf key (NewMLDSACommandSignerFromKey) must have the same public
// key the leaf certificate carries — this is exactly the match the server validates at startup
// before enabling janus-sig-v2 (JANUS_COMMAND_SIG_CERT_FILE vs the signing key).
func TestMLDSACommandSignerFromKeyMatchesCert(t *testing.T) {
	chain, err := certmanager.IssueMLDSAChain("ML-DSA-65", "Janus Command Root", "janus-command", 365)
	if err != nil {
		t.Fatalf("issue chain: %v", err)
	}
	keyBytes, err := chain.LeafPriv.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	signer, err := NewMLDSACommandSignerFromKey("ML-DSA-65", keyBytes)
	if err != nil {
		t.Fatalf("load signer from key: %v", err)
	}
	signerPub, _ := signer.PublicKey()

	certPub, name, err := certmanager.MLDSAPublicKeyFromCert(chain.LeafCertDER)
	if err != nil {
		t.Fatalf("pub from cert: %v", err)
	}
	if name != "ML-DSA-65" {
		t.Fatalf("scheme = %q", name)
	}
	certPubBytes, _ := certPub.MarshalBinary()
	if !bytes.Equal(signerPub, certPubBytes) {
		t.Fatal("signer public key must equal the leaf cert's public key (startup match check)")
	}

	// And a signature from the loaded key verifies under the cert's key.
	sig, _ := signer.Sign([]byte("hello"))
	if !chain.RootScheme.Verify(certPub, []byte("hello"), sig, nil) {
		t.Fatal("signature from the loaded key must verify under the cert public key")
	}
}

// Clearing the command cert reverts to the v1 (fingerprint-pin) envelope, so existing
// deployments are unaffected by the v2 addition.
func TestMLDSACommandV2RevertsToV1(t *testing.T) {
	chain, err := certmanager.IssueMLDSAChain("ML-DSA-65", "root", "leaf", 30)
	if err != nil {
		t.Fatalf("issue chain: %v", err)
	}
	leafPub, _ := chain.LeafPub.MarshalBinary()
	o := New([]byte("0123456789abcdef0123456789abcdef"))
	o.AddMLDSASigner(func(b []byte) ([]byte, error) {
		return chain.RootScheme.Sign(chain.LeafPriv, b, nil), nil
	}, leafPub)

	o.SetMLDSACommandCert(chain.LeafCertDER)
	if !strings.HasPrefix(string(o.BuildCommand("h", "s", "p", "/c", "x", "", true, "", "").SignedDirective), commandSigEnvelopeV2+"\n") {
		t.Fatal("with a cert set, expected v2 envelope")
	}
	o.SetMLDSACommandCert(nil)
	if !strings.HasPrefix(string(o.BuildCommand("h", "s", "p", "/c", "x", "", true, "", "").SignedDirective), commandSigEnvelopeV1+"\n") {
		t.Fatal("clearing the cert should revert to v1")
	}
}
