package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWriteOCSPFixture emits a committed fixture for the agent's OCSP revocation tests
// (FEAT-OCSP / WP-016): an ECDSA issuer and a leaf that carries an AIA OCSP responder URL,
// the shape a real TLS endpoint presents. The agent test extracts the URL and builds an OCSP
// request from (leaf, issuer). Uses Go stdlib x509 (OCSPServer -> AIA). Long validity so the
// committed fixture does not expire. Run with JANUS_WRITE_MLDSA_FIXTURE=1 to regenerate.
func TestWriteOCSPFixture(t *testing.T) {
	if os.Getenv("JANUS_WRITE_MLDSA_FIXTURE") == "" {
		t.Skip("set JANUS_WRITE_MLDSA_FIXTURE=1 to (re)write the OCSP fixture")
	}
	const ocspURL = "http://ocsp.janus.example/responder"
	notBefore := time.Unix(1_600_000_000, 0)
	notAfter := time.Unix(4_100_000_000, 0) // year ~2099

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Janus OCSP Test Issuer"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, _ := x509.ParseCertificate(issuerDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "leaf.janus.example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.janus.example"},
		OCSPServer:   []string{ocspURL}, // -> Authority Information Access (id-ad-ocsp)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerCert, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	b64 := base64.StdEncoding
	out := map[string]string{
		"leaf_der_b64":   b64.EncodeToString(leafDER),
		"issuer_der_b64": b64.EncodeToString(issuerDER),
		"ocsp_url":       ocspURL,
		"leaf_serial":    "4242",
	}
	blob, _ := json.MarshalIndent(out, "", "  ")
	path := filepath.Join("..", "..", "..", "agent", "tests", "fixtures", "ocsp_cert_vector.json")
	if err := os.WriteFile(path, append(blob, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}
