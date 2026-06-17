package certmanager

import (
	"crypto/x509"
	"encoding/pem"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func parseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

func TestInitPKIECDSA(t *testing.T) {
	b, err := InitPKI(PKIInitOptions{
		CommonName:  "janus.example.com",
		DNSNames:    []string{"janus.example.com", "controller.internal"},
		IPAddresses: []string{"10.0.0.5"},
		ServerDays:  30,
		CADays:      365,
	})
	if err != nil {
		t.Fatalf("InitPKI: %v", err)
	}
	if b.Algorithm != PKIAlgECDSAP384 {
		t.Fatalf("algorithm = %q, want %q", b.Algorithm, PKIAlgECDSAP384)
	}

	root := parseCert(t, b.RootCertPEM)
	server := parseCert(t, b.ServerCertPEM)

	if !root.IsCA {
		t.Error("root cert is not a CA")
	}
	if server.IsCA {
		t.Error("server cert must not be a CA")
	}

	// Server cert chains to the root.
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := server.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "controller.internal",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("server cert does not verify against root: %v", err)
	}

	// SANs landed.
	if got := server.DNSNames; len(got) != 2 {
		t.Errorf("DNSNames = %v, want 2", got)
	}
	if len(server.IPAddresses) != 1 || server.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("IPAddresses = %v, want [10.0.0.5]", server.IPAddresses)
	}

	// Validity windows roughly honor the options.
	if d := server.NotAfter.Sub(server.NotBefore); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("server validity = %v, want ~30d", d)
	}

	// Keys are usable EC private keys.
	if blk, _ := pem.Decode(b.ServerKeyPEM); blk == nil || blk.Type != "EC PRIVATE KEY" {
		t.Errorf("server key PEM type = %v, want EC PRIVATE KEY", blk)
	}
}

func TestInitPKIRequiresCommonName(t *testing.T) {
	if _, err := InitPKI(PKIInitOptions{}); err == nil {
		t.Fatal("expected error for empty CommonName")
	}
}

func TestInitPKIUnsupportedAlgorithm(t *testing.T) {
	_, err := InitPKI(PKIInitOptions{CommonName: "x", Algorithm: "RSA-4096"})
	if err == nil || !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("want unsupported-algorithm error, got %v", err)
	}
}

func TestInitPKIMLDSA(t *testing.T) {
	// ML-DSA issuance needs OpenSSL 3.5+; skip cleanly when unavailable (the common case
	// today). When present, the same chain invariants must hold.
	if !opensslSupportsMLDSA() {
		t.Skip("OpenSSL 3.5+ with ML-DSA not available")
	}
	b, err := InitPKI(PKIInitOptions{
		CommonName: "janus.example.com",
		DNSNames:   []string{"janus.example.com"},
		Algorithm:  PKIAlgMLDSA65,
		ServerDays: 30,
		CADays:     365,
	})
	if err != nil {
		t.Fatalf("InitPKI ML-DSA: %v", err)
	}
	root := parseCert(t, b.RootCertPEM)
	server := parseCert(t, b.ServerCertPEM)
	if !root.IsCA {
		t.Error("root cert is not a CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, DNSName: "janus.example.com"}); err != nil {
		t.Fatalf("ML-DSA server cert does not verify: %v", err)
	}
}

func opensslSupportsMLDSA() bool {
	out, err := exec.Command("openssl", "list", "-signature-algorithms").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(string(out)), "ML-DSA")
}
