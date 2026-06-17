package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PKI algorithms supported by InitPKI. ECDSA-P384 is issued in pure Go (CNSA 2.0
// transitional). ML-DSA-65/87 (FIPS 204) is issued via OpenSSL 3.5+, which is the only
// generally-available tool that can sign ML-DSA X.509 certificates today — Go's stdlib
// x509 does not know the ML-DSA OIDs.
const (
	PKIAlgECDSAP384 = "ECDSA-P384"
	PKIAlgMLDSA65   = "ML-DSA-65"
	PKIAlgMLDSA87   = "ML-DSA-87"
)

// PKIInitOptions configures InitPKI. It produces a two-level hierarchy: a self-signed
// Root CA whose certificate the agent bundles as its trust anchor (tls_ca_cert), and a
// leaf server certificate the controller loads for one-way TLS (JANUS_TLS_CERT_FILE).
type PKIInitOptions struct {
	CommonName   string   // server cert CN (also seeds the Root CA name)
	DNSNames     []string // server SANs
	IPAddresses  []string // server IP SANs
	Organization []string // O= for both certs
	Algorithm    string   // default ECDSA-P384
	ServerDays   int      // server cert validity, default 365
	CADays       int      // root CA validity, default 3650
}

// PKIBundle is the output of InitPKI, all PEM-encoded.
type PKIBundle struct {
	Algorithm     string
	RootCertPEM   []byte // bundle into the agent package as tls_ca_cert
	RootKeyPEM    []byte // keep offline — only needed to issue more certs
	ServerCertPEM []byte // JANUS_TLS_CERT_FILE
	ServerKeyPEM  []byte // JANUS_TLS_KEY_FILE
}

// InitPKI generates a Root CA + server certificate for one-way TLS (WP-029 P2).
func InitPKI(opts PKIInitOptions) (*PKIBundle, error) {
	if strings.TrimSpace(opts.CommonName) == "" {
		return nil, fmt.Errorf("pki: CommonName is required")
	}
	if opts.Algorithm == "" {
		opts.Algorithm = PKIAlgECDSAP384
	}
	if opts.ServerDays <= 0 {
		opts.ServerDays = 365
	}
	if opts.CADays <= 0 {
		opts.CADays = 3650
	}
	alg := strings.ToUpper(strings.ReplaceAll(opts.Algorithm, "_", "-"))
	switch {
	case alg == PKIAlgECDSAP384:
		return initPKIECDSA(opts)
	case strings.HasPrefix(alg, "ML-DSA"):
		return initPKIOpenSSL(opts, normalizeOpenSSLAlgorithm(alg))
	default:
		return nil, fmt.Errorf("pki: unsupported algorithm %q (use ECDSA-P384, ML-DSA-65, or ML-DSA-87)", opts.Algorithm)
	}
}

func initPKIECDSA(opts PKIInitOptions) (*PKIBundle, error) {
	now := time.Now()
	org := orgOrDefault(opts.Organization)

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	caSerial, err := randSerial()
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: opts.CommonName + " Root CA", Organization: org},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, opts.CADays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("pki: create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate server key: %w", err)
	}
	srvSerial, err := randSerial()
	if err != nil {
		return nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber:          srvSerial,
		Subject:               pkix.Name{CommonName: opts.CommonName, Organization: org},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, opts.ServerDays),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              opts.DNSNames,
		IPAddresses:           parseIPs(opts.IPAddresses),
		BasicConstraintsValid: true,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("pki: create server cert: %w", err)
	}

	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return nil, err
	}
	return &PKIBundle{
		Algorithm:     PKIAlgECDSAP384,
		RootCertPEM:   pemBlock("CERTIFICATE", caDER),
		RootKeyPEM:    pemBlock("EC PRIVATE KEY", caKeyDER),
		ServerCertPEM: pemBlock("CERTIFICATE", srvDER),
		ServerKeyPEM:  pemBlock("EC PRIVATE KEY", srvKeyDER),
	}, nil
}

// initPKIOpenSSL issues an ML-DSA hierarchy via OpenSSL 3.5+ (the only generally-available
// tool that can sign ML-DSA X.509). It fails with a clear error when OpenSSL is missing or
// too old to know the algorithm.
func initPKIOpenSSL(opts PKIInitOptions, algorithm string) (*PKIBundle, error) {
	dir, err := os.MkdirTemp("", "janus-pki-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	p := func(name string) string { return filepath.Join(dir, name) }
	caKey, caCrt := p("ca.key"), p("ca.crt")
	srvKey, srvCsr, srvCrt := p("server.key"), p("server.csr"), p("server.crt")

	// Probe support up front so the error names the real cause.
	if out, err := exec.Command("openssl", "genpkey", "-algorithm", algorithm, "-out", caKey).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pki: openssl genpkey %s failed (ML-DSA issuance requires OpenSSL 3.5+): %w: %s", algorithm, err, strings.TrimSpace(string(out)))
	}

	caDays := fmt.Sprintf("%d", opts.CADays)
	caSubj := subject(CSRProfile{CommonName: opts.CommonName + " Root CA", Organization: opts.Organization})
	caArgs := []string{
		"req", "-x509", "-new", "-key", caKey, "-out", caCrt, "-days", caDays, "-subj", caSubj,
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign",
	}
	if out, err := exec.Command("openssl", caArgs...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pki: openssl req -x509 (CA) failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	if out, err := exec.Command("openssl", "genpkey", "-algorithm", algorithm, "-out", srvKey).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pki: openssl genpkey %s (server) failed: %w: %s", algorithm, err, strings.TrimSpace(string(out)))
	}
	csrArgs := []string{"req", "-new", "-key", srvKey, "-out", srvCsr, "-subj", subject(CSRProfile{CommonName: opts.CommonName, Organization: opts.Organization})}
	if out, err := exec.Command("openssl", csrArgs...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pki: openssl req (server CSR) failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Leaf extensions (SAN + serverAuth EKU) go through an extfile so they land on the
	// signed certificate rather than the CSR.
	extPath := p("server.ext")
	ext := "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
	if san := opensslSAN(opts.DNSNames, opts.IPAddresses); san != "" {
		ext += "subjectAltName=" + san + "\n"
	}
	if err := os.WriteFile(extPath, []byte(ext), 0o600); err != nil {
		return nil, err
	}
	signArgs := []string{
		"x509", "-req", "-in", srvCsr, "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial",
		"-out", srvCrt, "-days", fmt.Sprintf("%d", opts.ServerDays), "-extfile", extPath,
	}
	if out, err := exec.Command("openssl", signArgs...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pki: openssl x509 -req (sign server) failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	read := func(path string) ([]byte, error) { return os.ReadFile(path) }
	caCrtPEM, err := read(caCrt)
	if err != nil {
		return nil, err
	}
	caKeyPEM, err := read(caKey)
	if err != nil {
		return nil, err
	}
	srvCrtPEM, err := read(srvCrt)
	if err != nil {
		return nil, err
	}
	srvKeyPEM, err := read(srvKey)
	if err != nil {
		return nil, err
	}
	return &PKIBundle{
		Algorithm:     algorithm,
		RootCertPEM:   caCrtPEM,
		RootKeyPEM:    caKeyPEM,
		ServerCertPEM: srvCrtPEM,
		ServerKeyPEM:  srvKeyPEM,
	}, nil
}

func randSerial() (*big.Int, error) {
	// 128-bit positive serial.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

func parseIPs(in []string) []net.IP {
	out := make([]net.IP, 0, len(in))
	for _, s := range in {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func orgOrDefault(org []string) []string {
	if len(org) == 0 {
		return []string{"Janus CryptoBOM"}
	}
	return org
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func opensslSAN(dns, ips []string) string {
	parts := make([]string, 0, len(dns)+len(ips))
	for _, d := range dns {
		if d = strings.TrimSpace(d); d != "" {
			parts = append(parts, "DNS:"+d)
		}
	}
	for _, ip := range ips {
		if ip = strings.TrimSpace(ip); ip != "" {
			parts = append(parts, "IP:"+ip)
		}
	}
	return strings.Join(parts, ",")
}
