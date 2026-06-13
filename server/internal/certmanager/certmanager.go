package certmanager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type CSRProfile struct {
	CommonName          string
	DNSNames            []string
	Organization        []string
	TargetSignature     string
	HybridCompatibility bool
}

type CSRBundle struct {
	CSRPEM     []byte
	PrivatePEM []byte
	Profile    CSRProfile
}

type ExternalIssuer struct {
	Command string
	Args    []string
}

func GenerateClassicalCSR(profile CSRProfile) (*CSRBundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   profile.CommonName,
			Organization: profile.Organization,
		},
		DNSNames: profile.DNSNames,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &CSRBundle{
		CSRPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Profile:    profile,
	}, nil
}

func GenerateCSR(profile CSRProfile) (*CSRBundle, error) {
	if profile.TargetSignature == "" {
		profile.TargetSignature = "ECDSA-P384-transition"
	}
	if strings.HasPrefix(strings.ToUpper(profile.TargetSignature), "ML-DSA") ||
		strings.HasPrefix(strings.ToUpper(profile.TargetSignature), "SLH-DSA") {
		return GenerateOpenSSLPQCSR(profile)
	}
	return GenerateClassicalCSR(profile)
}

func GenerateOpenSSLPQCSR(profile CSRProfile) (*CSRBundle, error) {
	dir, err := os.MkdirTemp("", "janus-pqc-csr-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	keyPath := filepath.Join(dir, "key.pem")
	csrPath := filepath.Join(dir, "request.pem")
	algorithm := normalizeOpenSSLAlgorithm(profile.TargetSignature)

	if out, err := exec.Command("openssl", "genpkey", "-algorithm", algorithm, "-out", keyPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("openssl genpkey %s failed: %w: %s", algorithm, err, string(out))
	}

	args := []string{"req", "-new", "-key", keyPath, "-out", csrPath, "-subj", subject(profile)}
	if len(profile.DNSNames) > 0 {
		args = append(args, "-addext", "subjectAltName="+subjectAltName(profile.DNSNames))
	}
	if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("openssl req failed: %w: %s", err, string(out))
	}

	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return &CSRBundle{CSRPEM: csrPEM, PrivatePEM: keyPEM, Profile: profile}, nil
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeOpenSSLAlgorithm(name string) string {
	upper := strings.ToUpper(strings.ReplaceAll(name, "_", "-"))
	switch upper {
	case "ML-DSA", "ML-DSA-65":
		return "ML-DSA-65"
	case "ML-DSA-44":
		return "ML-DSA-44"
	case "ML-DSA-87":
		return "ML-DSA-87"
	case "SLH-DSA", "SLH-DSA-SHA2-128S":
		return "SLH-DSA-SHA2-128S"
	default:
		return name
	}
}

func subject(profile CSRProfile) string {
	var b strings.Builder
	b.WriteString("/CN=")
	b.WriteString(escapeSubject(profile.CommonName))
	for _, org := range profile.Organization {
		b.WriteString("/O=")
		b.WriteString(escapeSubject(org))
	}
	return b.String()
}

func subjectAltName(names []string) string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			parts = append(parts, "DNS:"+name)
		}
	}
	return strings.Join(parts, ",")
}

func escapeSubject(s string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "/", "\\/", "\n", "", "\r", "")
	return replacer.Replace(s)
}

func (e ExternalIssuer) IssueWithCSR(ctx context.Context, csrPEM []byte) ([]byte, error) {
	if e.Command == "" {
		return nil, fmt.Errorf("issuer command is required; configure step-cli, lego, EST, or CMP adapter")
	}
	cmd := exec.CommandContext(ctx, e.Command, e.Args...)
	cmd.Stdin = bytes.NewReader(csrPEM)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("external issuer failed: %w: %s", err, stderr.String())
	}
	return out, nil
}
