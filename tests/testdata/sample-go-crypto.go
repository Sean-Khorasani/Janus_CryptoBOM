package main

// Test data: Go source with crypto usage
// Used by: tests/scripts/test-agent.ps1

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func generateRSAKey() *rsa.PrivateKey {
	// JANUS-PQC-001: RSA key generation
	key, err := rsa.GenerateKey(nil, 1024) // JANUS-PQC-002: RSA < 3072
	if err != nil {
		panic(err)
	}
	return key
}

func weakHashSum(data []byte) string {
	// JANUS-CLASSICAL-003: MD5 hash
	return fmt.Sprintf("%x", md5.Sum(data))
}

func sha1Hash(data []byte) []byte {
	// JANUS-CLASSICAL-003: SHA-1 hash
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

func configureTLS() *tls.Config {
	// JANUS-PQC-001: TLS configuration with classical ciphers
	return &tls.Config{
		MinVersion: tls.VersionTLS12, // JANUS-NET-002: not TLS 1.3
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

func parseCertificate(der []byte) (*x509.Certificate, error) {
	// VERIFY intent: parsing certificates
	return x509.ParseCertificate(der)
}

func sshClient() *ssh.Client {
	// Third-party crypto dependency: golang.org/x/crypto
	config := &ssh.ClientConfig{}
	client, _ := ssh.Dial("tcp", "localhost:22", config)
	return client
}
