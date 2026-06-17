package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/janus-cbom/janus/server/internal/certmanager"
)

// runPKICLI dispatches `janus-server pki <init>` (WP-029 P2). It generates a self-signed
// Root CA and a leaf server certificate for one-way TLS: bundle the Root CA into the agent
// package (tls_ca_cert) and load the server cert/key on the controller. ECDSA-P384 is issued
// in-process; ML-DSA-65/87 requires OpenSSL 3.5+.
func runPKICLI(args []string) {
	if len(args) == 0 {
		pkiUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		pkiInit(args[1:])
	case "command-ca":
		pkiCommandCA(args[1:])
	default:
		pkiUsage()
		os.Exit(2)
	}
}

func pkiUsage() {
	fmt.Fprintln(os.Stderr, `usage: janus-server pki <init|command-ca> [flags]

  command-ca   generate an ML-DSA command-signing Root CA + leaf for janus-sig-v2 (WP-029 P3):
    --alg <ML-DSA-65|ML-DSA-87>   ML-DSA parameter set (default ML-DSA-65)
    --out <dir>                   output directory (default command-pki)
    --days N                      leaf validity in days (default 365; root gets 5x)
    --force                       overwrite existing files
  Writes command-root-ca.crt (bundle into the agent package -> command_root_ca),
  command.crt + command.key (controller: JANUS_COMMAND_SIG_CERT_FILE / _KEY_FILE
  with JANUS_COMMAND_SIG_SCHEME=ml-dsa).

usage: janus-server pki init [flags]
  --cn <name>        server certificate CommonName (required)
  --dns a,b          comma-separated DNS SANs
  --ip 10.0.0.1,...  comma-separated IP SANs
  --org <name>       organization (O=), default "Janus CryptoBOM"
  --alg <algorithm>  ECDSA-P384 (default) | ML-DSA-65 | ML-DSA-87 (ML-DSA needs OpenSSL 3.5+)
  --out <dir>        output directory (default ./pki)
  --server-days N    server cert validity in days (default 365)
  --ca-days N        root CA validity in days (default 3650)
  --force            overwrite existing files in --out

Outputs root-ca.crt (agent trust anchor), root-ca.key (keep offline),
server.crt + server.key (controller TLS).`)
}

func pkiInit(args []string) {
	fs := flag.NewFlagSet("pki init", flag.ExitOnError)
	cn := fs.String("cn", "", "server certificate CommonName")
	dns := fs.String("dns", "", "comma-separated DNS SANs")
	ip := fs.String("ip", "", "comma-separated IP SANs")
	org := fs.String("org", "", "organization (O=)")
	alg := fs.String("alg", certmanager.PKIAlgECDSAP384, "key algorithm")
	out := fs.String("out", "pki", "output directory")
	serverDays := fs.Int("server-days", 365, "server cert validity (days)")
	caDays := fs.Int("ca-days", 3650, "root CA validity (days)")
	force := fs.Bool("force", false, "overwrite existing files")
	_ = fs.Parse(args)

	if strings.TrimSpace(*cn) == "" {
		fmt.Fprintln(os.Stderr, "pki init: --cn is required")
		os.Exit(2)
	}

	opts := certmanager.PKIInitOptions{
		CommonName:   *cn,
		DNSNames:     splitCSV(*dns),
		IPAddresses:  splitCSV(*ip),
		Organization: splitCSV(*org),
		Algorithm:    *alg,
		ServerDays:   *serverDays,
		CADays:       *caDays,
	}
	bundle, err := certmanager.InitPKI(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pki init:", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*out, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "pki init: create out dir:", err)
		os.Exit(1)
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"root-ca.crt", bundle.RootCertPEM, 0o644},
		{"root-ca.key", bundle.RootKeyPEM, 0o600},
		{"server.crt", bundle.ServerCertPEM, 0o644},
		{"server.key", bundle.ServerKeyPEM, 0o600},
	}
	for _, f := range files {
		path := filepath.Join(*out, f.name)
		if !*force {
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(os.Stderr, "pki init: %s exists (use --force to overwrite)\n", path)
				os.Exit(1)
			}
		}
		if err := os.WriteFile(path, f.data, f.mode); err != nil {
			fmt.Fprintf(os.Stderr, "pki init: write %s: %v\n", path, err)
			os.Exit(1)
		}
	}

	fmt.Printf("# PKI generated (%s) in %s\n", bundle.Algorithm, *out)
	fmt.Println("# Controller TLS:")
	fmt.Printf("export JANUS_TLS_CERT_FILE=%s\n", filepath.Join(*out, "server.crt"))
	fmt.Printf("export JANUS_TLS_KEY_FILE=%s\n", filepath.Join(*out, "server.key"))
	fmt.Println("# Agent trust anchor — bundle root-ca.crt into the agent package and set:")
	fmt.Printf("#   tls_ca_cert = \"%s\"   (janus-agent.toml)\n", filepath.Join(*out, "root-ca.crt"))
	fmt.Println("# Keep root-ca.key offline — it is only needed to issue more certs.")
}

func pkiCommandCA(args []string) {
	fs := flag.NewFlagSet("pki command-ca", flag.ExitOnError)
	alg := fs.String("alg", "ML-DSA-65", "ML-DSA parameter set (ML-DSA-65 or ML-DSA-87)")
	out := fs.String("out", "command-pki", "output directory")
	days := fs.Int("days", 365, "leaf validity in days (root gets 5x)")
	force := fs.Bool("force", false, "overwrite existing files")
	_ = fs.Parse(args)

	chain, err := certmanager.IssueMLDSAChain(*alg, "Janus Command Root CA", "janus-command-signer", *days)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pki command-ca:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "pki command-ca: create out dir:", err)
		os.Exit(1)
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"command-root-ca.crt", chain.RootCertPEM, 0o644},
		{"command-root-ca.key", chain.RootKeyPEM, 0o600},
		{"command.crt", chain.LeafCertPEM, 0o644},
		{"command.key", chain.LeafKeyPEM, 0o600},
	}
	for _, f := range files {
		path := filepath.Join(*out, f.name)
		if !*force {
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(os.Stderr, "pki command-ca: %s exists (use --force to overwrite)\n", path)
				os.Exit(1)
			}
		}
		if err := os.WriteFile(path, f.data, f.mode); err != nil {
			fmt.Fprintf(os.Stderr, "pki command-ca: write %s: %v\n", path, err)
			os.Exit(1)
		}
	}
	fmt.Printf("# ML-DSA command-signing PKI generated (%s) in %s\n", chain.Scheme, *out)
	fmt.Println("# Controller (with JANUS_COMMAND_SIG_SCHEME=ml-dsa):")
	fmt.Printf("export JANUS_COMMAND_SIG_CERT_FILE=%s\n", filepath.Join(*out, "command.crt"))
	fmt.Printf("export JANUS_COMMAND_SIG_KEY_FILE=%s\n", filepath.Join(*out, "command.key"))
	fmt.Println("# Agent trust anchor — bundle command-root-ca.crt and set in janus-agent.toml:")
	fmt.Printf("#   command_root_ca = \"%s\"\n", filepath.Join(*out, "command-root-ca.crt"))
	fmt.Println("# Keep command-root-ca.key offline — only needed to issue more command certs.")
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
