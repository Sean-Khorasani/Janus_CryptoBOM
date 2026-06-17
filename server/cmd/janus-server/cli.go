package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// runCLIIfRequested turns `janus-server <subcommand> ...` into an admin CLI for the bits
// an operator needs after install — generating the baseline HMAC command-signing key and
// managing HSM signing keys — without a separate binary or external tools (openssl etc.).
// Returns true if it handled a subcommand (caller then exits instead of starting the server).
//
//	janus-server gen-hmac-key                generate a 32-byte hex HMAC command-signing key
//	janus-server hsm info    --module ...    list HSM slots (index, id, token info)
//	janus-server hsm keygen  --module ... --slot-index N --pin ... [--algorithm ML-DSA-65] [--label ...]
//	janus-server hsm list    --module ... --slot-index N --pin ...
//	janus-server hsm pubkey  --module ... --slot-index N --pin ... --label ...   (prints key hex + SHA-256 fingerprint)
//	janus-server hsm rm      --module ... --slot-index N --pin ... --label ...
func runCLIIfRequested() bool {
	if len(os.Args) < 2 {
		return false
	}
	switch os.Args[1] {
	case "gen-hmac-key":
		genHMACKey()
		return true
	case "hsm":
		runHSMCLI(os.Args[2:]) // platform-specific (cgo vs stub)
		return true
	case "agent":
		runAgentCLI(os.Args[2:]) // per-agent identity management (WP-029 P1)
		return true
	case "pki":
		runPKICLI(os.Args[2:]) // Root CA + server cert for one-way TLS (WP-029 P2)
		return true
	default:
		return false
	}
}

// genHMACKey prints a fresh 32-byte hex key for JANUS_COMMAND_SIGNING_KEY (and the agents'
// command_signing_key). Replaces "openssl rand -hex 32" so operators need no external tools.
func genHMACKey() {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintln(os.Stderr, "gen-hmac-key:", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(b))
}
