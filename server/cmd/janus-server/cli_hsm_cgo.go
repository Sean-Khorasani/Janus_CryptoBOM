//go:build cgo || windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/janus-cbom/janus/server/internal/hsm"
)

// runHSMCLI dispatches `janus-server hsm <sub>` to the PKCS#11 management commands.
func runHSMCLI(args []string) {
	if len(args) < 1 {
		hsmUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "info":
		hsmInfo(args[1:])
	case "keygen":
		hsmKeygen(args[1:])
	case "list":
		hsmList(args[1:])
	case "pubkey":
		hsmPubkey(args[1:])
	case "rm", "remove":
		hsmRemove(args[1:])
	default:
		hsmUsage()
		os.Exit(2)
	}
}

func hsmUsage() {
	fmt.Fprintln(os.Stderr, `usage: janus-server hsm <info|keygen|list|pubkey|rm> [flags]
  info    --module PATH
  keygen  --module PATH --slot-index N --pin PIN [--algorithm ML-DSA-65] [--label NAME]
  list    --module PATH --slot-index N --pin PIN
  pubkey  --module PATH --slot-index N --pin PIN --label NAME
  rm      --module PATH --slot-index N --pin PIN --label NAME
PIN may also be supplied via JANUS_HSM_PIN.`)
}

// commonFlags registers the flags shared by the token-opening subcommands.
func commonFlags(fs *flag.FlagSet) (*string, *int, *string) {
	module := fs.String("module", "", "path to the PKCS#11 module (.so/.dll)")
	slotIndex := fs.Int("slot-index", 0, "0-based slot index from `hsm info`")
	pin := fs.String("pin", os.Getenv("JANUS_HSM_PIN"), "token user PIN (or set JANUS_HSM_PIN)")
	return module, slotIndex, pin
}

// openToken builds the pkcs11 backend for a slot index. Caller must Close().
func openToken(module string, slotIndex int, pin string) hsm.HSM {
	if module == "" {
		fmt.Fprintln(os.Stderr, "error: --module is required")
		os.Exit(2)
	}
	backend, err := hsm.NewBackend(hsm.HSMConfig{
		Mode: hsm.ModePKCS11, ModulePath: module, SlotIndex: slotIndex, Pin: pin, SlotID: -1,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error opening token:", err)
		os.Exit(1)
	}
	return backend
}

func hsmInfo(args []string) {
	fs := flag.NewFlagSet("hsm info", flag.ExitOnError)
	module := fs.String("module", "", "path to the PKCS#11 module (.so/.dll)")
	_ = fs.Parse(args)
	if *module == "" {
		fmt.Fprintln(os.Stderr, "error: --module is required")
		os.Exit(2)
	}
	slots, err := hsm.ListSlots(*module)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(slots) == 0 {
		fmt.Println("no initialized tokens found")
		return
	}
	fmt.Printf("%-5s  %-20s  %-24s  %-16s  %s\n", "INDEX", "SLOT_ID", "TOKEN_LABEL", "MODEL", "SERIAL")
	for _, s := range slots {
		fmt.Printf("%-5d  %-20d  %-24s  %-16s  %s\n", s.Index, s.SlotID, s.Label, s.Model, s.SerialNumber)
	}
}

func hsmKeygen(args []string) {
	fs := flag.NewFlagSet("hsm keygen", flag.ExitOnError)
	module, slotIndex, pin := commonFlags(fs)
	alg := fs.String("algorithm", "ML-DSA-65", "PQC signature algorithm (ML-DSA-44/65/87)")
	label := fs.String("label", "janus-command-mldsa", "key label")
	_ = fs.Parse(args)

	backend := openToken(*module, *slotIndex, *pin)
	defer backend.Close()
	ckm, ok := backend.(hsm.CommandKeyManager)
	if !ok {
		fmt.Fprintln(os.Stderr, "error: this backend cannot manage signing keys")
		os.Exit(1)
	}
	keyID, err := ckm.EnsureMLDSAKey(*label, *alg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen failed:", err)
		os.Exit(1)
	}
	printPubKey(ckm, keyID, *alg)
}

func hsmList(args []string) {
	fs := flag.NewFlagSet("hsm list", flag.ExitOnError)
	module, slotIndex, pin := commonFlags(fs)
	_ = fs.Parse(args)
	backend := openToken(*module, *slotIndex, *pin)
	defer backend.Close()
	keys, err := backend.ListKeys()
	if err != nil {
		fmt.Fprintln(os.Stderr, "list failed:", err)
		os.Exit(1)
	}
	if len(keys) == 0 {
		fmt.Println("no keys on this token")
		return
	}
	fmt.Printf("%-40s  %-14s  %s\n", "LABEL", "ALGORITHM", "PQC")
	for _, k := range keys {
		fmt.Printf("%-40s  %-14s  %v\n", k.Label, k.Algorithm, k.IsPQC)
	}
}

func hsmPubkey(args []string) {
	fs := flag.NewFlagSet("hsm pubkey", flag.ExitOnError)
	module, slotIndex, pin := commonFlags(fs)
	label := fs.String("label", "janus-command-mldsa", "key label")
	_ = fs.Parse(args)
	backend := openToken(*module, *slotIndex, *pin)
	defer backend.Close()
	ckm, ok := backend.(hsm.CommandKeyManager)
	if !ok {
		fmt.Fprintln(os.Stderr, "error: this backend cannot export public keys")
		os.Exit(1)
	}
	printPubKey(ckm, *label, "")
}

func hsmRemove(args []string) {
	fs := flag.NewFlagSet("hsm rm", flag.ExitOnError)
	module, slotIndex, pin := commonFlags(fs)
	label := fs.String("label", "", "key label to remove")
	_ = fs.Parse(args)
	if *label == "" {
		fmt.Fprintln(os.Stderr, "error: --label is required")
		os.Exit(2)
	}
	backend := openToken(*module, *slotIndex, *pin)
	defer backend.Close()
	remover, ok := backend.(interface {
		RemoveKey(string) (int, error)
	})
	if !ok {
		fmt.Fprintln(os.Stderr, "error: this backend cannot remove keys")
		os.Exit(1)
	}
	n, err := remover.RemoveKey(*label)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rm failed:", err)
		os.Exit(1)
	}
	fmt.Printf("removed %d object(s) labelled %q\n", n, *label)
}

// printPubKey prints the verification key as hex plus its SHA-256 fingerprint (hex) — the
// fingerprint operators pin in agent configs to trust ML-DSA-signed commands.
func printPubKey(ckm hsm.CommandKeyManager, keyID, alg string) {
	pub, err := ckm.PublicKey(keyID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not read public key:", err)
		os.Exit(1)
	}
	fp := sha256.Sum256(pub)
	if alg != "" {
		fmt.Printf("algorithm:    %s\n", alg)
	}
	fmt.Printf("label:        %s\n", keyID)
	fmt.Printf("public_key:   %s\n", hex.EncodeToString(pub))
	fmt.Printf("fingerprint:  %s\n", hex.EncodeToString(fp[:]))
}
