//go:build !cgo && !windows

package main

import (
	"fmt"
	"os"
)

// runHSMCLI is unavailable without cgo: the PKCS#11 client dlopen's the module via cgo.
// Build with CGO_ENABLED=1 to use `janus-server hsm ...`.
func runHSMCLI(_ []string) {
	fmt.Fprintln(os.Stderr, "hsm CLI requires a cgo-enabled build (CGO_ENABLED=1)")
	os.Exit(1)
}
