//go:build !windows && !cgo

package hsm

import "fmt"

// This stub is built only for non-Windows targets WITHOUT cgo (e.g. a static
// CGO_ENABLED=0 release binary). The real PKCS#11 client (pkcs11_cgo.go) needs cgo to
// dlopen the module. JANUS_HSM_MODE=pkcs11 therefore fails closed on a cgo-less build
// rather than pretending to talk to a token.
func newPKCS11(_ HSMConfig) (HSM, error) {
	return nil, fmt.Errorf("PKCS#11 HSM support requires a cgo-enabled build (CGO_ENABLED=1); use JANUS_HSM_MODE=software for a cgo-less binary")
}
