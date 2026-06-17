//go:build !windows && cgo

package orchestrator_test

import (
	"os"
	"testing"

	"github.com/janus-cbom/janus/server/internal/hsm"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
)

// End-to-end on a live SoftHSM2 token: provision the command-signing key in the HSM, wire
// it into the orchestrator, and confirm an HSM-resident-signed migration command is
// byte-identical to the in-process HMAC over the same key — i.e. agents verify it
// unchanged while the key now lives in the HSM. Skipped unless JANUS_HSM_TEST_MODULE is set
// (scripts/hsm-softhsm-init.sh).
func TestCommandSigningOnLiveSoftHSM(t *testing.T) {
	module := os.Getenv("JANUS_HSM_TEST_MODULE")
	if module == "" {
		t.Skip("set JANUS_HSM_TEST_MODULE (+ SOFTHSM2_CONF/label/pin via scripts/hsm-softhsm-init.sh)")
	}
	label := envOr("JANUS_HSM_TEST_LABEL", "JanusTestToken")
	pin := envOr("JANUS_HSM_TEST_PIN", "1234")

	backend, err := hsm.NewBackend(hsm.HSMConfig{Mode: hsm.ModePKCS11, ModulePath: module, Label: label, Pin: pin})
	if err != nil {
		t.Fatalf("open token: %v", err)
	}
	defer backend.Close()

	mac, ok := backend.(hsm.MACSigner)
	if !ok {
		t.Fatal("pkcs11 backend must implement MACSigner")
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	const keyLabel = "janus-e2e-cmdkey"
	if err := mac.EnsureMACKey(keyLabel, key); err != nil {
		t.Fatalf("provision command key in HSM: %v", err)
	}

	inProc := orchestrator.New(key)
	cmd := inProc.BuildCommand("host-9", "nginx", "cnsa-2.0", "/etc/nginx/nginx.conf", "patch-body", "csum", true, "ML-KEM-1024", "ML-DSA-87")

	hsmOrch := orchestrator.New(key)
	hsmOrch.UseHSMSigner(mac, keyLabel)
	hsmSig := hsmOrch.Sign(cmd)

	if len(hsmSig) == 0 {
		t.Fatal("HSM-resident signing produced no signature")
	}
	if string(hsmSig) != string(cmd.SignedDirective) {
		t.Fatalf("HSM-resident signature must match in-process HMAC over the same key:\n in-proc=%s\n hsm    =%s", cmd.SignedDirective, hsmSig)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
