package orchestrator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// fakeMAC mimics an HSM-resident HMAC key: MAC(label,data) = HMAC-SHA256(key, data),
// optionally failing for a chosen label to exercise the fail-closed path.
type fakeMAC struct {
	key       []byte
	failLabel string
}

func (f *fakeMAC) MAC(label string, data []byte) ([]byte, error) {
	if label == f.failLabel {
		return nil, errors.New("hsm unreachable")
	}
	m := hmac.New(sha256.New, f.key)
	m.Write(data)
	return m.Sum(nil), nil
}

// The whole point of HSM-resident command signing: the signature is byte-identical to the
// in-process HMAC over the same key, so the agent's existing verification is unchanged.
func TestHSMSignerMatchesInProcess(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	inProc := New(key)
	cmd := inProc.BuildCommand("host-1", "nginx", "nist-pqc", "/etc/nginx/nginx.conf", "patch", "abc", true, "ML-KEM-1024", "ML-DSA-87")

	hsmOrch := New(key)
	hsmOrch.UseHSMSigner(&fakeMAC{key: key}, "janus-command-signing")
	hsmSig := hsmOrch.Sign(cmd)

	if string(hsmSig) != string(cmd.SignedDirective) {
		t.Fatalf("HSM signature must equal the in-process HMAC over the same key:\n in-proc=%s\n hsm    =%s", cmd.SignedDirective, hsmSig)
	}
	// And it must be a valid lowercase-hex HMAC-SHA256 (64 hex chars).
	if _, err := hex.DecodeString(string(hsmSig)); err != nil || len(hsmSig) != 64 {
		t.Fatalf("signature is not hex HMAC-SHA256: len=%d err=%v", len(hsmSig), err)
	}
}

// When the HSM is unreachable, signing must fail closed (empty signature, Verify false),
// never emit an unsigned-but-accepted command.
func TestHSMSignerFailsClosed(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	o := New(key)
	o.UseHSMSigner(&fakeMAC{key: key, failLabel: "lbl"}, "lbl")
	cmd := o.BuildCommand("h", "svc", "p", "/c", "patch", "", true, "", "")
	if len(cmd.SignedDirective) != 0 {
		t.Fatalf("HSM signing failure must yield an empty signature, got %q", cmd.SignedDirective)
	}
	if o.Verify(cmd) {
		t.Fatal("an empty signature must not verify")
	}
}

// UseHSMSigner drops the in-process key so it no longer lives in server memory.
func TestUseHSMSignerDropsInProcessKey(t *testing.T) {
	o := New([]byte("0123456789abcdef0123456789abcdef"))
	o.UseHSMSigner(&fakeMAC{key: []byte("0123456789abcdef0123456789abcdef")}, "lbl")
	if o.signingKey != nil {
		t.Fatal("in-process signing key must be cleared once HSM signing is enabled")
	}
}
