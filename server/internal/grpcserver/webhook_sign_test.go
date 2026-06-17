package grpcserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSignWebhookBody(t *testing.T) {
	// No secret -> no signature (caller omits the header).
	if got := signWebhookBody("", []byte(`{"x":1}`)); got != "" {
		t.Fatalf("empty secret should yield empty signature, got %q", got)
	}

	body := []byte(`{"finding":"abc","severity":5}`)
	secret := "shared-webhook-secret"
	got := signWebhookBody(secret, body)

	if !strings.HasPrefix(got, "sha256=") {
		t.Fatalf("signature must be prefixed sha256=, got %q", got)
	}
	// A receiver recomputes the same HMAC to verify authenticity.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("signature mismatch:\n got %s\nwant %s", got, want)
	}

	// A different body produces a different signature (integrity).
	if signWebhookBody(secret, []byte(`{"finding":"abc","severity":4}`)) == got {
		t.Fatal("altered body must change the signature")
	}
}
