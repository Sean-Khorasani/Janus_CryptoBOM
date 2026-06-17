package policy

import "testing"

// UX-006: engine profile add/get/remove with active-profile protection.
func TestEngineProfileCRUD(t *testing.T) {
	e := NewEngine(NIST2026Profile())

	// Add a new profile and read it back.
	custom := Profile{Version: "custom-x", MinimumRSAKeyBits: 4096, PreferredKEM: "ML-KEM-1024"}
	e.AddProfile(custom)
	got, ok := e.GetProfile("custom-x")
	if !ok || got.MinimumRSAKeyBits != 4096 || got.PreferredKEM != "ML-KEM-1024" {
		t.Fatalf("GetProfile round-trip failed: %+v ok=%v", got, ok)
	}

	// Unknown profile.
	if _, ok := e.GetProfile("does-not-exist"); ok {
		t.Error("GetProfile returned ok for unknown version")
	}

	// Remove the non-active profile.
	if err := e.RemoveProfile("custom-x"); err != nil {
		t.Fatalf("RemoveProfile(custom-x): %v", err)
	}
	if _, ok := e.GetProfile("custom-x"); ok {
		t.Error("profile still present after RemoveProfile")
	}

	// Removing the active profile must be refused.
	active := e.ProfileVersion()
	if err := e.RemoveProfile(active); err == nil {
		t.Errorf("expected RemoveProfile(active=%q) to be refused", active)
	}

	// Removing an unknown profile errors.
	if err := e.RemoveProfile("nope"); err == nil {
		t.Error("expected error removing unknown profile")
	}
}
