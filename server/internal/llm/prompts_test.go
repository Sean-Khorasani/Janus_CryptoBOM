package llm

import "testing"

func TestVerdictPromptSetIdentity(t *testing.T) {
	ps := VerdictPromptSet()
	if ps.Name != "finding-verdict" {
		t.Errorf("name = %q, want finding-verdict", ps.Name)
	}
	if ps.Version != VerdictPromptVersion || ps.Version == "" {
		t.Errorf("version = %q, want %q", ps.Version, VerdictPromptVersion)
	}
	// Regression: the version must move when the prompt changes. LLM-019 hardened
	// the prompt, so it must no longer be the original "1.0".
	if ps.Version == "1.0" {
		t.Error("prompt version still 1.0 after the injection-defense change — bump it")
	}
	if ps.System == "" {
		t.Error("system prompt must not be empty")
	}
	// The current prompt carries the injection-defense clause; the version must
	// reflect that hardened content.
	if !contains(ps.System, "UNTRUSTED DATA") {
		t.Error("registered system prompt missing the injection-defense clause")
	}
}
