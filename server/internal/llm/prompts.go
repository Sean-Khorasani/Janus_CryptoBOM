package llm

// Versioned server-side prompt registry (LLM-005). Centralizes prompt identity
// and version so each provenance record names exactly which prompt produced a
// verdict. Bump the version whenever the prompt text changes — otherwise
// provenance silently misattributes verdicts to an older prompt (which is what
// happened when LLM-019 hardened the prompts but the version stayed "1.0").

const (
	// VerdictPromptName identifies the finding-analysis prompt family.
	VerdictPromptName = "finding-verdict"
	// VerdictPromptVersion is bumped on every change to the system/user prompt.
	//   1.0 — initial verdict prompt
	//   2.0 — injection-defense hardening: untrusted_evidence quarantine +
	//         system-prompt authority reassertion (LLM-019)
	VerdictPromptVersion = "2.0"
)

// PromptSet is a named, versioned prompt the registry can hand out.
type PromptSet struct {
	Name    string
	Version string
	System  string
}

// VerdictPromptSet returns the current finding-analysis system prompt with its
// registry identity. The user turn is built per-request (it embeds quarantined
// evidence) via buildUserPrompt.
func VerdictPromptSet() PromptSet {
	return PromptSet{
		Name:    VerdictPromptName,
		Version: VerdictPromptVersion,
		System:  buildSystemPrompt(),
	}
}
