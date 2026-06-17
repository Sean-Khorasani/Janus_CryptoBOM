package llm

import (
	"fmt"
	"path"
	"strings"
)

// agentAllowedExtensions MUST mirror ALLOWED_EXTENSIONS in agent/src/mutation.rs. The
// agent's migration engine rejects any patch whose target file is not on this list, so
// enqueuing such a command would silently fail at the endpoint. We pre-check here (for
// both manual LLM-014 apply and autonomous LLM-017) and refuse with a clear reason
// instead. Keep this in sync if the agent allowlist changes.
var agentAllowedExtensions = map[string]bool{
	"conf": true, "config": true, "cnf": true, "json": true, "toml": true,
	"yaml": true, "yml": true, "xml": true, "ini": true, "properties": true,
}

// agentAllowedNoExtNames mirrors ALLOWED_NO_EXT_NAMES in agent/src/mutation.rs.
var agentAllowedNoExtNames = map[string]bool{"sshd_config": true, "ssh_config": true}

// PatchTargetPath extracts the post-image file path from a unified diff (the `+++ b/...`
// header), stripping the `b/` prefix and any trailing tab-delimited timestamp. Returns
// "" if no usable target header is present.
func PatchTargetPath(patch string) string {
	for _, line := range strings.Split(patch, "\n") {
		if !strings.HasPrefix(line, "+++ ") {
			continue
		}
		p := strings.TrimSpace(line[4:])
		if i := strings.IndexByte(p, '\t'); i >= 0 {
			p = p[:i]
		}
		p = strings.TrimPrefix(p, "b/")
		if p == "/dev/null" {
			continue // deletion marker — keep scanning for a real target
		}
		return p
	}
	return ""
}

// AgentWillApplyPatch reports whether the agent's migration engine would accept the
// patch's target file type (the extension allowlist). It is the correctness gate before
// enqueuing: a passing ValidatePatch only proves the diff is structurally safe, not that
// the agent will act on it. Returns the resolved target path and, on rejection, a reason.
func AgentWillApplyPatch(patch string) (target string, ok bool, reason string) {
	target = PatchTargetPath(patch)
	if target == "" {
		return "", false, "candidate patch has no resolvable target file"
	}
	base := path.Base(target)
	if dot := strings.LastIndexByte(base, '.'); dot >= 0 && dot < len(base)-1 {
		ext := strings.ToLower(base[dot+1:])
		if agentAllowedExtensions[ext] {
			return target, true, ""
		}
		return target, false, fmt.Sprintf("agent will not apply file type .%s (only config file types are mutable); use manual remediation for source files", ext)
	}
	if agentAllowedNoExtNames[base] {
		return target, true, ""
	}
	return target, false, fmt.Sprintf("agent will not apply extensionless file %q (not a known config file)", base)
}
