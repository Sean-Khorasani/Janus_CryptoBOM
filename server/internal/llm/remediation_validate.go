package llm

import (
	"fmt"
	"strings"
)

// maxPatchBytes bounds a candidate patch. Mirrors the limit in ValidateSuggestion.
const maxPatchBytes = 4096

// ValidatePatch runs the deterministic LLM-013 safety checks on a candidate unified
// diff BEFORE it is persisted or surfaced as actionable. It never applies anything —
// it is a verifier, not an executor. An empty patch is valid (guidance-only
// suggestions carry no diff). Rules:
//   - size <= maxPatchBytes
//   - no NUL bytes
//   - every file path in a ---/+++ header is repo-relative: no absolute paths,
//     no "..", no "~"; "/dev/null" is permitted (add/delete markers)
//   - a non-empty patch must contain at least one hunk header ("@@")
//
// The path-boundary rule is the load-bearing control: it stops an LLM (or injected
// evidence) from proposing edits that escape the working tree.
func ValidatePatch(patch string) error {
	if patch == "" {
		return nil
	}
	if len(patch) > maxPatchBytes {
		return fmt.Errorf("candidate_patch exceeds %d byte limit", maxPatchBytes)
	}
	if strings.ContainsRune(patch, 0) {
		return fmt.Errorf("candidate_patch contains NUL bytes")
	}
	hasHunk := false
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "@@"):
			hasHunk = true
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			path := patchHeaderPath(line[4:])
			if err := checkPatchPath(path); err != nil {
				return err
			}
		}
	}
	if !hasHunk {
		return fmt.Errorf("candidate_patch is not a valid unified diff (no @@ hunk header)")
	}
	return nil
}

// patchHeaderPath extracts the file path from a "--- "/"+++ " header body, stripping
// the trailing tab-delimited timestamp some diff tools append.
func patchHeaderPath(body string) string {
	body = strings.TrimSpace(body)
	if i := strings.IndexByte(body, '\t'); i >= 0 {
		body = body[:i]
	}
	return body
}

// checkPatchPath rejects any path that is not safely repo-relative.
func checkPatchPath(p string) error {
	if p == "/dev/null" {
		return nil
	}
	p = strings.TrimPrefix(p, "a/")
	p = strings.TrimPrefix(p, "b/")
	if p == "" {
		return fmt.Errorf("candidate_patch has an empty file path")
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") {
		return fmt.Errorf("candidate_patch targets a non-relative path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("candidate_patch path %q escapes the working tree", p)
		}
	}
	return nil
}
