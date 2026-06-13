package policy

import (
	"strings"
	"testing"
)

func TestBuiltinControlPack(t *testing.T) {
	pack := BuiltinControlPack()

	if pack.PackID == "" {
		t.Error("PackID must not be empty")
	}
	if pack.Version == "" {
		t.Error("Version must not be empty")
	}
	if pack.EffectiveDate == "" {
		t.Error("EffectiveDate must not be empty")
	}
	if len(pack.Rules) == 0 {
		t.Error("BuiltinControlPack must contain at least one rule")
	}
}

func TestBuiltinControlPackRuleIDs(t *testing.T) {
	pack := BuiltinControlPack()
	seen := make(map[string]struct{})
	for _, r := range pack.Rules {
		if r.RuleID == "" {
			t.Error("rule with empty RuleID found")
		}
		if _, dup := seen[r.RuleID]; dup {
			t.Errorf("duplicate RuleID: %s", r.RuleID)
		}
		seen[r.RuleID] = struct{}{}
	}
}

func TestBuiltinControlPackAllRulesHaveRequiredFields(t *testing.T) {
	pack := BuiltinControlPack()
	for _, r := range pack.Rules {
		if r.Title == "" {
			t.Errorf("rule %s: Title must not be empty", r.RuleID)
		}
		if r.Description == "" {
			t.Errorf("rule %s: Description must not be empty", r.RuleID)
		}
		if r.Rationale == "" {
			t.Errorf("rule %s: Rationale must not be empty", r.RuleID)
		}
		if len(r.FrameworkRefs) == 0 {
			t.Errorf("rule %s: FrameworkRefs must not be empty", r.RuleID)
		}
		if r.EffectiveDate == "" {
			t.Errorf("rule %s: EffectiveDate must not be empty", r.RuleID)
		}
		if r.Severity < 1 || r.Severity > 5 {
			t.Errorf("rule %s: Severity %d out of range [1,5]", r.RuleID, r.Severity)
		}
	}
}

func TestGetRuleKnownIDs(t *testing.T) {
	knownIDs := []string{
		"JANUS-PQC-001", "JANUS-PQC-002",
		"JANUS-NET-001",
		"JANUS-CNSA-001", "JANUS-CNSA-002", "JANUS-CNSA-003",
	}
	for _, id := range knownIDs {
		rule, ok := GetRule(id)
		if !ok {
			t.Errorf("GetRule(%q): not found", id)
			continue
		}
		if rule.RuleID != id {
			t.Errorf("GetRule(%q): returned rule with ID %q", id, rule.RuleID)
		}
	}
}

func TestGetRuleUnknownID(t *testing.T) {
	_, ok := GetRule("JANUS-DOES-NOT-EXIST")
	if ok {
		t.Error("GetRule on unknown ID should return ok=false")
	}
	_, ok = GetRule("CVE-2023-48795")
	if ok {
		t.Error("GetRule on CVE ID should return ok=false (CVE IDs are dynamic)")
	}
	_, ok = GetRule("")
	if ok {
		t.Error("GetRule on empty string should return ok=false")
	}
}

func TestBuiltinControlPackCoversEngineRuleIDs(t *testing.T) {
	// All rule IDs used by the policy engine should be findable via GetRule.
	// This ensures WP-017 coverage is complete — update this list when new rules are added.
	engineRuleIDs := []string{
		"JANUS-PQC-001", "JANUS-PQC-002", "JANUS-PQC-004",
		"JANUS-PQC-005", "JANUS-PQC-006", "JANUS-PQC-007",
		"JANUS-CLASSICAL-003",
		"JANUS-NET-001", "JANUS-NET-002",
		"JANUS-CNSA-001", "JANUS-CNSA-002", "JANUS-CNSA-003",
	}
	for _, id := range engineRuleIDs {
		if _, ok := GetRule(id); !ok {
			t.Errorf("engine emits rule ID %q but it is not in BuiltinControlPack", id)
		}
	}
}

func TestBuiltinControlPackFrameworkRefsNotEmpty(t *testing.T) {
	pack := BuiltinControlPack()
	for _, r := range pack.Rules {
		for _, ref := range r.FrameworkRefs {
			if strings.TrimSpace(ref) == "" {
				t.Errorf("rule %s has blank FrameworkRef", r.RuleID)
			}
		}
	}
}

func TestNIST2026ProfileHasMetadata(t *testing.T) {
	p := NIST2026Profile()
	if p.EffectiveDate == "" {
		t.Error("NIST2026Profile EffectiveDate must be set")
	}
	if len(p.FrameworkMappings) == 0 {
		t.Error("NIST2026Profile FrameworkMappings must not be empty")
	}
	// Must include FIPS 203, 204, 205
	required := []string{"NIST.FIPS.203", "NIST.FIPS.204", "NIST.FIPS.205"}
	refs := strings.Join(p.FrameworkMappings, ",")
	for _, r := range required {
		if !strings.Contains(refs, r) {
			t.Errorf("NIST2026Profile FrameworkMappings missing %q", r)
		}
	}
}
