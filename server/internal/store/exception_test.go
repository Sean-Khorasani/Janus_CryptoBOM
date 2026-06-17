package store

import (
	"testing"
	"time"
)

func TestComplianceExceptionActive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	cases := []struct {
		name string
		e    ComplianceException
		want bool
	}{
		{"active no expiry", ComplianceException{Status: "active"}, true},
		{"active future expiry", ComplianceException{Status: "active", ExpiresAt: &future}, true},
		{"active past expiry", ComplianceException{Status: "active", ExpiresAt: &past}, false},
		{"revoked", ComplianceException{Status: "revoked"}, false},
		{"empty status", ComplianceException{}, false},
	}
	for _, c := range cases {
		if got := c.e.Active(now); got != c.want {
			t.Errorf("%s: Active = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestExceptionSuppresses(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	past := now.Add(-time.Hour)
	exs := []ComplianceException{
		{RuleID: "JANUS-PQC-001", Status: "active"},                         // rule-scoped, all assets
		{RuleID: "JANUS-PQC-002", AssetRef: "host-1:rsa", Status: "active"}, // asset-scoped
		{RuleID: "JANUS-PQC-004", Status: "active", ExpiresAt: &past},       // expired
		{RuleID: "JANUS-PQC-005", Status: "revoked"},                        // revoked
	}

	// Rule-scoped exception covers any asset for that rule.
	if !ExceptionSuppresses(exs, "JANUS-PQC-001", "anything", now) {
		t.Error("rule-scoped exception should cover any asset")
	}
	// Asset-scoped covers only the matching asset.
	if !ExceptionSuppresses(exs, "JANUS-PQC-002", "host-1:rsa", now) {
		t.Error("asset-scoped exception should cover its asset")
	}
	if ExceptionSuppresses(exs, "JANUS-PQC-002", "host-2:rsa", now) {
		t.Error("asset-scoped exception must not cover a different asset")
	}
	// Expired and revoked never suppress.
	if ExceptionSuppresses(exs, "JANUS-PQC-004", "x", now) {
		t.Error("expired exception must not suppress")
	}
	if ExceptionSuppresses(exs, "JANUS-PQC-005", "x", now) {
		t.Error("revoked exception must not suppress")
	}
	// A rule with no exception is never suppressed.
	if ExceptionSuppresses(exs, "JANUS-NET-001", "x", now) {
		t.Error("a rule with no exception must not be suppressed")
	}
}
