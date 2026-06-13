package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/janus-cbom/janus/server/internal/store"
)

func sampleFindings() []store.Finding {
	return []store.Finding{
		{FindingID: "f1", Severity: 5, Status: "open", Algorithm: "RSA", HostUUID: "h1"},
		{FindingID: "f2", Severity: 4, Status: "open", Algorithm: "ECDSA", HostUUID: "h1"},
		{FindingID: "f3", Severity: 5, Status: "remediated", Algorithm: "RSA", HostUUID: "h2"},
		{FindingID: "f4", Severity: 2, Status: "open", Algorithm: "SHA-1", HostUUID: "h2"},
	}
}

func ids(fs []store.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.FindingID
	}
	return out
}

func TestSelectFindingsExplicitIDs(t *testing.T) {
	got := selectFindings(sampleFindings(), batchAnalyzeRequest{FindingIDs: []string{"f2", "f4"}})
	if len(got) != 2 || got[0].FindingID != "f2" || got[1].FindingID != "f4" {
		t.Fatalf("explicit ids: got %v", ids(got))
	}
}

func TestSelectFindingsScopeAllCritical(t *testing.T) {
	req := batchAnalyzeRequest{}
	req.Filter = &struct {
		SeverityGte int32  `json:"severity_gte"`
		Status      string `json:"status"`
		Algorithm   string `json:"algorithm"`
		HostUUID    string `json:"host_uuid"`
		Scope       string `json:"scope"`
	}{Scope: "all_critical"}
	got := selectFindings(sampleFindings(), req)
	// severity>=5: f1 and f3
	if len(got) != 2 {
		t.Fatalf("all_critical: expected 2, got %v", ids(got))
	}
}

func TestSelectFindingsFilterAlgorithmAndStatus(t *testing.T) {
	req := batchAnalyzeRequest{}
	req.Filter = &struct {
		SeverityGte int32  `json:"severity_gte"`
		Status      string `json:"status"`
		Algorithm   string `json:"algorithm"`
		HostUUID    string `json:"host_uuid"`
		Scope       string `json:"scope"`
	}{Algorithm: "rsa", Status: "open"}
	got := selectFindings(sampleFindings(), req)
	if len(got) != 1 || got[0].FindingID != "f1" {
		t.Fatalf("rsa+open: expected [f1], got %v", ids(got))
	}
}

func TestSelectFindingsScopeAllDefaultsToOpen(t *testing.T) {
	req := batchAnalyzeRequest{}
	req.Filter = &struct {
		SeverityGte int32  `json:"severity_gte"`
		Status      string `json:"status"`
		Algorithm   string `json:"algorithm"`
		HostUUID    string `json:"host_uuid"`
		Scope       string `json:"scope"`
	}{Scope: "all"}
	got := selectFindings(sampleFindings(), req)
	// open findings only: f1, f2, f4 (f3 is remediated)
	if len(got) != 3 {
		t.Fatalf("all->open: expected 3, got %v", ids(got))
	}
}

func TestBuildFindingEvidenceIsMetadataOnly(t *testing.T) {
	ev := buildFindingEvidence(store.Finding{FindingID: "f1", Algorithm: "RSA", Severity: 5, Status: "open"})
	var m map[string]any
	if err := json.Unmarshal(ev, &m); err != nil {
		t.Fatalf("evidence not valid JSON: %v", err)
	}
	if m["finding_id"] != "f1" || m["algorithm"] != "RSA" {
		t.Fatalf("evidence missing fields: %v", m)
	}
	if m["sensitivity"] != "metadata-only" {
		t.Fatalf("evidence must be labelled metadata-only, got %v", m["sensitivity"])
	}
}
