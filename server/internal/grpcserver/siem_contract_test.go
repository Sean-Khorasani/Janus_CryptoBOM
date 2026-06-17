package grpcserver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/janus-cbom/janus/server/internal/pb"
	"github.com/janus-cbom/janus/server/internal/policy"
)

// WP-024 contract test: the SIEM/SOAR webhook event is the integration contract external
// consumers (SIEM, SOAR, ticketing) depend on. Lock its schema — field names, nesting, and
// value mapping — so a change cannot silently break downstream integrations. Also assert it
// is valid JSON (what a consumer actually receives over the wire).
func TestSIEMEventContract(t *testing.T) {
	payload := &pb.CbomTelemetryPayload{HostUuid: "host-abc"}
	finding := &pb.CryptoFinding{
		FindingId:    "f-123",
		PolicyRuleId: "JANUS-PQC-001",
		Title:        "RSA signature is quantum-vulnerable",
		Severity:     5,
		Algorithm:    "RSA-2048",
		AssetRef:     "host-abc:/etc/nginx/nginx.conf:10",
		EvidenceIds:  []string{"ev-1"},
	}
	prof := policy.Profile{PreferredKEM: "X25519MLKEM768", PreferredSignature: "ML-DSA-65"}

	evt := buildSIEMEvent(payload, finding, prof)

	// Top-level contract.
	if evt["event_type"] != "janus.finding.critical" {
		t.Errorf("event_type = %v", evt["event_type"])
	}
	if evt["event_version"] != "1.0" {
		t.Errorf("event_version = %v", evt["event_version"])
	}
	if ts, _ := evt["timestamp"].(string); ts == "" {
		t.Error("timestamp must be present")
	} else if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("timestamp must be RFC3339: %v", err)
	}

	// source block.
	src, ok := evt["source"].(map[string]interface{})
	if !ok {
		t.Fatal("source must be an object")
	}
	if src["product"] != "Janus CryptoBOM" || src["host_uuid"] != "host-abc" {
		t.Errorf("source contract mismatch: %v", src)
	}

	// finding block — the fields a SIEM rule keys on.
	fb, ok := evt["finding"].(map[string]interface{})
	if !ok {
		t.Fatal("finding must be an object")
	}
	if fb["finding_id"] != "f-123" || fb["rule_id"] != "JANUS-PQC-001" ||
		fb["algorithm"] != "RSA-2048" || fb["asset_ref"] != "host-abc:/etc/nginx/nginx.conf:10" {
		t.Errorf("finding contract mismatch: %v", fb)
	}
	if fb["severity_label"] != "critical" {
		t.Errorf("severity_label = %v, want critical", fb["severity_label"])
	}

	// remediation block carries the active profile's migration targets.
	rb, ok := evt["remediation"].(map[string]interface{})
	if !ok {
		t.Fatal("remediation must be an object")
	}
	if rb["migration_target_kem"] != "X25519MLKEM768" || rb["migration_target_sig"] != "ML-DSA-65" {
		t.Errorf("remediation contract mismatch: %v", rb)
	}

	// The event must serialize to valid JSON (what the consumer receives).
	if _, err := json.Marshal(evt); err != nil {
		t.Fatalf("SIEM event must marshal to JSON: %v", err)
	}
}
