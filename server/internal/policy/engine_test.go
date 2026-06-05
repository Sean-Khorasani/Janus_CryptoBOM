package policy

import (
	"testing"

	"github.com/janus-cbom/janus/server/internal/pb"
)

func newTestPayload() *pb.CbomTelemetryPayload {
	return &pb.CbomTelemetryPayload{}
}

// TestLowConfidenceSkipped verifies that algorithms with confidence < 0.4 are not assessed.
func TestLowConfidenceSkipped(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:test.go",
			Name:   "test.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "RSA",
					Family:     "RSA",
					Role:       pb.CryptoRoleSignature,
					Confidence: 0.20, // Low confidence (e.g., from test file)
					Status:     "observed",
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) > 0 {
		t.Errorf("expected 0 findings for low-confidence algorithm, got %d", len(payload.Findings))
	}
}

// TestTestOnlyStatusSkipped verifies that test-only algorithms are skipped entirely.
func TestTestOnlyStatusSkipped(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:crypto_test.go",
			Name:   "crypto_test.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "RSA",
					Family:     "RSA",
					Role:       pb.CryptoRoleSignature,
					Confidence: 0.90,
					Status:     "test-only",
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) > 0 {
		t.Errorf("expected 0 findings for test-only algorithm, got %d", len(payload.Findings))
	}
}

// TestVerifyIntentDowngradesSeverity verifies that verification-only usage lowers severity.
func TestVerifyIntentDowngradesSeverity(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:verifier.go",
			Name:   "verifier.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "RSA",
					Family:     "RSA",
					Role:       pb.CryptoRoleSignature,
					Confidence: 0.50,
					Status:     "verify", // Verification-only context
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(payload.Findings))
	}

	f := payload.Findings[0]
	// Original severity would be High (4), verify should downgrade by 2 to Low (2)
	if f.Severity != pb.RiskSeverityLow {
		t.Errorf("expected severity Low (%d) for verify context, got %d", pb.RiskSeverityLow, f.Severity)
	}
}

// TestNegotiateIntentDowngradesSeverity verifies that negotiation context lowers severity by 1.
func TestNegotiateIntentDowngradesSeverity(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:tls_config.go",
			Name:   "tls_config.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "ECDHE",
					Family:     "ECC",
					Role:       pb.CryptoRoleKeyExchange,
					Confidence: 0.70,
					Status:     "negotiate", // Negotiation / cipher suite list
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(payload.Findings))
	}

	f := payload.Findings[0]
	// Original severity would be High (4), negotiate should downgrade by 1 to Medium (3)
	if f.Severity != pb.RiskSeverityMedium {
		t.Errorf("expected severity Medium (%d) for negotiate context, got %d", pb.RiskSeverityMedium, f.Severity)
	}
}

// TestProtectIntentKeepsSeverity verifies that active protection contexts keep full severity.
func TestProtectIntentKeepsSeverity(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:crypto_signer.go",
			Name:   "crypto_signer.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "RSA",
					Family:     "RSA",
					Role:       pb.CryptoRoleSignature,
					Confidence: 0.90,
					Status:     "protect", // Active signing
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(payload.Findings))
	}

	f := payload.Findings[0]
	if f.Severity != pb.RiskSeverityHigh {
		t.Errorf("expected severity High (%d) for protect context, got %d", pb.RiskSeverityHigh, f.Severity)
	}
}

// TestHighConfidenceRSAProduceFinding verifies that high-confidence RSA generates findings.
func TestHighConfidenceRSAProduceFinding(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:handler.go",
			Name:   "handler.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "RSA",
					Family:     "RSA",
					Role:       pb.CryptoRoleSignature,
					Confidence: 0.90,
					Status:     "observed",
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) == 0 {
		t.Error("expected at least 1 finding for high-confidence RSA")
	}

	f := payload.Findings[0]
	if f.PolicyRuleId != "JANUS-PQC-001" {
		t.Errorf("expected rule JANUS-PQC-001, got %s", f.PolicyRuleId)
	}
}

// TestWeakRSAKeyBelowThreshold verifies critical severity for RSA keys below 3072 bits.
func TestWeakRSAKeyBelowThreshold(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:legacy.go",
			Name:   "legacy.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "RSA",
					Family:     "RSA",
					Role:       pb.CryptoRoleSignature,
					KeyBits:    2048,
					Confidence: 0.90,
					Status:     "protect",
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(payload.Findings))
	}

	f := payload.Findings[0]
	if f.Severity != pb.RiskSeverityCritical {
		t.Errorf("expected Critical severity for RSA-2048 protect, got %d", f.Severity)
	}
	if f.PolicyRuleId != "JANUS-PQC-002" {
		t.Errorf("expected rule JANUS-PQC-002, got %s", f.PolicyRuleId)
	}
}

// TestVerifyContextAnnotation verifies that low-risk intent adds context annotation.
func TestVerifyContextAnnotation(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:verifier.go",
			Name:   "verifier.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "RSA",
					Family:     "RSA",
					Role:       pb.CryptoRoleSignature,
					Confidence: 0.50,
					Status:     "verify",
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(payload.Findings))
	}

	f := payload.Findings[0]
	if f.Description == "" {
		t.Error("expected non-empty description")
	}
	// Should contain usage context annotation
	if !containsStr(f.Description, "Usage context") {
		t.Errorf("expected description to contain usage context annotation, got: %s", f.Description)
	}
}

// TestDeprecatedHashDetection verifies MD5/SHA-1 hash detection.
func TestDeprecatedHashDetection(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.Components = []*pb.CbomComponent{
		{
			BomRef: "file:hasher.go",
			Name:   "hasher.go",
			Algorithms: []*pb.CryptoAlgorithm{
				{
					Name:       "MD5",
					Family:     "hash",
					Role:       pb.CryptoRoleHash,
					Confidence: 0.90,
					Status:     "protect",
				},
			},
		},
	}

	e.Assess(payload)

	if len(payload.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(payload.Findings))
	}

	f := payload.Findings[0]
	if f.PolicyRuleId != "JANUS-CLASSICAL-003" {
		t.Errorf("expected rule JANUS-CLASSICAL-003, got %s", f.PolicyRuleId)
	}
}

// TestNetworkCleartextDetection verifies cleartext network finding.
func TestNetworkCleartextDetection(t *testing.T) {
	e := NewEngine(NIST2026Profile())
	payload := newTestPayload()
	payload.NetworkObservations = []*pb.NetworkObservation{
		{
			Endpoint:  "app.example.com:80",
			Protocol:  "HTTP",
			Cleartext: true,
		},
	}

	e.Assess(payload)

	if len(payload.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(payload.Findings))
	}

	f := payload.Findings[0]
	if f.PolicyRuleId != "JANUS-NET-001" {
		t.Errorf("expected rule JANUS-NET-001, got %s", f.PolicyRuleId)
	}
	if f.Severity != pb.RiskSeverityCritical {
		t.Errorf("expected Critical severity, got %d", f.Severity)
	}
}

// TestAdjustSeverityForIntent tests the severity adjustment function directly.
func TestAdjustSeverityForIntent(t *testing.T) {
	tests := []struct {
		name     string
		base     int32
		status   string
		expected int32
	}{
		{"verify high", pb.RiskSeverityHigh, "verify", pb.RiskSeverityLow},
		{"verify critical", pb.RiskSeverityCritical, "verify", pb.RiskSeverityMedium},
		{"parse high", pb.RiskSeverityHigh, "parse", pb.RiskSeverityLow},
		{"negotiate high", pb.RiskSeverityHigh, "negotiate", pb.RiskSeverityMedium},
		{"negotiate medium", pb.RiskSeverityMedium, "negotiate", pb.RiskSeverityLow},
		{"protect high", pb.RiskSeverityHigh, "protect", pb.RiskSeverityHigh},
		{"observed critical", pb.RiskSeverityCritical, "observed", pb.RiskSeverityCritical},
		{"nil alg", pb.RiskSeverityHigh, "", pb.RiskSeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg := &pb.CryptoAlgorithm{Status: tt.status}
			got := adjustSeverityForIntent(tt.base, alg)
			if got != tt.expected {
				t.Errorf("adjustSeverityForIntent(%d, %q) = %d, want %d", tt.base, tt.status, got, tt.expected)
			}
		})
	}

	// Test nil alg
	got := adjustSeverityForIntent(pb.RiskSeverityHigh, nil)
	if got != pb.RiskSeverityHigh {
		t.Errorf("adjustSeverityForIntent with nil alg = %d, want %d", got, pb.RiskSeverityHigh)
	}
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
