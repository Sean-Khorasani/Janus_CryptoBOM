package llm

import (
	"testing"
)

func TestValidateVerdict_ValidCases(t *testing.T) {
	tests := []struct {
		name             string
		verdict          string
		abstentionReason string
		adjustedSeverity *int
		confidence       float64
		citations        []string
		wantErr          bool
	}{
		{
			name:       "confirmed with citations",
			verdict:    VerdictConfirmed,
			confidence: 0.85,
			citations:  []string{"finding-123"},
		},
		{
			name:       "false_positive with citations",
			verdict:    VerdictFalsePositive,
			confidence: 0.75,
			citations:  []string{"ev-1", "ev-2"},
		},
		{
			name:             "abstain requires reason",
			verdict:          VerdictAbstain,
			abstentionReason: "insufficient evidence to determine",
			confidence:       0.0,
			citations:        []string{},
		},
		{
			name:             "severity_adjusted with valid severity",
			verdict:          VerdictSeverityAdjusted,
			confidence:       0.80,
			citations:        []string{"ev-1"},
			adjustedSeverity: intPtr(3),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateVerdict(tc.verdict, tc.abstentionReason, tc.adjustedSeverity, tc.confidence, tc.citations)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateVerdict() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateVerdict_InvalidCases(t *testing.T) {
	tests := []struct {
		name             string
		verdict          string
		abstentionReason string
		adjustedSeverity *int
		confidence       float64
		citations        []string
	}{
		{
			name:      "unknown verdict value",
			verdict:   "unknown_verdict",
			confidence: 0.5,
			citations: []string{"ev-1"},
		},
		{
			name:      "confidence below 0",
			verdict:   VerdictConfirmed,
			confidence: -0.1,
			citations: []string{"ev-1"},
		},
		{
			name:      "confidence above 1",
			verdict:   VerdictConfirmed,
			confidence: 1.5,
			citations: []string{"ev-1"},
		},
		{
			name:             "abstain without reason",
			verdict:          VerdictAbstain,
			abstentionReason: "",
			confidence:       0.0,
			citations:        []string{},
		},
		{
			name:      "non-abstain with empty citations",
			verdict:   VerdictConfirmed,
			confidence: 0.8,
			citations: []string{},
		},
		{
			name:             "severity_adjusted without adjusted_severity",
			verdict:          VerdictSeverityAdjusted,
			confidence:       0.8,
			citations:        []string{"ev-1"},
			adjustedSeverity: nil,
		},
		{
			name:             "severity_adjusted with out-of-range severity",
			verdict:          VerdictSeverityAdjusted,
			confidence:       0.8,
			citations:        []string{"ev-1"},
			adjustedSeverity: intPtr(0),
		},
		{
			name:             "non-severity_adjusted with adjusted_severity set",
			verdict:          VerdictConfirmed,
			confidence:       0.8,
			citations:        []string{"ev-1"},
			adjustedSeverity: intPtr(3),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateVerdict(tc.verdict, tc.abstentionReason, tc.adjustedSeverity, tc.confidence, tc.citations)
			if err == nil {
				t.Errorf("expected error for case %q but got nil", tc.name)
			}
		})
	}
}

func TestValidateSuggestion(t *testing.T) {
	validSuggestion := &RemediationSuggestion{
		SuggestionID:          "s-1",
		RecommendationType:    RecommendationConfigChange,
		TargetAlgorithm:       "X25519MLKEM768",
		HumanApprovalRequired: true,
		Confidence:            0.80,
	}
	if err := ValidateSuggestion(validSuggestion); err != nil {
		t.Errorf("valid suggestion rejected: %v", err)
	}

	// Patch too large
	big := validSuggestion
	big.CandidatePatch = string(make([]byte, 4097))
	if err := ValidateSuggestion(big); err == nil {
		t.Error("expected error for oversized patch")
	}

	// human_approval_required must be true
	noApproval := *validSuggestion
	noApproval.CandidatePatch = ""
	noApproval.HumanApprovalRequired = false
	if err := ValidateSuggestion(&noApproval); err == nil {
		t.Error("expected error when human_approval_required is false")
	}

	// Invalid recommendation type
	bad := *validSuggestion
	bad.RecommendationType = "auto_patch"
	if err := ValidateSuggestion(&bad); err == nil {
		t.Error("expected error for invalid recommendation_type")
	}
}

func TestHashString_Deterministic(t *testing.T) {
	h1 := HashString("test input")
	h2 := HashString("test input")
	if h1 != h2 {
		t.Error("HashString is not deterministic")
	}
	h3 := HashString("different input")
	if h1 == h3 {
		t.Error("HashString should differ for different inputs")
	}
}

func TestHashString_Length(t *testing.T) {
	h := HashString("any string")
	if len(h) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got %d chars", len(h))
	}
}

func intPtr(i int) *int { return &i }
