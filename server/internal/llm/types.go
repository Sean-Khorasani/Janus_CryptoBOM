package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// JobType values for LLMAnalysisJob.
const (
	JobTypeIntentClassification  = "intent_classification"
	JobTypeFalsePositiveTriage   = "false_positive_triage"
	JobTypeRemediationSuggestion = "remediation_suggestion"
)

// JobStatus values for LLMAnalysisJob.
const (
	JobStatusQueued    = "queued"
	JobStatusRunning   = "running"
	JobStatusCompleted = "completed"
	JobStatusFailed    = "failed"
	JobStatusCancelled = "cancelled"
)

// VerdictValue values for LLMVerdict.
const (
	VerdictFalsePositive    = "false_positive"
	VerdictConfirmed        = "confirmed"
	VerdictSeverityAdjusted = "severity_adjusted"
	VerdictNeedsReview      = "needs_review"
	VerdictAbstain          = "abstain"
)

// RecommendationType values for RemediationSuggestion.
const (
	RecommendationConfigChange        = "config_change"
	RecommendationDependencyUpgrade   = "dependency_upgrade"
	RecommendationAPIRefactor         = "api_refactor"
	RecommendationCompensatingControl = "compensating_control"
	RecommendationBinaryNotSupported  = "binary_not_supported"
)

// RemediationSuggestion is the schema-validated output of a remediation_suggestion job.
// human_approval_required is always true — there is no automated application path.
type RemediationSuggestion struct {
	SuggestionID          string   `json:"suggestion_id"`
	JobID                 string   `json:"job_id"`
	FindingID             string   `json:"finding_id"`
	RecommendationType    string   `json:"recommendation_type"`
	TargetAlgorithm       string   `json:"target_algorithm"`
	CandidatePatch        string   `json:"candidate_patch,omitempty"` // unified diff, max 4096 bytes
	Assumptions           []string `json:"assumptions"`
	CompatibilityNotes    string   `json:"compatibility_notes"`
	ValidationRequired    []string `json:"validation_required"`
	HumanApprovalRequired bool     `json:"human_approval_required"` // always true
	Confidence            float64  `json:"confidence"`
	CreatedAt             string   `json:"created_at"`
}

// ValidateVerdict checks the eight invariants from LLM_CAPABILITY_CONTRACT.md §4.
func ValidateVerdict(verdict, abstentionReason string, adjustedSeverity *int, confidence float64, evidenceCitations []string) error {
	allowed := map[string]bool{
		VerdictFalsePositive:    true,
		VerdictConfirmed:        true,
		VerdictSeverityAdjusted: true,
		VerdictNeedsReview:      true,
		VerdictAbstain:          true,
	}
	if !allowed[verdict] {
		return errors.New("verdict must be one of: false_positive, confirmed, severity_adjusted, needs_review, abstain")
	}
	if confidence < 0.0 || confidence > 1.0 {
		return errors.New("confidence must be in [0.0, 1.0]")
	}
	if verdict == VerdictAbstain && strings.TrimSpace(abstentionReason) == "" {
		return errors.New("abstention_reason is required when verdict is abstain")
	}
	if verdict != VerdictAbstain && len(evidenceCitations) == 0 {
		return errors.New("evidence_citations must be non-empty for non-abstain verdicts")
	}
	if verdict == VerdictSeverityAdjusted {
		if adjustedSeverity == nil {
			return errors.New("adjusted_severity is required when verdict is severity_adjusted")
		}
		if *adjustedSeverity < 1 || *adjustedSeverity > 5 {
			return errors.New("adjusted_severity must be in [1, 5]")
		}
	}
	if verdict != VerdictSeverityAdjusted && adjustedSeverity != nil {
		return errors.New("adjusted_severity must be null when verdict is not severity_adjusted")
	}
	return nil
}

// ValidateSuggestion checks that a remediation suggestion is well-formed.
func ValidateSuggestion(s *RemediationSuggestion) error {
	allowed := map[string]bool{
		RecommendationConfigChange:        true,
		RecommendationDependencyUpgrade:   true,
		RecommendationAPIRefactor:         true,
		RecommendationCompensatingControl: true,
		RecommendationBinaryNotSupported:  true,
	}
	if !allowed[s.RecommendationType] {
		return errors.New("invalid recommendation_type")
	}
	if s.Confidence < 0.0 || s.Confidence > 1.0 {
		return errors.New("confidence must be in [0.0, 1.0]")
	}
	if len(s.CandidatePatch) > 4096 {
		return errors.New("candidate_patch exceeds 4096 byte limit")
	}
	if !s.HumanApprovalRequired {
		return errors.New("human_approval_required must be true; automated application is not supported")
	}
	return nil
}

// HashString returns the SHA-256 hex digest of a string.
// Used to generate input_hash and output_hash for provenance records.
func HashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
