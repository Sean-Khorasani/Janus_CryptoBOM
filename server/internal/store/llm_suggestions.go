package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrSuggestionNotFound is returned when no suggestion matches the id.
var ErrSuggestionNotFound = errors.New("suggestion not found")

const suggestionColumns = `suggestion_id, job_id, finding_id, recommendation_type, target_algorithm,
  candidate_patch, assumptions, compatibility_notes, validation_required, validation_status,
  validation_detail, human_approval_required, confidence, model, prompt_version, created_at,
  review_decision, reviewed_by, reviewed_at, review_note`

func scanSuggestion(row interface{ Scan(...any) error }) (*LLMSuggestion, error) {
	var s LLMSuggestion
	var assumptions, validation []byte
	var reviewedAt *time.Time
	err := row.Scan(
		&s.SuggestionID, &s.JobID, &s.FindingID, &s.RecommendationType, &s.TargetAlgorithm,
		&s.CandidatePatch, &assumptions, &s.CompatibilityNotes, &validation, &s.ValidationStatus,
		&s.ValidationDetail, &s.HumanApprovalRequired, &s.Confidence, &s.Model, &s.PromptVersion, &s.CreatedAt,
		&s.ReviewDecision, &s.ReviewedBy, &reviewedAt, &s.ReviewNote)
	if err != nil {
		return nil, err
	}
	s.ReviewedAt = reviewedAt
	_ = json.Unmarshal(assumptions, &s.Assumptions)
	_ = json.Unmarshal(validation, &s.ValidationRequired)
	return &s, nil
}

// CreateSuggestion persists a remediation suggestion (LLM-011). The unique index on
// job_id makes this idempotent per job.
func (p *Postgres) CreateSuggestion(ctx context.Context, s *LLMSuggestion) error {
	if s.SuggestionID == "" {
		s.SuggestionID = uuid.NewString()
	}
	assumptions, _ := json.Marshal(s.Assumptions)
	validation, _ := json.Marshal(s.ValidationRequired)
	_, err := p.pool.Exec(ctx, `
INSERT INTO llm_suggestions (suggestion_id, job_id, finding_id, recommendation_type, target_algorithm,
  candidate_patch, assumptions, compatibility_notes, validation_required, validation_status,
  validation_detail, human_approval_required, confidence, model, prompt_version, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb,$10,$11,$12,$13,$14,$15,now())
ON CONFLICT (job_id) DO NOTHING`,
		s.SuggestionID, s.JobID, s.FindingID, s.RecommendationType, s.TargetAlgorithm,
		s.CandidatePatch, string(assumptions), s.CompatibilityNotes, string(validation), s.ValidationStatus,
		s.ValidationDetail, s.HumanApprovalRequired, s.Confidence, s.Model, s.PromptVersion)
	return err
}

func (p *Postgres) GetSuggestionByJob(ctx context.Context, jobID string) (*LLMSuggestion, error) {
	return scanSuggestion(p.pool.QueryRow(ctx,
		`SELECT `+suggestionColumns+` FROM llm_suggestions WHERE job_id=$1`, jobID))
}

func (p *Postgres) GetSuggestionByFinding(ctx context.Context, findingID string) (*LLMSuggestion, error) {
	return scanSuggestion(p.pool.QueryRow(ctx,
		`SELECT `+suggestionColumns+` FROM llm_suggestions WHERE finding_id=$1 ORDER BY created_at DESC LIMIT 1`, findingID))
}

func (p *Postgres) GetSuggestionByID(ctx context.Context, suggestionID string) (*LLMSuggestion, error) {
	s, err := scanSuggestion(p.pool.QueryRow(ctx,
		`SELECT `+suggestionColumns+` FROM llm_suggestions WHERE suggestion_id=$1`, suggestionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSuggestionNotFound
	}
	return s, err
}

// SetSuggestionReview records a human approve/reject decision (advisory only — it never
// applies the patch; authority inversion, parallels SetVerdictReview).
func (p *Postgres) SetSuggestionReview(ctx context.Context, suggestionID, decision, reviewedBy, note string) (*LLMSuggestion, error) {
	s, err := scanSuggestion(p.pool.QueryRow(ctx, `
UPDATE llm_suggestions
SET review_decision=$2, reviewed_by=$3, review_note=$4, reviewed_at=now()
WHERE suggestion_id=$1
RETURNING `+suggestionColumns, suggestionID, decision, reviewedBy, note))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSuggestionNotFound
	}
	return s, err
}
