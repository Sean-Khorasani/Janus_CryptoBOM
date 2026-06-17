package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FindingComment is an investigation note attached to a finding (UX-003).
type FindingComment struct {
	CommentID string    `json:"comment_id"`
	FindingID string    `json:"finding_id"`
	Actor     string    `json:"actor"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// FindingAssignment is the owner + remediation deadline for a finding (UX-003).
type FindingAssignment struct {
	FindingID  string     `json:"finding_id"`
	AssignedTo string     `json:"assigned_to"`
	DueDate    *time.Time `json:"due_date,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (p *Postgres) AddFindingComment(ctx context.Context, c *FindingComment) error {
	if c.CommentID == "" {
		c.CommentID = uuid.NewString()
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO finding_comments (comment_id, finding_id, actor, body) VALUES ($1,$2,$3,$4)`,
		c.CommentID, c.FindingID, c.Actor, c.Body)
	return err
}

func (p *Postgres) ListFindingComments(ctx context.Context, findingID string) ([]FindingComment, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT comment_id, finding_id, actor, body, created_at FROM finding_comments
		 WHERE finding_id=$1 ORDER BY created_at`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingComment
	for rows.Next() {
		var c FindingComment
		if err := rows.Scan(&c.CommentID, &c.FindingID, &c.Actor, &c.Body, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) UpsertFindingAssignment(ctx context.Context, a *FindingAssignment) error {
	_, err := p.pool.Exec(ctx, `
INSERT INTO finding_assignments (finding_id, assigned_to, due_date, updated_at)
VALUES ($1,$2,$3,now())
ON CONFLICT (finding_id) DO UPDATE SET assigned_to=EXCLUDED.assigned_to, due_date=EXCLUDED.due_date, updated_at=now()`,
		a.FindingID, a.AssignedTo, a.DueDate)
	return err
}

// GetFindingAssignment returns the assignment for one finding, or (nil,nil) if
// the finding has never been assigned (UX-003).
func (p *Postgres) GetFindingAssignment(ctx context.Context, findingID string) (*FindingAssignment, error) {
	var a FindingAssignment
	err := p.pool.QueryRow(ctx,
		`SELECT finding_id, assigned_to, due_date, updated_at FROM finding_assignments WHERE finding_id=$1`, findingID).
		Scan(&a.FindingID, &a.AssignedTo, &a.DueDate, &a.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

func (p *Postgres) ListFindingAssignments(ctx context.Context) ([]FindingAssignment, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT finding_id, assigned_to, due_date, updated_at FROM finding_assignments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingAssignment
	for rows.Next() {
		var a FindingAssignment
		if err := rows.Scan(&a.FindingID, &a.AssignedTo, &a.DueDate, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
