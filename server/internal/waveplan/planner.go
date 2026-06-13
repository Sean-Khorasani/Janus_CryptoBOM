// Package waveplan implements migration wave planning for Janus CryptoBOM (WAVE-01 / WP-022).
//
// Wave plans are planning artifacts — they group assets and algorithm targets into
// sequenced migration batches. They do NOT drive automated execution.
// See docs/WAVE_PLANNING_GUIDE.md for operator usage.
package waveplan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/store"
)

// WaveStatus values.
const (
	StatusPlanned   = "planned"
	StatusActive    = "active"
	StatusCompleted = "completed"
	StatusCancelled = "cancelled"
)

// ValidStatuses is the complete set of allowed wave plan statuses.
var ValidStatuses = map[string]bool{
	StatusPlanned:   true,
	StatusActive:    true,
	StatusCompleted: true,
	StatusCancelled: true,
}

// Planner provides wave plan CRUD operations and basic validation.
type Planner struct {
	store store.Store
}

func New(s store.Store) *Planner {
	return &Planner{store: s}
}

// Create validates and persists a new wave plan.
func (p *Planner) Create(ctx context.Context, plan *store.WavePlan, createdBy string) error {
	if err := validate(plan); err != nil {
		return err
	}
	plan.PlanID = uuid.NewString()
	plan.Status = StatusPlanned
	plan.CreatedBy = createdBy
	plan.CreatedAt = time.Now().UTC()
	plan.UpdatedAt = plan.CreatedAt
	return p.store.CreateWavePlan(ctx, plan)
}

// List returns all wave plans ordered by wave_number then created_at.
func (p *Planner) List(ctx context.Context) ([]store.WavePlan, error) {
	return p.store.GetWavePlans(ctx)
}

// UpdateStatus transitions a wave plan to a new status, enforcing allowed transitions.
// Allowed: planned→active, active→completed, active→cancelled, planned→cancelled.
func (p *Planner) UpdateStatus(ctx context.Context, planID, newStatus string) error {
	if !ValidStatuses[newStatus] {
		return fmt.Errorf("invalid status %q", newStatus)
	}
	plans, err := p.store.GetWavePlans(ctx)
	if err != nil {
		return err
	}
	var plan *store.WavePlan
	for i := range plans {
		if plans[i].PlanID == planID {
			plan = &plans[i]
			break
		}
	}
	if plan == nil {
		return errors.New("wave plan not found")
	}
	if err := checkTransition(plan.Status, newStatus); err != nil {
		return err
	}
	plan.Status = newStatus
	return p.store.UpdateWavePlan(ctx, plan)
}

// Delete removes a wave plan. Only planned or cancelled plans can be deleted.
func (p *Planner) Delete(ctx context.Context, planID string) error {
	plans, err := p.store.GetWavePlans(ctx)
	if err != nil {
		return err
	}
	for _, wp := range plans {
		if wp.PlanID == planID {
			if wp.Status == StatusActive || wp.Status == StatusCompleted {
				return fmt.Errorf("cannot delete a %s wave plan; cancel it first", wp.Status)
			}
			return p.store.DeleteWavePlan(ctx, planID)
		}
	}
	return errors.New("wave plan not found")
}

// ReadinessChecklist returns the pre-activation checklist items for a wave plan.
// Callers display this to operators before they activate a wave.
func ReadinessChecklist() []string {
	return []string{
		"All assets in wave have completed a discovery scan",
		"Critical and high findings reviewed and triaged",
		"Dry-run migration simulation passed for a representative asset",
		"Rollback plan documented",
		"Stakeholder approval recorded in audit log",
		"Monitoring alerts configured for target services",
	}
}

// validApprovalPolicies is the complete set of allowed approval_policy values.
var validApprovalPolicies = map[string]bool{
	"":         true,
	"auto":     true,
	"operator": true,
	"admin":    true,
}

func validate(plan *store.WavePlan) error {
	if plan.Name == "" {
		return errors.New("wave plan name is required")
	}
	if plan.WaveNumber < 1 {
		return errors.New("wave_number must be >= 1")
	}
	if plan.TargetDate != nil && plan.StartDate != nil && plan.TargetDate.Before(*plan.StartDate) {
		return errors.New("target_date must not be before start_date")
	}
	if !validApprovalPolicies[plan.ApprovalPolicy] {
		return fmt.Errorf("approval_policy must be one of auto, operator, admin (got %q)", plan.ApprovalPolicy)
	}
	if plan.BudgetHours < 0 {
		return errors.New("budget_hours must be >= 0")
	}
	if plan.ActualHours < 0 {
		return errors.New("actual_hours must be >= 0")
	}
	return nil
}

func checkTransition(from, to string) error {
	allowed := map[string]map[string]bool{
		StatusPlanned:   {StatusActive: true, StatusCancelled: true},
		StatusActive:    {StatusCompleted: true, StatusCancelled: true},
		StatusCompleted: {},
		StatusCancelled: {},
	}
	if !allowed[from][to] {
		return fmt.Errorf("cannot transition wave plan from %q to %q", from, to)
	}
	return nil
}
