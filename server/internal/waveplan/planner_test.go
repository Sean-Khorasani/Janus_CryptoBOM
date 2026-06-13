package waveplan

import (
	"context"
	"testing"
	"time"

	"github.com/janus-cbom/janus/server/internal/store"
)

// mockStore implements the subset of store.Store needed for waveplan tests.
type mockStore struct {
	plans []store.WavePlan
}

func (m *mockStore) CreateWavePlan(_ context.Context, plan *store.WavePlan) error {
	m.plans = append(m.plans, *plan)
	return nil
}

func (m *mockStore) GetWavePlans(_ context.Context) ([]store.WavePlan, error) {
	return m.plans, nil
}

func (m *mockStore) UpdateWavePlan(_ context.Context, plan *store.WavePlan) error {
	for i := range m.plans {
		if m.plans[i].PlanID == plan.PlanID {
			m.plans[i] = *plan
			return nil
		}
	}
	return nil
}

func (m *mockStore) DeleteWavePlan(_ context.Context, planID string) error {
	for i := range m.plans {
		if m.plans[i].PlanID == planID {
			m.plans = append(m.plans[:i], m.plans[i+1:]...)
			return nil
		}
	}
	return nil
}

// storeMock wraps mockStore to satisfy the full store.Store interface
// via embedding a nil pointer and only implementing needed methods.
type storeMock struct {
	store.Store // embed nil — panics if any unimplemented method is called
	mock        *mockStore
}

func (s *storeMock) CreateWavePlan(ctx context.Context, plan *store.WavePlan) error {
	return s.mock.CreateWavePlan(ctx, plan)
}
func (s *storeMock) GetWavePlans(ctx context.Context) ([]store.WavePlan, error) {
	return s.mock.GetWavePlans(ctx)
}
func (s *storeMock) UpdateWavePlan(ctx context.Context, plan *store.WavePlan) error {
	return s.mock.UpdateWavePlan(ctx, plan)
}
func (s *storeMock) DeleteWavePlan(ctx context.Context, planID string) error {
	return s.mock.DeleteWavePlan(ctx, planID)
}

func newTestPlanner() (*Planner, *mockStore) {
	m := &mockStore{}
	return New(&storeMock{mock: m}), m
}

func TestCreate_ValidPlan(t *testing.T) {
	p, m := newTestPlanner()
	plan := &store.WavePlan{
		Name:       "Wave 1 — Internet-facing TLS",
		WaveNumber: 1,
		AssetIDs:   []string{"host-1", "host-2"},
	}
	if err := p.Create(context.Background(), plan, "admin"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if len(m.plans) != 1 {
		t.Errorf("expected 1 plan, got %d", len(m.plans))
	}
	if m.plans[0].PlanID == "" {
		t.Error("plan_id should be set by Create")
	}
	if m.plans[0].Status != StatusPlanned {
		t.Errorf("expected status=planned, got %s", m.plans[0].Status)
	}
}

func TestCreate_MissingName(t *testing.T) {
	p, _ := newTestPlanner()
	plan := &store.WavePlan{WaveNumber: 1}
	if err := p.Create(context.Background(), plan, "admin"); err == nil {
		t.Error("expected error for missing name")
	}
}

func TestCreate_InvalidWaveNumber(t *testing.T) {
	p, _ := newTestPlanner()
	plan := &store.WavePlan{Name: "Test", WaveNumber: 0}
	if err := p.Create(context.Background(), plan, "admin"); err == nil {
		t.Error("expected error for wave_number < 1")
	}
}

func TestCreate_TargetBeforeStart(t *testing.T) {
	p, _ := newTestPlanner()
	start := time.Now().Add(30 * 24 * time.Hour)
	target := time.Now().Add(10 * 24 * time.Hour)
	plan := &store.WavePlan{Name: "Test", WaveNumber: 1, StartDate: &start, TargetDate: &target}
	if err := p.Create(context.Background(), plan, "admin"); err == nil {
		t.Error("expected error when target_date < start_date")
	}
}

func TestUpdateStatus_ValidTransitions(t *testing.T) {
	transitions := []struct{ from, to string }{
		{StatusPlanned, StatusActive},
		{StatusActive, StatusCompleted},
		{StatusActive, StatusCancelled},
		{StatusPlanned, StatusCancelled},
	}
	for _, tr := range transitions {
		t.Run(tr.from+"->"+tr.to, func(t *testing.T) {
			p, m := newTestPlanner()
			m.plans = []store.WavePlan{{PlanID: "p1", Name: "T", Status: tr.from, WaveNumber: 1}}
			if err := p.UpdateStatus(context.Background(), "p1", tr.to); err != nil {
				t.Errorf("expected valid transition %s->%s, got error: %v", tr.from, tr.to, err)
			}
		})
	}
}

func TestUpdateStatus_InvalidTransitions(t *testing.T) {
	invalid := []struct{ from, to string }{
		{StatusCompleted, StatusActive},
		{StatusCancelled, StatusPlanned},
		{StatusCompleted, StatusPlanned},
		{StatusPlanned, StatusCompleted},
	}
	for _, tr := range invalid {
		t.Run(tr.from+"->"+tr.to, func(t *testing.T) {
			p, m := newTestPlanner()
			m.plans = []store.WavePlan{{PlanID: "p1", Name: "T", Status: tr.from, WaveNumber: 1}}
			if err := p.UpdateStatus(context.Background(), "p1", tr.to); err == nil {
				t.Errorf("expected error for invalid transition %s->%s", tr.from, tr.to)
			}
		})
	}
}

func TestDelete_PlannedAllowed(t *testing.T) {
	p, m := newTestPlanner()
	m.plans = []store.WavePlan{{PlanID: "p1", Name: "T", Status: StatusPlanned, WaveNumber: 1}}
	if err := p.Delete(context.Background(), "p1"); err != nil {
		t.Errorf("delete of planned wave should succeed: %v", err)
	}
	if len(m.plans) != 0 {
		t.Error("plan should be removed")
	}
}

func TestDelete_ActiveBlocked(t *testing.T) {
	p, m := newTestPlanner()
	m.plans = []store.WavePlan{{PlanID: "p1", Name: "T", Status: StatusActive, WaveNumber: 1}}
	if err := p.Delete(context.Background(), "p1"); err == nil {
		t.Error("expected error when deleting active wave plan")
	}
}

func TestReadinessChecklist_NonEmpty(t *testing.T) {
	items := ReadinessChecklist()
	if len(items) == 0 {
		t.Error("ReadinessChecklist should return non-empty list")
	}
}

func TestWavePlanValidatesApprovalPolicy(t *testing.T) {
	valid := []string{"auto", "operator", "admin", ""}
	for _, policy := range valid {
		t.Run("valid:"+policy, func(t *testing.T) {
			p, _ := newTestPlanner()
			plan := &store.WavePlan{Name: "Test Wave", WaveNumber: 1, ApprovalPolicy: policy}
			if err := p.Create(context.Background(), plan, "admin"); err != nil {
				t.Errorf("expected approval_policy %q to be valid, got error: %v", policy, err)
			}
		})
	}

	invalid := []string{"superadmin", "root", "ADMIN", "Operator"}
	for _, policy := range invalid {
		t.Run("invalid:"+policy, func(t *testing.T) {
			p, _ := newTestPlanner()
			plan := &store.WavePlan{Name: "Test Wave", WaveNumber: 1, ApprovalPolicy: policy}
			if err := p.Create(context.Background(), plan, "admin"); err == nil {
				t.Errorf("expected approval_policy %q to be rejected, but Create succeeded", policy)
			}
		})
	}
}

func TestWavePlanCanaryTargetsAllowed(t *testing.T) {
	p, m := newTestPlanner()
	plan := &store.WavePlan{
		Name:          "Wave with Canaries",
		WaveNumber:    1,
		CanaryTargets: []string{"host-uuid-1", "host-uuid-2"},
	}
	if err := p.Create(context.Background(), plan, "admin"); err != nil {
		t.Fatalf("Create with canary_targets failed: %v", err)
	}
	if len(m.plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(m.plans))
	}
	if len(m.plans[0].CanaryTargets) != 2 {
		t.Errorf("expected 2 canary_targets, got %d", len(m.plans[0].CanaryTargets))
	}
}

func TestWavePlanDefaultApprovalPolicy(t *testing.T) {
	p, m := newTestPlanner()
	// Empty approval_policy (the zero value) must be accepted — it is optional.
	plan := &store.WavePlan{Name: "Test Wave", WaveNumber: 1}
	if err := p.Create(context.Background(), plan, "admin"); err != nil {
		t.Fatalf("expected empty approval_policy to pass validation, got: %v", err)
	}
	if m.plans[0].ApprovalPolicy != "" {
		t.Errorf("expected approval_policy to remain empty, got %q", m.plans[0].ApprovalPolicy)
	}
}

func TestWavePlanBudgetValidation(t *testing.T) {
	// Negative budget_hours must be rejected.
	t.Run("negative budget_hours rejected", func(t *testing.T) {
		p, _ := newTestPlanner()
		plan := &store.WavePlan{Name: "Test Wave", WaveNumber: 1, BudgetHours: -1.0}
		if err := p.Create(context.Background(), plan, "admin"); err == nil {
			t.Error("expected error for negative budget_hours")
		}
	})
	// Negative actual_hours must be rejected.
	t.Run("negative actual_hours rejected", func(t *testing.T) {
		p, _ := newTestPlanner()
		plan := &store.WavePlan{Name: "Test Wave", WaveNumber: 1, ActualHours: -0.5}
		if err := p.Create(context.Background(), plan, "admin"); err == nil {
			t.Error("expected error for negative actual_hours")
		}
	})
	// Zero must pass.
	t.Run("zero budget and actual pass", func(t *testing.T) {
		p, _ := newTestPlanner()
		plan := &store.WavePlan{Name: "Test Wave", WaveNumber: 1, BudgetHours: 0, ActualHours: 0}
		if err := p.Create(context.Background(), plan, "admin"); err != nil {
			t.Errorf("expected zero budget/actual to pass, got: %v", err)
		}
	})
	// Positive values must pass.
	t.Run("positive budget and actual pass", func(t *testing.T) {
		p, _ := newTestPlanner()
		plan := &store.WavePlan{Name: "Test Wave", WaveNumber: 1, BudgetHours: 40.0, ActualHours: 12.5}
		if err := p.Create(context.Background(), plan, "admin"); err != nil {
			t.Errorf("expected positive budget/actual to pass, got: %v", err)
		}
	})
}

func TestWavePlanActualHoursCanExceedBudget(t *testing.T) {
	// actual_hours > budget_hours is valid — it's a tracking field, not a cap.
	p, m := newTestPlanner()
	plan := &store.WavePlan{
		Name:        "Over-budget wave",
		WaveNumber:  2,
		BudgetHours: 20.0,
		ActualHours: 35.0,
	}
	if err := p.Create(context.Background(), plan, "admin"); err != nil {
		t.Fatalf("actual_hours > budget_hours should be allowed, got: %v", err)
	}
	if m.plans[0].ActualHours != 35.0 {
		t.Errorf("expected actual_hours=35.0, got %f", m.plans[0].ActualHours)
	}
	if m.plans[0].BudgetHours != 20.0 {
		t.Errorf("expected budget_hours=20.0, got %f", m.plans[0].BudgetHours)
	}
}
