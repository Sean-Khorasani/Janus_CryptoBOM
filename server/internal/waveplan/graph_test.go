package waveplan

import (
	"context"
	"testing"

	"github.com/janus-cbom/janus/server/internal/store"
)

// WP-022: dependency graph (cycle detection, topological order, activation
// guard) and budget rollup.

func TestBuildGraph_TopologicalOrder(t *testing.T) {
	// c depends on b, b depends on a → order must place a before b before c.
	plans := []store.WavePlan{
		{PlanID: "c", Name: "C", WaveNumber: 3, Status: StatusPlanned, DependsOn: []string{"b"}},
		{PlanID: "a", Name: "A", WaveNumber: 1, Status: StatusPlanned},
		{PlanID: "b", Name: "B", WaveNumber: 2, Status: StatusPlanned, DependsOn: []string{"a"}},
	}
	g := BuildGraph(plans)
	if g.HasCycle() {
		t.Fatalf("unexpected cycle: %v", g.Cycles)
	}
	pos := map[string]int{}
	for i, id := range g.TopologicalOrder {
		pos[id] = i
	}
	if !(pos["a"] < pos["b"] && pos["b"] < pos["c"]) {
		t.Fatalf("topological order wrong: %v", g.TopologicalOrder)
	}
	if len(g.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d: %v", len(g.Edges), g.Edges)
	}
}

func TestBuildGraph_DetectsCycle(t *testing.T) {
	plans := []store.WavePlan{
		{PlanID: "a", Name: "A", WaveNumber: 1, Status: StatusPlanned, DependsOn: []string{"b"}},
		{PlanID: "b", Name: "B", WaveNumber: 2, Status: StatusPlanned, DependsOn: []string{"a"}},
	}
	g := BuildGraph(plans)
	if !g.HasCycle() {
		t.Fatal("expected a cycle to be detected")
	}
	if len(g.TopologicalOrder) != 0 {
		t.Fatalf("topological order must be empty under a cycle, got %v", g.TopologicalOrder)
	}
}

func TestBuildGraph_UnknownRefAndActivatable(t *testing.T) {
	plans := []store.WavePlan{
		{PlanID: "a", Name: "A", WaveNumber: 1, Status: StatusCompleted},
		{PlanID: "b", Name: "B", WaveNumber: 2, Status: StatusPlanned, DependsOn: []string{"a"}},
		{PlanID: "c", Name: "C", WaveNumber: 3, Status: StatusPlanned, DependsOn: []string{"ghost"}},
	}
	g := BuildGraph(plans)
	if len(g.UnknownRefs) != 1 || g.UnknownRefs[0].To != "ghost" {
		t.Fatalf("expected one unknown ref to ghost, got %v", g.UnknownRefs)
	}
	node := map[string]GraphNode{}
	for _, n := range g.Nodes {
		node[n.PlanID] = n
	}
	// b depends on a (completed) → activatable.
	if !node["b"].Activatable {
		t.Errorf("b should be activatable (dependency a is completed)")
	}
	// a is already completed (not planned) → not activatable.
	if node["a"].Activatable {
		t.Errorf("a should not be activatable (already completed)")
	}
}

func TestBuildGraph_BlockedByIncompleteDependency(t *testing.T) {
	plans := []store.WavePlan{
		{PlanID: "a", Name: "A", WaveNumber: 1, Status: StatusActive}, // not completed
		{PlanID: "b", Name: "B", WaveNumber: 2, Status: StatusPlanned, DependsOn: []string{"a"}},
	}
	g := BuildGraph(plans)
	node := map[string]GraphNode{}
	for _, n := range g.Nodes {
		node[n.PlanID] = n
	}
	if node["b"].Activatable {
		t.Error("b must not be activatable while dependency a is not completed")
	}
	if len(node["b"].BlockedBy) != 1 || node["b"].BlockedBy[0] != "a" {
		t.Errorf("b should be blocked by a, got %v", node["b"].BlockedBy)
	}
}

func TestComputeBudget(t *testing.T) {
	plans := []store.WavePlan{
		{PlanID: "a", Status: StatusCompleted, BudgetHours: 10, ActualHours: 12, ComponentCount: 5},
		{PlanID: "b", Status: StatusPlanned, BudgetHours: 20, ActualHours: 0, ComponentCount: 8},
	}
	s := ComputeBudget(plans)
	if s.TotalBudgetHours != 30 || s.TotalActualHours != 12 {
		t.Fatalf("budget totals wrong: %+v", s)
	}
	if s.VarianceHours != -18 {
		t.Fatalf("variance = %v, want -18", s.VarianceHours)
	}
	if s.OverBudget {
		t.Error("should not be over budget (12 < 30)")
	}
	if s.TotalComponents != 13 {
		t.Errorf("total components = %d, want 13", s.TotalComponents)
	}
	if s.CompletionPercent != 50 {
		t.Errorf("completion = %v, want 50", s.CompletionPercent)
	}
}

func TestComputeBudget_OverBudget(t *testing.T) {
	plans := []store.WavePlan{
		{PlanID: "a", Status: StatusActive, BudgetHours: 10, ActualHours: 25},
	}
	s := ComputeBudget(plans)
	if !s.OverBudget || s.VarianceHours != 15 {
		t.Fatalf("expected over budget with +15 variance, got %+v", s)
	}
}

func TestCreate_RejectsUnknownDependency(t *testing.T) {
	planner, _ := newTestPlanner()
	plan := &store.WavePlan{Name: "depends on nothing real", WaveNumber: 1, DependsOn: []string{"does-not-exist"}}
	if err := planner.Create(context.Background(), plan, "tester"); err == nil {
		t.Fatal("expected Create to reject an unknown dependency reference")
	}
}

func TestUpdateStatus_BlocksActivationUntilDependencyCompletes(t *testing.T) {
	planner, m := newTestPlanner()
	ctx := context.Background()

	// Create dependency A.
	depA := &store.WavePlan{Name: "A", WaveNumber: 1}
	if err := planner.Create(ctx, depA, "tester"); err != nil {
		t.Fatalf("create A: %v", err)
	}
	aID := m.plans[0].PlanID

	// Create B depending on A.
	depB := &store.WavePlan{Name: "B", WaveNumber: 2, DependsOn: []string{aID}}
	if err := planner.Create(ctx, depB, "tester"); err != nil {
		t.Fatalf("create B: %v", err)
	}
	bID := m.plans[1].PlanID

	// Activating B must fail while A is still planned.
	if err := planner.UpdateStatus(ctx, bID, StatusActive); err == nil {
		t.Fatal("expected activation of B to be blocked while A is not completed")
	}

	// Complete A: planned → active → completed.
	if err := planner.UpdateStatus(ctx, aID, StatusActive); err != nil {
		t.Fatalf("activate A: %v", err)
	}
	if err := planner.UpdateStatus(ctx, aID, StatusCompleted); err != nil {
		t.Fatalf("complete A: %v", err)
	}

	// Now B can activate.
	if err := planner.UpdateStatus(ctx, bID, StatusActive); err != nil {
		t.Fatalf("expected B to activate once A completed, got: %v", err)
	}
}
