package waveplan

import (
	"context"
	"sort"

	"github.com/janus-cbom/janus/server/internal/store"
)

// GraphNode is one wave plan in the dependency graph, annotated with the
// activation-readiness derived from its dependencies (WP-022).
type GraphNode struct {
	PlanID     string   `json:"plan_id"`
	Name       string   `json:"name"`
	WaveNumber int      `json:"wave_number"`
	Status     string   `json:"status"`
	DependsOn  []string `json:"depends_on"`
	// BlockedBy lists dependency plan_ids that are not yet "completed" and thus
	// currently block this wave from being activated. Empty means activatable.
	BlockedBy []string `json:"blocked_by"`
	// Activatable is true when the plan is in "planned" state and every
	// dependency has reached "completed".
	Activatable bool `json:"activatable"`
}

// GraphEdge is a directed dependency edge: From depends on To (To must complete
// before From can activate).
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// DependencyGraph is the full wave dependency DAG plus derived ordering.
type DependencyGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
	// TopologicalOrder lists plan_ids in a dependency-safe execution order
	// (dependencies before dependents). Empty when a cycle is present.
	TopologicalOrder []string `json:"topological_order"`
	// Cycles holds any dependency cycles detected (each a list of plan_ids).
	// A non-empty value means the graph is not a DAG and ordering is undefined.
	Cycles [][]string `json:"cycles"`
	// UnknownRefs lists depends_on references that point at non-existent plans.
	UnknownRefs []GraphEdge `json:"unknown_refs"`
}

// BuildGraph constructs the dependency graph from a set of plans. It detects
// cycles, computes a topological order (Kahn's algorithm), flags unknown
// references, and marks which plans are blocked from activation.
func BuildGraph(plans []store.WavePlan) DependencyGraph {
	byID := make(map[string]store.WavePlan, len(plans))
	for _, p := range plans {
		byID[p.PlanID] = p
	}

	g := DependencyGraph{
		Nodes:            make([]GraphNode, 0, len(plans)),
		Edges:            []GraphEdge{},
		TopologicalOrder: []string{},
		Cycles:           [][]string{},
		UnknownRefs:      []GraphEdge{},
	}

	// adjacency: dependency (To) -> dependents (From); indegree counts deps.
	dependents := make(map[string][]string)
	indegree := make(map[string]int)
	for _, p := range plans {
		if _, ok := indegree[p.PlanID]; !ok {
			indegree[p.PlanID] = 0
		}
	}

	for _, p := range plans {
		seen := make(map[string]bool)
		for _, dep := range p.DependsOn {
			if dep == p.PlanID || seen[dep] {
				continue // ignore self-references and duplicate edges
			}
			seen[dep] = true
			if _, ok := byID[dep]; !ok {
				g.UnknownRefs = append(g.UnknownRefs, GraphEdge{From: p.PlanID, To: dep})
				continue
			}
			g.Edges = append(g.Edges, GraphEdge{From: p.PlanID, To: dep})
			dependents[dep] = append(dependents[dep], p.PlanID)
			indegree[p.PlanID]++
		}
	}

	// Nodes with activation-readiness.
	for _, p := range plans {
		var blockedBy []string
		for _, dep := range p.DependsOn {
			d, ok := byID[dep]
			if !ok || dep == p.PlanID {
				continue
			}
			if d.Status != StatusCompleted {
				blockedBy = append(blockedBy, dep)
			}
		}
		g.Nodes = append(g.Nodes, GraphNode{
			PlanID:      p.PlanID,
			Name:        p.Name,
			WaveNumber:  p.WaveNumber,
			Status:      p.Status,
			DependsOn:   nonNilSlice(p.DependsOn),
			BlockedBy:   nonNilSlice(blockedBy),
			Activatable: p.Status == StatusPlanned && len(blockedBy) == 0,
		})
	}
	sort.Slice(g.Nodes, func(i, j int) bool {
		if g.Nodes[i].WaveNumber != g.Nodes[j].WaveNumber {
			return g.Nodes[i].WaveNumber < g.Nodes[j].WaveNumber
		}
		return g.Nodes[i].PlanID < g.Nodes[j].PlanID
	})

	// Kahn's topological sort. Process zero-indegree nodes in a stable order.
	queue := make([]string, 0)
	for id, deg := range indegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}
	sort.Strings(queue)
	processed := 0
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		g.TopologicalOrder = append(g.TopologicalOrder, id)
		processed++
		next := append([]string(nil), dependents[id]...)
		sort.Strings(next)
		for _, dependent := range next {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
		sort.Strings(queue)
	}

	// If not all nodes were processed, a cycle exists. Report the residual
	// nodes (those still carrying indegree) as the cyclic set.
	if processed < len(indegree) {
		var cyclic []string
		for id, deg := range indegree {
			if deg > 0 {
				cyclic = append(cyclic, id)
			}
		}
		sort.Strings(cyclic)
		g.Cycles = append(g.Cycles, cyclic)
		g.TopologicalOrder = []string{} // ordering undefined under a cycle
	}

	return g
}

// HasCycle reports whether the graph contains a dependency cycle.
func (g DependencyGraph) HasCycle() bool { return len(g.Cycles) > 0 }

// nonNilSlice returns an empty slice for nil so JSON renders [] not null.
func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// BudgetSummary rolls up effort/budget across all wave plans (WP-022).
type BudgetSummary struct {
	TotalBudgetHours float64        `json:"total_budget_hours"`
	TotalActualHours float64        `json:"total_actual_hours"`
	VarianceHours    float64        `json:"variance_hours"` // actual - budget; positive = over budget
	OverBudget       bool           `json:"over_budget"`
	TotalComponents  int            `json:"total_components"`
	PlanCount        int            `json:"plan_count"`
	StatusCounts     map[string]int `json:"status_counts"`
	// CompletionPercent is completed plans / total plans, 0–100.
	CompletionPercent float64 `json:"completion_percent"`
}

// ComputeBudget aggregates budget, effort, and progress across plans.
func ComputeBudget(plans []store.WavePlan) BudgetSummary {
	s := BudgetSummary{StatusCounts: map[string]int{}}
	for _, p := range plans {
		s.TotalBudgetHours += p.BudgetHours
		s.TotalActualHours += p.ActualHours
		s.TotalComponents += p.ComponentCount
		s.StatusCounts[p.Status]++
	}
	s.PlanCount = len(plans)
	s.VarianceHours = s.TotalActualHours - s.TotalBudgetHours
	s.OverBudget = s.TotalBudgetHours > 0 && s.TotalActualHours > s.TotalBudgetHours
	if s.PlanCount > 0 {
		s.CompletionPercent = float64(s.StatusCounts[StatusCompleted]) / float64(s.PlanCount) * 100.0
	}
	return s
}

// Graph loads all plans and returns the dependency graph (WP-022).
func (p *Planner) Graph(ctx context.Context) (DependencyGraph, error) {
	plans, err := p.store.GetWavePlans(ctx)
	if err != nil {
		return DependencyGraph{}, err
	}
	return BuildGraph(plans), nil
}

// Budget loads all plans and returns the budget summary (WP-022).
func (p *Planner) Budget(ctx context.Context) (BudgetSummary, error) {
	plans, err := p.store.GetWavePlans(ctx)
	if err != nil {
		return BudgetSummary{}, err
	}
	return ComputeBudget(plans), nil
}
