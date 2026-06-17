import { useEffect, useState, useCallback } from "react";
import { GitBranch, AlertTriangle, RefreshCw, CheckCircle2, Lock } from "lucide-react";

// Mirrors server/internal/waveplan/graph.go (WP-022) GET /api/waves/graph.
interface GraphNode {
  plan_id: string;
  name: string;
  wave_number: number;
  status: string;
  depends_on: string[];
  blocked_by: string[];
  activatable: boolean;
}
interface GraphEdge {
  from: string;
  to: string;
}
interface DependencyGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  topological_order: string[];
  cycles: string[][];
  unknown_refs: GraphEdge[];
}
interface BudgetSummary {
  total_budget_hours: number;
  total_actual_hours: number;
  variance_hours: number;
  over_budget: boolean;
  total_components: number;
  plan_count: number;
  status_counts: Record<string, number>;
  completion_percent: number;
}
interface GraphResponse {
  graph: DependencyGraph;
  budget: BudgetSummary;
}

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function StatusDot({ status }: { status: string }) {
  const cls: Record<string, string> = {
    planned: "bg-[#9aa8a0]",
    active: "bg-[#3a7d44]",
    completed: "bg-[#2f6638]",
    cancelled: "bg-[#c0584a]",
  };
  return <span className={`inline-block h-2 w-2 rounded-full ${cls[status] ?? "bg-[#9aa8a0]"}`} aria-hidden="true" />;
}

/**
 * WaveDependencyGraph visualizes the wave-plan dependency DAG, topological
 * execution order, blocked plans (with blocker names), and the budget rollup —
 * consuming GET /api/waves/graph (WP-022). UX-007.
 */
export function WaveDependencyGraph() {
  const [data, setData] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    fetch("/api/waves/graph", { headers: authHeaders() })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json() as Promise<GraphResponse>;
      })
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Failed to load dependency graph"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => load(), [load]);

  const nameOf = (id: string) => data?.graph.nodes.find((n) => n.plan_id === id)?.name ?? id.slice(0, 8);

  if (loading) {
    return <div className="h-24 animate-pulse rounded-md bg-[#edf1ea] dark:bg-[#22302a]" aria-label="Loading dependency graph" />;
  }
  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16] dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]" role="alert">
        <AlertTriangle size={16} aria-hidden="true" /> <span>Dependency graph: {error}</span>
      </div>
    );
  }
  if (!data || data.graph.nodes.length === 0) {
    return null; // nothing to show until plans exist; the CRUD view handles the empty case
  }

  const { graph, budget } = data;
  const order = graph.topological_order.length > 0 ? graph.topological_order : graph.nodes.map((n) => n.plan_id);

  return (
    <div className="rounded-md border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#1a2620]">
      <div className="flex items-center justify-between border-b border-[#dfe5dc] px-4 py-3 dark:border-[#2a3a30]">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-[#17211c] dark:text-[#e8ede9]">
          <GitBranch size={16} aria-hidden="true" /> Dependencies &amp; Budget
        </h2>
        <button
          type="button"
          onClick={load}
          className="flex items-center gap-1.5 rounded border border-[#dfe5dc] bg-[#f7f8f5] px-2.5 py-1.5 text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
          aria-label="Refresh dependency graph"
        >
          <RefreshCw size={13} aria-hidden="true" /> Refresh
        </button>
      </div>

      {/* Budget rollup */}
      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 border-b border-[#dfe5dc] px-4 py-3 text-xs sm:grid-cols-4 dark:border-[#2a3a30]">
        <div><dt className="text-[#697469] dark:text-[#8fa991]">Plans</dt><dd className="font-medium text-[#17211c] dark:text-[#e8ede9]">{budget.plan_count}</dd></div>
        <div><dt className="text-[#697469] dark:text-[#8fa991]">Budget / Actual (h)</dt><dd className="font-medium text-[#17211c] dark:text-[#e8ede9]">{budget.total_budget_hours} / {budget.total_actual_hours}</dd></div>
        <div>
          <dt className="text-[#697469] dark:text-[#8fa991]">Variance (h)</dt>
          <dd className={`font-medium ${budget.over_budget ? "text-[#8b2d16] dark:text-[#f87171]" : "text-[#3a7d44] dark:text-[#4ade80]"}`}>
            {budget.variance_hours > 0 ? "+" : ""}{budget.variance_hours}{budget.over_budget ? " (over)" : ""}
          </dd>
        </div>
        <div><dt className="text-[#697469] dark:text-[#8fa991]">Completion</dt><dd className="font-medium text-[#17211c] dark:text-[#e8ede9]">{budget.completion_percent.toFixed(0)}%</dd></div>
      </dl>

      {graph.cycles.length > 0 && (
        <div className="flex items-start gap-2 border-b border-[#dfe5dc] bg-[#fff4ee] px-4 py-2 text-xs text-[#8b2d16] dark:border-[#2a3a30] dark:bg-[#2d1518] dark:text-[#f87171]" role="alert">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>Dependency cycle detected — execution order is undefined until resolved: {graph.cycles.map((c) => c.map(nameOf).join(" → ")).join("; ")}</span>
        </div>
      )}
      {graph.unknown_refs.length > 0 && (
        <div className="border-b border-[#dfe5dc] px-4 py-2 text-xs text-[#713f12] dark:border-[#2a3a30] dark:text-[#fbbf24]">
          {graph.unknown_refs.length} dependency reference(s) point to plans that no longer exist.
        </div>
      )}

      {/* Topological execution order with blocked-by */}
      <ol className="divide-y divide-[#edf1ea] dark:divide-[#2a3a30]">
        {order.map((id, idx) => {
          const n = graph.nodes.find((x) => x.plan_id === id);
          if (!n) return null;
          return (
            <li key={id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-xs">
              <span className="font-mono text-[#697469] dark:text-[#8fa991]">{idx + 1}.</span>
              <StatusDot status={n.status} />
              <span className="font-medium text-[#17211c] dark:text-[#e8ede9]">{n.name}</span>
              <span className="rounded bg-[#edf1ea] px-1.5 py-0.5 text-[10px] text-[#4d594f] dark:bg-[#22302a] dark:text-[#8fa991]">wave {n.wave_number}</span>
              <span className="text-[#697469] dark:text-[#8fa991]">{n.status}</span>
              {n.depends_on.length > 0 && (
                <span className="text-[#697469] dark:text-[#8fa991]">depends on {n.depends_on.map(nameOf).join(", ")}</span>
              )}
              <span className="ml-auto">
                {n.blocked_by.length > 0 ? (
                  <span className="flex items-center gap-1 text-[#8b2d16] dark:text-[#f87171]">
                    <Lock size={12} aria-hidden="true" /> blocked by {n.blocked_by.map(nameOf).join(", ")}
                  </span>
                ) : n.activatable ? (
                  <span className="flex items-center gap-1 text-[#3a7d44] dark:text-[#4ade80]">
                    <CheckCircle2 size={12} aria-hidden="true" /> ready to activate
                  </span>
                ) : null}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
