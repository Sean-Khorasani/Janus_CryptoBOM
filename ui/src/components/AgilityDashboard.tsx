import React, { useState, useEffect, useCallback } from "react";
import { RefreshCw, ChevronLeft, Shield, TrendingDown, TrendingUp, Zap, Clock, AlertTriangle } from "lucide-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Scorecard {
  host_uuid?: string;
  hardcode_index: number;
  negotiation_coverage: number;
  blast_radius_score: number;
  ttsa_days?: number;
  profile_adoption_latency_days?: number;
  maturity_level: number;
  maturity_name: string;
  algorithm_blast_radii: Record<string, number> | null;
  computed_at: string;
}

interface FleetResponse {
  fleet: Scorecard;
  hosts: Scorecard[] | null;
  top_blast_radius: { algorithm: string; asset_count: number }[] | null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

/** Returns a Tailwind text + bg badge class set for a maturity name. */
function maturityBadgeClasses(name: string): string {
  switch (name) {
    case "crypto_agile":
      return "bg-[#edf7ef] text-[#3a7d44] dark:bg-[#16281e] dark:text-[#4ade80]";
    case "agile":
      return "bg-blue-100 text-blue-800 dark:bg-[#152238] dark:text-[#60a5fa]";
    case "planned":
      return "bg-yellow-100 text-yellow-800 dark:bg-[#2a2010] dark:text-[#fbbf24]";
    case "reactive":
      return "bg-orange-100 text-orange-800 dark:bg-[#2a1810] dark:text-[#fb923c]";
    default: // "none" or unknown
      return "bg-red-100 text-[#8b2d16] dark:bg-[#2a1010] dark:text-[#f87171]";
  }
}

function maturityLabel(name: string): string {
  switch (name) {
    case "crypto_agile": return "Crypto-Agile";
    case "agile":        return "Agile";
    case "planned":      return "Planned";
    case "reactive":     return "Reactive";
    default:             return "None";
  }
}

/**
 * Returns a Tailwind bg color class for a progress bar.
 * @param value    0–1
 * @param inverted true when lower value is better (hardcode_index, blast_radius_score)
 */
function barColor(value: number, inverted: boolean): string {
  const goodEnough = inverted ? value < 0.2 : value > 0.8;
  const warn       = inverted ? value < 0.5 : value > 0.5;
  if (goodEnough) return "bg-[#3a7d44] dark:bg-[#4ade80]";
  if (warn)       return "bg-amber-400 dark:bg-amber-500";
  return "bg-[#8b2d16] dark:bg-red-500";
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface MetricTileProps {
  label: string;
  value: string;
  icon: React.ReactNode;
  note?: string;
}

function MetricTile({ label, value, icon, note }: MetricTileProps) {
  return (
    <div className="rounded-lg border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#111e17] p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-[#697469] dark:text-[#8fa991]">{label}</span>
        <span className="text-[#697469] dark:text-[#8fa991]" aria-hidden="true">{icon}</span>
      </div>
      <div className="text-2xl font-bold text-[#17211c] dark:text-[#e8ede9]">{value}</div>
      {note && <div className="mt-1 text-[11px] text-[#697469] dark:text-[#8fa991]">{note}</div>}
    </div>
  );
}

interface MetricBarProps {
  label: string;
  value: number;
  inverted: boolean;
}

function MetricBar({ label, value, inverted }: MetricBarProps) {
  const widthPct = Math.round(value * 100);
  const color = barColor(value, inverted);
  const id = `bar-${label.replace(/\s+/g, "-").toLowerCase()}`;
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-[#49504a] dark:text-[#8fa991]">{label}</span>
        <span className="text-xs font-semibold text-[#17211c] dark:text-[#e8ede9]">{pct(value)}</span>
      </div>
      <div
        role="progressbar"
        aria-valuenow={widthPct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
        id={id}
        className="h-2 w-full rounded-full bg-[#dfe5dc] dark:bg-[#2a3a30] overflow-hidden"
      >
        <div
          className={`h-full rounded-full transition-all duration-500 ${color}`}
          style={{ width: `${widthPct}%` }}
        />
      </div>
    </div>
  );
}

interface ScorecardPanelProps {
  sc: Scorecard;
  title: string;
}

function ScorecardPanel({ sc, title }: ScorecardPanelProps) {
  const ttsa = sc.ttsa_days != null
    ? `${Math.round(sc.ttsa_days)}d`
    : null;

  return (
    <section className="rounded-lg border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#111e17] p-4">
      {/* Header row: title + maturity badge */}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <h2 className="text-base font-semibold text-[#17211c] dark:text-[#e8ede9]">{title}</h2>
        <span
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide ${maturityBadgeClasses(sc.maturity_name)}`}
          aria-label={`Maturity level: ${maturityLabel(sc.maturity_name)}`}
        >
          <Shield size={11} aria-hidden="true" />
          {maturityLabel(sc.maturity_name)}
        </span>
      </div>

      {/* 4 metric tiles */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 mb-5">
        <MetricTile
          label="Hardcode Index"
          value={pct(sc.hardcode_index)}
          icon={<TrendingDown size={16} aria-hidden="true" />}
          note="lower is better"
        />
        <MetricTile
          label="Negotiation Coverage"
          value={pct(sc.negotiation_coverage)}
          icon={<TrendingUp size={16} aria-hidden="true" />}
          note="higher is better"
        />
        <MetricTile
          label="Blast Radius Score"
          value={pct(sc.blast_radius_score)}
          icon={<Zap size={16} aria-hidden="true" />}
          note="lower is better"
        />
        <MetricTile
          label="TTSA"
          value={ttsa ?? "—"}
          icon={<Clock size={16} aria-hidden="true" />}
          note={ttsa ? "days to swap" : "not measured"}
        />
      </div>

      {/* Progress bars */}
      <div className="space-y-3">
        <MetricBar label="Hardcode Index" value={sc.hardcode_index} inverted={true} />
        <MetricBar label="Negotiation Coverage" value={sc.negotiation_coverage} inverted={false} />
        <MetricBar label="Blast Radius Score" value={sc.blast_radius_score} inverted={true} />
      </div>

      <div className="mt-3 text-[10px] text-[#697469] dark:text-[#8fa991] text-right">
        Computed {new Date(sc.computed_at).toLocaleString()}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function AgilityDashboard() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [fleetScorecard, setFleetScorecard] = useState<Scorecard | null>(null);
  const [hosts, setHosts] = useState<Scorecard[]>([]);
  const [topBlast, setTopBlast] = useState<{ algorithm: string; asset_count: number }[]>([]);

  // Per-host drill-down state
  const [selectedHostUuid, setSelectedHostUuid] = useState<string | null>(null);
  const [hostDetail, setHostDetail] = useState<Scorecard | null>(null);
  const [hostLoading, setHostLoading] = useState(false);
  const [hostError, setHostError] = useState<string | null>(null);

  const fetchFleet = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/agility/scorecard", { headers: getAuthHeaders() });
      if (!res.ok) {
        throw new Error(`Server returned ${res.status}`);
      }
      const data: FleetResponse = await res.json();
      setFleetScorecard(data.fleet);
      setHosts(data.hosts ?? []);
      setTopBlast(data.top_blast_radius ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scorecard");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchFleet();
  }, [fetchFleet]);

  const handleRowClick = useCallback(async (uuid: string) => {
    setSelectedHostUuid(uuid);
    setHostDetail(null);
    setHostError(null);
    setHostLoading(true);
    try {
      const res = await fetch(`/api/agility/scorecard?host_uuid=${encodeURIComponent(uuid)}`, {
        headers: getAuthHeaders(),
      });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data: Scorecard = await res.json();
      setHostDetail(data);
    } catch (err) {
      setHostError(err instanceof Error ? err.message : "Failed to load host scorecard");
    } finally {
      setHostLoading(false);
    }
  }, []);

  const handleBack = useCallback(() => {
    setSelectedHostUuid(null);
    setHostDetail(null);
    setHostError(null);
  }, []);

  // ---------------------------------------------------------------------------
  // Render: loading / error states
  // ---------------------------------------------------------------------------

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 text-sm text-[#697469] dark:text-[#8fa991]">
        <RefreshCw size={16} className="animate-spin mr-2" aria-hidden="true" />
        Loading agility scorecard…
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-200 bg-[#fff4ee] dark:border-red-900 dark:bg-[#2a1010] p-6 text-center">
        <AlertTriangle size={20} className="mx-auto mb-2 text-[#8b2d16] dark:text-red-400" aria-hidden="true" />
        <p className="text-sm font-medium text-[#8b2d16] dark:text-red-400">{error}</p>
        <button
          type="button"
          onClick={fetchFleet}
          className="mt-3 inline-flex items-center gap-1 rounded bg-[#8b2d16] text-white hover:bg-[#6b2010] px-3 py-1.5 text-xs font-semibold transition dark:bg-red-800 dark:hover:bg-red-700"
        >
          <RefreshCw size={12} aria-hidden="true" />
          Retry
        </button>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Render: per-host drill-down
  // ---------------------------------------------------------------------------

  if (selectedHostUuid !== null) {
    // Optimistic: use row data from hosts[] while per-host fetch is in flight
    const optimisticSc = hosts.find(h => h.host_uuid === selectedHostUuid) ?? null;
    const displaySc = hostDetail ?? optimisticSc;

    return (
      <div className="space-y-4">
        {/* Breadcrumb / back button */}
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={handleBack}
            className="inline-flex items-center gap-1.5 text-sm font-medium text-[#3a7d44] hover:text-[#2a6034] dark:text-[#4ade80] dark:hover:text-[#34d270] transition"
            aria-label="Back to fleet scorecard"
          >
            <ChevronLeft size={16} aria-hidden="true" />
            Fleet Scorecard
          </button>
          <button
            type="button"
            onClick={() => handleRowClick(selectedHostUuid)}
            className="inline-flex items-center gap-1.5 rounded border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#111e17] px-3 py-1.5 text-xs font-medium text-[#4d594f] hover:bg-[#edf7ef] dark:text-[#8fa991] dark:hover:bg-[#16281e] transition"
            aria-label="Refresh host scorecard"
          >
            <RefreshCw size={12} className={hostLoading ? "animate-spin" : ""} aria-hidden="true" />
            Refresh
          </button>
        </div>

        {hostError && (
          <div className="rounded-lg border border-red-200 bg-[#fff4ee] dark:border-red-900 dark:bg-[#2a1010] px-4 py-3 text-sm text-[#8b2d16] dark:text-red-400 flex items-center gap-2">
            <AlertTriangle size={14} aria-hidden="true" />
            {hostError}
          </div>
        )}

        {displaySc ? (
          <ScorecardPanel
            sc={displaySc}
            title={`Host: ${displaySc.host_uuid ?? selectedHostUuid}`}
          />
        ) : hostLoading ? (
          <div className="flex items-center justify-center py-16 text-sm text-[#697469] dark:text-[#8fa991]">
            <RefreshCw size={16} className="animate-spin mr-2" aria-hidden="true" />
            Loading host scorecard…
          </div>
        ) : null}
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Render: fleet view
  // ---------------------------------------------------------------------------

  // Sort hosts worst-first (lowest maturity_level first, then highest hardcode_index)
  const sortedHosts = [...hosts].sort((a, b) => {
    if (a.maturity_level !== b.maturity_level) return a.maturity_level - b.maturity_level;
    return b.hardcode_index - a.hardcode_index;
  });

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-[#17211c] dark:text-[#e8ede9]">
            Crypto-Agility Scorecard
          </h1>
          <p className="text-xs text-[#697469] dark:text-[#8fa991] mt-0.5">
            AGILE-01 — Fleet-wide and per-host quantum readiness posture
          </p>
        </div>
        <button
          type="button"
          onClick={fetchFleet}
          className="inline-flex items-center gap-1.5 rounded border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#111e17] px-3 py-1.5 text-xs font-medium text-[#4d594f] hover:bg-[#edf7ef] dark:text-[#8fa991] dark:hover:bg-[#16281e] transition"
          aria-label="Refresh scorecard"
        >
          <RefreshCw size={12} aria-hidden="true" />
          Refresh
        </button>
      </div>

      {/* Fleet scorecard summary panel */}
      {fleetScorecard ? (
        <ScorecardPanel sc={fleetScorecard} title="Fleet Summary" />
      ) : (
        <div className="rounded-lg border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#111e17] p-8 text-center text-sm text-[#697469] dark:text-[#8fa991]">
          No fleet data available
        </div>
      )}

      {/* Two-column: blast radius + host list */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Top blast radius table */}
        <section className="rounded-lg border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#111e17] p-4">
          <h2 className="text-sm font-semibold text-[#17211c] dark:text-[#e8ede9] mb-3 flex items-center gap-2">
            <Zap size={15} className="text-amber-500" aria-hidden="true" />
            Top Blast Radius
          </h2>
          {topBlast.length === 0 ? (
            <p className="text-xs text-[#697469] dark:text-[#8fa991] py-4 text-center">
              No algorithm blast radius data
            </p>
          ) : (
            <table className="w-full text-left text-xs" role="table">
              <thead>
                <tr className="border-b border-[#dfe5dc] dark:border-[#2a3a30] text-[#697469] dark:text-[#8fa991]">
                  <th className="pb-2 font-semibold" scope="col">Algorithm</th>
                  <th className="pb-2 font-semibold text-right" scope="col">Assets</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#edf1ea] dark:divide-[#2a3a30]">
                {topBlast.map((entry) => (
                  <tr key={entry.algorithm} className="hover:bg-[#f7f8f5] dark:hover:bg-[#16281e] transition-colors">
                    <td className="py-1.5 font-mono font-medium text-[#17211c] dark:text-[#e8ede9]">
                      {entry.algorithm || "—"}
                    </td>
                    <td className="py-1.5 text-right tabular-nums text-[#4d594f] dark:text-[#6b7e6f]">
                      {Math.round(entry.asset_count)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {/* Per-host list */}
        <section className="lg:col-span-2 rounded-lg border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#111e17] p-4">
          <h2 className="text-sm font-semibold text-[#17211c] dark:text-[#e8ede9] mb-3">
            Host Breakdown
            <span className="ml-2 rounded bg-[#edf1ea] px-1.5 py-0.5 text-[10px] text-[#697469] font-normal dark:bg-[#22302a] dark:text-[#8fa991]">
              {sortedHosts.length} host{sortedHosts.length !== 1 ? "s" : ""} — worst first
            </span>
          </h2>
          {sortedHosts.length === 0 ? (
            <p className="text-xs text-[#697469] dark:text-[#8fa991] py-6 text-center">
              No host scorecards available
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm border-collapse" role="table">
                <thead>
                  <tr className="border-b border-[#dfe5dc] dark:border-[#2a3a30] text-xs text-[#697469] dark:text-[#8fa991]">
                    <th className="pb-2 pr-3 font-semibold" scope="col">Host UUID</th>
                    <th className="pb-2 pr-3 font-semibold" scope="col">Maturity</th>
                    <th className="pb-2 pr-3 font-semibold" scope="col">Hardcode Index</th>
                    <th className="pb-2 font-semibold" scope="col">Negotiation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#edf1ea] dark:divide-[#2a3a30]">
                  {sortedHosts.map((host) => (
                    <tr
                      key={host.host_uuid}
                      onClick={() => host.host_uuid && handleRowClick(host.host_uuid)}
                      className="hover:bg-[#edf7ef] dark:hover:bg-[#16281e] transition-colors cursor-pointer"
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if ((e.key === "Enter" || e.key === " ") && host.host_uuid) {
                          handleRowClick(host.host_uuid);
                        }
                      }}
                      aria-label={`View scorecard for host ${host.host_uuid}`}
                    >
                      <td className="py-2 pr-3 font-mono text-xs text-[#17211c] dark:text-[#e8ede9] max-w-[160px] truncate" title={host.host_uuid}>
                        {host.host_uuid ?? "—"}
                      </td>
                      <td className="py-2 pr-3">
                        <span
                          className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${maturityBadgeClasses(host.maturity_name)}`}
                        >
                          {maturityLabel(host.maturity_name)}
                        </span>
                      </td>
                      <td className="py-2 pr-3">
                        <div className="flex items-center gap-2">
                          <div className="w-20 h-1.5 rounded-full bg-[#dfe5dc] dark:bg-[#2a3a30] overflow-hidden">
                            <div
                              className={`h-full rounded-full ${barColor(host.hardcode_index, true)}`}
                              style={{ width: `${Math.round(host.hardcode_index * 100)}%` }}
                            />
                          </div>
                          <span className="text-xs tabular-nums text-[#4d594f] dark:text-[#6b7e6f]">
                            {pct(host.hardcode_index)}
                          </span>
                        </div>
                      </td>
                      <td className="py-2">
                        <div className="flex items-center gap-2">
                          <div className="w-20 h-1.5 rounded-full bg-[#dfe5dc] dark:bg-[#2a3a30] overflow-hidden">
                            <div
                              className={`h-full rounded-full ${barColor(host.negotiation_coverage, false)}`}
                              style={{ width: `${Math.round(host.negotiation_coverage * 100)}%` }}
                            />
                          </div>
                          <span className="text-xs tabular-nums text-[#4d594f] dark:text-[#6b7e6f]">
                            {pct(host.negotiation_coverage)}
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
