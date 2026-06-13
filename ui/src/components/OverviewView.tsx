import React from "react";
import { AlertTriangle, Database, Gauge, GitBranch, Layers3, ShieldAlert } from "lucide-react";
import { Finding, Overview, ComponentRecord, Asset } from "../hooks/useApi";
import { Empty, FindingTable } from "./FindingsGrid";
import { CryptoGraph, GraphSelection } from "./CryptoGraph";
import { HomeAgentStatus } from "./HomeAgentStatus";
import { HonestCoverage } from "./HonestCoverage";

// ---------------------------------------------------------------------------
// Cert Health types & helpers
// ---------------------------------------------------------------------------

interface CertHealth {
  total_tracked: number;
  expired: number;
  expiring_30_days: number;
  expiring_90_days: number;
}

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

function CertHealthCard({ certHealth }: { certHealth: CertHealth }) {
  return (
    <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[#17211c] dark:text-[#e8ede9]">Certificate Health</h2>
        <ShieldAlert size={17} className="text-[#2f6fed]" aria-hidden="true" />
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded border border-[#edf1ea] bg-[#f7f8f5] p-3 dark:border-[#2a3a30] dark:bg-[#0d1210]">
          <div className="text-xl font-bold text-[#17211c] dark:text-[#e8ede9]">
            {certHealth.total_tracked}
          </div>
          <div className="mt-0.5 text-xs text-[#697469] dark:text-[#8fa991]">Total Tracked</div>
        </div>
        <div className="rounded border border-[#edf1ea] bg-[#f7f8f5] p-3 dark:border-[#2a3a30] dark:bg-[#0d1210]">
          <div className="flex items-center gap-1.5">
            <span className="text-xl font-bold text-[#17211c] dark:text-[#e8ede9]">
              {certHealth.expired ?? 0}
            </span>
            {(certHealth.expired ?? 0) > 0 && (
              <span className="rounded bg-[#d33f49] px-1.5 py-0.5 text-[10px] font-bold text-white">
                !</span>
            )}
          </div>
          <div className="mt-0.5 text-xs text-[#697469] dark:text-[#8fa991]">Expired</div>
        </div>
        <div className="rounded border border-[#edf1ea] bg-[#f7f8f5] p-3 dark:border-[#2a3a30] dark:bg-[#0d1210]">
          <div className="flex items-center gap-1.5">
            <span className="text-xl font-bold text-[#17211c] dark:text-[#e8ede9]">
              {certHealth.expiring_30_days ?? 0}
            </span>
            {(certHealth.expiring_30_days ?? 0) > 0 && (
              <span className="rounded bg-[#e07a2f] px-1.5 py-0.5 text-[10px] font-bold text-white">
                !</span>
            )}
          </div>
          <div className="mt-0.5 text-xs text-[#697469] dark:text-[#8fa991]">Expiring in 30d</div>
        </div>
        <div className="rounded border border-[#edf1ea] bg-[#f7f8f5] p-3 dark:border-[#2a3a30] dark:bg-[#0d1210]">
          <div className="flex items-center gap-1.5">
            <span className="text-xl font-bold text-[#17211c] dark:text-[#e8ede9]">
              {certHealth.expiring_90_days ?? 0}
            </span>
            {(certHealth.expiring_90_days ?? 0) > 0 && (
              <span className="rounded bg-[#ffd166] px-1.5 py-0.5 text-[10px] font-bold text-[#3a2a00]">
                !</span>
            )}
          </div>
          <div className="mt-0.5 text-xs text-[#697469] dark:text-[#8fa991]">Expiring in 90d</div>
        </div>
      </div>
    </section>
  );
}

export function Metric({ icon, label, value, accent, hint }: { icon: React.ReactNode; label: string; value: string; accent: string; hint?: string }) {
  return (
    <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]" title={hint}>
      <div className="mb-3 flex items-center justify-between">
        <div className={`flex h-9 w-9 items-center justify-center rounded ${accent} text-white`} aria-hidden="true">{icon}</div>
      </div>
      <div className="text-2xl font-semibold dark:text-[#e8ede9]">{value}</div>
      <div className="mt-1 text-sm text-[#697469] dark:text-[#8fa991]">{label}{hint ? <span className="ml-1 cursor-help text-[#9aa69c]" title={hint} aria-hidden="true">ⓘ</span> : null}</div>
    </section>
  );
}

interface OverviewViewProps {
  overview: Overview;
  score: number;
  findings: Finding[];
  components: ComponentRecord[];
  assets: Asset[];
  statuses: Record<string, string>;
  updateStatus: (id: string, status: string) => void;
  onOpenFleet: (hostUuid?: string) => void;
}

export function OverviewView({ overview, score, findings, components, assets, statuses, updateStatus, onOpenFleet }: OverviewViewProps) {
  const [graphSelection, setGraphSelection] = React.useState<GraphSelection | null>(null);
  const [certHealth, setCertHealth] = React.useState<CertHealth | null>(null);

  React.useEffect(() => {
    fetch("/api/sla/metrics", { headers: getAuthHeaders() })
      .then((res) => {
        if (!res.ok) return null;
        return res.json();
      })
      .then((data: { cert_health?: CertHealth } | null) => {
        if (data?.cert_health && (data.cert_health.total_tracked ?? 0) >= 0) {
          setCertHealth(data.cert_health);
        }
      })
      .catch(() => { /* non-critical, silently ignore */ });
  }, []);

  const activeScans = assets.filter(
    (asset) =>
      asset.status &&
      asset.status !== "Idle" &&
      asset.status !== "offline" &&
      asset.status !== ""
  );

  const histData = React.useMemo(() => {
    const counts: Record<string, number> = {};
    for (const finding of findings) {
      const status = statuses[finding.finding_id];
      if (status === "remediated" || status === "false-positive") {
        continue;
      }
      const rawAlg = finding.algorithm ? finding.algorithm.trim() : "";
      let alg = rawAlg;
      if (!rawAlg) {
        alg = "UNKNOWN";
      } else {
        const upper = rawAlg.toUpperCase();
        if (upper.startsWith("RSA")) {
          alg = "RSA";
        } else if (upper.startsWith("SHA")) {
          alg = "SHA";
        } else if (upper.startsWith("ML-KEM") || upper.startsWith("MLKEM")) {
          alg = "ML-KEM";
        } else if (upper.startsWith("ML-DSA") || upper.startsWith("MLDSA")) {
          alg = "ML-DSA";
        } else if (upper.startsWith("SLH-DSA") || upper.startsWith("SLHDSA")) {
          alg = "SLH-DSA";
        }
      }
      counts[alg] = (counts[alg] || 0) + 1;
    }
    return counts;
  }, [findings, statuses]);

  const histogram = Object.entries(histData);
  const max = Math.max(1, ...histogram.map(([, v]) => v));
  const contextualFindings = React.useMemo(() => {
    if (!graphSelection) return findings;
    if (graphSelection.type === "host") {
      const latestScan = components.filter(c => c.host_uuid === graphSelection.hostUuid).sort((a, b) => b.scan_finished_unix - a.scan_finished_unix)[0]?.telemetry_id;
      return findings.filter(f => f.host_uuid === graphSelection.hostUuid && (!latestScan || !f.telemetry_id || f.telemetry_id === latestScan));
    }
    if (graphSelection.type === "component") {
      return findings.filter(f => f.host_uuid === graphSelection.hostUuid && (f.asset_ref === graphSelection.bomRef || f.asset_ref === graphSelection.filePath));
    }
    return findings.filter(f => f.algorithm === graphSelection.algorithm);
  }, [components, findings, graphSelection]);
  const findingsTitle = graphSelection?.type === "host"
    ? `Latest findings from ${graphSelection.label}`
    : graphSelection?.type === "component"
      ? `Findings for ${graphSelection.label}`
      : graphSelection?.type === "algorithm"
        ? `${graphSelection.label} findings`
        : "Highest Priority Findings";

  return (
    <div className="space-y-5">
      {/* Active Scan Banners — bounded so a fleet-wide scan storm can't push the
          rest of the dashboard off-screen (UX-013). */}
      {activeScans.length > 0 && (
      <div className="max-h-72 space-y-3 overflow-y-auto pr-1">
      {activeScans.map((asset) => (
        <div key={asset.host_uuid} className="rounded-md border border-[#f59e0b] bg-[#fffbeb] p-4 text-[#78350f] active-scan-banner dark:bg-[#2d2010] dark:text-[#fbbf24]" role="status">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm md:text-base">Active Scan: {asset.hostname}</span>
                <span className="px-2 py-0.5 rounded text-xs font-semibold bg-[#fef3c7] border border-[#f59e0b] dark:bg-[#2d2010] dark:text-[#fbbf24]">
                  {asset.status}
                </span>
              </div>
              <div className="mt-1 text-xs md:text-sm text-[#92400e] dark:text-[#f59e0b]">
                <span className="font-medium">Path:</span> <span className="font-mono">{asset.current_scan_path || "N/A"}</span>
                <span className="mx-2">|</span>
                <span className="font-medium">Files Scanned:</span> <span>{asset.total_files_scanned?.toLocaleString() ?? 0}</span>
              </div>
            </div>
            <div className="w-full md:w-64 space-y-1">
              <div className="flex justify-between text-xs font-semibold">
                <span>Progress</span>
                <span>{asset.scan_progress}%</span>
              </div>
              <div className="h-2 w-full rounded-full bg-[#fef3c7] overflow-hidden border border-[#f59e0b]/30 dark:bg-[#2d2010]">
                <div
                  className="h-full rounded-full bg-[#f59e0b] transition-all duration-500"
                  style={{ width: `${asset.scan_progress}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      ))}
      </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric icon={<Gauge aria-hidden="true" />} label="Safety Score" value={`${score}/100`} accent="bg-[#11845b]" hint="100 minus weighted open findings: critical ×18, high ×8, other ×2. Findings marked remediated, false-positive, or accepted are excluded, so triaging raises the score." />
        <Metric icon={<Database aria-hidden="true" />} label="Tracked Assets" value={overview.assets.toLocaleString()} accent="bg-[#2f6fed]" />
        <Metric icon={<Layers3 aria-hidden="true" />} label="CBOM Components" value={overview.components.toLocaleString()} accent="bg-[#8b5cf6]" />
        <Metric icon={<AlertTriangle aria-hidden="true" />} label="Critical Warnings" value={overview.critical_findings.toLocaleString()} accent="bg-[#d33f49]" />
        {(overview.stalled_agents ?? 0) > 0 && (
          <Metric icon={<AlertTriangle aria-hidden="true" />} label="Stalled Agents" value={(overview.stalled_agents ?? 0).toLocaleString()} accent="bg-[#b42318]" />
        )}
      </div>

      {certHealth !== null && <CertHealthCard certHealth={certHealth} />}

      <HomeAgentStatus assets={assets} onOpenFleet={onOpenFleet} />

      <HonestCoverage assets={assets} components={components} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Left Column: Interactive Crypto Exposure Graph & Algorithm Exposure Distribution */}
        <div className="space-y-4">
          <CryptoGraph assets={assets} components={components} findings={findings} statuses={statuses} onSelectionChange={setGraphSelection} />

          <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-base font-semibold dark:text-[#e8ede9]">Algorithm Exposure Distribution</h2>
              <GitBranch size={18} className="text-[#8b5cf6]" aria-hidden="true" />
            </div>
            <div className="max-h-80 space-y-3 overflow-y-auto pr-1">
              {histogram.length === 0 ? (
                <div className="text-xs text-[#697469] text-center py-8 dark:text-[#8fa991]">
                  No algorithms cataloged in the CBOM index yet.
                </div>
              ) : (
                histogram.map(([alg, count]) => {
                  const percent = Math.round((count / max) * 100);
                  const isPQC = alg.toUpperCase().includes("ML-KEM") || alg.toUpperCase().includes("ML-DSA") || alg.toUpperCase().includes("SLH-DSA") || alg.toUpperCase().includes("MLKEM");
                  return (
                    <div key={alg} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold font-mono text-[#17211c] dark:text-[#e8ede9]">{alg}</span>
                        <span className="text-[#697469] font-medium dark:text-[#8fa991]">{count} instances</span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-[#f7f8f5] overflow-hidden dark:bg-[#0d1210]">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            isPQC ? "bg-[#11845b]" : "bg-[#8b5cf6]"
                          }`}
                          style={{ width: `${percent}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </section>
        </div>

        {/* Right Column: Highest Priority Findings & Asset Remediation Status */}
        <div className="space-y-4">
          <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold dark:text-[#e8ede9]">{findingsTitle}</h2>
                {graphSelection && <button type="button" onClick={() => setGraphSelection(null)} className="text-xs text-[#2f6fed] hover:underline">Clear report scope</button>}
              </div>
              <AlertTriangle size={18} className="text-[#d33f49]" aria-hidden="true" />
            </div>
            <FindingTable findings={contextualFindings} components={components} assets={assets} statuses={statuses} updateStatus={updateStatus} />
          </section>

          <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
            <h2 className="text-base font-semibold mb-3 dark:text-[#e8ede9]">Asset Remediation Status</h2>
            <div className="flex max-h-72 flex-wrap gap-4 overflow-y-auto pr-1">
              {assets.length === 0 ? (
                <span className="remediation-progress text-sm font-medium text-[#4d594f] dark:text-[#6b7e6f]" data-testid="remediation-progress">
                  {findings.filter(f => statuses[f.finding_id] === "remediated" || statuses[f.finding_id] === "false-positive").length}/{findings.length} findings remediated
                </span>
              ) : (
                (() => {
                  // Map findings to each asset honestly by host_uuid/hostname. The
                  // previous code dumped ALL findings onto assets[0] when nothing
                  // matched, producing misleading per-asset numbers (B1) — removed.
                  return assets.map((asset) => {
                    const assetFindings = findings.filter(f => f.host_uuid === asset.host_uuid || f.asset_ref === asset.hostname);
                    const total = assetFindings.length;
                    const remediated = assetFindings.filter(f => {
                      const s = statuses[f.finding_id];
                      return s === "remediated" || s === "false-positive";
                    }).length;
                    return (
                      <div key={asset.host_uuid} className="rounded border border-[#edf1ea] p-3 bg-[#f7f8f5] flex-1 min-w-[200px] dark:border-[#2a3a30] dark:bg-[#0d1210]">
                        <div className="text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">Asset Status ({asset.hostname})</div>
                        <span className="remediation-progress font-medium text-sm text-[#17211c] dark:text-[#e8ede9]" data-testid="remediation-progress">
                          {remediated}/{total} findings remediated
                        </span>
                      </div>
                    );
                  });
                })()
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
