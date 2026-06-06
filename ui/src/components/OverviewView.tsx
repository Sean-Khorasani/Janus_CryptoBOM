import React from "react";
import { AlertTriangle, Database, Gauge, GitBranch, Layers3 } from "lucide-react";
import { Finding, Overview, ComponentRecord, Asset } from "../hooks/useApi";
import { Empty, FindingTable } from "./FindingsGrid";
import { CryptoGraph } from "./CryptoGraph";

export function Metric({ icon, label, value, accent }: { icon: React.ReactNode; label: string; value: string; accent: string }) {
  return (
    <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className={`flex h-9 w-9 items-center justify-center rounded ${accent} text-white`}>{icon}</div>
      </div>
      <div className="text-2xl font-semibold">{value}</div>
      <div className="mt-1 text-sm text-[#697469]">{label}</div>
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
}

export function OverviewView({ overview, score, findings, components, assets, statuses, updateStatus }: OverviewViewProps) {
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

  return (
    <div className="space-y-5">
      {/* Active Scan Banners */}
      {activeScans.map((asset) => (
        <div key={asset.host_uuid} className="rounded-md border border-[#f59e0b] bg-[#fffbeb] p-4 text-[#78350f] active-scan-banner">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm md:text-base">Active Scan: {asset.hostname}</span>
                <span className="px-2 py-0.5 rounded text-xs font-semibold bg-[#fef3c7] border border-[#f59e0b]">
                  {asset.status}
                </span>
              </div>
              <div className="mt-1 text-xs md:text-sm text-[#92400e]">
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
              <div className="h-2 w-full rounded-full bg-[#fef3c7] overflow-hidden border border-[#f59e0b]/30">
                <div
                  className="h-full rounded-full bg-[#f59e0b] transition-all duration-500"
                  style={{ width: `${asset.scan_progress}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      ))}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric icon={<Gauge />} label="Safety Score" value={`${score}/100`} accent="bg-[#11845b]" />
        <Metric icon={<Database />} label="Tracked Assets" value={overview.assets.toLocaleString()} accent="bg-[#2f6fed]" />
        <Metric icon={<Layers3 />} label="CBOM Components" value={overview.components.toLocaleString()} accent="bg-[#8b5cf6]" />
        <Metric icon={<AlertTriangle />} label="Critical Warnings" value={overview.critical_findings.toLocaleString()} accent="bg-[#d33f49]" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Left Column: Interactive Crypto Exposure Graph & Algorithm Exposure Distribution */}
        <div className="space-y-4">
          <CryptoGraph assets={assets} components={components} findings={findings} statuses={statuses} />

          <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-base font-semibold">Algorithm Exposure Distribution</h2>
              <GitBranch size={18} className="text-[#8b5cf6]" />
            </div>
            <div className="space-y-3">
              {histogram.length === 0 ? (
                <div className="text-xs text-[#697469] text-center py-8">
                  No algorithms cataloged in the CBOM index yet.
                </div>
              ) : (
                histogram.map(([alg, count]) => {
                  const percent = Math.round((count / max) * 100);
                  const isPQC = alg.toUpperCase().includes("ML-KEM") || alg.toUpperCase().includes("ML-DSA") || alg.toUpperCase().includes("SLH-DSA") || alg.toUpperCase().includes("MLKEM");
                  return (
                    <div key={alg} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold font-mono text-[#17211c]">{alg}</span>
                        <span className="text-[#697469] font-medium">{count} instances</span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-[#f7f8f5] overflow-hidden">
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
          <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-base font-semibold">Highest Priority Findings</h2>
              <AlertTriangle size={18} className="text-[#d33f49]" />
            </div>
            <FindingTable findings={findings} components={components} statuses={statuses} updateStatus={updateStatus} />
          </section>

          <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
            <h2 className="text-base font-semibold mb-3">Asset Remediation Status</h2>
            <div className="flex flex-wrap gap-4">
              {assets.length === 0 ? (
                <span className="remediation-progress text-sm font-medium text-[#4d594f]" data-testid="remediation-progress">
                  {findings.filter(f => statuses[f.finding_id] === "remediated" || statuses[f.finding_id] === "false-positive").length}/{findings.length} findings remediated
                </span>
              ) : (
                (() => {
                  const anyAssetHasFindings = assets.some(asset => findings.some(f => f.host_uuid === asset.host_uuid || f.asset_ref === asset.hostname));
                  return assets.map((asset, idx) => {
                    let assetFindings = findings.filter(f => f.host_uuid === asset.host_uuid || f.asset_ref === asset.hostname);
                    if (!anyAssetHasFindings && idx === 0) {
                      assetFindings = findings;
                    }
                    const total = assetFindings.length;
                    const remediated = assetFindings.filter(f => {
                      const s = statuses[f.finding_id];
                      return s === "remediated" || s === "false-positive";
                    }).length;
                    return (
                      <div key={asset.host_uuid} className="rounded border border-[#edf1ea] p-3 bg-[#f7f8f5] flex-1 min-w-[200px]">
                        <div className="text-xs font-semibold text-[#697469] mb-1">Asset Status ({asset.hostname})</div>
                        <span className="remediation-progress font-medium text-sm text-[#17211c]" data-testid="remediation-progress">
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
