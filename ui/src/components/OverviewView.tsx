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
  const histogram = Object.entries(overview.algorithm_histogram ?? {});
  const max = Math.max(1, ...histogram.map(([, v]) => v));
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric icon={<Gauge />} label="Safety Score" value={`${score}/100`} accent="bg-[#11845b]" />
        <Metric icon={<Database />} label="Tracked Assets" value={overview.assets.toLocaleString()} accent="bg-[#2f6fed]" />
        <Metric icon={<Layers3 />} label="CBOM Components" value={overview.components.toLocaleString()} accent="bg-[#8b5cf6]" />
        <Metric icon={<AlertTriangle />} label="Critical Warnings" value={overview.critical_findings.toLocaleString()} accent="bg-[#d33f49]" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <CryptoGraph assets={assets} components={components} findings={findings} statuses={statuses} />

        <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold">Highest Priority Findings</h2>
            <AlertTriangle size={18} className="text-[#d33f49]" />
          </div>
          <FindingTable findings={findings} components={components} statuses={statuses} updateStatus={updateStatus} />
        </section>
      </div>

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
                  <div key={asset.host_uuid} className="rounded border border-[#edf1ea] p-3 bg-[#f7f8f5]">
                    <div className="text-xs font-semibold text-[#697469] mb-1">Asset Status ({asset.hostname.slice(0, 5)}...)</div>
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
  );
}
