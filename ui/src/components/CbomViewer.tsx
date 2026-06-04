import { RadioTower } from "lucide-react";
import { Asset, ComponentRecord, Finding, Overview } from "../hooks/useApi";
import { FindingTable, Empty, formatDate } from "./FindingsGrid";

interface CbomViewerProps {
  assets: Asset[];
  components: ComponentRecord[];
  findings: Finding[];
  overview: Overview;
  statuses: Record<string, string>;
  updateStatus: (id: string, status: string) => void;
}

export function CbomViewer({ assets, components, findings, overview, statuses, updateStatus }: CbomViewerProps) {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[0.9fr_1.3fr]">
      <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold">Asset Inventory</h2>
          <RadioTower size={18} className="text-[#2f6fed]" />
        </div>
        <div className="overflow-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469]">
              <tr>
                <th className="py-2 pr-3">Host</th>
                <th className="py-2 pr-3">Platform</th>
                <th className="py-2 pr-3">Mode</th>
                <th className="py-2 pr-3">Remediation Progress</th>
                <th className="py-2 pr-3">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {(() => {
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
                    <tr key={asset.host_uuid} className="border-b border-[#edf1ea]">
                      <td className="py-2 pr-3 font-medium">{asset.hostname}</td>
                      <td className="py-2 pr-3">{asset.os_name} {asset.os_version} / {asset.arch}</td>
                      <td className="py-2 pr-3">{asset.execution_mode === 2 ? "Active" : "Passive"}</td>
                      <td className="py-2 pr-3">
                        <span className="remediation-progress font-medium text-xs text-[#4d594f]" data-testid="remediation-progress">
                          {remediated}/{total} findings remediated
                        </span>
                      </td>
                      <td className="py-2 pr-3">{formatDate(asset.last_seen)}</td>
                    </tr>
                  );
                });
              })()}
            </tbody>
          </table>
          {assets.length === 0 && <Empty label="No agents registered" />}
        </div>
      </section>

      <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold">CBOM Findings Matrix</h2>
          <span className="rounded bg-[#edf1ea] px-2 py-1 text-xs">{overview.components} components</span>
        </div>
        <div className="mb-5 overflow-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469]">
              <tr>
                <th className="py-2 pr-3">Component</th>
                <th className="py-2 pr-3">Type</th>
                <th className="py-2 pr-3">Path</th>
                <th className="py-2 pr-3">Algorithms</th>
              </tr>
            </thead>
            <tbody>
              {components.slice(0, 12).map((component) => (
                <tr key={`${component.telemetry_id}-${component.bom_ref}`} className="border-b border-[#edf1ea]">
                  <td className="py-2 pr-3">
                    <div className="font-medium">{component.name}</div>
                    <div className="max-w-[260px] truncate font-mono text-xs text-[#697469]">{component.bom_ref}</div>
                  </td>
                  <td className="py-2 pr-3">{component.component_type}</td>
                  <td className="max-w-[340px] truncate py-2 pr-3">{component.file_path}</td>
                  <td className="py-2 pr-3">{component.algorithms?.join(", ") || "none"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {components.length === 0 && <Empty label="No CBOM components received" />}
        </div>
        <FindingTable findings={findings} components={components} statuses={statuses} updateStatus={updateStatus} />
      </section>
    </div>
  );
}
