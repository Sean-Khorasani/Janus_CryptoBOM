import { useMemo } from "react";
import { Eye } from "lucide-react";
import type { Asset, ComponentRecord } from "../hooks/useApi";

interface HonestCoverageProps {
  assets: Asset[];
  components: ComponentRecord[];
}

function freshness(unixSeconds: number): { label: string; stale: boolean } {
  if (!unixSeconds) return { label: "never", stale: true };
  const ageMs = Date.now() - unixSeconds * 1000;
  const days = ageMs / 86_400_000;
  if (days >= 1) return { label: `${Math.round(days)}d ago`, stale: days > 7 };
  const hours = ageMs / 3_600_000;
  if (hours >= 1) return { label: `${Math.round(hours)}h ago`, stale: false };
  return { label: `${Math.max(1, Math.round(ageMs / 60_000))}m ago`, stale: false };
}

/**
 * Per-host coverage panel (PROJECT-REVIEW.md rec 6 / RESEARCH.md §4.2): shows
 * what evidence each host actually produced, when it was last collected, and is
 * explicit that absence of a finding is NOT proof of absence. Never implies 100%
 * coverage. Derived entirely from data already on the client (assets + CBOM
 * components), so it works on every platform with no extra endpoint.
 */
export function HonestCoverage({ assets, components }: HonestCoverageProps) {
  const rows = useMemo(() => {
    return assets.map((asset) => {
      const hostComponents = components.filter((c) => c.host_uuid === asset.host_uuid);
      const sources = Array.from(new Set(hostComponents.map((c) => c.component_type).filter(Boolean))).sort();
      const lastScanUnix = hostComponents.reduce((max, c) => Math.max(max, c.scan_finished_unix || 0), 0);
      const fileLastScan = asset.last_scan_finished ? Math.floor(new Date(asset.last_scan_finished).getTime() / 1000) : 0;
      return {
        hostUuid: asset.host_uuid,
        hostname: asset.hostname || asset.host_uuid,
        filesScanned: asset.total_files_scanned || 0,
        evidenceCount: hostComponents.length,
        sources,
        fresh: freshness(Math.max(lastScanUnix, fileLastScan)),
        scanned: hostComponents.length > 0 || (asset.total_files_scanned || 0) > 0,
      };
    });
  }, [assets, components]);

  return (
    <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-base font-semibold dark:text-[#e8ede9]">Scan Coverage &amp; Evidence Freshness</h2>
        <Eye size={18} className="text-[#2f6fed]" aria-hidden="true" />
      </div>
      <p className="mb-3 text-xs text-[#697469] dark:text-[#8fa991]">
        Best-effort inventory. The absence of a finding is <strong>not</strong> proof a host is clean — only proof of what these sensors observed, when.
      </p>
      {rows.length === 0 ? (
        <div className="rounded border border-dashed border-[#dfe5dc] p-3 text-xs text-[#697469] dark:border-[#2a3a30] dark:text-[#8fa991]">
          No agents have reported evidence yet.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#dfe5dc] dark:border-[#2a3a30] text-[#697469] dark:text-[#8fa991]">
                <th scope="col" className="p-2">Host</th>
                <th scope="col" className="p-2">Evidence freshness</th>
                <th scope="col" className="p-2">Files scanned</th>
                <th scope="col" className="p-2">Evidence items</th>
                <th scope="col" className="p-2">Sensor classes exercised</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.hostUuid} className="border-b border-[#edf1ea] dark:border-[#2a3a30]">
                  <td className="p-2"><strong>{row.hostname}</strong></td>
                  <td className="p-2">
                    {row.scanned ? (
                      <span className={row.fresh.stale ? "text-[#d33f49] font-semibold" : ""}>
                        {row.fresh.label}{row.fresh.stale ? " (stale)" : ""}
                      </span>
                    ) : (
                      <span className="text-[#d33f49] font-semibold">not scanned</span>
                    )}
                  </td>
                  <td className="p-2">{row.filesScanned.toLocaleString()}</td>
                  <td className="p-2">{row.evidenceCount.toLocaleString()}</td>
                  <td className="p-2">
                    {row.sources.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {row.sources.map((s) => (
                          <span key={s} className="rounded bg-[#edf1ea] px-1.5 py-0.5 font-mono text-[10px] dark:bg-[#22302a]">{s}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[#697469] dark:text-[#8fa991]">none</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
