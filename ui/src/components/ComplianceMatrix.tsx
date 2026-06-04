import { Asset, Finding } from "../hooks/useApi";

interface ComplianceMatrixProps {
  assets: Asset[];
  findings: Finding[];
  statuses: Record<string, string>;
}

export function ComplianceMatrix({ assets, findings, statuses }: ComplianceMatrixProps) {
  const categories = ["JANUS-PQC", "JANUS-NET", "JANUS-CLASSICAL"];

  // Returns "pass" | "fail" | "unknown"
  const getCellStatus = (asset: Asset, category: string): "pass" | "fail" | "unknown" => {
    const assetFindings = findings.filter(
      (f) => f.host_uuid === asset.host_uuid || f.asset_ref === asset.hostname
    );
    const categoryFindings = assetFindings.filter((f) =>
      f.policy_rule_id.startsWith(category)
    );
    if (categoryFindings.length === 0) return "pass";
    const openFindings = categoryFindings.filter((f) => {
      const s = statuses[f.finding_id];
      return s !== "remediated" && s !== "false-positive";
    });
    return openFindings.length === 0 ? "pass" : "fail";
  };

  const getOverallScore = (asset: Asset) => {
    const statList = categories.map((cat) => getCellStatus(asset, cat));
    const known = statList.filter((s) => s !== "unknown");
    if (known.length === 0) return null; // no data
    const passCount = known.filter((s) => s === "pass").length;
    return Math.round((passCount / known.length) * 100);
  };

  const fleetRates = categories.map((cat) => {
    const known = assets.filter((a) => getCellStatus(a, cat) !== "unknown");
    if (known.length === 0) return null;
    const passing = known.filter((a) => getCellStatus(a, cat) === "pass").length;
    return Math.round((passing / known.length) * 100);
  });

  const fleetOverall = (() => {
    const scores = assets.map(getOverallScore).filter((s) => s !== null) as number[];
    if (scores.length === 0) return null;
    return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  })();

  return (
    <div className="rounded-md border border-[#dfe5dc] bg-white p-4">
      <div className="mb-4">
        <h2 className="text-base font-semibold">Compliance Posture Matrix</h2>
        <p className="text-xs text-[#697469] mt-0.5">
          Real-time compliance validation per policy category across registered assets.
        </p>
      </div>
      <div className="overflow-auto">
        <table
          className="compliance compliance-matrix w-full min-w-[720px] text-left text-sm"
          data-testid="compliance-matrix"
        >
          <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469]">
            <tr>
              <th className="py-2 pr-3">Host</th>
              {categories.map((cat) => (
                <th key={cat} className="py-2 pr-3">{cat}</th>
              ))}
              <th className="py-2 pr-3">Overall Compliance</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset) => {
              const score = getOverallScore(asset);
              return (
                <tr
                  key={asset.host_uuid}
                  className="border-b border-[#edf1ea] hover:bg-[#edf1ea]/40 transition-colors"
                >
                  <td className="py-2 pr-3 font-medium">{asset.hostname}</td>
                  {categories.map((cat) => {
                    const st = getCellStatus(asset, cat);
                    return (
                      <td
                        key={cat}
                        className={`py-2 pr-3 font-bold ${
                          st === "pass" ? "cell-pass text-green-600" :
                          st === "fail" ? "cell-fail text-red-600" :
                          "cell-unknown text-[#697469]"
                        }`}
                        data-status={st}
                      >
                        {st === "pass" ? "✓" : st === "fail" ? "✗" : "—"}
                      </td>
                    );
                  })}
                  <td
                    className="asset-compliance-score py-2 pr-3 font-semibold"
                    data-testid="compliance-score"
                  >
                    {score !== null ? `${score}%` : "—"}
                  </td>
                </tr>
              );
            })}
            
            {assets.length > 0 && (
              <tr className="font-semibold bg-[#f7f8f5]">
                <td className="py-2 pr-3">Fleet Summary</td>
                {fleetRates.map((rate, idx) => (
                  <td key={idx} className="py-2 pr-3 text-xs uppercase tracking-wider text-[#4d594f]">
                    {rate}%
                  </td>
                ))}
                <td className="py-2 pr-3 text-xs uppercase tracking-wider text-[#4d594f]">
                  {fleetOverall}%
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {assets.length === 0 && (
          <div className="py-8 text-center text-sm text-[#697469]">No assets found</div>
        )}
      </div>
    </div>
  );
}
