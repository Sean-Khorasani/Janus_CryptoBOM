import { useState } from "react";
import { PolicyProfile } from "../hooks/useApi";
import { Shield, CheckCircle, AlertCircle, ChevronDown, ChevronUp } from "lucide-react";
import { SeverityBadge, Empty } from "./FindingsGrid";

// ---------------------------------------------------------------------------
// Compliance Rules types
// ---------------------------------------------------------------------------

interface ControlRule {
  rule_id: string;
  title: string;
  description: string;
  rationale: string;
  framework_refs: string[];
  effective_date: string;
  expiry_date?: string;
  severity: number;
  remediation_hint: string;
}

interface ControlPack {
  pack_id: string;
  name: string;
  version: string;
  effective_date: string;
  rules: ControlRule[];
}

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

// ---------------------------------------------------------------------------
// Compliance Rules Panel
// ---------------------------------------------------------------------------

function ComplianceRulesPanel() {
  const [open, setOpen] = useState(false);
  const [pack, setPack] = useState<ControlPack | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRule, setSelectedRule] = useState<ControlRule | null>(null);

  const loadRules = () => {
    if (pack !== null) {
      setOpen(!open);
      return;
    }
    setOpen(true);
    setLoading(true);
    setError(null);
    fetch("/api/policy/rules", { headers: getAuthHeaders() })
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`);
        return res.json();
      })
      .then((data: ControlPack) => {
        setPack(data);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load rules");
      })
      .finally(() => setLoading(false));
  };

  return (
    <div className="rounded-md border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#1a2620]">
      {/* Collapsible header */}
      <button
        type="button"
        onClick={loadRules}
        className="flex w-full items-center justify-between px-5 py-4 text-left"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <Shield size={18} className="text-[#11845b] dark:text-[#3da06a]" aria-hidden="true" />
          <div>
            <span className="text-sm font-bold text-[#17211c] dark:text-[#e8ede9]">Control Pack</span>
            {pack && (
              <span className="ml-2 text-xs text-[#697469] dark:text-[#8fa991]">
                {pack.name} · v{pack.version} · effective {pack.effective_date}
              </span>
            )}
          </div>
        </div>
        {open
          ? <ChevronUp size={16} className="text-[#697469] dark:text-[#8fa991]" aria-hidden="true" />
          : <ChevronDown size={16} className="text-[#697469] dark:text-[#8fa991]" aria-hidden="true" />
        }
      </button>

      {open && (
        <div className="border-t border-[#dfe5dc] px-5 pb-5 pt-4 dark:border-[#2a3a30]">
          {loading && (
            <div className="py-6 text-center text-sm text-[#697469] dark:text-[#8fa991]">
              Loading control pack...
            </div>
          )}
          {error && !loading && (
            <div className="flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16] dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]">
              <AlertCircle size={15} aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}
          {!loading && !error && pack && pack.rules.length === 0 && (
            <Empty label="No rules in control pack" />
          )}
          {!loading && !error && pack && pack.rules.length > 0 && (
            <div className="overflow-auto">
              <table className="w-full min-w-[640px] text-left text-sm">
                <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469] dark:border-[#2a3a30] dark:text-[#8fa991]">
                  <tr>
                    <th className="py-2 pr-3" scope="col">Rule ID</th>
                    <th className="py-2 pr-3" scope="col">Title</th>
                    <th className="py-2 pr-3" scope="col">Severity</th>
                    <th className="py-2" scope="col">Framework Refs</th>
                  </tr>
                </thead>
                <tbody>
                  {pack.rules.map((rule) => (
                    <tr
                      key={rule.rule_id}
                      className="border-b border-[#edf1ea] hover:bg-[#edf1ea]/40 cursor-pointer transition-colors dark:border-[#2a3a30] dark:hover:bg-[#22302a]/40"
                      onClick={() => setSelectedRule(selectedRule?.rule_id === rule.rule_id ? null : rule)}
                      tabIndex={0}
                      onKeyDown={(e) => { if (e.key === "Enter") setSelectedRule(selectedRule?.rule_id === rule.rule_id ? null : rule); }}
                      role="button"
                      aria-expanded={selectedRule?.rule_id === rule.rule_id}
                      aria-label={`Rule ${rule.rule_id}: ${rule.title}`}
                    >
                      <td className="py-2 pr-3 font-mono text-xs text-[#17211c] dark:text-[#e8ede9]">{rule.rule_id}</td>
                      <td className="py-2 pr-3 max-w-[260px]">
                        <span className="font-medium text-[#17211c] dark:text-[#e8ede9]">{rule.title}</span>
                      </td>
                      <td className="py-2 pr-3"><SeverityBadge severity={rule.severity} /></td>
                      <td className="py-2">
                        <div className="flex flex-wrap gap-1">
                          {(rule.framework_refs ?? []).map((ref) => (
                            <span
                              key={ref}
                              className="rounded bg-[#edf1ea] px-1.5 py-0.5 font-mono text-[10px] text-[#4d594f] dark:bg-[#22302a] dark:text-[#6b7e6f]"
                            >
                              {ref}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Rule detail expansion */}
          {selectedRule && (
            <div className="mt-4 rounded-md border border-[#dfe5dc] bg-[#f7f8f5] p-4 dark:border-[#2a3a30] dark:bg-[#0d1210]">
              <div className="flex items-start justify-between gap-2 mb-2">
                <h4 className="text-sm font-bold text-[#17211c] dark:text-[#e8ede9]">{selectedRule.title}</h4>
                <button
                  type="button"
                  onClick={() => setSelectedRule(null)}
                  className="rounded p-0.5 text-[#697469] hover:bg-[#edf1ea] dark:text-[#8fa991] dark:hover:bg-[#22302a]"
                  aria-label="Close rule details"
                >
                  <ChevronUp size={14} aria-hidden="true" />
                </button>
              </div>
              <div className="space-y-3 text-xs text-[#4d594f] dark:text-[#6b7e6f]">
                <div>
                  <span className="block font-semibold uppercase tracking-wider text-[#697469] dark:text-[#8fa991] mb-0.5">Description</span>
                  <p>{selectedRule.description}</p>
                </div>
                {selectedRule.rationale && (
                  <div>
                    <span className="block font-semibold uppercase tracking-wider text-[#697469] dark:text-[#8fa991] mb-0.5">Rationale</span>
                    <p>{selectedRule.rationale}</p>
                  </div>
                )}
                {selectedRule.remediation_hint && (
                  <div>
                    <span className="block font-semibold uppercase tracking-wider text-[#697469] dark:text-[#8fa991] mb-0.5">Remediation Hint</span>
                    <p className="italic">{selectedRule.remediation_hint}</p>
                  </div>
                )}
                <div className="flex items-center gap-3 pt-1">
                  <span className="text-[#697469] dark:text-[#8fa991]">Effective: {selectedRule.effective_date}</span>
                  {selectedRule.expiry_date && (
                    <span className="text-[#697469] dark:text-[#8fa991]">Expires: {selectedRule.expiry_date}</span>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface PolicyStudioProps {
  activePolicy: string;
  policies: PolicyProfile[];
  switchPolicy: (version: string) => Promise<string>;
}

export function PolicyStudio({ activePolicy, policies, switchPolicy }: PolicyStudioProps) {
  const [switching, setSwitching] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Custom policy profile creation states
  const [newVersion, setNewVersion] = useState("");
  const [newMinRsa, setNewMinRsa] = useState(3072);
  const [newMinDh, setNewMinDh] = useState(3072);
  const [newReqTls13, setNewReqTls13] = useState(true);
  const [newReqPqc, setNewReqPqc] = useState(true);
  const [newKem, setNewKem] = useState("X25519MLKEM768");
  const [newSig, setNewSig] = useState("ML-DSA-65");
  const [success, setSuccess] = useState<string | null>(null);

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    if (!newVersion) {
      setError("Policy profile version name is required");
      return;
    }
    try {
      const res = await fetch("/api/policies/create", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          version: newVersion,
          minimum_rsa_key_bits: newMinRsa,
          minimum_dh_safe_prime_bits: newMinDh,
          require_tls_13: newReqTls13,
          require_hybrid_pq_tls_13: newReqPqc,
          preferred_kem: newKem,
          preferred_signature: newSig
        })
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      setSuccess(`Custom policy profile '${newVersion}' created successfully!`);
      setNewVersion("");
      setTimeout(() => {
        window.location.reload();
      }, 1500);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create policy profile");
    }
  };

  const handleSwitch = async (version: string) => {
    setSwitching(version);
    setError(null);
    try {
      await switchPolicy(version);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to switch policy");
    } finally {
      setSwitching(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
        <div className="flex items-center gap-3">
          <div className="rounded bg-[#eef2ec] p-2 text-[#11845b] dark:bg-[#22302a] dark:text-[#3da06a]" aria-hidden="true">
            <Shield size={24} />
          </div>
          <div>
            <h2 className="text-base font-semibold dark:text-[#e8ede9]">Centralized Policy Studio</h2>
            <p className="text-xs text-[#697469] mt-0.5 dark:text-[#8fa991]">
              Manage and select active PQC compliance standards. Telemetry rules are evaluated in real-time.
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16] dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]" role="alert">
          <AlertCircle size={17} aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-3">
        {policies.map((p) => {
          const isActive = p.version === activePolicy;
          return (
            <div
              key={p.version}
              className={`rounded-md border p-5 transition-all flex flex-col justify-between ${
                isActive
                  ? "border-[#11845b] bg-[#eef2ec]/30 shadow-sm dark:border-[#3da06a] dark:bg-[#16281e]"
                  : "border-[#dfe5dc] bg-white hover:border-[#cbd5c7] dark:border-[#2a3a30] dark:bg-[#1a2620] dark:hover:border-[#3a4a42]"
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-3">
                  <h3 className="font-bold text-sm tracking-wide text-[#17211c] truncate dark:text-[#e8ede9]">
                    {p.version}
                  </h3>
                  {isActive && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-bold text-[#11845b] uppercase tracking-wider bg-[#d4ebd0] px-2 py-0.5 rounded-full dark:bg-[#0f2a1a] dark:text-[#4ade80]">
                      <CheckCircle size={10} aria-hidden="true" /> Active
                    </span>
                  )}
                </div>

                <ul className="space-y-2.5 text-xs text-[#4d594f] mb-6 dark:text-[#6b7e6f]">
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1 dark:border-[#2a3a30]">
                    <span>Min RSA Bits</span>
                    <span className="font-semibold text-[#17211c] dark:text-[#e8ede9]">{p.minimum_rsa_key_bits}</span>
                  </li>
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1 dark:border-[#2a3a30]">
                    <span>Min DH Prime</span>
                    <span className="font-semibold text-[#17211c] dark:text-[#e8ede9]">{p.minimum_dh_safe_prime_bits}</span>
                  </li>
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1 dark:border-[#2a3a30]">
                    <span>Require TLS 1.3</span>
                    <span className="font-semibold text-[#17211c] dark:text-[#e8ede9]">{p.require_tls_13 ? "Yes" : "No"}</span>
                  </li>
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1 dark:border-[#2a3a30]">
                    <span>Require Hybrid PQC</span>
                    <span className="font-semibold text-[#17211c] dark:text-[#e8ede9]">{p.require_hybrid_pq_tls_13 ? "Yes" : "No"}</span>
                  </li>
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1 dark:border-[#2a3a30]">
                    <span>Preferred KEM</span>
                    <span className="font-semibold text-[#17211c] font-mono text-[10px] bg-[#edf1ea] px-1 py-0.5 rounded dark:bg-[#22302a] dark:text-[#e8ede9]">
                      {p.preferred_kem}
                    </span>
                  </li>
                  <li className="flex justify-between pb-1">
                    <span>Preferred Signature</span>
                    <span className="font-semibold text-[#17211c] font-mono text-[10px] bg-[#edf1ea] px-1 py-0.5 rounded dark:bg-[#22302a] dark:text-[#e8ede9]">
                      {p.preferred_signature}
                    </span>
                  </li>
                </ul>
              </div>

              {!isActive && (
                <button
                  type="button"
                  onClick={() => handleSwitch(p.version)}
                  disabled={switching !== null}
                  className="w-full h-9 rounded bg-[#17211c] text-white text-xs font-semibold hover:bg-[#25322b] transition-colors disabled:opacity-50 dark:bg-[#2a3a32] dark:hover:bg-[#3a4a42]"
                  aria-label={`Activate profile ${p.version}`}
                >
                  {switching === p.version ? "Activating..." : "Activate Profile"}
                </button>
              )}
            </div>
          );
        })}
      </div>

      {success && (
        <div className="flex items-center gap-2 rounded-md border border-[#b7efd4] bg-[#eefaf4] px-3 py-2 text-sm text-[#0e6b4a] dark:border-[#3da06a] dark:bg-[#16281e] dark:text-[#4ade80]" role="status">
          <CheckCircle size={17} aria-hidden="true" />
          <span>{success}</span>
        </div>
      )}

      {/* Compliance Rules Panel */}
      <ComplianceRulesPanel />

      {/* Policy Profile Creator Form */}
      <div className="rounded-md border border-[#dfe5dc] bg-white p-6 max-w-xl dark:border-[#2a3a30] dark:bg-[#1a2620]">
        <h3 className="text-sm font-bold mb-4 text-[#17211c] dark:text-[#e8ede9]">Create Custom Compliance Profile</h3>
        <form onSubmit={handleCreatePolicy} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="policy-version" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                Profile Name / Version ID
              </label>
              <input
                id="policy-version"
                type="text"
                value={newVersion}
                onChange={e => setNewVersion(e.target.value)}
                placeholder="e.g. custom-compliance-1.0"
                className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs focus:outline-none focus:ring-1 focus:ring-[#17211c] dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9] dark:placeholder-[#6b7e6f]"
                required
              />
            </div>
            <div>
              <label htmlFor="policy-min-rsa" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                Minimum RSA Key Bits
              </label>
              <input
                id="policy-min-rsa"
                type="number"
                value={newMinRsa}
                onChange={e => setNewMinRsa(parseInt(e.target.value) || 2048)}
                className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs focus:outline-none focus:ring-1 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
                required
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="policy-min-dh" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                Minimum DH Safe Prime Bits
              </label>
              <input
                id="policy-min-dh"
                type="number"
                value={newMinDh}
                onChange={e => setNewMinDh(parseInt(e.target.value) || 2048)}
                className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs focus:outline-none focus:ring-1 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
                required
              />
            </div>
            <div className="flex flex-col justify-center space-y-2 mt-4">
              <label className="flex items-center gap-2 text-xs text-[#4d594f] select-none cursor-pointer dark:text-[#6b7e6f]">
                <input
                  type="checkbox"
                  checked={newReqTls13}
                  onChange={e => setNewReqTls13(e.target.checked)}
                  className="rounded border-[#dfe5dc] dark:border-[#2a3a30] dark:bg-[#0d1210]"
                />
                <span>Require TLS 1.3</span>
              </label>
              <label className="flex items-center gap-2 text-xs text-[#4d594f] select-none cursor-pointer dark:text-[#6b7e6f]">
                <input
                  type="checkbox"
                  checked={newReqPqc}
                  onChange={e => setNewReqPqc(e.target.checked)}
                  className="rounded border-[#dfe5dc] dark:border-[#2a3a30] dark:bg-[#0d1210]"
                />
                <span>Require Hybrid PQC</span>
              </label>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="policy-kem" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                Preferred KEM
              </label>
              <input
                id="policy-kem"
                type="text"
                value={newKem}
                onChange={e => setNewKem(e.target.value)}
                className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs font-mono focus:outline-none focus:ring-1 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
                required
              />
            </div>
            <div>
              <label htmlFor="policy-sig" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                Preferred Signature
              </label>
              <input
                id="policy-sig"
                type="text"
                value={newSig}
                onChange={e => setNewSig(e.target.value)}
                className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs font-mono focus:outline-none focus:ring-1 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            className="rounded bg-[#11845b] text-white hover:bg-[#0e6b4a] px-4 py-2 text-xs font-bold transition-colors dark:bg-[#0e6b4a] dark:hover:bg-[#0d8055]"
          >
            Create Compliance Profile
          </button>
        </form>
      </div>
    </div>
  );
}
