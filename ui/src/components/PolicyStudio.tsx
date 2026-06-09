import { useState } from "react";
import { PolicyProfile } from "../hooks/useApi";
import { Shield, CheckCircle, AlertCircle } from "lucide-react";

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
