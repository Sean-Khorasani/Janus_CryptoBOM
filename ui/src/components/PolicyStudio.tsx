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
      <div className="rounded-md border border-[#dfe5dc] bg-white p-4">
        <div className="flex items-center gap-3">
          <div className="rounded bg-[#eef2ec] p-2 text-[#11845b]">
            <Shield size={24} />
          </div>
          <div>
            <h2 className="text-base font-semibold">Centralized Policy Studio</h2>
            <p className="text-xs text-[#697469] mt-0.5">
              Manage and select active PQC compliance standards. Telemetry rules are evaluated in real-time.
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16]">
          <AlertCircle size={17} />
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
                  ? "border-[#11845b] bg-[#eef2ec]/30 shadow-sm"
                  : "border-[#dfe5dc] bg-white hover:border-[#cbd5c7]"
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-3">
                  <h3 className="font-bold text-sm tracking-wide text-[#17211c] truncate">
                    {p.version}
                  </h3>
                  {isActive && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-bold text-[#11845b] uppercase tracking-wider bg-[#d4ebd0] px-2 py-0.5 rounded-full">
                      <CheckCircle size={10} /> Active
                    </span>
                  )}
                </div>

                <ul className="space-y-2.5 text-xs text-[#4d594f] mb-6">
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1">
                    <span>Min RSA Bits</span>
                    <span className="font-semibold text-[#17211c]">{p.minimum_rsa_key_bits}</span>
                  </li>
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1">
                    <span>Min DH Prime</span>
                    <span className="font-semibold text-[#17211c]">{p.minimum_dh_safe_prime_bits}</span>
                  </li>
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1">
                    <span>Require TLS 1.3</span>
                    <span className="font-semibold text-[#17211c]">{p.require_tls_13 ? "Yes" : "No"}</span>
                  </li>
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1">
                    <span>Require Hybrid PQC</span>
                    <span className="font-semibold text-[#17211c]">{p.require_hybrid_pq_tls_13 ? "Yes" : "No"}</span>
                  </li>
                  <li className="flex justify-between border-b border-[#edf1ea] pb-1">
                    <span>Preferred KEM</span>
                    <span className="font-semibold text-[#17211c] font-mono text-[10px] bg-[#edf1ea] px-1 py-0.5 rounded">
                      {p.preferred_kem}
                    </span>
                  </li>
                  <li className="flex justify-between pb-1">
                    <span>Preferred Signature</span>
                    <span className="font-semibold text-[#17211c] font-mono text-[10px] bg-[#edf1ea] px-1 py-0.5 rounded">
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
                  className="w-full h-9 rounded bg-[#17211c] text-white text-xs font-semibold hover:bg-[#25322b] transition-colors disabled:opacity-50"
                >
                  {switching === p.version ? "Activating..." : "Activate Profile"}
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
