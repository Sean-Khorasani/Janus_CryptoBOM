import React, { useEffect, useState } from "react";
import { CheckCircle2, Play, RadioTower, TerminalSquare } from "lucide-react";
import { Asset, Migration } from "../hooks/useApi";
import { Empty, formatDate } from "./FindingsGrid";
import { Metric } from "./OverviewView";

interface MigrationConsoleProps {
  migrations: Migration[];
  assets: Asset[];
  enqueueMigration: (hostUuid: string, targetService: string, configPath: string, patch: string) => Promise<string>;
}

function StateBadge({ state }: { state: number }) {
  const label = state === 6 ? "Succeeded" : state === 7 ? "Failed" : state === 4 ? "Validating" : state === 3 ? "Applying" : "Pending";
  const color = state === 6 ? "bg-[#dff3e9] text-[#0f6847] dark:bg-[#0f2a1a] dark:text-[#4ade80]" : state === 7 ? "bg-[#ffe3dc] text-[#8b2d16] dark:bg-[#2d1518] dark:text-[#f87171]" : "bg-[#edf1ea] text-[#4d594f] dark:bg-[#22302a] dark:text-[#6b7e6f]";
  return <span className={`rounded px-2 py-1 text-xs font-medium ${color}`}>{label}</span>;
}

export function MigrationConsole({ migrations, assets, enqueueMigration }: MigrationConsoleProps) {
  const [hostUuid, setHostUuid] = useState(assets[0]?.host_uuid ?? "");
  const [targetService, setTargetService] = useState("nginx");
  const [configPath, setConfigPath] = useState("");
  const [patch, setPatch] = useState("");
  const [message, setMessage] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    if (!hostUuid && assets.length > 0) {
      setHostUuid(assets[0].host_uuid);
    }
  }, [assets, hostUuid]);

  const enqueue = async () => {
    setMessage("");
    try {
      const resMessage = await enqueueMigration(hostUuid, targetService, configPath, patch);
      setMessage(resMessage);
      setTimeout(() => {
        setMessage("");
      }, 3000);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Enqueue failed");
      setTimeout(() => {
        setMessage("");
      }, 3000);
    }
  };

  return (
    <div className="space-y-4">
      {/* Fixed-position toast notification */}
      {message && (
        <div
          data-testid="toast"
          className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 rounded-lg border px-4 py-3 text-sm font-medium shadow-xl animate-toast ${
            message.startsWith("Queued")
              ? "border-green-300 bg-green-50 text-green-800 dark:border-[#3da06a] dark:bg-[#16281e] dark:text-[#4ade80]"
              : "border-red-300 bg-red-50 text-red-800 dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]"
          }`}
          role="status"
          aria-live="polite"
        >
          {message.startsWith("Queued") ? "✓" : "✕"} {message}
        </div>
      )}
      <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold dark:text-[#e8ede9]">Migration Control Console</h2>
          <button onClick={enqueue} data-action="enqueue" className="flex h-9 items-center gap-2 rounded bg-[#17211c] px-3 text-sm text-white dark:bg-[#2a3a32] dark:hover:bg-[#3a4a42]" type="button" aria-label="Queue dry run migration">
            <Play size={15} aria-hidden="true" />
            Queue Dry Run
          </button>
        </div>
        <div className="mb-4 grid grid-cols-1 gap-3 xl:grid-cols-[1fr_160px_1fr]">
          <label className="text-sm">
            <span className="mb-1 block text-[#697469] dark:text-[#8fa991]">Agent</span>
            <select
              value={hostUuid}
              onChange={(event) => setHostUuid(event.target.value)}
              className="h-10 w-full rounded border border-[#dfe5dc] bg-white px-3 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
            >
              <option value="">Select agent</option>
              {assets.map((asset) => (
                <option key={asset.host_uuid} value={asset.host_uuid}>
                  {asset.hostname} / {asset.host_uuid.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-[#697469] dark:text-[#8fa991]">Service</span>
            <select
              value={targetService}
              onChange={(event) => setTargetService(event.target.value)}
              className="h-10 w-full rounded border border-[#dfe5dc] bg-white px-3 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9]"
            >
              <option value="nginx">nginx</option>
              <option value="apache">apache</option>
              <option value="ssh">ssh</option>
              <option value="windows-trust-store">Windows trust store</option>
              <option value="windows-schannel-policy">Windows Schannel</option>
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-[#697469] dark:text-[#8fa991]">Config path or certificate store</span>
            <input
              value={configPath}
              onChange={(event) => setConfigPath(event.target.value)}
              placeholder={
                targetService === "windows-trust-store"
                  ? "CurrentUser\\Root"
                  : targetService === "windows-schannel-policy"
                  ? "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"
                  : "C:\\path\\to\\service.conf"
              }
              className="h-10 w-full rounded border border-[#dfe5dc] bg-white px-3 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9] dark:placeholder-[#6b7e6f]"
            />
          </label>
          <label className="text-sm xl:col-span-3">
            <span className="mb-1 block text-[#697469] dark:text-[#8fa991]">Unified diff, PEM certificate, or Schannel JSON payload</span>
            <textarea
              value={patch}
              onChange={(event) => setPatch(event.target.value)}
              className="h-28 w-full resize-y rounded border border-[#dfe5dc] bg-white p-3 font-mono text-xs dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9] dark:placeholder-[#6b7e6f]"
            />
          </label>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Metric icon={<RadioTower aria-hidden="true" />} label="Connected Agents" value={assets.length.toString()} accent="bg-[#2f6fed]" />
          <Metric icon={<TerminalSquare aria-hidden="true" />} label="Transactions" value={migrations.length.toString()} accent="bg-[#8b5cf6]" />
          <Metric icon={<CheckCircle2 aria-hidden="true" />} label="Completed" value={migrations.filter((m) => m.state === 6).length.toString()} accent="bg-[#11845b]" />
        </div>
      </section>

      <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
        <div className="overflow-auto">
          <table className="w-full min-w-[980px] text-left text-sm" role="table">
            <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469] dark:border-[#2a3a30] dark:text-[#8fa991]">
              <tr>
                <th className="py-2 pr-3" scope="col">Command</th>
                <th className="py-2 pr-3" scope="col">Host</th>
                <th className="py-2 pr-3" scope="col">Service</th>
                <th className="py-2 pr-3" scope="col">Target</th>
                <th className="py-2 pr-3" scope="col">State</th>
                <th className="py-2 pr-3" scope="col">Updated</th>
              </tr>
            </thead>
            <tbody>
              {migrations.map((m) => {
                const isExpanded = expandedId === m.command_id;
                return (
                  <React.Fragment key={m.command_id}>
                    <tr
                      onClick={() => setExpandedId(isExpanded ? null : m.command_id)}
                      className="border-b border-[#edf1ea] cursor-pointer hover:bg-gray-50 transition-colors dark:border-[#2a3a30] dark:hover:bg-[#0d1210]"
                      data-testid={`migration-row-${m.command_id}`}
                      tabIndex={0}
                      onKeyDown={(e) => { if (e.key === "Enter") setExpandedId(isExpanded ? null : m.command_id); }}
                      role="button"
                      aria-expanded={isExpanded}
                      aria-label={`Migration ${m.command_id.slice(0, 12)}, state: ${m.state}`}
                    >
                      <td className="py-2 pr-3 font-mono text-xs dark:text-[#8fa991]">
                        {m.command_id.slice(0, 12)}
                        <span className="sr-only">{m.command_id}</span>
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs dark:text-[#8fa991]">{m.host_uuid.slice(0, 12)}</td>
                      <td className="py-2 pr-3 dark:text-[#e8ede9]">{m.target_service}</td>
                      <td className="py-2 pr-3 dark:text-[#e8ede9]">{m.target_kem} / {m.target_signature}</td>
                      <td className="py-2 pr-3"><StateBadge state={m.state} /></td>
                      <td className="py-2 pr-3 dark:text-[#8fa991]">{formatDate(m.updated_at)}</td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-gray-50/50 dark:bg-[#0d1210]/50">
                        <td colSpan={6} className="px-4 py-3 text-xs border-b border-[#edf1ea] dark:border-[#2a3a30]">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                              <h4 className="font-semibold text-gray-700 dark:text-[#e8ede9]">Transaction Details</h4>
                              <p className="dark:text-[#8fa991]"><strong className="text-gray-500 dark:text-[#6b7e6f]">Config Path:</strong> {m.config_path}</p>
                              <p className="dark:text-[#8fa991]"><strong className="text-gray-500 dark:text-[#6b7e6f]">Execution Mode:</strong> {m.dry_run ? "Dry Run (Non-mutating)" : "Active Mutation"}</p>
                              {m.last_error && (
                                <div className="rounded border border-red-200 bg-red-50 p-2 text-red-700 dark:border-[#f87171] dark:bg-[#2d1518] dark:text-[#f87171]">
                                  <strong>Error:</strong> {m.last_error}
                                </div>
                              )}
                              {m.output && (
                                <div className="rounded border border-gray-200 bg-gray-50 p-2 font-mono text-[10px] whitespace-pre-wrap max-h-40 overflow-auto dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#8fa991]">
                                  {m.output}
                                </div>
                              )}
                            </div>
                            <div className="space-y-2">
                              <h4 className="font-semibold text-gray-700 dark:text-[#e8ede9]">Post-Migration Verification</h4>
                              {m.state === 6 ? (
                                m.observed_tls ? (
                                  <div className="space-y-2 rounded border border-green-200 bg-green-50/50 p-3 dark:border-[#3da06a] dark:bg-[#16281e]">
                                    <div className="flex items-center gap-2 text-green-700 font-semibold dark:text-[#4ade80]" data-testid="verification-success">
                                      <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" aria-hidden="true"></span>
                                      Active Verification Successful
                                    </div>
                                    <div className="grid grid-cols-2 gap-2 text-[11px] text-gray-600 dark:text-[#8fa991]">
                                      <p><strong>Endpoint:</strong> {m.observed_tls.endpoint}</p>
                                      <p><strong>TLS Version:</strong> {m.observed_tls.tls_version}</p>
                                      <p><strong>Cipher Suite:</strong> {m.observed_tls.cipher_suite}</p>
                                      <p><strong>KEM Group:</strong> {m.observed_tls.named_group || "N/A"}</p>
                                      <div className="col-span-2 mt-1">
                                        {m.observed_tls.pqc_hybrid ? (
                                          <span className="inline-block rounded bg-green-100 text-green-800 px-2 py-0.5 font-semibold dark:bg-[#0f2a1a] dark:text-[#4ade80]" data-testid="pqc-hybrid-badge">
                                            PQC Hybrid (ML-KEM) Verified
                                          </span>
                                        ) : (
                                          <span className="inline-block rounded bg-amber-100 text-amber-800 px-2 py-0.5 font-semibold dark:bg-[#2d2010] dark:text-[#fbbf24]">
                                            Classical Non-PQC (Quantum Vulnerable)
                                          </span>
                                        )}
                                      </div>
                                      {m.observed_tls.certificate_subject && (
                                        <p className="col-span-2 text-[10px] truncate dark:text-[#8fa991]">
                                          <strong>Cert Subject:</strong> {m.observed_tls.certificate_subject}
                                        </p>
                                      )}
                                    </div>
                                  </div>
                                ) : (
                                  <p className="text-gray-500 italic dark:text-[#6b7e6f]">No verification handshake details returned (dry-run or local trust update).</p>
                                )
                              ) : m.state === 7 ? (
                                <p className="text-red-600 font-medium dark:text-red-400">Verification failed due to migration failure.</p>
                              ) : (
                                <p className="text-gray-500 italic animate-pulse dark:text-[#6b7e6f]">Verification pending transaction completion...</p>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
          {migrations.length === 0 && <Empty label="No migration transactions queued" />}
        </div>
      </section>
    </div>
  );
}
