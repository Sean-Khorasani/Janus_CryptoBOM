import { Activity, ExternalLink, HelpCircle, RefreshCw, RotateCcw, Server, Settings, X } from "lucide-react";
import { useState } from "react";
import type { Asset } from "../hooks/useApi";
import { FocusTrap } from "../a11y/FocusTrap";

interface HomeAgentStatusProps {
  assets: Asset[];
  onOpenFleet: (hostUuid?: string) => void;
}

interface ScanConfigSchema {
  defaults: {
    scan_interval_seconds: number;
    max_file_bytes: number;
    max_binary_bytes: number;
  };
  limits: {
    scan_interval_seconds: { min: number; max: number };
    scan_bytes: { min: number; max: number };
  };
}

function authHeaders(extra: Record<string, string> = {}) {
  const token = localStorage.getItem("janus_token");
  return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
}

function formatDate(value?: string) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

function stateFor(asset: Asset) {
  const state = (asset.status || "").toLowerCase();
  if (state === "offline") return { label: "Offline", color: "bg-[#d33f49]", text: "text-[#b42318]" };
  if (state && state !== "idle") return { label: asset.status, color: "bg-[#f59e0b]", text: "text-[#a15c00]" };
  return { label: "Connected", color: "bg-[#11845b]", text: "text-[#08734d]" };
}

const sizeUnits: Record<string, number> = { KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3 };

function displaySize(bytes: number) {
  if (bytes >= sizeUnits.GB && bytes % sizeUnits.GB === 0) return { value: bytes / sizeUnits.GB, unit: "GB" };
  if (bytes >= sizeUnits.MB && bytes % sizeUnits.MB === 0) return { value: bytes / sizeUnits.MB, unit: "MB" };
  return { value: Math.max(1, Math.round(bytes / sizeUnits.KB)), unit: "KB" };
}

function FieldHelp({ text }: { text: string }) {
  return <span title={text} aria-label={text}><HelpCircle size={13} className="inline text-[#697469]" aria-hidden="true" /></span>;
}

export function HomeAgentStatus({ assets, onOpenFleet }: HomeAgentStatusProps) {
  const [commandState, setCommandState] = useState<Record<string, string>>({});
  const [reportState, setReportState] = useState<Record<string, string>>({});
  const [configAgent, setConfigAgent] = useState<Asset | null>(null);
  const [config, setConfig] = useState<any>(null);
  const [savedConfig, setSavedConfig] = useState<any>(null);
  const [configStatus, setConfigStatus] = useState("");
  const [configSchema, setConfigSchema] = useState<ScanConfigSchema | null>(null);
  const [policies, setPolicies] = useState<any[]>([]);
  const visibleAgents = assets.slice(0, 10);

  const requestScan = async (asset: Asset) => {
    setCommandState(previous => ({ ...previous, [asset.host_uuid]: "Queueing..." }));
    try {
      const response = await fetch(`/api/agents/${encodeURIComponent(asset.host_uuid)}/commands`, {
        method: "POST",
        headers: authHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({ command: "scan-now" })
      });
      if (!response.ok) throw new Error((await response.text()) || `HTTP ${response.status}`);
      const accepted = await response.json();
      setCommandState(previous => ({ ...previous, [asset.host_uuid]: accepted.message || "Scan queued" }));
      // Bounded polling (UX-005): a command queued for an offline agent stays
      // "queued" indefinitely — cap attempts so the timer loop terminates.
      const maxAttempts = 120; // ~2 min at 1s
      let attempts = 0;
      const poll = async () => {
        const statusResponse = await fetch(`/api/agents/${encodeURIComponent(asset.host_uuid)}/commands/${encodeURIComponent(accepted.command_id)}`, { headers: authHeaders() });
        if (!statusResponse.ok) return;
        const command = await statusResponse.json();
        if (!command.status) return;
        const labels: Record<string, string> = {
          queued: asset.status === "offline" ? "Queued until agent reconnects" : "Waiting for agent delivery",
          delivered: "Delivered to agent",
          executing: "Scan is running",
          completed: "Scan completed",
          failed: "Scan failed"
        };
        setCommandState(previous => ({ ...previous, [asset.host_uuid]: labels[command.status] || command.status }));
        attempts += 1;
        if (["completed", "failed"].includes(command.status)) return;
        if (attempts >= maxAttempts) {
          setCommandState(previous => ({ ...previous, [asset.host_uuid]: `${labels[command.status] || command.status} (still pending; stopped watching)` }));
          return;
        }
        window.setTimeout(poll, 1000);
      };
      window.setTimeout(poll, 500);
    } catch (error) {
      const message = error instanceof Error ? error.message : "request failed";
      setCommandState(previous => ({ ...previous, [asset.host_uuid]: `Failed: ${message}` }));
    }
  };

  const openConfig = async (asset: Asset) => {
    setConfigAgent(asset);
    const [configResponse, policyResponse, schemaResponse] = await Promise.all([
      fetch(`/api/agents/${encodeURIComponent(asset.host_uuid)}/config`, { headers: authHeaders() }),
      fetch("/api/policies", { headers: authHeaders() }),
      fetch("/api/scan-config/schema", { headers: authHeaders() })
    ]);
    const value = configResponse.ok ? await configResponse.json() : {};
    const schema = schemaResponse.ok ? await schemaResponse.json() as ScanConfigSchema : null;
    const sourceSize = displaySize(value.max_file_bytes ?? schema?.defaults.max_file_bytes ?? 0);
    const binarySize = displaySize(value.max_binary_bytes ?? schema?.defaults.max_binary_bytes ?? 0);
    const editable = {
      ...value,
      scan_roots: (value.scan_roots || []).join(", "),
      exclude_dirs: (value.exclude_dirs || []).join(", "),
      include_extensions: (value.include_extensions || []).join(", "),
      network_targets: (value.network_targets || []).join(", "),
      source_size_value: sourceSize.value,
      source_size_unit: sourceSize.unit,
      binary_size_value: binarySize.value,
      binary_size_unit: binarySize.unit
    };
    setConfig(editable);
    setSavedConfig(structuredClone(editable));
    setConfigSchema(schema);
    setConfigStatus(configResponse.ok && schema ? "" : "Configuration metadata could not be loaded; Apply is unavailable.");
    if (policyResponse.ok) setPolicies((await policyResponse.json()).available || []);
  };

  const saveConfig = async () => {
    if (!configAgent || !config || !configSchema) {
      setConfigStatus("Configuration cannot be applied until server validation metadata is available.");
      return;
    }
    const list = (value: string) => value.split(",").map(item => item.trim()).filter(Boolean);
    const scanRoots = list(config.scan_roots);
    const interval = Number(config.scan_interval_seconds);
    const sourceBytes = Number(config.source_size_value) * sizeUnits[config.source_size_unit];
    const binaryBytes = Number(config.binary_size_value) * sizeUnits[config.binary_size_unit];
    const intervalLimits = configSchema.limits.scan_interval_seconds;
    const byteLimits = configSchema.limits.scan_bytes;
    if (scanRoots.length === 0 || interval < intervalLimits.min || interval > intervalLimits.max || sourceBytes < byteLimits.min || sourceBytes > byteLimits.max || binaryBytes < byteLimits.min || binaryBytes > byteLimits.max) {
      setConfigStatus(`Validation failed: provide scan roots; interval ${intervalLimits.min}-${intervalLimits.max} seconds; size limits ${byteLimits.min}-${byteLimits.max} bytes.`);
      return;
    }
    setConfigStatus("Applying configuration...");
    const response = await fetch(`/api/agents/${encodeURIComponent(configAgent.host_uuid)}/config`, {
      method: "PUT",
      headers: authHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({
        ...config,
        scan_roots: scanRoots,
        exclude_dirs: list(config.exclude_dirs),
        include_extensions: list(config.include_extensions),
        network_targets: list(config.network_targets),
        scan_interval_seconds: Number(config.scan_interval_seconds),
        max_file_bytes: sourceBytes,
        max_binary_bytes: binaryBytes
      })
    });
    if (!response.ok) {
      setConfigStatus(`Configuration failed: ${response.status} ${await response.text()}`);
      return;
    }
    setSavedConfig(structuredClone(config));
    setConfigStatus("Configuration applied successfully; the agent will use it before the next scan.");
    setCommandState(previous => ({ ...previous, [configAgent.host_uuid]: "Configuration applied; effective before the next scan" }));
  };

  const restoreConfig = () => {
    if (!savedConfig) return;
    setConfig(structuredClone(savedConfig));
    setConfigStatus("Configuration restored to last saved values.");
  };

  const downloadReport = async (asset: Asset) => {
    if (!asset.last_scan_id) return;
    setReportState(previous => ({ ...previous, [asset.host_uuid]: "Loading report..." }));
    try {
      const response = await fetch(`/api/reports/${encodeURIComponent(asset.last_scan_id)}/findings`, { headers: authHeaders() });
      if (!response.ok) throw new Error((await response.text()) || `HTTP ${response.status}`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `${asset.hostname}-${asset.last_scan_id}-findings.json`;
      link.click();
      URL.revokeObjectURL(url);
      setReportState(previous => ({ ...previous, [asset.host_uuid]: "" }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "request failed";
      setReportState(previous => ({ ...previous, [asset.host_uuid]: `Report failed: ${message}` }));
    }
  };

  return (
    <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]" aria-labelledby="home-agent-status-title">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="home-agent-status-title" className="flex items-center gap-2 text-base font-semibold dark:text-[#e8ede9]">
            <Server size={18} aria-hidden="true" /> Agent Status
          </h2>
          <p className="mt-1 text-xs text-[#697469] dark:text-[#8fa991]">
            {assets.length > visibleAgents.length
              ? `Showing ${visibleAgents.length} of ${assets.length} agents — use "View and search all agents" for the full fleet.`
              : `Current connectivity and scan activity for ${visibleAgents.length} agent${visibleAgents.length === 1 ? "" : "s"}.`}
          </p>
        </div>
        <button type="button" onClick={() => onOpenFleet()} className="rounded border border-[#dfe5dc] px-3 py-2 text-xs font-semibold text-[#2f6fed] hover:bg-[#edf1ea] dark:border-[#2a3a30] dark:hover:bg-[#22302a]">
          View and search all agents
        </button>
      </div>

      {visibleAgents.length === 0 ? (
        <div className="rounded border border-dashed border-[#dfe5dc] p-6 text-center text-sm text-[#697469] dark:border-[#2a3a30] dark:text-[#8fa991]">
          No agents have registered with this server.
        </div>
      ) : (
        <div className="max-h-[28rem] space-y-2 overflow-y-auto pr-1 text-xs">
          {visibleAgents.map(asset => {
            const state = stateFor(asset);
            const progress = Math.max(0, Math.min(100, asset.scan_progress || 0));
            // A live progress bar is only meaningful while the agent is connected AND
            // scanning. Offline/idle agents have no "current work" — showing a frozen
            // bar (stale 100% or 0%) is misleading (UX-001).
            const statusLower = (asset.status || "").toLowerCase();
            const isScanning = statusLower !== "offline" && statusLower !== "idle" && statusLower !== "";
            return (
              <article key={asset.host_uuid} className="grid gap-3 rounded border border-[#edf1ea] p-3 dark:border-[#2a3a30] md:grid-cols-2 xl:grid-cols-[1.4fr_.7fr_1fr_1fr_1.3fr_auto]" data-testid={`home-agent-${asset.host_uuid}`}>
                    <div>
                      <button type="button" onClick={() => onOpenFleet(asset.host_uuid)} className="text-left font-semibold text-[#2f6fed] hover:underline">{asset.hostname}</button>
                      <div className="mt-1 text-[11px] text-[#697469] dark:text-[#8fa991]">{asset.os_name} {asset.os_version} / {asset.arch}</div>
                      <div className="font-mono text-[10px] text-[#697469] dark:text-[#8fa991]">{asset.observed_ip || asset.dns_name || "Network identity unknown"} / agent {asset.agent_version || "unknown"}</div>
                    </div>
                    <div>
                      <div className="mb-1 text-[10px] uppercase text-[#697469] dark:text-[#8fa991]">State</div>
                      <span className={`inline-flex items-center gap-1.5 font-semibold ${state.text}`}>
                        <span className={`h-2 w-2 rounded-full ${state.color}`} aria-hidden="true" />{state.label}
                      </span>
                    </div>
                    <div><div className="mb-1 text-[10px] uppercase text-[#697469] dark:text-[#8fa991]">Last Connection</div>{formatDate(asset.last_seen)}</div>
                    <div>
                      <div className="mb-1 text-[10px] uppercase text-[#697469] dark:text-[#8fa991]">Last Scan Report</div>
                      <div>{formatDate(asset.last_scan_finished)}</div>
                      <div className="mt-1">{asset.open_findings || 0} open finding{asset.open_findings === 1 ? "" : "s"}</div>
                      {asset.last_scan_id && (
                        <button type="button" onClick={() => downloadReport(asset)} className="mt-1 inline-flex items-center gap-1 text-[#2f6fed] hover:underline">
                          Findings JSON <ExternalLink size={11} aria-hidden="true" />
                        </button>
                      )}
                      {reportState[asset.host_uuid] && <div className="mt-1 text-[10px]" role="status">{reportState[asset.host_uuid]}</div>}
                    </div>
                    <div>
                      <div className="mb-1 text-[10px] uppercase text-[#697469] dark:text-[#8fa991]">Current Work</div>
                      {isScanning ? (
                        <>
                          <div className="flex items-center justify-between gap-2"><span>{asset.status}</span><span>{progress}%</span></div>
                          <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-[#edf1ea] dark:bg-[#0d1210]">
                            <div className="h-full rounded bg-[#f59e0b]" style={{ width: `${progress}%` }} />
                          </div>
                          <div className="mt-1 max-w-56 truncate font-mono text-[10px] text-[#697469] dark:text-[#8fa991]" title={asset.current_scan_path}>
                            {asset.current_scan_path || `${(asset.total_files_scanned || 0).toLocaleString()} files processed`}
                          </div>
                        </>
                      ) : (
                        <div className="text-[#697469] dark:text-[#8fa991]">
                          {state.label === "Offline" ? "Not connected — no active scan" : "Idle — no scan running"}
                          <div className="mt-1 text-[10px]">{(asset.total_files_scanned || 0).toLocaleString()} files in last scan</div>
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="flex flex-wrap gap-2 xl:flex-col">
                        <button type="button" onClick={() => requestScan(asset)} disabled={commandState[asset.host_uuid] === "Queueing..."} className="inline-flex items-center gap-1 rounded bg-[#17211c] px-2 py-1.5 font-semibold text-white disabled:opacity-50 dark:bg-[#2a3a32]">
                          <RefreshCw size={12} aria-hidden="true" /> Rescan
                        </button>
                        <button type="button" onClick={() => onOpenFleet(asset.host_uuid)} className="inline-flex items-center gap-1 rounded border border-[#dfe5dc] px-2 py-1.5 font-semibold dark:border-[#2a3a30]">
                          <Activity size={12} aria-hidden="true" /> Details
                        </button>
                        <button type="button" onClick={() => openConfig(asset)} className="inline-flex items-center gap-1 rounded border border-[#dfe5dc] px-2 py-1.5 font-semibold dark:border-[#2a3a30]">
                          <Settings size={12} aria-hidden="true" /> Configure
                        </button>
                      </div>
                      {commandState[asset.host_uuid] && <div className="mt-2 max-w-48 text-[10px]" role="status">{commandState[asset.host_uuid]}</div>}
                    </div>
              </article>
            );
          })}
        </div>
      )}
      {configAgent && config && (
        <FocusTrap active onEscape={() => setConfigAgent(null)}>
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" role="dialog" aria-modal="true" aria-label={`Configure ${configAgent.hostname}`}>
          <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded bg-white p-5 shadow-xl dark:bg-[#1a2620]">
            <div className="mb-4 flex justify-between"><div><h2 className="font-semibold">Configure {configAgent.hostname}</h2><p className="text-xs text-[#697469]">Apply saves server-side values; Restore discards edits and reloads the last saved values.</p></div><button onClick={() => setConfigAgent(null)} aria-label="Close configuration" title="Close without applying unsaved changes"><X /></button></div>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="text-xs">Assessment policy <FieldHelp text="Policy used by the server to assess this agent's future scans. Blank uses the globally active policy." /><select title="Select a known policy version or use the global active policy" value={config.policy_version || ""} onChange={event => setConfig({...config, policy_version:event.target.value})} className="mt-1 w-full rounded border p-2 dark:bg-[#0d1210]"><option value="">Global active policy</option>{policies.map(policy => <option key={policy.version} value={policy.version}>{policy.version}</option>)}</select></label>
              <label className="text-xs">Scan interval <FieldHelp text={configSchema ? `Automatic scan interval in seconds. Accepted range: ${configSchema.limits.scan_interval_seconds.min} to ${configSchema.limits.scan_interval_seconds.max}.` : "Automatic scan interval in seconds."} /><div className="mt-1 flex items-center gap-2"><input title={configSchema ? `${configSchema.limits.scan_interval_seconds.min} to ${configSchema.limits.scan_interval_seconds.max} seconds` : "Scan interval in seconds"} type="number" min={configSchema?.limits.scan_interval_seconds.min} max={configSchema?.limits.scan_interval_seconds.max} value={config.scan_interval_seconds ?? ""} onChange={event => setConfig({...config, scan_interval_seconds:event.target.value})} className="w-full rounded border p-2 dark:bg-[#0d1210]" /><span className="text-xs text-[#697469] dark:text-[#8fa991]">seconds</span></div></label>
              <label className="text-xs md:col-span-2">Scan roots <FieldHelp text="Absolute paths are recommended. Relative paths resolve from the agent process working directory, not from the filesystem root. Comma-separated; at least one root is required." /><input title="Use absolute paths such as /srv/apps. A value such as ./ scans only the agent working directory." value={config.scan_roots} onChange={event => setConfig({...config, scan_roots:event.target.value})} placeholder="/srv/apps, /etc/nginx" className="mt-1 w-full rounded border p-2 dark:bg-[#0d1210]" /><span className="mt-1 block text-[10px] text-[#a15c00]">Use absolute paths for managed hosts. `./` scans the agent working directory; Linux filesystem root is `/`.</span></label>
              <label className="text-xs md:col-span-2">Excluded directories <FieldHelp text="Directory names or paths skipped during traversal. Comma-separated; examples: .git, node_modules, target." /><input title="Comma-separated directory names or paths to skip" value={config.exclude_dirs} onChange={event => setConfig({...config, exclude_dirs:event.target.value})} placeholder=".git, node_modules, target" className="mt-1 w-full rounded border p-2 dark:bg-[#0d1210]" /></label>
              <label className="text-xs md:col-span-2">Source extensions <FieldHelp text="Optional comma-separated extension allowlist without leading dots. Blank uses all built-in supported source types." /><input title="Examples: rs, go, java, cs, py, js, ts; blank uses built-in types" value={config.include_extensions} onChange={event => setConfig({...config, include_extensions:event.target.value})} placeholder="rs, go, java, cs, py, js, ts" className="mt-1 w-full rounded border p-2 dark:bg-[#0d1210]" /></label>
              <label className="text-xs">Maximum source/manifest size <FieldHelp text="Files larger than this limit are skipped. Accepted converted range: 1 KB to 10 GB." /><div className="mt-1 flex"><input title="Numeric size from 1 KB through 10 GB" type="number" min="1" value={config.source_size_value} onChange={event => setConfig({...config, source_size_value:event.target.value})} className="w-full rounded-l border p-2 dark:bg-[#0d1210]" /><select title="Size unit" value={config.source_size_unit} onChange={event => setConfig({...config, source_size_unit:event.target.value})} className="rounded-r border border-l-0 p-2 dark:bg-[#0d1210]">{Object.keys(sizeUnits).map(unit => <option key={unit}>{unit}</option>)}</select></div></label>
              <label className="text-xs">Maximum binary size <FieldHelp text="Binaries larger than this limit are skipped to bound memory and scan time. Accepted converted range: 1 KB to 10 GB." /><div className="mt-1 flex"><input title="Numeric size from 1 KB through 10 GB" type="number" min="1" value={config.binary_size_value} onChange={event => setConfig({...config, binary_size_value:event.target.value})} className="w-full rounded-l border p-2 dark:bg-[#0d1210]" /><select title="Size unit" value={config.binary_size_unit} onChange={event => setConfig({...config, binary_size_unit:event.target.value})} className="rounded-r border border-l-0 p-2 dark:bg-[#0d1210]">{Object.keys(sizeUnits).map(unit => <option key={unit}>{unit}</option>)}</select></div></label>
              <label className="text-xs md:col-span-2">TLS/network targets <FieldHelp text="Comma-separated host:port targets used only when Active TLS probing is enabled. Use approved in-scope endpoints." /><input title="Comma-separated host:port values; requires Active TLS probing" value={config.network_targets} onChange={event => setConfig({...config, network_targets:event.target.value})} placeholder="example.org:443, internal.service:8443" className="mt-1 w-full rounded border p-2 dark:bg-[#0d1210]" /></label>
            </div>
            <div className="mt-4 grid gap-2 text-xs md:grid-cols-2">
              {[
                ["enable_runtime_discovery","Runtime process/service discovery","Reads process and service metadata; may require additional OS permissions."],
                ["enable_process_memory_scraping","Process-memory scraping","High-sensitivity opt-in; requires runtime discovery and elevated permissions."],
                ["enable_plugin_discovery","Approved plugin discovery","Runs only locally configured, approved discovery plugins under their resource limits."],
                ["enable_active_tls_probing","Active TLS probing","Connects to configured network targets; enable only for approved in-scope endpoints."]
              ].map(([field,label,help]) => <label key={field} title={help} className="flex items-center gap-2"><input type="checkbox" checked={Boolean(config[field])} onChange={event => setConfig({...config,[field]:event.target.checked})} />{label}<FieldHelp text={help} /></label>)}
            </div>
            {configStatus && <div className="mt-4 rounded bg-[#edf1ea] p-3 text-xs dark:bg-[#22302a]" role="status">{configStatus}</div>}
            <div className="mt-5 flex justify-end gap-2"><button onClick={() => setConfigAgent(null)} className="rounded border px-3 py-2 text-xs">Close</button><button onClick={restoreConfig} className="inline-flex items-center gap-1 rounded border px-3 py-2 text-xs"><RotateCcw size={12} />Restore</button><button onClick={saveConfig} disabled={!configSchema} className="rounded bg-[#17211c] px-3 py-2 text-xs font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50">Apply</button></div>
          </div>
        </div>
        </FocusTrap>
      )}
    </section>
  );
}
