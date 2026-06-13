import { useEffect, useMemo, useState } from "react";
import { Search, X, Download } from "lucide-react";
import type { Asset, Finding, ScanRun } from "../hooks/useApi";
import { openAuthenticatedResource } from "../authenticatedResource";

type Connection = {
  session_id: string;
  connected_at: string;
  disconnected_at?: string;
  last_seen: string;
  observed_ip: string;
  agent_version: string;
  status: string;
};

function headers(): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function severityLabel(value: number) {
  return value >= 5 ? "Critical" : value === 4 ? "High" : value === 3 ? "Medium" : value === 2 ? "Low" : "None";
}

export function AgentFleetInventory() {
  const initialQuery = useMemo(() => new URLSearchParams(window.location.search), []);
  const [agents, setAgents] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(Number(initialQuery.get("offset") || "0"));
  const [search, setSearch] = useState(initialQuery.get("search") || "");
  const [status, setStatus] = useState(initialQuery.get("status") || "");
  const [severity, setSeverity] = useState(initialQuery.get("severity") || "");
  const [dateFrom, setDateFrom] = useState(() => initialQuery.get("date_from")?.slice(0, 10) || "");
  const [dateTo, setDateTo] = useState(() => initialQuery.get("date_to")?.slice(0, 10) || "");
  const [sort, setSort] = useState(initialQuery.get("sort") || "last_seen");
  const [order, setOrder] = useState(initialQuery.get("order") || "desc");
  const [requestedAgent, setRequestedAgent] = useState(initialQuery.get("agent") || "");
  const [selected, setSelected] = useState<Asset | null>(null);
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [latestFindings, setLatestFindings] = useState<Finding[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [detailsStatus, setDetailsStatus] = useState("");
  const [selectedAgents, setSelectedAgents] = useState<Set<string>>(new Set());
  const [reload, setReload] = useState(0);
  const limit = 50;

  const query = useMemo(() => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset), sort, order });
    if (search) params.set("search", search);
    if (status) params.set("status", status);
    if (severity) params.set("severity", severity);
    if (dateFrom) params.set("date_from", new Date(`${dateFrom}T00:00:00`).toISOString());
    if (dateTo) params.set("date_to", new Date(`${dateTo}T23:59:59`).toISOString());
    return params;
  }, [dateFrom, dateTo, offset, order, search, severity, sort, status]);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/assets?${query}`, { headers: headers(), signal: controller.signal })
      .then(async response => {
        setTotal(Number(response.headers.get("X-Total-Count") || "0"));
        setAgents(response.ok ? await response.json() : []);
      })
      .catch(() => {});
    return () => controller.abort();
  }, [query, reload]);

  useEffect(() => {
    const params = new URLSearchParams(query);
    if (selected) params.set("agent", selected.host_uuid);
    else if (requestedAgent) params.set("agent", requestedAgent);
    window.history.replaceState(null, "", `${window.location.pathname}?${params}`);
  }, [query, requestedAgent, selected]);

  useEffect(() => {
    const token = localStorage.getItem("janus_token") || "";
    const socket = new WebSocket(`${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/api/ws?access_token=${encodeURIComponent(token)}`);
    socket.onmessage = event => {
      try {
        const message = JSON.parse(event.data);
        if (["agent_progress", "agent_registered", "telemetry_update"].includes(message.type)) setReload(value => value + 1);
      } catch {}
    };
    return () => socket.close();
  }, []);

  useEffect(() => {
    const hostUUID = requestedAgent;
    if (!hostUUID || selected) return;
    fetch(`/api/agents/${encodeURIComponent(hostUUID)}`, { headers: headers() })
      .then(response => response.ok ? response.json() : null)
      .then(agent => { if (agent) setSelected(agent); })
      .catch(() => {});
  }, [requestedAgent, selected]);

  const openAgent = (agent: Asset) => {
    setRequestedAgent(agent.host_uuid);
    setSelected(agent);
  };

  const closeAgent = () => {
    setRequestedAgent("");
    setSelected(null);
  };

  useEffect(() => {
    if (!selected) return;
    setDetailsStatus("Loading scan findings and history...");
    const scansRequest = fetch(`/api/agents/${encodeURIComponent(selected.host_uuid)}/scans?limit=50`, { headers: headers() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error("scan history unavailable")));
    const connectionsRequest = fetch(`/api/agents/${encodeURIComponent(selected.host_uuid)}/connections?limit=50`, { headers: headers() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error("connection history unavailable")));
    Promise.all([scansRequest, connectionsRequest]).then(async ([scanRows, connectionRows]) => {
      const normalizedScans = Array.isArray(scanRows) ? scanRows : [];
      setScans(normalizedScans);
      setConnections(Array.isArray(connectionRows) ? connectionRows : []);
      const latestScanID = normalizedScans[0]?.scan_id || selected.last_scan_id;
      if (!latestScanID) {
        setLatestFindings([]);
        setDetailsStatus("This agent has not completed a scan yet.");
        return;
      }
      const findingsResponse = await fetch(`/api/reports/${encodeURIComponent(latestScanID)}/findings?limit=100`, { headers: headers() });
      if (!findingsResponse.ok) throw new Error("latest scan findings unavailable");
      const rows = await findingsResponse.json();
      setLatestFindings(Array.isArray(rows) ? rows : []);
      setDetailsStatus("");
    }).catch(error => {
      setDetailsStatus(`Details failed: ${error instanceof Error ? error.message : "request failed"}`);
    });
  }, [selected]);

  const changeSort = (field: string) => {
    if (sort === field) setOrder(value => value === "asc" ? "desc" : "asc");
    else { setSort(field); setOrder("asc"); }
    setOffset(0);
  };

  const [bulkStatus, setBulkStatus] = useState("");
  // Bulk CSV export of the selected agents' findings. Built entirely client-side
  // from /api/findings filtered to the selection, so it needs no extra endpoint
  // and works identically on every platform.
  const exportSelected = async () => {
    const ids = new Set(selectedAgents);
    if (ids.size === 0) return;
    setBulkStatus(`Exporting ${ids.size} agent${ids.size === 1 ? "" : "s"}…`);
    try {
      const response = await fetch("/api/findings", { headers: headers() });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const all: Finding[] = await response.json();
      const rows = all.filter(f => ids.has(f.host_uuid));
      const esc = (v: unknown) => {
        const s = String(v ?? "");
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const cols: (keyof Finding)[] = ["finding_id", "host_uuid", "severity", "title", "asset_ref", "algorithm", "policy_rule_id", "migration_profile", "status", "created_at"];
      const csv = [cols.join(","), ...rows.map(r => cols.map(c => esc(r[c])).join(","))].join("\n");
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `janus-findings-${ids.size}-agents.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setBulkStatus(`Exported ${rows.length} finding${rows.length === 1 ? "" : "s"} from ${ids.size} agent${ids.size === 1 ? "" : "s"}.`);
    } catch (error) {
      setBulkStatus(`Export failed: ${error instanceof Error ? error.message : "request failed"}`);
    }
  };

  return (
    <section className="rounded-md border border-[#dfe5dc] bg-white p-4 dark:border-[#2a3a30] dark:bg-[#1a2620]">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">Agent Inventory</h2>
          <p className="text-xs text-[#697469] dark:text-[#8fa991]">Server-paginated fleet inventory. Showing {agents.length} of {total} agents.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <label className="relative">
            <Search size={14} className="absolute left-2 top-2.5 text-[#697469]" />
            <input value={search} onChange={e => { setSearch(e.target.value); setOffset(0); }} placeholder="Search all agent fields" className="h-9 w-64 rounded border border-[#dfe5dc] pl-7 pr-2 text-xs dark:border-[#2a3a30] dark:bg-[#0d1210]" />
          </label>
          <select value={status} onChange={e => { setStatus(e.target.value); setOffset(0); }} className="h-9 rounded border border-[#dfe5dc] px-2 text-xs dark:border-[#2a3a30] dark:bg-[#0d1210]">
            <option value="">All states</option><option value="offline">Offline</option><option value="Idle">Connected</option><option value="Scanning">Scanning</option>
          </select>
          <select value={severity} onChange={e => { setSeverity(e.target.value); setOffset(0); }} className="h-9 rounded border border-[#dfe5dc] px-2 text-xs dark:border-[#2a3a30] dark:bg-[#0d1210]">
            <option value="">All severities</option><option value="5">Critical</option><option value="4">High+</option><option value="3">Medium+</option>
          </select>
          <input type="date" aria-label="Last connection from" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setOffset(0); }} className="h-9 rounded border border-[#dfe5dc] px-2 text-xs dark:border-[#2a3a30] dark:bg-[#0d1210]" />
          <input type="date" aria-label="Last connection to" value={dateTo} onChange={e => { setDateTo(e.target.value); setOffset(0); }} className="h-9 rounded border border-[#dfe5dc] px-2 text-xs dark:border-[#2a3a30] dark:bg-[#0d1210]" />
        </div>
      </div>
      {selectedAgents.size > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-3 rounded bg-[#edf1ea] px-3 py-2 text-xs dark:bg-[#22302a]" role="region" aria-label="Bulk agent operations">
          <span className="font-semibold">{selectedAgents.size} agent{selectedAgents.size === 1 ? "" : "s"} selected</span>
          <button
            type="button"
            onClick={exportSelected}
            className="inline-flex items-center gap-1.5 rounded border border-[#dfe5dc] bg-white px-2 py-1 font-medium hover:bg-[#f7f8f5] dark:border-[#2a3a30] dark:bg-[#1a2620] dark:hover:bg-[#22302a]"
          >
            <Download size={13} aria-hidden="true" /> Export findings (CSV)
          </button>
          <button
            type="button"
            onClick={() => { setSelectedAgents(new Set()); setBulkStatus(""); }}
            className="rounded px-2 py-1 font-medium text-[#697469] hover:underline dark:text-[#8fa991]"
          >
            Clear selection
          </button>
          {bulkStatus && <span className="text-[#4d594f] dark:text-[#8fa991]" role="status">{bulkStatus}</span>}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1200px] text-left text-xs">
          <thead><tr className="border-b border-[#dfe5dc] dark:border-[#2a3a30]">
            <th className="p-2"><input type="checkbox" aria-label="Select visible agents" checked={agents.length > 0 && agents.every(a => selectedAgents.has(a.host_uuid))} onChange={e => setSelectedAgents(e.target.checked ? new Set(agents.map(a => a.host_uuid)) : new Set())} /></th>
            {[["hostname","Agent"],["os_name","OS / Version"],["observed_ip","IP / DNS"],["agent_version","Agent Version"],["status","State"],["scan_progress","Progress"],["last_seen","Last Connection"],["last_scan_severity","Last Scan Risk"],["open_findings","Open Findings"]].map(([field,label]) => (
              <th
                key={field}
                scope="col"
                className="p-0"
                aria-sort={sort === field ? (order === "asc" ? "ascending" : "descending") : "none"}
              >
                <button
                  type="button"
                  onClick={() => changeSort(field)}
                  className="flex w-full items-center gap-1 p-2 text-left font-semibold hover:bg-[#edf1ea] dark:hover:bg-[#22302a]"
                >
                  {label}{sort === field ? (order === "asc" ? " ↑" : " ↓") : ""}
                </button>
              </th>
            ))}
          </tr></thead>
          <tbody>{agents.map(agent => <tr key={agent.host_uuid} onClick={() => openAgent(agent)} className="cursor-pointer border-b border-[#edf1ea] hover:bg-[#edf1ea]/40 dark:border-[#2a3a30]">
            <td className="p-2" onClick={e => e.stopPropagation()}><input type="checkbox" aria-label={`Select ${agent.hostname}`} checked={selectedAgents.has(agent.host_uuid)} onChange={e => setSelectedAgents(previous => { const next=new Set(previous); e.target.checked ? next.add(agent.host_uuid) : next.delete(agent.host_uuid); return next; })} /></td>
            <td className="p-2"><strong>{agent.hostname}</strong><div className="font-mono text-[10px] text-[#697469]">{agent.host_uuid}</div></td>
            <td className="p-2">{agent.os_name} {agent.os_version}<div>{agent.arch}</div></td>
            <td className="p-2 font-mono">{agent.observed_ip || "unknown"}<div>{agent.dns_name}</div></td>
            <td className="p-2">{agent.agent_version || "unknown"}</td>
            <td className="p-2">{agent.status || "unknown"}</td>
            <td className="p-2"><div>{agent.scan_progress || 0}%</div><div className="h-1.5 w-24 rounded bg-gray-100"><div className="h-full rounded bg-orange-500" style={{width:`${agent.scan_progress || 0}%`}} /></div><div className="max-w-32 truncate" title={agent.current_scan_path}>{agent.current_scan_path}</div></td>
            <td className="p-2">{new Date(agent.last_seen).toLocaleString()}</td>
            <td className="p-2">{severityLabel(agent.last_scan_severity)}</td>
            <td className="p-2">{agent.open_findings || 0}</td>
          </tr>)}</tbody>
        </table>
      </div>
      <div className="mt-3 flex justify-between text-xs">
        <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset-limit))}>Previous</button>
        <span>{offset + 1}-{Math.min(offset + limit, total)} of {total}</span>
        <button disabled={offset + limit >= total} onClick={() => setOffset(offset+limit)}>Next</button>
      </div>
      {selected && <div className="fixed inset-0 z-50 flex justify-end bg-black/40" role="dialog" aria-modal="true" aria-label={`Agent details ${selected.hostname}`} onClick={closeAgent}>
        <div className="h-full w-full max-w-3xl overflow-y-auto bg-white p-5 dark:bg-[#1a2620]" onClick={e => e.stopPropagation()}>
          <div className="flex justify-between"><div><h2 className="text-lg font-bold">{selected.hostname}</h2><p className="font-mono text-xs">{selected.host_uuid}</p></div><button onClick={closeAgent} aria-label="Close agent details"><X /></button></div>
          <dl className="my-4 grid grid-cols-2 gap-3 text-xs">
            <div><dt className="font-semibold">Identity</dt><dd>{selected.os_name} {selected.os_version} / {selected.arch} / agent {selected.agent_version || "unknown"}</dd></div>
            <div><dt className="font-semibold">Network</dt><dd>{selected.observed_ip || "unknown"} / {selected.dns_name || "unknown"}</dd></div>
            <div><dt className="font-semibold">Registered</dt><dd>{new Date(selected.first_registered_at).toLocaleString()}</dd></div>
            <div><dt className="font-semibold">Current progress</dt><dd>{selected.status}: {selected.scan_progress}% {selected.current_scan_path}</dd></div>
          </dl>
          {detailsStatus && <div className="my-3 rounded bg-[#edf1ea] p-3 text-xs dark:bg-[#22302a]" role="status">{detailsStatus}</div>}
          <h3 className="mt-5 font-semibold">Latest Scan Findings</h3>
          {latestFindings.length === 0 ? (
            <p className="mt-2 rounded border border-dashed border-[#dfe5dc] p-3 text-xs text-[#697469] dark:border-[#2a3a30] dark:text-[#8fa991]">The latest completed scan reported no findings.</p>
          ) : (
            <table className="mt-2 w-full text-xs"><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Algorithm</th></tr></thead><tbody>{latestFindings.map(finding => <tr key={finding.finding_id}><td>{severityLabel(finding.severity)}</td><td><strong>{finding.title}</strong><div className="text-[10px] text-[#697469]">{finding.description}</div></td><td className="font-mono text-[10px]">{finding.asset_ref}</td><td>{finding.algorithm}</td></tr>)}</tbody></table>
          )}
          <h3 className="mt-5 font-semibold">Scan History</h3>
          <table className="mt-2 w-full text-xs"><thead><tr><th>Finished</th><th>Status</th><th>Findings</th><th>Risk</th><th>Report</th></tr></thead><tbody>{scans.map(scan => <tr key={scan.scan_id}><td>{new Date(scan.scan_finished).toLocaleString()}</td><td>{scan.status}</td><td>{scan.finding_count}</td><td>{severityLabel(scan.max_severity)}</td><td><button className="text-blue-600 underline" onClick={() => openAuthenticatedResource(`/api/reports/${scan.scan_id}/findings`, "application/json")}>Findings JSON</button></td></tr>)}</tbody></table>
          <h3 className="mt-5 font-semibold">Connection History</h3>
          <table className="mt-2 w-full text-xs"><thead><tr><th>Connected</th><th>Disconnected</th><th>IP</th><th>Version</th><th>Status</th></tr></thead><tbody>{connections.map(row => <tr key={row.session_id}><td>{new Date(row.connected_at).toLocaleString()}</td><td>{row.disconnected_at ? new Date(row.disconnected_at).toLocaleString() : "Active"}</td><td>{row.observed_ip}</td><td>{row.agent_version}</td><td>{row.status}</td></tr>)}</tbody></table>
        </div>
      </div>}
    </section>
  );
}
