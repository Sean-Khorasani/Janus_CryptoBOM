import { useEffect, useMemo, useRef, useState } from "react";
import { authChangedEvent, clearSession } from "../auth";
import { requiredApiVersion } from "../version";
import { useWebSocket } from "./useWebSocket";

export type Overview = {
  assets: number;
  components: number;
  findings: number;
  critical_findings: number;
  high_findings: number;
  open_migrations: number;
  algorithm_histogram: Record<string, number>;
  stalled_agents?: number;
};

export type Asset = {
  host_uuid: string;
  hostname: string;
  os_name: string;
  os_version: string;
  arch: string;
  execution_mode: number;
  last_seen: string;
  scan_progress: number;
  current_scan_path: string;
  cpu_usage: number;
  mem_usage: number;
  status: string;
  total_files_scanned: number;
  agent_version: string;
  observed_ip: string;
  dns_name: string;
  first_registered_at: string;
  last_registered_at: string;
  last_scan_id: string;
  last_scan_finished?: string;
  last_scan_severity: number;
  open_findings: number;
};

export type Finding = {
  finding_id: string;
  host_uuid: string;
  severity: number;
  title: string;
  description: string;
  asset_ref: string;
  algorithm: string;
  policy_rule_id: string;
  migration_profile: string;
  created_at: string;
  confidence: number;
  status: string;
  telemetry_id?: string;
  hostname?: string;
  agent_version?: string;
  scan_finished?: string;
};

export type ScanRun = {
  scan_id: string;
  host_uuid: string;
  hostname: string;
  agent_version: string;
  os_name: string;
  os_version: string;
  observed_ip: string;
  scan_started: string;
  scan_finished: string;
  received_at: string;
  status: string;
  component_count: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
  max_severity: number;
};

export type ComponentRecord = {
  host_uuid: string;
  telemetry_id: string;
  bom_ref: string;
  name: string;
  version: string;
  component_type: string;
  file_path: string;
  language: string;
  algorithms: string[];
  dependencies: string[];
  reachable: boolean;
  scan_finished_unix: number;
};

export type Migration = {
  command_id: string;
  host_uuid: string;
  target_service: string;
  migration_profile: string;
  target_kem: string;
  target_signature: string;
  config_path: string;
  state: number;
  dry_run: boolean;
  issued_at: string;
  updated_at: string;
  last_error: string;
  output: string;
  observed_tls?: {
    endpoint: string;
    protocol: string;
    tls_version: string;
    cipher_suite: string;
    named_group: string;
    signature_algorithm: string;
    certificate_subject: string;
    certificate_issuer: string;
    certificate_not_after_unix: number;
    pqc_hybrid: boolean;
    cleartext: boolean;
  };
};

export const emptyOverview: Overview = {
  assets: 0,
  components: 0,
  findings: 0,
  critical_findings: 0,
  high_findings: 0,
  open_migrations: 0,
  algorithm_histogram: {}
};

function migrationProfileFor(targetService: string) {
  if (targetService === "windows-trust-store") return "windows-trust-store-import";
  if (targetService === "windows-schannel-policy") return "windows-schannel-tls-policy";
  return "hybrid-tls13-mlkem-mldsa";
}

async function authedFetch(url: string, options?: RequestInit): Promise<Response> {
  const token = localStorage.getItem("janus_token");
  const finalOpts = options || {};
  const headers = new Headers(finalOpts.headers || {});
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(url, { ...finalOpts, headers });
  if (response.status === 401) {
    clearSession();
    window.dispatchEvent(new Event(authChangedEvent));
  }
  return response;
}

function fetchWithTimeout(url: string, options?: RequestInit): Promise<Response> {
  return new Promise<Response>((resolve) => {
    const timer = setTimeout(() => {
      resolve(new Response("Timeout", { status: 504 }));
    }, 10000);

    authedFetch(url, options)
      .then((res) => {
        clearTimeout(timer);
        resolve(res);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(new Response("Error", { status: 500 }));
      });
  });
}

export type PolicyProfile = {
  version: string;
  minimum_rsa_key_bits: number;
  minimum_dh_safe_prime_bits: number;
  require_tls_13: boolean;
  require_hybrid_pq_tls_13: boolean;
  preferred_kem: string;
  preferred_signature: string;
};

export function useApi(enabled = true) {
  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [components, setComponents] = useState<ComponentRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [migrations, setMigrations] = useState<Migration[]>([]);
  const [activePolicy, setActivePolicy] = useState<string>("");
  const [policies, setPolicies] = useState<PolicyProfile[]>([]);
  const [error, setError] = useState("");

  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);

  const load = async () => {
    try {
      const [healthRes, overviewRes, assetsRes, componentsRes, findingsRes, migrationsRes, policiesRes] = await Promise.all([
        fetchWithTimeout("/api/health").catch(() => null),
        fetchWithTimeout("/api/overview").catch(() => null),
        fetchWithTimeout("/api/assets").catch(() => null),
        fetchWithTimeout("/api/components").catch(() => null),
        fetchWithTimeout("/api/findings").catch(() => null),
        fetchWithTimeout("/api/migrations").catch(() => null),
        fetchWithTimeout("/api/policies").catch(() => null)
      ]);
      const failed = [healthRes, overviewRes, assetsRes, componentsRes, findingsRes, migrationsRes, policiesRes]
        .filter(response => !response || !response.ok);
      if (healthRes?.ok) {
        const health = await healthRes.json();
        if (health.api_version !== requiredApiVersion) {
          throw new Error(`Incompatible Janus server API ${health.api_version || "unknown"}; UI requires API ${requiredApiVersion}.`);
        }
      }
      if (overviewRes && overviewRes.ok) {
        try { setOverview(await overviewRes.json() || emptyOverview); } catch (e) {}
      }
      if (assetsRes && assetsRes.ok) {
        try { setAssets(await assetsRes.json() || []); } catch (e) {}
      }
      if (componentsRes && componentsRes.ok) {
        try { setComponents(await componentsRes.json() || []); } catch (e) {}
      }
      if (findingsRes && findingsRes.ok) {
        try { setFindings(await findingsRes.json() || []); } catch (e) {}
      }
      if (migrationsRes && migrationsRes.ok) {
        try { setMigrations(await migrationsRes.json() || []); } catch (e) {}
      }
      if (policiesRes && policiesRes.ok) {
        try {
          const p = await policiesRes.json();
          setActivePolicy(p.active || "");
          setPolicies(p.available || []);
        } catch (e) {}
      }
      // Distinguish a fully unreachable controller from a partial outage so the
      // status surface can say something useful (B5).
      if (!healthRes || !healthRes.ok) {
        setError("Controller unreachable; showing last known data.");
      } else {
        setError(failed.length > 0 ? `${failed.length} dashboard request${failed.length === 1 ? "" : "s"} failed; showing last known data.` : "");
      }
      setLastUpdated(Date.now());
    } catch (err) {
      setError(err instanceof Error ? err.message : "API unavailable");
    } finally {
      setLoading(false);
    }
  };

  // Debounced refetch so a burst of WebSocket events triggers a single reload.
  const refetchTimer = useRef<number | undefined>(undefined);
  const scheduleLoad = () => {
    if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    refetchTimer.current = window.setTimeout(load, 400);
  };

  // Real-time: refetch on relevant hub events. Polling remains the fallback so
  // the dashboard stays fresh even if the socket cannot connect.
  const liveEvents = new Set([
    "telemetry_update", "finding_status", "migration_enqueued",
    "migration_status", "policy_switched", "agent_progress", "agent_registered",
  ]);
  const { connected: live } = useWebSocket((event) => {
    if (enabled && liveEvents.has(event.type)) scheduleLoad();
  }, enabled);

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    load();
    // With the socket live, poll slowly as a safety net; without it, poll at 10s.
    const id = window.setInterval(load, live ? 30000 : 10000);
    return () => {
      window.clearInterval(id);
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    };
  }, [enabled, live]);

  const score = useMemo(() => {
    const penalty =
      overview.critical_findings * 18 +
      overview.high_findings * 8 +
      Math.max(0, overview.findings - overview.critical_findings - overview.high_findings) * 2;
    return Math.max(0, Math.min(100, 100 - penalty));
  }, [overview]);

  const enqueueMigration = async (hostUuid: string, targetService: string, configPath: string, patch: string) => {
    const response = await authedFetch("/api/migrations/enqueue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        host_uuid: hostUuid,
        target_service: targetService,
        migration_profile: migrationProfileFor(targetService),
        config_path: configPath,
        patch_unified_diff: patch,
        dry_run: true
      })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const body = await response.json();
    load();
    return `Queued ${body.command_id}`;
  };

  const switchPolicy = async (version: string) => {
    const response = await authedFetch("/api/policies/active", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ version })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const body = await response.json();
    setActivePolicy(body.active);
    load();
    return body.active;
  };

  const fetchFleetConfig = async () => {
    const res = await authedFetch("/api/fleet/config");
    if (!res.ok) throw new Error("Failed to fetch fleet config");
    return await res.json();
  };

  const saveFleetConfig = async (fc: { exclude_dirs: string; min_key_size: number; scan_schedule: string; llm_api_key?: string; llm_api_url?: string }) => {
    const res = await authedFetch("/api/fleet/config", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(fc)
    });
    if (!res.ok) throw new Error("Failed to save fleet config");
    return await res.json();
  };

  const fetchAuditLogs = async () => {
    const res = await authedFetch("/api/audit-logs");
    if (!res.ok) throw new Error("Failed to fetch audit logs");
    return await res.json();
  };

  const fetchAgentDiagnostics = async (hostUuid: string) => {
    const res = await authedFetch(`/api/agent/diagnostics?host_uuid=${hostUuid}`);
    if (!res.ok) throw new Error("Failed to fetch diagnostics");
    return await res.json();
  };

  const saveAgentDiagnostics = async (hostUuid: string, logs: string) => {
    const res = await authedFetch("/api/agent/diagnostics", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ host_uuid: hostUuid, logs })
    });
    if (!res.ok) throw new Error("Failed to save diagnostics");
    return await res.json();
  };

  const updateFindingStatus = async (findingId: string, status: string) => {
    const res = await authedFetch(`/api/findings/${findingId}/status`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status, updated_by: localStorage.getItem("janus_user") || "admin" })
    });
    if (!res.ok) throw new Error(await res.text());
    return await res.json();
  };

  return {
    overview,
    assets,
    components,
    findings,
    migrations,
    activePolicy,
    policies,
    error,
    score,
    loading,
    live,
    lastUpdated,
    enqueueMigration,
    switchPolicy,
    fetchFleetConfig,
    saveFleetConfig,
    fetchAuditLogs,
    fetchAgentDiagnostics,
    saveAgentDiagnostics,
    updateFindingStatus,
  };
}
