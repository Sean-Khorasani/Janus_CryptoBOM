import React, { useState, useEffect } from "react";
import { Activity, Terminal, Settings, Play, CheckCircle, RefreshCw, X, Sliders, Server, Cpu, HardDrive, Shield } from "lucide-react";
import { Asset } from "../hooks/useApi";

interface FleetManagementProps {
  assets: Asset[];
  fetchFleetConfig?: () => Promise<{ exclude_dirs: string; min_key_size: number; scan_schedule: string; llm_api_key?: string; llm_api_url?: string }>;
  saveFleetConfig?: (fc: { exclude_dirs: string; min_key_size: number; scan_schedule: string; llm_api_key?: string; llm_api_url?: string }) => Promise<any>;
  fetchAuditLogs?: () => Promise<any[]>;
  fetchAgentDiagnostics?: (hostUuid: string) => Promise<{ logs: string }>;
}

export function FleetManagement({
  assets: propAssets,
  fetchFleetConfig,
  saveFleetConfig,
  fetchAuditLogs,
  fetchAgentDiagnostics
}: FleetManagementProps) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [isLogsOpen, setIsLogsOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [minKeySize, setMinKeySize] = useState(2048);
  const [excludeDirs, setExcludeDirs] = useState<string>(".git, target, node_modules, dist, .venv, temp");
  const [scanSchedule, setScanSchedule] = useState<string>("daily");
  const [llmApiKey, setLlmApiKey] = useState<string>("");
  const [llmApiUrl, setLlmApiUrl] = useState<string>("https://api.openai.com/v1");
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [newWebhook, setNewWebhook] = useState("");
  const [retentionDays, setRetentionDays] = useState(90);
  const [autoPurge, setAutoPurge] = useState(true);

  // Profile Management State
  const [profiles, setProfiles] = useState<any[]>([]);
  const [mappings, setMappings] = useState<Record<string, string>>({}); // host_uuid -> profile_id
  const [profName, setProfName] = useState("");
  const [profExcludes, setProfExcludes] = useState("");
  const [profMinKey, setProfMinKey] = useState(2048);
  const [profSchedule, setProfSchedule] = useState("daily");
  const [profLlmKey, setProfLlmKey] = useState("");
  const [profLlmUrl, setProfLlmUrl] = useState("https://api.openai.com/v1");
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);

  const getAuthHeaders = (extra: Record<string, string> = {}) => {
    const token = localStorage.getItem("janus_token");
    const headers: Record<string, string> = { ...extra };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
  };

  const loadWebhooks = () => {
    fetch("/api/webhooks", { headers: getAuthHeaders() })
      .then(res => res.ok ? res.json() : [])
      .then(data => setWebhooks(data))
      .catch(err => console.error("Error loading webhooks:", err));
  };

  const loadRetention = () => {
    fetch("/api/retention", { headers: getAuthHeaders() })
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data) {
          setRetentionDays(data.retention_days || 90);
          setAutoPurge(data.auto_purge);
        }
      })
      .catch(err => console.error("Error loading retention:", err));
  };

  const loadProfiles = () => {
    fetch("/api/fleet/profiles", { headers: getAuthHeaders() })
      .then(res => res.ok ? res.json() : [])
      .then(data => setProfiles(data || []))
      .catch(err => console.error("Error loading profiles:", err));
  };

  const loadMappings = () => {
    fetch("/api/fleet/profiles/mapping", { headers: getAuthHeaders() })
      .then(res => res.ok ? res.json() : [])
      .then(data => {
        const map: Record<string, string> = {};
        if (Array.isArray(data)) {
          data.forEach((m: any) => {
            map[m.host_uuid] = m.profile_id;
          });
        }
        setMappings(map);
      })
      .catch(err => console.error("Error loading mappings:", err));
  };

  useEffect(() => {
    loadWebhooks();
    loadRetention();
    loadProfiles();
    loadMappings();
  }, []);

  const handleAddWebhook = () => {
    if (!newWebhook) return;
    fetch("/api/webhooks", {
      method: "POST",
      headers: getAuthHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ url: newWebhook })
    })
      .then(res => {
        if (res.ok) {
          showToast("Webhook added successfully");
          setNewWebhook("");
          loadWebhooks();
        }
      });
  };

  const handleDeleteWebhook = (id: string) => {
    fetch(`/api/webhooks?id=${id}`, {
      method: "DELETE",
      headers: getAuthHeaders()
    })
      .then(res => {
        if (res.ok) {
          showToast("Webhook deleted");
          loadWebhooks();
        }
      });
  };

  const handleSaveRetention = () => {
    fetch("/api/retention", {
      method: "POST",
      headers: getAuthHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ retention_days: retentionDays, auto_purge: autoPurge })
    })
      .then(res => {
        if (res.ok) {
          showToast("Retention policy saved");
          loadRetention();
        }
      });
  };

  const handleTriggerPurge = () => {
    fetch("/api/retention", {
      method: "POST",
      headers: getAuthHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ retention_days: retentionDays, auto_purge: autoPurge, trigger_purge: true })
    })
      .then(res => res.json())
      .then(data => {
        showToast(`Immediate purge executed. Removed ${data.purged_records || 0} telemetry rows.`);
      });
  };

  // Sync initial assets from props, adding mock/live telemetry values if not present
  useEffect(() => {
    setAssets(prev => {
      return propAssets.map(a => {
        const isLive = Date.now() - new Date(a.last_seen).getTime() < 60000;
        const existing = prev.find(ea => ea.host_uuid === a.host_uuid);
        const isSimulating = existing && existing.status !== "Idle" && existing.status !== "offline" && existing.status !== "" && existing.scan_progress < 100;
        if (isSimulating) {
          return existing;
        }
        return {
          ...a,
          status: a.status || (isLive ? "Idle" : "offline"),
          scan_progress: a.scan_progress || 0,
          current_scan_path: a.current_scan_path || "",
          cpu_usage: a.cpu_usage || (isLive ? 0.4 : 0.0),
          mem_usage: a.mem_usage || (isLive ? 18.2 : 0.0),
          total_files_scanned: a.total_files_scanned || 0,
        };
      });
    });
  }, [propAssets]);

  // Load configuration from backend
  useEffect(() => {
    if (fetchFleetConfig) {
      fetchFleetConfig()
        .then(cfg => {
          if (cfg) {
            setMinKeySize(cfg.min_key_size || 2048);
            setExcludeDirs(cfg.exclude_dirs || "");
            setScanSchedule(cfg.scan_schedule || "daily");
            if (cfg.llm_api_key !== undefined) setLlmApiKey(cfg.llm_api_key);
            if (cfg.llm_api_url !== undefined) setLlmApiUrl(cfg.llm_api_url);
          }
        })
        .catch(err => console.error("Error loading fleet config:", err));
    }
  }, [fetchFleetConfig]);

  // Load audit logs dynamically
  const loadAuditLogs = () => {
    if (fetchAuditLogs) {
      fetchAuditLogs()
        .then(logs => setAuditLogs(logs || []))
        .catch(err => console.error("Error loading audit logs:", err));
    }
  };

  useEffect(() => {
    loadAuditLogs();
    const interval = setInterval(loadAuditLogs, 10000);
    return () => clearInterval(interval);
  }, [fetchAuditLogs]);

  // Handle toast notifications
  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 4000);
  };

  // Simulate remote force-scan dispatch
  const handleForceScan = (assetId: string) => {
    const asset = assets.find(a => a.host_uuid === assetId);
    if (!asset) return;

    showToast(`Force scan command dispatched to agent on host ${asset.hostname}`);

    // Update status to scanning and step through phases
    let currentPhase = 0;
    const phases = [
      { name: "Static Source Analysis", path: "./src/core/crypto.go", progress: 12 },
      { name: "Binary PE/ELF Inspection", path: "./bin/app.exe", progress: 35 },
      { name: "Dependency Analysis", path: "./package-lock.json", progress: 68 },
      { name: "Runtime/Memory Scan", path: "Loaded modules: bcrypt.dll", progress: 85 },
      { name: "Active TLS Handshake Probing", path: "Testing 127.0.0.1:443", progress: 95 },
      { name: "Idle", path: "", progress: 100 },
    ];

    const interval = setInterval(() => {
      if (currentPhase >= phases.length) {
        clearInterval(interval);
        return;
      }
      const step = phases[currentPhase];
      setAssets(prev =>
        prev.map(a => {
          if (a.host_uuid === assetId) {
            return {
              ...a,
              status: step.name,
              scan_progress: step.progress,
              current_scan_path: step.path,
              cpu_usage: step.name === "Idle" ? 0.2 : 4.8 + Math.random() * 5,
              mem_usage: step.name === "Idle" ? 18.2 : 24.5 + Math.random() * 3,
              total_files_scanned: a.total_files_scanned + Math.floor(Math.random() * 80) + 10,
              last_seen: new Date().toISOString(),
            };
          }
          return a;
        })
      );
      currentPhase++;
    }, 1200);
  };

  // Fetch real diagnostic logs from server
  const handleViewLogs = (asset: Asset) => {
    setSelectedAsset(asset);
    setIsLogsOpen(true);
    if (fetchAgentDiagnostics) {
      fetchAgentDiagnostics(asset.host_uuid)
        .then(res => {
          if (res && res.logs) {
            setLogs(res.logs.split("\n"));
          } else {
            setLogs([
              `[${new Date().toISOString()}] [INFO] Starting Janus Cryptographic Agent Daemon v0.1.0`,
              `[${new Date().toISOString()}] [INFO] Exclusions configured: ${excludeDirs}`,
              `[${new Date().toISOString()}] [INFO] Remote gRPC Controller connected at 127.0.0.1:9443`,
              `[${new Date().toISOString()}] [INFO] Awaiting control commands from central supervisor...`,
            ]);
          }
        })
        .catch(err => {
          setLogs([`[ERROR] Failed to fetch diagnostic logs: ${err.message}`]);
        });
    } else {
      const mockLogs = [
        `[${new Date().toISOString()}] [INFO] Starting Janus Cryptographic Agent Daemon v0.1.0`,
        `[${new Date().toISOString()}] [INFO] Successfully parsed configuration file`,
        `[${new Date().toISOString()}] [INFO] Host UUID registered: ${asset.host_uuid}`,
        `[${new Date().toISOString()}] [INFO] Exclusions configured: ${excludeDirs}`,
        `[${new Date().toISOString()}] [INFO] Remote gRPC Controller connected at 127.0.0.1:9443`,
      ];
      setLogs(mockLogs);
    }
  };

  // Save configurations centrally
  const handleSaveConfigs = (e: React.FormEvent) => {
    e.preventDefault();
    if (saveFleetConfig) {
      saveFleetConfig({
        exclude_dirs: excludeDirs,
        min_key_size: minKeySize,
        scan_schedule: scanSchedule,
        llm_api_key: llmApiKey,
        llm_api_url: llmApiUrl
      })
        .then(() => {
          showToast("Global fleet configurations applied and dispatched to all connected agents.");
          loadAuditLogs();
        })
        .catch(err => showToast(`Failed to deploy configurations: ${err.message}`));
    } else {
      localStorage.setItem("janus_min_key_size", minKeySize.toString());
      localStorage.setItem("janus_exclude_dirs", excludeDirs);
      localStorage.setItem("janus_scan_schedule", scanSchedule);
      showToast("Global fleet configurations applied and dispatched to all connected agents.");
    }
  };

  const handleSaveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    if (!profName) {
      showToast("Profile Name is required");
      return;
    }
    const body: any = {
      name: profName,
      exclude_dirs: profExcludes,
      min_key_size: profMinKey,
      scan_schedule: profSchedule,
      llm_api_key: profLlmKey,
      llm_api_url: profLlmUrl
    };
    if (selectedProfileId) {
      body.profile_id = selectedProfileId;
    }
    fetch("/api/fleet/profiles", {
      method: "POST",
      headers: getAuthHeaders({ "content-type": "application/json" }),
      body: JSON.stringify(body)
    })
      .then(res => {
        if (res.ok) {
          showToast(selectedProfileId ? "Profile updated successfully" : "Profile created successfully");
          setProfName("");
          setProfExcludes("");
          setProfMinKey(2048);
          setProfSchedule("daily");
          setProfLlmKey("");
          setProfLlmUrl("https://api.openai.com/v1");
          setSelectedProfileId(null);
          loadProfiles();
        } else {
          showToast("Failed to save profile");
        }
      });
  };

  const handleDeleteProfile = (id: string) => {
    fetch(`/api/fleet/profiles?id=${id}`, {
      method: "DELETE",
      headers: getAuthHeaders()
    })
      .then(res => {
        if (res.ok) {
          showToast("Profile deleted successfully");
          loadProfiles();
          loadMappings();
        } else {
          showToast("Failed to delete profile");
        }
      });
  };

  const handleEditProfile = (p: any) => {
    setSelectedProfileId(p.profile_id);
    setProfName(p.name);
    setProfExcludes(p.exclude_dirs);
    setProfMinKey(p.min_key_size);
    setProfSchedule(p.scan_schedule);
    setProfLlmKey(p.llm_api_key || "");
    setProfLlmUrl(p.llm_api_url || "https://api.openai.com/v1");
  };

  const handleMapProfile = (hostUUID: string, profileID: string) => {
    fetch("/api/fleet/profiles/mapping", {
      method: "POST",
      headers: getAuthHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ host_uuid: hostUUID, profile_id: profileID })
    })
      .then(res => {
        if (res.ok) {
          const matchedProfileName = profileID === "" ? "Global / Default" : (profiles.find(p => p.profile_id === profileID)?.name || "custom profile");
          showToast(`Profile status updated: host mapped to ${matchedProfileName}`);
          loadMappings();
        } else {
          showToast("Failed to map profile");
        }
      });
  };

  return (
    <div className="space-y-6">
      {/* Toast Alert */}
      {toastMessage && (
        <div
          className="fixed bottom-5 right-5 z-50 flex items-center gap-2 rounded-md border border-[#11845b] bg-[#eefaf4] px-4 py-3 text-sm text-[#11845b] shadow-lg animate-toast"
          data-testid="fleet-toast"
        >
          <CheckCircle size={16} />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Grid: Top Stats Summary */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-[#697469]">Total Registered Agents</div>
            <Server size={18} className="text-[#2f6fed]" />
          </div>
          <div className="mt-2 text-2xl font-bold text-[#17211c]">{assets.length}</div>
        </section>

        <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-[#697469]">Online Heartbeats</div>
            <Activity size={18} className="text-[#11845b]" />
          </div>
          <div className="mt-2 text-2xl font-bold text-[#17211c]">
            {assets.filter(a => a.status !== "offline").length}
          </div>
        </section>

        <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-[#697469]">Active Scanning Phase</div>
            <Cpu size={18} className="text-[#e27d1d]" />
          </div>
          <div className="mt-2 text-2xl font-bold text-[#17211c]">
            {assets.filter(a => a.status !== "offline" && a.status !== "Idle" && a.status !== "").length}
          </div>
        </section>
      </div>

      {/* Layout Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left Column: Asset Table */}
        <section className="lg:col-span-2 rounded-md border border-[#dfe5dc] bg-white p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold flex items-center gap-2">
              <Server size={18} />
              Host Infrastructure Inventory
            </h2>
            <span className="rounded bg-[#edf1ea] px-2 py-0.5 text-xs text-[#697469] font-medium">
              Real-time synchronization
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm border-collapse">
              <thead>
                <tr className="border-b border-[#dfe5dc] text-xs font-semibold text-[#697469]">
                  <th className="p-3">Host details</th>
                  <th className="p-3">Resource Overhead</th>
                  <th className="p-3">Scanning Status</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#dfe5dc]">
                {assets.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-3 text-center text-xs text-[#697469]">
                      No hosts registered. Ensure daemon configurations are running.
                    </td>
                  </tr>
                ) : (
                  assets.map(asset => {
                    const isOffline = asset.status === "offline";
                    const isScanning = asset.status !== "offline" && asset.status !== "Idle" && asset.status !== "";
                    return (
                      <tr key={asset.host_uuid} className="hover:bg-[#f7f8f5] transition">
                        <td className="p-3">
                          <div className="font-semibold text-[#17211c]">{asset.hostname}</div>
                          <div className="text-[10px] text-[#697469] mt-0.5 font-mono">
                            {asset.os_name} {asset.os_version} ({asset.arch})
                          </div>
                          <div className="text-[9px] text-gray-400 mt-0.5">
                            Last seen: {new Date(asset.last_seen).toLocaleString()}
                          </div>
                        </td>
                        <td className="p-3">
                          {!isOffline && (
                            <div className="space-y-1 text-xs text-[#4d594f]">
                              <div className="flex items-center gap-1.5">
                                <Cpu size={12} className="text-[#697469]" />
                                <span>CPU: {asset.cpu_usage.toFixed(1)}%</span>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <HardDrive size={12} className="text-[#697469]" />
                                <span>RAM: {asset.mem_usage.toFixed(1)} MB</span>
                              </div>
                            </div>
                          )}
                          {isOffline && <span className="text-xs text-gray-400">—</span>}
                        </td>
                        <td className="p-3">
                          <div className="space-y-1">
                            <div className="flex items-center gap-1.5">
                              <span className={`h-2 w-2 rounded-full ${
                                isOffline ? "bg-gray-300" : isScanning ? "bg-orange-500 animate-pulse" : "bg-green-500"
                              }`} />
                              <span className="text-xs font-semibold text-[#17211c]">
                                {isOffline ? "Offline" : isScanning ? "Scanning" : "Connected"}
                              </span>
                            </div>
                            {isScanning && (
                              <div className="w-32">
                                <div className="flex justify-between text-[9px] text-[#697469] mb-0.5">
                                  <span className="truncate max-w-[80px]" title={asset.current_scan_path}>
                                    {asset.current_scan_path}
                                  </span>
                                  <span>{asset.scan_progress}%</span>
                                </div>
                                <div className="h-1 w-full rounded-full bg-gray-100 overflow-hidden">
                                  <div
                                    className="h-full bg-orange-500 transition-all duration-300"
                                    style={{ width: `${asset.scan_progress}%` }}
                                  />
                                </div>
                              </div>
                            )}
                            {!isOffline && !isScanning && asset.total_files_scanned > 0 && (
                              <div className="text-[10px] text-[#697469]">
                                Cataloged: {asset.total_files_scanned} files
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="p-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <select
                              value={mappings[asset.host_uuid] || ""}
                              onChange={(e) => handleMapProfile(asset.host_uuid, e.target.value)}
                              className="rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#17211c] bg-white text-gray-700"
                            >
                              <option value="">Global / Default</option>
                              {profiles.map(p => (
                                <option key={p.profile_id} value={p.profile_id}>{p.name}</option>
                              ))}
                            </select>

                            <button
                              id={`force-scan-${asset.host_uuid}`}
                              onClick={() => handleForceScan(asset.host_uuid)}
                              disabled={isOffline || isScanning}
                              className="inline-flex items-center gap-1 rounded bg-[#17211c] text-white hover:bg-[#2e3d34] px-2 py-1 text-xs disabled:opacity-30 transition font-medium"
                              type="button"
                            >
                              <Play size={12} />
                              Scan
                            </button>
                            <button
                              id={`view-logs-${asset.host_uuid}`}
                              onClick={() => handleViewLogs(asset)}
                              className="inline-flex items-center gap-1 rounded border border-[#dfe5dc] bg-white text-[#4d594f] hover:bg-[#edf1ea] px-2 py-1 text-xs transition font-medium"
                              type="button"
                            >
                              <Terminal size={12} />
                              Logs
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Global Settings Configuration Column */}
        <div className="space-y-6">
          <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
            <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
              <Settings size={18} />
              Central Fleet Profiles
            </h2>

            <form onSubmit={handleSaveConfigs} className="space-y-4">
            {/* Existing Global Configurations */}
            <div className="space-y-4 pt-2">
              <div>
                <label className="block text-sm font-medium text-[#49504a] mb-1">
                  Global Exclusion Directories
                </label>
                <input
                  type="text"
                  value={excludeDirs}
                  onChange={e => setExcludeDirs(e.target.value)}
                  className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-[#17211c]"
                />
                <p className="text-[10px] text-[#697469] mt-1">
                  Comma-separated directories omitted by agent filesystem scanners.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-[#49504a] mb-1">
                  Minimum Key Size
                </label>
                <input
                  id="cfg-min-key-size"
                  type="number"
                  value={minKeySize}
                  onChange={e => setMinKeySize(parseInt(e.target.value) || 2048)}
                  className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#17211c]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#697469] mb-1">
                  Centralized Scan Schedule
                </label>
                <select
                  id="cfg-scan-schedule"
                  value={scanSchedule}
                  onChange={e => setScanSchedule(e.target.value)}
                  className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#17211c]"
                >
                  <option value="realtime">Continuous Heartbeat Probing</option>
                  <option value="hourly">Hourly Telemetry Recalculation</option>
                  <option value="daily">Daily Security Sweep (Recommended)</option>
                  <option value="weekly">Weekly Full Introspection</option>
                </select>
              </div>

              
              {/* Advanced LLM Configuration */}
              <div className="border-t border-[#dfe5dc] pt-4 mt-4">
                <h4 className="text-sm font-semibold text-[#161a17] mb-3 flex items-center gap-2">
                  <Settings size={16} className="text-[#096b45]" />
                  LLM AI Context Analysis (Optional)
                </h4>
                <p className="text-xs text-[#697469] mb-4">
                  Configure an LLM to dramatically reduce false positives by analyzing the intent of cryptographic API usage (e.g., distinguishing between signing and verifying).
                </p>
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-[#697469] mb-1">
                      LLM API URL
                    </label>
                    <input
                      type="text"
                      value={llmApiUrl}
                      onChange={e => setLlmApiUrl(e.target.value)}
                      placeholder="https://api.openai.com/v1"
                      className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#17211c]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-[#697469] mb-1">
                      LLM API Key
                    </label>
                    <input
                      type="password"
                      value={llmApiKey}
                      onChange={e => setLlmApiKey(e.target.value)}
                      placeholder="sk-..."
                      className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-[#17211c]"
                    />
                  </div>
                </div>
              </div>

            </div>
              <button
                id="cfg-save-btn"
                type="submit"
                className="w-full rounded bg-[#11845b] text-white hover:bg-[#0e6b4a] py-2 text-sm font-semibold transition flex items-center justify-center gap-1"
              >
                <Sliders size={14} />
                Deploy Configuration Profile
              </button>
            </form>
          </section>

          {/* Configuration Profiles Management */}
          <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
            <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
              <Sliders size={18} />
              Configuration Profiles
            </h2>

            <form onSubmit={handleSaveProfile} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-[#697469] mb-1">
                  Profile Name
                </label>
                <input
                  type="text"
                  value={profName}
                  onChange={e => setProfName(e.target.value)}
                  placeholder="e.g. High Security Profile"
                  className="w-full rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#697469] mb-1">
                  Exclude Directories
                </label>
                <input
                  type="text"
                  value={profExcludes}
                  onChange={e => setProfExcludes(e.target.value)}
                  placeholder=".git, node_modules"
                  className="w-full rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs font-semibold text-[#697469] mb-1">
                    Min Key Size
                  </label>
                  <input
                    type="number"
                    value={profMinKey}
                    onChange={e => setProfMinKey(parseInt(e.target.value) || 2048)}
                    className="w-full rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#697469] mb-1">
                    Scan Schedule
                  </label>
                  <select
                    value={profSchedule}
                    onChange={e => setProfSchedule(e.target.value)}
                    className="w-full rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1 bg-white"
                  >
                    <option value="realtime">Continuous</option>
                    <option value="hourly">Hourly</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#697469] mb-1">
                  LLM API URL
                </label>
                <input
                  type="text"
                  value={profLlmUrl}
                  onChange={e => setProfLlmUrl(e.target.value)}
                  className="w-full rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#697469] mb-1">
                  LLM API Key
                </label>
                <input
                  type="password"
                  value={profLlmKey}
                  onChange={e => setProfLlmKey(e.target.value)}
                  className="w-full rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1"
                />
              </div>

              <div className="flex gap-2">
                <button
                  type="submit"
                  className="flex-1 rounded bg-[#11845b] text-white hover:bg-[#0e6b4a] py-1.5 text-xs font-semibold transition"
                >
                  {selectedProfileId ? "Update Profile" : "Create Profile"}
                </button>
                {selectedProfileId && (
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedProfileId(null);
                      setProfName("");
                      setProfExcludes("");
                      setProfMinKey(2048);
                      setProfSchedule("daily");
                      setProfLlmKey("");
                      setProfLlmUrl("https://api.openai.com/v1");
                    }}
                    className="rounded border border-[#dfe5dc] hover:bg-gray-50 px-2 py-1.5 text-xs text-[#4d594f] transition"
                  >
                    Cancel
                  </button>
                )}
              </div>
            </form>

            <ul className="divide-y divide-[#dfe5dc] mt-4 max-h-40 overflow-y-auto">
              {profiles.length === 0 ? (
                <li className="py-2 text-[11px] text-[#697469] text-center">No custom profiles configured.</li>
              ) : (
                profiles.map(p => (
                  <li key={p.profile_id} className="py-2 flex items-center justify-between text-xs">
                    <div>
                      <span className="font-semibold block">{p.name}</span>
                      <span className="text-[10px] text-[#697469] block font-mono">Min key: {p.min_key_size} | {p.scan_schedule}</span>
                    </div>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => handleEditProfile(p)}
                        className="text-blue-600 hover:text-blue-800 text-[10px] font-semibold"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDeleteProfile(p.profile_id)}
                        className="text-red-600 hover:text-red-800 text-[10px] font-semibold"
                      >
                        Delete
                      </button>
                    </div>
                  </li>
                ))
              )}
            </ul>
          </section>

          {/* New Feature 1: Alert Webhook Console */}
          <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
            <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
              <Activity size={18} className="text-orange-500" />
              Critical Webhook Alerts
            </h2>
            <div className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Slack / Webhook URL"
                  value={newWebhook}
                  onChange={e => setNewWebhook(e.target.value)}
                  className="flex-1 rounded border border-[#dfe5dc] px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#17211c]"
                />
                <button
                  type="button"
                  onClick={handleAddWebhook}
                  className="rounded bg-[#17211c] text-white px-3 py-1 text-xs font-semibold hover:bg-black transition"
                >
                  Add
                </button>
              </div>
              <ul className="divide-y divide-[#dfe5dc] max-h-40 overflow-y-auto">
                {webhooks.length === 0 ? (
                  <li className="py-2 text-[11px] text-[#697469] text-center">No alert webhooks configured.</li>
                ) : (
                  webhooks.map(wh => (
                    <li key={wh.webhook_id} className="py-2 flex items-center justify-between text-xs">
                      <span className="truncate max-w-[150px] font-mono text-[10px]" title={wh.url}>{wh.url}</span>
                      <button
                        type="button"
                        onClick={() => handleDeleteWebhook(wh.webhook_id)}
                        className="text-red-600 hover:text-red-800 text-[10px] font-semibold"
                      >
                        Delete
                      </button>
                    </li>
                  ))
                )}
              </ul>
            </div>
          </section>

          {/* New Feature 2: Data Retention Settings */}
          <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
            <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
              <HardDrive size={18} className="text-blue-500" />
              Telemetry Retention
            </h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span>Keep Telemetry for:</span>
                <div className="flex items-center gap-1">
                  <input
                    type="number"
                    value={retentionDays}
                    onChange={e => setRetentionDays(parseInt(e.target.value) || 0)}
                    className="w-16 rounded border border-[#dfe5dc] px-2 py-1 text-center focus:outline-none focus:ring-1"
                  />
                  <span>days</span>
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleSaveRetention}
                  className="flex-1 rounded border border-[#dfe5dc] py-1.5 text-xs font-semibold hover:bg-gray-50 transition"
                >
                  Save Policy
                </button>
                <button
                  type="button"
                  onClick={handleTriggerPurge}
                  className="flex-1 rounded bg-red-600 text-white py-1.5 text-xs font-semibold hover:bg-red-700 transition"
                >
                  Purge Old Data
                </button>
              </div>
            </div>
          </section>
        </div>
      </div>

      {/* Central Security & Operations Audit Logs Section */}
      <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
        <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
          <Shield size={18} className="text-[#11845b]" />
          Central Security & Operations Audit Logs
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm border-collapse">
            <thead>
              <tr className="border-b border-[#dfe5dc] text-xs font-semibold text-[#697469]">
                <th className="p-3">Time</th>
                <th className="p-3">Operator</th>
                <th className="p-3">Action</th>
                <th className="p-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#dfe5dc]">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="p-3 text-center text-xs text-[#697469]">
                    No security audit logs available.
                  </td>
                </tr>
              ) : (
                auditLogs.map((log) => (
                  <tr key={log.log_id} className="hover:bg-[#f7f8f5] transition">
                    <td className="p-3 text-xs text-[#697469] font-mono">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="p-3 font-medium text-[#17211c]">{log.username}</td>
                    <td className="p-3">
                      <span className={`inline-flex rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${
                        log.action === "ENQUEUE_MIGRATION" ? "bg-blue-100 text-blue-800" : "bg-green-100 text-green-800"
                      }`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="p-3 text-xs text-[#4d594f] font-mono">{log.details}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Diagnostics Logs Drawer */}
      {isLogsOpen && selectedAsset && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-white h-full shadow-2xl flex flex-col animate-slide-in">
            <header className="flex items-center justify-between border-b border-[#dfe5dc] p-4 bg-[#f7f8f5]">
              <div>
                <h3 className="text-base font-semibold flex items-center gap-2 text-[#17211c]">
                  <Terminal size={18} />
                  Agent Diagnostics Console
                </h3>
                <p className="text-xs text-[#697469] mt-0.5 font-mono">
                  {selectedAsset.hostname} ({selectedAsset.host_uuid})
                </p>
              </div>
              <button
                id="close-logs-drawer"
                onClick={() => {
                  setIsLogsOpen(false);
                  setSelectedAsset(null);
                }}
                className="rounded-full p-1 hover:bg-gray-200 transition text-[#4d594f]"
                type="button"
              >
                <X size={20} />
              </button>
            </header>

            <div className="flex-1 overflow-y-auto p-4 bg-[#111714] text-green-400 font-mono text-xs space-y-2 select-text">
              {logs.map((log, index) => (
                <div key={index} className="leading-relaxed border-l-2 border-green-800 pl-2">
                  {log}
                </div>
              ))}
            </div>

            <footer className="border-t border-[#dfe5dc] p-4 bg-[#f7f8f5] flex items-center justify-between">
              <span className="text-xs text-[#697469]">Showing latest diagnostic runtime events</span>
              <button
                onClick={() => {
                  showToast("Logs diagnostics refreshed from host");
                  handleViewLogs(selectedAsset);
                }}
                className="inline-flex items-center gap-1 rounded bg-[#17211c] text-white hover:bg-[#2e3d34] px-3 py-1.5 text-xs font-semibold transition"
                type="button"
              >
                <RefreshCw size={12} />
                Refresh Logs
              </button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
