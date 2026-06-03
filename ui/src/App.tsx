import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  FileSearch,
  Gauge,
  GitBranch,
  Layers3,
  Play,
  FileText,
  RadioTower,
  ShieldCheck,
  TerminalSquare
} from "lucide-react";

type Overview = {
  assets: number;
  components: number;
  findings: number;
  critical_findings: number;
  high_findings: number;
  open_migrations: number;
  algorithm_histogram: Record<string, number>;
};

type Asset = {
  host_uuid: string;
  hostname: string;
  os_name: string;
  os_version: string;
  arch: string;
  execution_mode: number;
  last_seen: string;
};

type Finding = {
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
};

type ComponentRecord = {
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

type Migration = {
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
};

const emptyOverview: Overview = {
  assets: 0,
  components: 0,
  findings: 0,
  critical_findings: 0,
  high_findings: 0,
  open_migrations: 0,
  algorithm_histogram: {}
};

function App() {
  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [components, setComponents] = useState<ComponentRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [migrations, setMigrations] = useState<Migration[]>([]);
  const [tab, setTab] = useState<"overview" | "cbom" | "migrations">("overview");
  const [error, setError] = useState("");

  useEffect(() => {
    const load = async () => {
      try {
        const [overviewRes, assetsRes, componentsRes, findingsRes, migrationsRes] = await Promise.all([
          fetch("/api/overview"),
          fetch("/api/assets"),
          fetch("/api/components"),
          fetch("/api/findings"),
          fetch("/api/migrations")
        ]);
        if (!overviewRes.ok) throw new Error(await overviewRes.text());
        setOverview(await overviewRes.json());
        setAssets(assetsRes.ok ? await assetsRes.json() : []);
        setComponents(componentsRes.ok ? await componentsRes.json() : []);
        setFindings(findingsRes.ok ? await findingsRes.json() : []);
        setMigrations(migrationsRes.ok ? await migrationsRes.json() : []);
        setError("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "API unavailable");
      }
    };
    load();
    const id = window.setInterval(load, 10000);
    return () => window.clearInterval(id);
  }, []);

  const score = useMemo(() => {
    const penalty = overview.critical_findings * 18 + overview.high_findings * 8 + Math.max(0, overview.findings - overview.critical_findings - overview.high_findings) * 2;
    return Math.max(0, Math.min(100, 100 - penalty));
  }, [overview]);

  return (
    <main className="min-h-screen bg-[#f7f8f5] text-[#17211c]">
      <header className="border-b border-[#dfe5dc] bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-md bg-[#17211c] text-white">
              <ShieldCheck size={22} />
            </div>
            <div>
              <h1 className="text-xl font-semibold tracking-normal">Janus CryptoBOM</h1>
              <p className="text-sm text-[#697469]">Cryptographic exposure graph and PQC migration control</p>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-md border border-[#dfe5dc] bg-[#f7f8f5] px-3 py-2 text-sm">
            <Activity size={16} className="text-[#11845b]" />
            <span>{error ? "API offline" : "Live controller"}</span>
          </div>
          <a
            href="/api/report.html"
            target="_blank"
            rel="noreferrer"
            className="flex h-9 items-center gap-2 rounded-md border border-[#dfe5dc] bg-white px-3 text-sm text-[#17211c] hover:bg-[#edf1ea]"
          >
            <FileText size={16} />
            Report
          </a>
        </div>
      </header>

      <section className="mx-auto max-w-7xl px-5 py-5">
        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16]">
            <AlertTriangle size={17} />
            <span>{error}</span>
          </div>
        )}

        <nav className="mb-5 inline-flex rounded-md border border-[#dfe5dc] bg-white p-1">
          <TabButton active={tab === "overview"} onClick={() => setTab("overview")} icon={<Gauge size={16} />} label="Overview" />
          <TabButton active={tab === "cbom"} onClick={() => setTab("cbom")} icon={<FileSearch size={16} />} label="CBOM" />
          <TabButton active={tab === "migrations"} onClick={() => setTab("migrations")} icon={<TerminalSquare size={16} />} label="Migrations" />
        </nav>

        {tab === "overview" && <OverviewView overview={overview} score={score} findings={findings} />}
        {tab === "cbom" && <CbomView assets={assets} components={components} findings={findings} overview={overview} />}
        {tab === "migrations" && <MigrationView migrations={migrations} assets={assets} />}
      </section>
    </main>
  );
}

function TabButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex h-9 items-center gap-2 rounded px-3 text-sm ${active ? "bg-[#17211c] text-white" : "text-[#4d594f] hover:bg-[#eef2ec]"}`}
    >
      {icon}
      {label}
    </button>
  );
}

function OverviewView({ overview, score, findings }: { overview: Overview; score: number; findings: Finding[] }) {
  const histogram = Object.entries(overview.algorithm_histogram ?? {});
  const max = Math.max(1, ...histogram.map(([, v]) => v));
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric icon={<Gauge />} label="Safety Score" value={`${score}/100`} accent="bg-[#11845b]" />
        <Metric icon={<Database />} label="Tracked Assets" value={overview.assets.toLocaleString()} accent="bg-[#2f6fed]" />
        <Metric icon={<Layers3 />} label="CBOM Components" value={overview.components.toLocaleString()} accent="bg-[#8b5cf6]" />
        <Metric icon={<AlertTriangle />} label="Critical Warnings" value={overview.critical_findings.toLocaleString()} accent="bg-[#d33f49]" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_1.2fr]">
        <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold">Algorithm Density</h2>
            <GitBranch size={18} className="text-[#697469]" />
          </div>
          <div className="space-y-3">
            {histogram.length === 0 && <Empty label="No algorithm observations received" />}
            {histogram.map(([name, count]) => (
              <div key={name}>
                <div className="mb-1 flex justify-between text-sm">
                  <span className="truncate pr-3">{name || "unknown"}</span>
                  <span className="font-medium">{count}</span>
                </div>
                <div className="h-2 rounded bg-[#edf1ea]">
                  <div className="h-2 rounded bg-[#2f6fed]" style={{ width: `${Math.max(4, (count / max) * 100)}%` }} />
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold">Highest Priority Findings</h2>
            <AlertTriangle size={18} className="text-[#d33f49]" />
          </div>
          <FindingTable findings={findings.slice(0, 6)} />
        </section>
      </div>
    </div>
  );
}

function CbomView({ assets, components, findings, overview }: { assets: Asset[]; components: ComponentRecord[]; findings: Finding[]; overview: Overview }) {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[0.9fr_1.3fr]">
      <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold">Asset Inventory</h2>
          <RadioTower size={18} className="text-[#2f6fed]" />
        </div>
        <div className="overflow-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469]">
              <tr>
                <th className="py-2 pr-3">Host</th>
                <th className="py-2 pr-3">Platform</th>
                <th className="py-2 pr-3">Mode</th>
                <th className="py-2 pr-3">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((asset) => (
                <tr key={asset.host_uuid} className="border-b border-[#edf1ea]">
                  <td className="py-2 pr-3 font-medium">{asset.hostname}</td>
                  <td className="py-2 pr-3">{asset.os_name} {asset.os_version} / {asset.arch}</td>
                  <td className="py-2 pr-3">{asset.execution_mode === 2 ? "Active" : "Passive"}</td>
                  <td className="py-2 pr-3">{formatDate(asset.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {assets.length === 0 && <Empty label="No agents registered" />}
        </div>
      </section>

      <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold">CBOM Findings Matrix</h2>
          <span className="rounded bg-[#edf1ea] px-2 py-1 text-xs">{overview.components} components</span>
        </div>
        <div className="mb-5 overflow-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469]">
              <tr>
                <th className="py-2 pr-3">Component</th>
                <th className="py-2 pr-3">Type</th>
                <th className="py-2 pr-3">Path</th>
                <th className="py-2 pr-3">Algorithms</th>
              </tr>
            </thead>
            <tbody>
              {components.slice(0, 12).map((component) => (
                <tr key={`${component.telemetry_id}-${component.bom_ref}`} className="border-b border-[#edf1ea]">
                  <td className="py-2 pr-3">
                    <div className="font-medium">{component.name}</div>
                    <div className="max-w-[260px] truncate font-mono text-xs text-[#697469]">{component.bom_ref}</div>
                  </td>
                  <td className="py-2 pr-3">{component.component_type}</td>
                  <td className="max-w-[340px] truncate py-2 pr-3">{component.file_path}</td>
                  <td className="py-2 pr-3">{component.algorithms?.join(", ") || "none"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {components.length === 0 && <Empty label="No CBOM components received" />}
        </div>
        <FindingTable findings={findings} />
      </section>
    </div>
  );
}

function MigrationView({ migrations, assets }: { migrations: Migration[]; assets: Asset[] }) {
  const [hostUuid, setHostUuid] = useState(assets[0]?.host_uuid ?? "");
  const [targetService, setTargetService] = useState("nginx");
  const [configPath, setConfigPath] = useState("");
  const [patch, setPatch] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!hostUuid && assets.length > 0) {
      setHostUuid(assets[0].host_uuid);
    }
  }, [assets, hostUuid]);

  const enqueue = async () => {
    setMessage("");
    const response = await fetch("/api/migrations/enqueue", {
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
      setMessage(await response.text());
      return;
    }
    const body = await response.json();
    setMessage(`Queued ${body.command_id}`);
  };

  return (
    <div className="space-y-4">
      <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold">Migration Control Console</h2>
          <button onClick={enqueue} className="flex h-9 items-center gap-2 rounded bg-[#17211c] px-3 text-sm text-white" type="button">
            <Play size={15} />
            Queue Dry Run
          </button>
        </div>
        <div className="mb-4 grid grid-cols-1 gap-3 xl:grid-cols-[1fr_160px_1fr]">
          <label className="text-sm">
            <span className="mb-1 block text-[#697469]">Agent</span>
            <select
              value={hostUuid}
              onChange={(event) => setHostUuid(event.target.value)}
              className="h-10 w-full rounded border border-[#dfe5dc] bg-white px-3"
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
            <span className="mb-1 block text-[#697469]">Service</span>
            <select
              value={targetService}
              onChange={(event) => setTargetService(event.target.value)}
              className="h-10 w-full rounded border border-[#dfe5dc] bg-white px-3"
            >
              <option value="nginx">nginx</option>
              <option value="apache">apache</option>
              <option value="ssh">ssh</option>
              <option value="windows-trust-store">Windows trust store</option>
              <option value="windows-schannel-policy">Windows Schannel</option>
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-[#697469]">Config path or certificate store</span>
            <input
              value={configPath}
              onChange={(event) => setConfigPath(event.target.value)}
              placeholder={targetService === "windows-trust-store" ? "CurrentUser\\Root" : targetService === "windows-schannel-policy" ? "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL" : "C:\\path\\to\\service.conf"}
              className="h-10 w-full rounded border border-[#dfe5dc] bg-white px-3"
            />
          </label>
          <label className="text-sm xl:col-span-3">
            <span className="mb-1 block text-[#697469]">Unified diff, PEM certificate, or Schannel JSON payload</span>
            <textarea
              value={patch}
              onChange={(event) => setPatch(event.target.value)}
              className="h-28 w-full resize-y rounded border border-[#dfe5dc] bg-white p-3 font-mono text-xs"
            />
          </label>
          {message && <div className="text-sm text-[#4d594f] xl:col-span-3">{message}</div>}
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Metric icon={<RadioTower />} label="Connected Agents" value={assets.length.toString()} accent="bg-[#2f6fed]" />
          <Metric icon={<TerminalSquare />} label="Transactions" value={migrations.length.toString()} accent="bg-[#8b5cf6]" />
          <Metric icon={<CheckCircle2 />} label="Completed" value={migrations.filter((m) => m.state === 6).length.toString()} accent="bg-[#11845b]" />
        </div>
      </section>

      <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
        <div className="overflow-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469]">
              <tr>
                <th className="py-2 pr-3">Command</th>
                <th className="py-2 pr-3">Host</th>
                <th className="py-2 pr-3">Service</th>
                <th className="py-2 pr-3">Target</th>
                <th className="py-2 pr-3">State</th>
                <th className="py-2 pr-3">Updated</th>
              </tr>
            </thead>
            <tbody>
              {migrations.map((m) => (
                <tr key={m.command_id} className="border-b border-[#edf1ea]">
                  <td className="py-2 pr-3 font-mono text-xs">{m.command_id.slice(0, 12)}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{m.host_uuid.slice(0, 12)}</td>
                  <td className="py-2 pr-3">{m.target_service}</td>
                  <td className="py-2 pr-3">{m.target_kem} / {m.target_signature}</td>
                  <td className="py-2 pr-3"><StateBadge state={m.state} /></td>
                  <td className="py-2 pr-3">{formatDate(m.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {migrations.length === 0 && <Empty label="No migration transactions queued" />}
        </div>
      </section>
    </div>
  );
}

function migrationProfileFor(targetService: string) {
  if (targetService === "windows-trust-store") return "windows-trust-store-import";
  if (targetService === "windows-schannel-policy") return "windows-schannel-tls-policy";
  return "hybrid-tls13-mlkem-mldsa";
}

function Metric({ icon, label, value, accent }: { icon: React.ReactNode; label: string; value: string; accent: string }) {
  return (
    <section className="rounded-md border border-[#dfe5dc] bg-white p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className={`flex h-9 w-9 items-center justify-center rounded ${accent} text-white`}>{icon}</div>
      </div>
      <div className="text-2xl font-semibold">{value}</div>
      <div className="mt-1 text-sm text-[#697469]">{label}</div>
    </section>
  );
}

function FindingTable({ findings }: { findings: Finding[] }) {
  return (
    <div className="overflow-auto">
      <table className="w-full min-w-[820px] text-left text-sm">
        <thead className="border-b border-[#dfe5dc] text-xs uppercase text-[#697469]">
          <tr>
            <th className="py-2 pr-3">Severity</th>
            <th className="py-2 pr-3">Finding</th>
            <th className="py-2 pr-3">Asset</th>
            <th className="py-2 pr-3">Algorithm</th>
            <th className="py-2 pr-3">Rule</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={finding.finding_id} className="border-b border-[#edf1ea]">
              <td className="py-2 pr-3"><SeverityBadge severity={finding.severity} /></td>
              <td className="py-2 pr-3">
                <div className="font-medium">{finding.title}</div>
                <div className="max-w-[420px] truncate text-xs text-[#697469]">{finding.description}</div>
              </td>
              <td className="py-2 pr-3 max-w-[240px] truncate">{finding.asset_ref}</td>
              <td className="py-2 pr-3">{finding.algorithm || "unknown"}</td>
              <td className="py-2 pr-3 font-mono text-xs">{finding.policy_rule_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {findings.length === 0 && <Empty label="No findings received" />}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: number }) {
  const label = severity >= 5 ? "Critical" : severity === 4 ? "High" : severity === 3 ? "Medium" : severity === 2 ? "Low" : "Info";
  const color = severity >= 5 ? "bg-[#d33f49] text-white" : severity === 4 ? "bg-[#e07a2f] text-white" : severity === 3 ? "bg-[#ffd166] text-[#3a2a00]" : "bg-[#edf1ea] text-[#4d594f]";
  return <span className={`rounded px-2 py-1 text-xs font-medium ${color}`}>{label}</span>;
}

function StateBadge({ state }: { state: number }) {
  const label = state === 6 ? "Succeeded" : state === 7 ? "Failed" : state === 4 ? "Validating" : state === 3 ? "Applying" : "Pending";
  const color = state === 6 ? "bg-[#dff3e9] text-[#0f6847]" : state === 7 ? "bg-[#ffe3dc] text-[#8b2d16]" : "bg-[#edf1ea] text-[#4d594f]";
  return <span className={`rounded px-2 py-1 text-xs font-medium ${color}`}>{label}</span>;
}

function Empty({ label }: { label: string }) {
  return <div className="py-8 text-center text-sm text-[#697469]">{label}</div>;
}

function formatDate(value: string) {
  if (!value) return "n/a";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

export default App;
