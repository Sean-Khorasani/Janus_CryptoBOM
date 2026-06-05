import { useEffect, useState } from "react";
import { AlertTriangle, FileSearch, Gauge, TerminalSquare, Shield, Sliders } from "lucide-react";
import { useApi } from "./hooks/useApi";
import { Header } from "./components/Header";
import { OverviewView } from "./components/OverviewView";
import { CbomViewer } from "./components/CbomViewer";
import { MigrationConsole } from "./components/MigrationConsole";
import { ComplianceMatrix } from "./components/ComplianceMatrix";
import { PolicyStudio } from "./components/PolicyStudio";
import { FleetManagement } from "./components/FleetManagement";
import { Activity } from "lucide-react";

function TabButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex h-9 items-center gap-2 rounded px-3 text-sm ${
        active ? "bg-[#17211c] text-white" : "text-[#4d594f] hover:bg-[#eef2ec]"
      }`}
    >
      {icon}
      {label}
    </button>
  );
}

function App() {
  const {
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
    enqueueMigration,
    switchPolicy,
    fetchFleetConfig,
    saveFleetConfig,
    fetchAuditLogs,
    fetchAgentDiagnostics
  } = useApi();
  const [tab, setTab] = useState<"overview" | "cbom" | "compliance" | "policy" | "migrations" | "fleet">("overview");

  const [statuses, setStatuses] = useState<Record<string, string>>(() => {
    const init: Record<string, string> = {};
    try { Object.assign(init, JSON.parse(localStorage.getItem("janus_finding_statuses") || "{}")); } catch (e) {}
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      const v = k ? localStorage.getItem(k) : null;
      if (k && v && ["accepted", "false-positive", "remediated"].includes(v)) init[k] = v;
    }
    return init;
  });

  const updateStatus = (findingId: string, status: string) => {
    localStorage.setItem(findingId, status);
    let comp = {};
    try { comp = JSON.parse(localStorage.getItem("janus_finding_statuses") || "{}"); } catch (e) {}
    const updated = { ...comp, [findingId]: status };
    localStorage.setItem("janus_finding_statuses", JSON.stringify(updated));
    setStatuses(updated);
  };

  const [theme, setTheme] = useState(() => {
    const d = localStorage.getItem("darkMode");
    return localStorage.getItem("theme") === "dark" || d === "true" || d === "dark" ? "dark" : "light";
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
    localStorage.setItem("darkMode", theme === "dark" ? "true" : "false");
  }, [theme]);

  return (
    <main className="min-h-screen bg-[#f7f8f5] text-[#17211c]">
      <Header error={error} />

      <section className="mx-auto max-w-7xl px-5 py-5">
        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16]">
            <AlertTriangle size={17} />
            <span>{error}</span>
          </div>
        )}

        <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
          <nav className="inline-flex rounded-md border border-[#dfe5dc] bg-white p-1">
            <TabButton active={tab === "overview"} onClick={() => setTab("overview")} icon={<Gauge size={16} />} label="Overview" />
            <TabButton active={tab === "cbom"} onClick={() => setTab("cbom")} icon={<FileSearch size={16} />} label="CBOM" />
            <TabButton active={tab === "compliance"} onClick={() => setTab("compliance")} icon={<Shield size={16} />} label="Compliance" />
            <TabButton active={tab === "policy"} onClick={() => setTab("policy")} icon={<Sliders size={16} />} label="Policy Studio" />
            <TabButton active={tab === "migrations"} onClick={() => setTab("migrations")} icon={<TerminalSquare size={16} />} label="Migrations" />
            <TabButton active={tab === "fleet"} onClick={() => setTab("fleet")} icon={<Activity size={16} />} label="Fleet Command" />
          </nav>
          
          <button
            onClick={() => setTheme(t => t === "dark" ? "light" : "dark")}
            className="dark-mode-toggle h-9 px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] flex items-center gap-2"
            data-action="toggle-dark-mode"
            type="button"
          >
            Theme: {theme === "dark" ? "Dark" : "Light"}
          </button>
        </div>

        {loading ? (
          <div className="skeleton loading animate-pulse space-y-4" data-testid="skeleton">
            <div className="h-12 bg-gray-200 rounded w-1/4" />
            <div className="h-32 bg-gray-200 rounded" />
            <div className="h-64 bg-gray-200 rounded" />
          </div>
        ) : (
          <>
            {tab === "overview" && <OverviewView overview={overview} score={score} findings={findings} components={components} assets={assets} statuses={statuses} updateStatus={updateStatus} />}
            {tab === "cbom" && <CbomViewer assets={assets} components={components} findings={findings} overview={overview} statuses={statuses} updateStatus={updateStatus} />}
            {tab === "compliance" && <ComplianceMatrix assets={assets} findings={findings} statuses={statuses} />}
            {tab === "policy" && <PolicyStudio activePolicy={activePolicy} policies={policies} switchPolicy={switchPolicy} />}
            {tab === "migrations" && <MigrationConsole migrations={migrations} assets={assets} enqueueMigration={enqueueMigration} />}
            {tab === "fleet" && (
              <FleetManagement
                assets={assets}
                fetchFleetConfig={fetchFleetConfig}
                saveFleetConfig={saveFleetConfig}
                fetchAuditLogs={fetchAuditLogs}
                fetchAgentDiagnostics={fetchAgentDiagnostics}
              />
            )}
          </>
        )}
      </section>
    </main>
  );
}

export default App;
