import { useEffect, useState } from "react";
import { AlertTriangle, FileSearch, Gauge, TerminalSquare, Shield, Sliders, Globe, Activity } from "lucide-react";
import { useApi } from "./hooks/useApi";
import { Header } from "./components/Header";
import { OverviewView } from "./components/OverviewView";
import { CbomViewer } from "./components/CbomViewer";
import { MigrationConsole } from "./components/MigrationConsole";
import { ComplianceMatrix } from "./components/ComplianceMatrix";
import { PolicyStudio } from "./components/PolicyStudio";
import { FleetManagement } from "./components/FleetManagement";
import { SkipLink } from "./a11y/SkipLink";
import { useI18n } from "./i18n";
import type { Locale } from "./i18n/types";

function TabButton({ active, onClick, icon, label, id }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string; id: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      role="tab"
      aria-selected={active}
      aria-controls={`tabpanel-${id}`}
      id={`tab-${id}`}
      className={`flex h-9 items-center gap-2 rounded px-3 text-sm tab-transition ${
        active
          ? "bg-[#17211c] text-white dark:bg-[#2a3a32] dark:text-[#e8ede9]"
          : "text-[#4d594f] hover:bg-[#eef2ec] dark:text-[#6b7e6f] dark:hover:bg-[#2a3a32]"
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
    fetchAgentDiagnostics,
    updateFindingStatus,
  } = useApi();
  const [tab, setTab] = useState<"overview" | "cbom" | "compliance" | "policy" | "migrations" | "fleet">("overview");
  const { t, locale, setLocale, locales } = useI18n();

  // Initialize statuses from server-side findings data on each load
  const [statuses, setStatuses] = useState<Record<string, string>>({});

  // Keep statuses in sync with findings from the API
  useEffect(() => {
    const serverStatuses: Record<string, string> = {};
    findings.forEach(f => {
      if (f.status && f.status !== "open") {
        serverStatuses[f.finding_id] = f.status;
      }
    });
    // Merge with any pending local changes (optimistic updates)
    setStatuses(prev => {
      const merged = { ...serverStatuses };
      // Preserve optimistic updates that haven't been confirmed yet
      Object.entries(prev).forEach(([id, s]) => {
        if (!serverStatuses[id] && s) merged[id] = s;
      });
      return merged;
    });
  }, [findings]);

  const updateStatus = async (findingId: string, status: string) => {
    // Optimistic local update
    setStatuses(prev => ({ ...prev, [findingId]: status }));
    try {
      await updateFindingStatus(findingId, status);
    } catch (err) {
      // Revert on failure
      setStatuses(prev => {
        const reverted = { ...prev };
        delete reverted[findingId];
        return reverted;
      });
    }
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

  const tabs = [
    { id: "overview" as const, label: t("nav.overview"), icon: <Gauge size={16} /> },
    { id: "cbom" as const, label: t("nav.cbom"), icon: <FileSearch size={16} /> },
    { id: "compliance" as const, label: t("nav.compliance"), icon: <Shield size={16} /> },
    { id: "policy" as const, label: t("nav.policy_studio"), icon: <Sliders size={16} /> },
    { id: "migrations" as const, label: t("nav.migrations"), icon: <TerminalSquare size={16} /> },
    { id: "fleet" as const, label: t("nav.fleet_command"), icon: <Activity size={16} /> },
  ];

  return (
    <main className="min-h-screen bg-[#f7f8f5] text-[#17211c] dark:bg-[#0d1210] dark:text-[#e8ede9]">
      <SkipLink targetId="main-content" />
      <Header error={error} />

      <section id="main-content" className="mx-auto max-w-7xl px-5 py-5">
        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-md border border-[#efb7a5] bg-[#fff4ee] px-3 py-2 text-sm text-[#8b2d16]" role="alert">
            <AlertTriangle size={17} aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
          <nav className="inline-flex rounded-md border border-[#dfe5dc] bg-white p-1 dark:border-[#2a3a30] dark:bg-[#1a2620]" role="tablist" aria-label="Main navigation tabs">
            {tabs.map((t) => (
              <TabButton
                key={t.id}
                id={t.id}
                active={tab === t.id}
                onClick={() => setTab(t.id)}
                icon={t.icon}
                label={t.label}
              />
            ))}
          </nav>

          <div className="flex items-center gap-3">
            {/* Locale switcher */}
            <div className="relative">
              <select
                value={locale}
                onChange={(e) => setLocale(e.target.value as Locale)}
                aria-label="Select language / انتخاب زبان / 选择语言 / Seleccionar idioma"
                className="h-9 rounded border border-[#dfe5dc] bg-white px-2 text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a] appearance-none cursor-pointer"
              >
                {locales.map((l) => (
                  <option key={l.code} value={l.code}>
                    {l.name}
                  </option>
                ))}
              </select>
              <Globe size={14} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-[#697469] dark:text-[#8fa991]" aria-hidden="true" />
            </div>

            <button
              onClick={() => setTheme(t => t === "dark" ? "light" : "dark")}
              className="dark-mode-toggle h-9 px-3 rounded border border-[#dfe5dc] bg-white text-xs font-medium text-[#4d594f] hover:bg-[#edf1ea] dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#6b7e6f] dark:hover:bg-[#22302a] flex items-center gap-2"
              data-action="toggle-dark-mode"
              type="button"
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
            >
              Theme: {theme === "dark" ? "Dark" : "Light"}
            </button>
          </div>
        </div>

        {loading ? (
          <div className="skeleton loading animate-pulse space-y-4" data-testid="skeleton" role="status" aria-label={t("msg.loading")}>
            <div className="h-12 skeleton-shimmer rounded w-1/4" />
            <div className="h-32 skeleton-shimmer rounded" />
            <div className="h-64 skeleton-shimmer rounded" />
            <span className="sr-only">{t("msg.loading")}</span>
          </div>
        ) : (
          <>
            {tab === "overview" && (
              <div role="tabpanel" id="tabpanel-overview" aria-labelledby="tab-overview">
                <OverviewView overview={overview} score={score} findings={findings} components={components} assets={assets} statuses={statuses} updateStatus={updateStatus} />
              </div>
            )}
            {tab === "cbom" && (
              <div role="tabpanel" id="tabpanel-cbom" aria-labelledby="tab-cbom">
                <CbomViewer assets={assets} components={components} findings={findings} overview={overview} statuses={statuses} updateStatus={updateStatus} />
              </div>
            )}
            {tab === "compliance" && (
              <div role="tabpanel" id="tabpanel-compliance" aria-labelledby="tab-compliance">
                <ComplianceMatrix assets={assets} findings={findings} statuses={statuses} />
              </div>
            )}
            {tab === "policy" && (
              <div role="tabpanel" id="tabpanel-policy" aria-labelledby="tab-policy">
                <PolicyStudio activePolicy={activePolicy} policies={policies} switchPolicy={switchPolicy} />
              </div>
            )}
            {tab === "migrations" && (
              <div role="tabpanel" id="tabpanel-migrations" aria-labelledby="tab-migrations">
                <MigrationConsole migrations={migrations} assets={assets} enqueueMigration={enqueueMigration} />
              </div>
            )}
            {tab === "fleet" && (
              <div role="tabpanel" id="tabpanel-fleet" aria-labelledby="tab-fleet">
                <FleetManagement
                  assets={assets}
                  fetchFleetConfig={fetchFleetConfig}
                  saveFleetConfig={saveFleetConfig}
                  fetchAuditLogs={fetchAuditLogs}
                  fetchAgentDiagnostics={fetchAgentDiagnostics}
                />
              </div>
            )}
          </>
        )}
      </section>
    </main>
  );
}

export default App;
