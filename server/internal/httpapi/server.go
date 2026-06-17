package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/janus-cbom/janus/server/internal/certmanager"
	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/hsm"
	"github.com/janus-cbom/janus/server/internal/llm"
	"github.com/janus-cbom/janus/server/internal/metrics"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/sandbox"
	"github.com/janus-cbom/janus/server/internal/store"
	"github.com/janus-cbom/janus/server/internal/version"
	"github.com/janus-cbom/janus/server/internal/ws"
)

type API struct {
	store      store.Store
	orch       *orchestrator.Orchestrator
	engine     *policy.Engine
	wsHub      *ws.Hub
	simulator  *sandbox.Simulator
	confidence *policy.ConfidenceAnalyzer
	hsmClient  hsm.HSM
	cfg        config.Config
	llmSvc     *llm.Service // set lazily in llmService()
	jwtSecret  []byte
	creds      []config.Credential
	revoked    *revocationCache // session invalidation on password change (AUTH-002)
	wsTickets  *wsTicketStore   // short-lived single-use tickets for /api/ws (SEC: keeps the session JWT out of URLs)
	// shutdownCtx is cancelled when draining begins so detached background work
	// (e.g. LLM batch jobs) stops promptly on SIGTERM instead of running on an
	// uncancellable context.Background() (OPS-001 / REM-2).
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	// draining is set during graceful shutdown (OPS-001): the health endpoint
	// then reports "draining" and new non-health requests receive 503 so load
	// balancers stop routing traffic while in-flight requests finish.
	draining atomic.Bool
}

// BeginDraining flips the API into draining mode (OPS-001). After this call the
// health endpoint reports "draining" and new requests (other than /api/health)
// receive 503 Service Unavailable.
func (a *API) BeginDraining() {
	a.draining.Store(true)
	if a.shutdownCancel != nil {
		a.shutdownCancel()
	}
}

// New builds the HTTP API handler and returns it alongside the *API so the
// caller can drive graceful-shutdown draining via api.BeginDraining() (OPS-001).
func New(store store.Store, orch *orchestrator.Orchestrator, engine *policy.Engine, jwtSecret []byte, disableAuth bool, wsHub *ws.Hub, cfg config.Config) (http.Handler, *API) {
	api := &API{
		store:      store,
		orch:       orch,
		engine:     engine,
		wsHub:      wsHub,
		simulator:  sandbox.NewSimulator(store, orch, engine),
		confidence: policy.NewConfidenceAnalyzer(store),
		cfg:        cfg,
		jwtSecret:  jwtSecret,
		creds:      cfg.Credentials,
		revoked:    newRevocationCache(),
		wsTickets:  newWSTicketStore(),
	}
	api.shutdownCtx, api.shutdownCancel = context.WithCancel(context.Background())
	// Seed the session-revocation cache from persisted password changes so a restart
	// still rejects tokens minted before the last change (AUTH-002). Best-effort.
	if seed, err := store.ListCredentialOverrides(context.Background()); err == nil {
		api.revoked.seedFromTimes(seed)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", api.health)
	// Throttle the credential endpoints per client IP to blunt brute force (HTTP-01).
	mux.Handle("/api/auth/login", RateLimit(authRateLimitPerMinute, LoginHandler(jwtSecret, cfg.DisableAuth, cfg.Credentials, store)))
	// Authenticated user changes their own password (AUTH-002).
	mux.Handle("/api/auth/change-password", RateLimit(authRateLimitPerMinute, http.HandlerFunc(api.changePassword)))
	mux.HandleFunc("/api/overview", api.overview)
	mux.HandleFunc("/api/assets", api.assets)
	mux.HandleFunc("/api/components", api.components)
	mux.HandleFunc("/api/findings", api.findings)
	// Exact path wins over the /api/findings/ subtree below (UX-002 bulk status update).
	mux.Handle("/api/findings/bulk-update", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.bulkUpdateFindings)))
	mux.HandleFunc("/api/findings/", api.findingsDispatch) // PUT /api/findings/{id}/status | GET /api/findings/{id}/timeline
	mux.HandleFunc("/api/hosts/", api.hostFindings)        // GET /api/hosts/{uuid}/findings
	mux.HandleFunc("/api/migrations", api.migrations)
	mux.HandleFunc("/api/report.html", api.reportHTML)
	mux.HandleFunc("/api/agents/", api.agentRoutes)                 // per-agent detail/scans/connections/config/commands (UX-002)
	mux.HandleFunc("/api/reports/", api.reportFindings)             // GET /api/reports/{scan_id}/findings (UX-003)
	mux.HandleFunc("/api/scan-config/schema", api.scanConfigSchema) // GET scan-parameter schema (UX-004)
	// CSR generation is operator/admin-only (AUTH-003): certificate issuance must stay under operator control.
	mux.Handle("/api/certificates/csr", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.createCSR)))

	// Require operator or admin role to enqueue migrations
	mux.Handle("/api/migrations/enqueue", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.enqueueMigration)))

	mux.HandleFunc("/api/export/cyclonedx", api.exportCycloneDX)
	mux.HandleFunc("/api/export/csv", api.exportCSV)
	mux.HandleFunc("/api/export/sarif", api.exportSARIF)
	mux.HandleFunc("/api/policies", api.policies)
	mux.HandleFunc("/api/policies/active", api.activePolicy)
	mux.HandleFunc("/api/policies/create", api.createPolicy)
	// UX-006 policy update/delete/export/import. Exact paths above win over this
	// subtree; DELETE additionally requires admin (checked in the handler).
	mux.Handle("/api/policies/import", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.importPolicy)))
	mux.Handle("/api/policies/", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.policyByVersion)))
	// Versioned compliance control pack (WP-017)
	mux.HandleFunc("/api/policy/rules", api.complianceRules)
	mux.HandleFunc("/api/policy/rules/", api.complianceRuleByID)
	mux.HandleFunc("/api/agent/heartbeat", api.agentHeartbeat)
	mux.HandleFunc("/api/fleet/config", api.fleetConfig)
	mux.HandleFunc("/api/fleet/profiles", api.fleetProfiles)
	mux.HandleFunc("/api/fleet/profiles/mapping", api.fleetProfileMapping)
	mux.HandleFunc("/api/audit-logs", api.auditLogs)
	// Tamper-evident audit-log verification is admin-only (FEAT-AUDIT-TAMPER).
	mux.Handle("/api/audit-logs/verify", RequireRole([]string{"admin"})(http.HandlerFunc(api.auditVerify)))
	mux.HandleFunc("/api/agent/diagnostics", api.agentDiagnostics)
	mux.HandleFunc("/api/webhooks", api.webhooks)
	mux.HandleFunc("/api/retention", api.retention)
	mux.HandleFunc("/api/export/siem", api.exportSIEM)
	mux.HandleFunc("/api/llm/proxy", api.llmProxy)
	mux.Handle("/api/llm/test-connection", RequireRole([]string{"admin"})(http.HandlerFunc(api.llmTestConnection)))
	// LLM analysis pipeline (LLM-08/09/10/11/16)
	mux.Handle("/api/llm/analyze", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.llmAnalyze)))
	// Admin-initiated batch analysis (LLM-022): select N findings or a filter, one request.
	mux.Handle("/api/llm/analyze/batch", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.llmAnalyzeBatch)))
	mux.HandleFunc("/api/llm/batches/", api.llmBatchStatus)
	mux.HandleFunc("/api/llm/jobs", api.llmJobs)
	mux.HandleFunc("/api/llm/jobs/", api.llmJobs)
	mux.HandleFunc("/api/llm/verdicts/", api.llmVerdict)
	mux.HandleFunc("/api/llm/suggestions/", api.llmSuggestion) // remediation suggestions (LLM-011/013)
	mux.HandleFunc("/api/llm/provenance/", api.llmProvenance)
	mux.HandleFunc("/api/llm/status", api.llmStatus)
	mux.HandleFunc("/api/llm/usage", api.llmUsage) // token/cost/latency rollup (LLM-023)
	// Autonomous remediation (LLM-017): wire the governor (env-configured, OFF by default)
	// + the command enqueuer onto the LLM service. No-op unless JANUS_LLM_AUTOREMEDIATE_ENABLED.
	api.llmService().EnableAutonomousRemediation(llm.LoadGovernorFromEnv(), api.autoApplyRemediation)
	// Crypto-agility scorecard (AGILE-01/WP-023)
	mux.HandleFunc("/api/agility/scorecard", api.agilityScorecard)
	// Agility dry-run exercise (WP-023)
	mux.Handle("/api/agility/exercise", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.agilityExercise)))
	// Release readiness check (WP-025)
	mux.Handle("/api/admin/release-check", RequireRole([]string{"admin"})(http.HandlerFunc(api.releaseCheck)))
	// Migration wave planning (WAVE-01/WP-022)
	mux.Handle("/api/waves", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.wavePlans)))
	mux.Handle("/api/waves/", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.wavePlanByID)))
	// Compliance exception workflow (WP-017) — operator/admin only.
	mux.Handle("/api/compliance/exceptions", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.complianceExceptions)))
	mux.Handle("/api/compliance/exceptions/", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.complianceExceptionByID)))
	// Tenant administration (WP-020) — admin only.
	mux.Handle("/api/tenants", RequireRole([]string{"admin"})(http.HandlerFunc(api.tenants)))
	// /api/ws is authorized by a short-lived single-use ticket (issued below),
	// not the session JWT in the URL (SEC). serveWS validates ?ticket= then
	// hands off to the hub. The ticket endpoint is JWT-authed via the header.
	mux.HandleFunc("/api/ws/ticket", api.wsTicketIssue)
	mux.HandleFunc("/api/ws", api.serveWS)
	mux.HandleFunc("/api/report/compliance", api.complianceReport)
	mux.HandleFunc("/api/lab/simulate", api.pqcLabSimulate)
	mux.HandleFunc("/api/sla/metrics", api.slaMetrics)
	mux.HandleFunc("/api/agent/upgrade", api.agentUpgradeInfo)
	mux.HandleFunc("/api/export/audit", api.exportAuditLog)
	// F1 — PQC Migration Simulator
	mux.HandleFunc("/api/sandbox/simulate", api.sandboxSimulate)
	// F7 — Statistical Confidence Analysis
	mux.HandleFunc("/api/confidence/report", api.confidenceReport)
	// HSM signing/verification are privileged operations on platform keys — gate
	// them to operator/admin like other state-changing endpoints (AUTH-004). They
	// previously had no role guard, so any authenticated user (incl. viewer) could
	// drive the HSM.
	mux.Handle("/api/hsm/keys", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.hsmListKeys)))
	mux.Handle("/api/hsm/keys/generate", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.hsmGenerateKey)))
	mux.Handle("/api/hsm/sign", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.hsmSign)))
	mux.Handle("/api/hsm/verify", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.hsmVerify)))
	mux.HandleFunc("/metrics", api.metrics)

	// JWTs verified with jwtSecret; agent tokens with the command-signing key (AUTH-03),
	// or per-agent HMAC keys when AgentAuthMode=per-agent (WP-029 P1).
	var agentVerify func(*http.Request) bool
	if cfg.AgentAuthMode == "per-agent" {
		agentVerify = api.verifyAgentRequest
	}
	authWrapper := AuthMiddleware(jwtSecret, cfg.CommandSigningKey, disableAuth, api.revoked.before, agentVerify)
	// inner is the application stack; the auth-credential endpoints keep their own stricter
	// 20/min limiter (wired on the mux above).
	var inner http.Handler = drainGuard(api, authWrapper(bodyLimit(mux)))
	// Global per-IP rate limit across the whole REST API (OPS-002). Generous default so
	// dashboard polling / WS-fallback is unaffected; JANUS_API_RATE_LIMIT_PER_MIN=0 disables.
	if cfg.APIRateLimitPerMin > 0 {
		inner = RateLimit(cfg.APIRateLimitPerMin, inner)
	}
	// correlationMiddleware is outermost so every layer (logger, handlers, writeError)
	// shares one request ID (OPS-004). The limiter sits inside the logger so 429s are still
	// logged with a correlation ID.
	return correlationMiddleware(requestLogger(cors(cfg.CORSOrigin, inner))), api
}

// drainGuard rejects new requests with 503 while the server is draining during
// graceful shutdown (OPS-001). The health endpoint is exempt so readiness
// probes can observe the "draining" status and orchestrators can react.
func drainGuard(api *API, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if api.draining.Load() && r.URL.Path != "/api/health" {
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "draining",
				"error":  "server is shutting down; retry after reconnect",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// spaHandler serves a React SPA from root. Static assets in root are served
// directly; all other GET requests receive index.html for client-side routing.
func spaHandler(root string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		fi, err := os.Stat(root)
		if err != nil || !fi.IsDir() {
			http.NotFound(w, r)
			return
		}
		candidate := root + r.URL.Path
		if _, err := os.Stat(candidate); err == nil {
			http.ServeFile(w, r, candidate)
			return
		}
		http.ServeFile(w, r, root+"/index.html")
	})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	// During graceful shutdown report "draining" with 503 so orchestrators
	// (Kubernetes readiness probes, load balancers) stop sending new traffic
	// while in-flight requests finish (OPS-001).
	if a.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining", "api_version": version.APIVersion})
		return
	}
	if err := a.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "db": "connected", "api_version": version.APIVersion})
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.Overview(r.Context(), TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) assets(w http.ResponseWriter, r *http.Request) {
	// Row-level tenant scoping (WP-020): a login only sees assets in its own tenant.
	// The default tenant (and auth-disabled dev mode) sees all pre-tenancy data.
	params := store.FleetQueryParams{
		QueryParams: store.QueryParams{Limit: 5000, Sort: "last_seen", Order: "desc"},
		TenantID:    TenantFromContext(r.Context()),
	}
	out, _, err := a.store.AssetsPaginated(r.Context(), params)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) components(w http.ResponseWriter, r *http.Request) {
	// Always tenant-scoped (WP-020): components are read through ComponentsPaginated so the
	// caller's tenant filter applies on both the paginated and default paths.
	paginated := r.URL.Query().Has("limit") || r.URL.Query().Has("offset") || r.URL.Query().Has("search")
	params := store.QueryParams{
		Limit:    intParam(r, "limit", 100),
		Offset:   intParam(r, "offset", 0),
		Sort:     r.URL.Query().Get("sort"),
		Order:    r.URL.Query().Get("order"),
		Search:   r.URL.Query().Get("search"),
		TenantID: TenantFromContext(r.Context()),
	}
	if !paginated {
		params.Limit = 500
	}
	comps, total, err := a.store.ComponentsPaginated(r.Context(), params)
	if err != nil {
		writeError(w, err)
		return
	}
	if paginated {
		w.Header().Set("X-Total-Count", fmt.Sprintf("%d", total))
	}
	writeJSON(w, http.StatusOK, comps)
}

func (a *API) findings(w http.ResponseWriter, r *http.Request) {
	// Always tenant-scoped (WP-020): findings are read through FindingsPaginated so the
	// caller's tenant filter applies on both the paginated and default paths.
	paginated := r.URL.Query().Has("limit") || r.URL.Query().Has("offset") || r.URL.Query().Has("search")
	params := store.QueryParams{
		Limit:    intParam(r, "limit", 50),
		Offset:   intParam(r, "offset", 0),
		Sort:     r.URL.Query().Get("sort"),
		Order:    r.URL.Query().Get("order"),
		Search:   r.URL.Query().Get("search"),
		TenantID: TenantFromContext(r.Context()),
	}
	if !paginated {
		params.Limit = 200
	}
	findings, total, err := a.store.FindingsPaginated(r.Context(), params)
	if err != nil {
		writeError(w, err)
		return
	}
	if paginated {
		w.Header().Set("X-Total-Count", fmt.Sprintf("%d", total))
	}
	writeJSON(w, http.StatusOK, findings)
}

func (a *API) findingStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Path: /api/findings/{id}/status
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/findings/"), "/")
	if len(parts) < 2 || parts[1] != "status" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	findingID := parts[0]
	var body struct {
		Status    string `json:"status"`
		UpdatedBy string `json:"updated_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, err)
		return
	}
	if err := a.store.UpdateFindingStatus(r.Context(), findingID, body.Status, body.UpdatedBy); err != nil {
		writeError(w, err)
		return
	}
	a.wsHub.BroadcastTenant(TenantFromContext(r.Context()), "finding_status", map[string]string{
		"finding_id": findingID,
		"status":     body.Status,
		"updated_by": body.UpdatedBy,
	})
	writeJSON(w, http.StatusOK, map[string]string{"finding_id": findingID, "status": body.Status})
}

func (a *API) migrations(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.Migrations(r.Context(), TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) reportHTML(w http.ResponseWriter, r *http.Request) {
	overview, err := a.store.Overview(r.Context(), TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	assets, err := a.store.Assets(r.Context(), TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	findings, err := a.store.Findings(r.Context(), 500, TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	components, err := a.store.Components(r.Context(), 500, TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	migrations, err := a.store.Migrations(r.Context(), TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}

	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Janus CryptoBOM Report</title>")
	b.WriteString("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#17211c;background:#f7f8f5}table{border-collapse:collapse;width:100%;background:#fff;margin-bottom:24px}th,td{border:1px solid #dfe5dc;padding:8px;text-align:left;vertical-align:top}th{background:#edf1ea}.metric{display:inline-block;background:#fff;border:1px solid #dfe5dc;border-radius:6px;padding:12px;margin:0 12px 12px 0}.sev5{color:#b42318;font-weight:700}.sev4{color:#b54708;font-weight:700}.muted{color:#697469}</style>")
	b.WriteString("</head><body><h1>Janus CryptoBOM Enterprise Report</h1>")
	b.WriteString("<p class=\"muted\">Generated from controller evidence, CBOM telemetry, and migration transaction state.</p>")
	b.WriteString(metric("Assets", overview.Assets))
	b.WriteString(metric("Components", overview.Components))
	b.WriteString(metric("Findings", overview.Findings))
	b.WriteString(metric("Critical Findings", overview.CriticalFindings))
	b.WriteString(metric("Open Migrations", overview.OpenMigrations))

	b.WriteString("<h2>Assets</h2><table><thead><tr><th>Host</th><th>Platform</th><th>Mode</th><th>Last Seen</th></tr></thead><tbody>")
	for _, asset := range assets {
		b.WriteString(fmt.Sprintf("<tr><td>%s<br><span class=\"muted\">%s</span></td><td>%s %s / %s</td><td>%d</td><td>%s</td></tr>",
			esc(asset.Hostname), esc(asset.HostUUID), esc(asset.OSName), esc(asset.OSVersion), esc(asset.Arch), asset.ExecutionMode, esc(asset.LastSeen.String())))
	}
	b.WriteString("</tbody></table>")

	b.WriteString("<h2>CBOM Components</h2><table><thead><tr><th>Component</th><th>Type</th><th>Path</th><th>Algorithms</th></tr></thead><tbody>")
	for _, component := range components {
		b.WriteString(fmt.Sprintf("<tr><td>%s<br><span class=\"muted\">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>",
			esc(component.Name), esc(component.BomRef), esc(component.ComponentType), esc(component.FilePath), esc(strings.Join(component.Algorithms, ", "))))
	}
	b.WriteString("</tbody></table>")

	b.WriteString("<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Algorithm</th><th>Rule</th><th>Migration Profile</th></tr></thead><tbody>")
	for _, finding := range findings {
		b.WriteString(fmt.Sprintf("<tr><td class=\"sev%d\">%d</td><td>%s<br><span class=\"muted\">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			finding.Severity, finding.Severity, esc(finding.Title), esc(finding.Description), esc(finding.AssetRef), esc(finding.Algorithm), esc(finding.PolicyRuleID), esc(finding.MigrationProfile)))
	}
	b.WriteString("</tbody></table>")

	b.WriteString("<h2>Migration Transactions</h2><table><thead><tr><th>Command</th><th>Host</th><th>Service</th><th>Target</th><th>State</th><th>Error</th></tr></thead><tbody>")
	for _, migration := range migrations {
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s / %s</td><td>%d</td><td>%s</td></tr>",
			esc(migration.CommandID), esc(migration.HostUUID), esc(migration.TargetService), esc(migration.TargetKEM), esc(migration.TargetSignature), migration.State, esc(migration.LastError)))
	}
	b.WriteString("</tbody></table>")

	b.WriteString("<h2>Algorithm Density</h2><table><thead><tr><th>Algorithm</th><th>Count</th></tr></thead><tbody>")
	for algorithm, count := range overview.AlgorithmHistogram {
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", esc(algorithm), count))
	}
	b.WriteString("</tbody></table></body></html>")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

type csrRequest struct {
	CommonName          string   `json:"common_name"`
	DNSNames            []string `json:"dns_names"`
	Organization        []string `json:"organization"`
	TargetSignature     string   `json:"target_signature"`
	HybridCompatibility bool     `json:"hybrid_compatibility"`
}

func (a *API) createCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req csrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}
	if req.CommonName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "common_name is required"})
		return
	}
	bundle, err := certmanager.GenerateCSR(certmanager.CSRProfile{
		CommonName:          req.CommonName,
		DNSNames:            req.DNSNames,
		Organization:        req.Organization,
		TargetSignature:     req.TargetSignature,
		HybridCompatibility: req.HybridCompatibility,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	// AUTH-003: certificate issuance is operator-controlled — record the actor.
	username, _ := r.Context().Value(UserContextKey).(string)
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: username,
		Action:   "CSR_GENERATE",
		Details:  "common_name=" + req.CommonName + " target_signature=" + bundle.Profile.TargetSignature,
	})
	writeJSON(w, http.StatusCreated, map[string]string{
		"csr_pem":            string(bundle.CSRPEM),
		"private_key_sha256": certmanager.SHA256Hex(bundle.PrivatePEM),
		"profile":            bundle.Profile.TargetSignature,
		"custody":            "private key generated in controller process; persist using enterprise secret storage before production use",
	})
}

type enqueueRequest struct {
	HostUUID         string `json:"host_uuid"`
	TargetService    string `json:"target_service"`
	MigrationProfile string `json:"migration_profile"`
	ConfigPath       string `json:"config_path"`
	PatchUnifiedDiff string `json:"patch_unified_diff"`
	DryRun           bool   `json:"dry_run"`
}

func (a *API) enqueueMigration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req enqueueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}
	// Tenant isolation (WP-020): an operator may only enqueue migrations against hosts in
	// its own tenant. An unknown host falls through (the config-hash lookup 404s naturally).
	if tenant := TenantFromContext(r.Context()); tenant != "" {
		if owner, terr := a.store.AssetTenant(r.Context(), req.HostUUID); terr == nil && owner != "" && owner != tenant {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
	}
	hash, err := a.store.GetLatestConfigHash(r.Context(), req.HostUUID, req.ConfigPath)
	if err != nil {
		writeError(w, err)
		return
	}
	activeProfile := a.engine.GetActiveProfile()
	cmd := a.orch.BuildCommand(req.HostUUID, req.TargetService, req.MigrationProfile, req.ConfigPath, req.PatchUnifiedDiff, hash, req.DryRun, activeProfile.PreferredKEM, activeProfile.PreferredSignature)
	a.orch.Enqueue(cmd)
	if err := a.store.InsertMigrationCommand(r.Context(), cmd); err != nil {
		writeError(w, err)
		return
	}

	username, _ := r.Context().Value(UserContextKey).(string)
	if username == "" {
		username = "admin"
	}
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: username,
		Action:   "ENQUEUE_MIGRATION",
		Details:  fmt.Sprintf("Service: %s, Profile: %s, Config: %s, DryRun: %t, CommandId: %s", req.TargetService, req.MigrationProfile, req.ConfigPath, req.DryRun, cmd.CommandId),
	})

	a.wsHub.BroadcastTenant(TenantFromContext(r.Context()), "migration_enqueued", map[string]string{
		"command_id":        cmd.CommandId,
		"host_uuid":         cmd.HostUuid,
		"target_service":    cmd.TargetService,
		"migration_profile": cmd.MigrationProfile,
	})
	writeJSON(w, http.StatusAccepted, cmd)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError returns a generic 500 to the caller and logs the real error
// server-side (HTTP-03). Internal errors — SQL text, pgx errors, file paths, config
// values — must never reach an API client; operators get the detail in the logs.
func writeError(w http.ResponseWriter, err error) {
	cid := w.Header().Get(CorrelationHeader)
	slog.Error("internal API error", "error", err, "correlation_id", cid)
	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"error":          "internal server error",
		"correlation_id": cid,
	})
}

// HTTP request hardening (HTTP-01).
const (
	// maxRequestBodyBytes caps JSON request bodies. Bulk telemetry arrives over gRPC
	// (JANUS_GRPC_MAX_RECV_BYTES), so HTTP bodies are small control-plane payloads.
	maxRequestBodyBytes = 8 << 20 // 8 MiB
	// authRateLimitPerMinute throttles credential endpoints per client IP.
	authRateLimitPerMinute = 20
	// maskedSecret replaces a stored secret in GET responses so its presence is visible
	// without leaking the value (CRED-02). Echoed back on POST → keep the stored value.
	maskedSecret = "***configured***"
)

// bodyLimit caps request body size to bound memory on the HTTP control plane
// (HTTP-01). /api/ws is exempt — it is a GET upgrade that hijacks the connection.
func bodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.URL.Path != "/api/ws" {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response status (and preserves Flush for streaming
// endpoints) so requestLogger can record it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// requestLogger emits one structured log line per HTTP request (method, path,
// status, duration). It is the outermost layer so it observes the final status.
// /api/ws is bypassed (it hijacks the connection and is long-lived); health/metrics
// probes log at debug to avoid drowning the signal.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/ws" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Record request count + latency for /metrics (OPS-006). Path is normalized
		// to a route template to bound label cardinality.
		metrics.ObserveHTTP(r.Method, normalizePath(r.URL.Path), rec.status, time.Since(start).Seconds())

		level := slog.LevelInfo
		switch {
		case rec.status >= 500:
			level = slog.LevelError
		case rec.status >= 400:
			level = slog.LevelWarn
		case r.URL.Path == "/api/health" || r.URL.Path == "/metrics":
			level = slog.LevelDebug
		}
		slog.LogAttrs(r.Context(), level, "http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("correlation_id", correlationID(r.Context())),
		)
	})
}

func intParam(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n := 0
	fmt.Sscanf(v, "%d", &n)
	if n <= 0 {
		return def
	}
	return n
}

// ---------------------------------------------------------------------------
// Export handlers
// ---------------------------------------------------------------------------

// algCryptoProperties maps a CycloneDX algorithm name string to a cryptoProperties block
// following the CycloneDX 1.6 cryptography extension schema.
func algCryptoProperties(algName string) map[string]any {
	upper := strings.ToUpper(algName)
	props := map[string]any{"assetType": "algorithm"}
	ap := map[string]any{"implementationPlatform": "unknown"}
	switch {
	case strings.HasPrefix(upper, "ML-KEM") || strings.HasPrefix(upper, "MLKEM") ||
		strings.HasPrefix(upper, "KYBER") || strings.HasPrefix(upper, "X25519MLKEM"):
		ap["primitive"] = "kem"
		if strings.Contains(upper, "512") {
			ap["parameterSetIdentifier"] = "512"
			ap["nistQuantumSecurityLevel"] = 1
		} else if strings.Contains(upper, "768") || strings.Contains(upper, "X25519MLKEM768") {
			ap["parameterSetIdentifier"] = "768"
			ap["nistQuantumSecurityLevel"] = 3
		} else if strings.Contains(upper, "1024") {
			ap["parameterSetIdentifier"] = "1024"
			ap["nistQuantumSecurityLevel"] = 5
		}
	case strings.HasPrefix(upper, "ML-DSA") || strings.HasPrefix(upper, "MLDSA") || strings.HasPrefix(upper, "DILITHIUM"):
		ap["primitive"] = "signature"
		if strings.Contains(upper, "44") {
			ap["parameterSetIdentifier"] = "44"
			ap["nistQuantumSecurityLevel"] = 2
		} else if strings.Contains(upper, "65") {
			ap["parameterSetIdentifier"] = "65"
			ap["nistQuantumSecurityLevel"] = 3
		} else if strings.Contains(upper, "87") {
			ap["parameterSetIdentifier"] = "87"
			ap["nistQuantumSecurityLevel"] = 5
		}
	case strings.HasPrefix(upper, "SLH-DSA") || strings.HasPrefix(upper, "SLHDSA") || strings.HasPrefix(upper, "SPHINCS"):
		ap["primitive"] = "signature"
		ap["nistQuantumSecurityLevel"] = 1
	case strings.HasPrefix(upper, "RSA"):
		ap["primitive"] = "pke"
		ap["nistQuantumSecurityLevel"] = 0
		for _, bits := range []string{"4096", "3072", "2048", "1024", "512"} {
			if strings.Contains(upper, bits) {
				ap["parameterSetIdentifier"] = bits
				break
			}
		}
	case strings.HasPrefix(upper, "ECDSA") || strings.HasPrefix(upper, "ECDH"):
		ap["primitive"] = "signature"
		ap["nistQuantumSecurityLevel"] = 0
		for _, curve := range []string{"P-521", "P-384", "P-256", "SECP256K1"} {
			if strings.Contains(upper, strings.ReplaceAll(curve, "-", "")) || strings.Contains(upper, curve) {
				ap["parameterSetIdentifier"] = curve
				break
			}
		}
	case strings.HasPrefix(upper, "AES"):
		ap["primitive"] = "ae"
		ap["nistQuantumSecurityLevel"] = 0
		for _, size := range []string{"256", "192", "128"} {
			if strings.Contains(upper, size) {
				ap["parameterSetIdentifier"] = size
				break
			}
		}
		for _, mode := range []string{"GCM", "CBC", "CTR", "CCM", "CFB", "OFB"} {
			if strings.Contains(upper, mode) {
				ap["mode"] = strings.ToLower(mode)
				break
			}
		}
	case strings.HasPrefix(upper, "SHA"):
		ap["primitive"] = "hash"
		ap["nistQuantumSecurityLevel"] = 0
		for _, size := range []string{"3-512", "3-256", "512", "384", "256", "224"} {
			if strings.Contains(upper, size) {
				ap["parameterSetIdentifier"] = size
				break
			}
		}
	case strings.HasPrefix(upper, "CHACHA") || strings.HasPrefix(upper, "XCHACHA"):
		ap["primitive"] = "ae"
		ap["nistQuantumSecurityLevel"] = 0
	case strings.HasPrefix(upper, "ED25519") || strings.HasPrefix(upper, "ED448"):
		ap["primitive"] = "signature"
		ap["nistQuantumSecurityLevel"] = 0
	default:
		return nil
	}
	props["algorithmProperties"] = ap
	return props
}

func (a *API) exportCycloneDX(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Tenant-scoped (WP-020): the CBOM export must not leak another tenant's crypto inventory.
	components, err := a.store.Components(r.Context(), 2000, TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	type cdxCryptoComponent struct {
		BomRef           string         `json:"bom-ref"`
		Type             string         `json:"type"`
		Name             string         `json:"name"`
		Version          string         `json:"version,omitempty"`
		Evidence         map[string]any `json:"evidence,omitempty"`
		CryptoProperties map[string]any `json:"cryptoProperties,omitempty"`
	}
	cdxComps := make([]cdxCryptoComponent, 0, len(components))
	for _, c := range components {
		comp := cdxCryptoComponent{
			BomRef:  c.BomRef,
			Type:    c.ComponentType,
			Name:    c.Name,
			Version: c.Version,
		}
		if c.FilePath != "" {
			comp.Evidence = map[string]any{
				"occurrences": []map[string]any{{"location": c.FilePath}},
			}
		}
		// Add cryptoProperties for the first algorithm detected on this component.
		if len(c.Algorithms) > 0 {
			comp.CryptoProperties = algCryptoProperties(c.Algorithms[0])
		}
		cdxComps = append(cdxComps, comp)
	}
	cbom := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"version":      1,
		"serialNumber": "urn:uuid:" + uuid.New().String(),
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]any{{
				"vendor":  "Janus CryptoBOM",
				"name":    "janus-server",
				"version": version.Version,
			}},
		},
		"components": cdxComps,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="janus-cbom.cyclonedx.json"`)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(cbom)
}

func (a *API) exportCSV(w http.ResponseWriter, r *http.Request) {
	findings, err := a.store.Findings(r.Context(), 5000, TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="janus-findings.csv"`)
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "finding_id,host_uuid,severity,title,asset_ref,algorithm,policy_rule_id,migration_profile,status,created_at")
	for _, f := range findings {
		_, _ = fmt.Fprintf(w, "%s,%s,%d,%s,%s,%s,%s,%s,%s,%s\n",
			csvEsc(f.FindingID), csvEsc(f.HostUUID), f.Severity,
			csvEsc(f.Title), csvEsc(f.AssetRef), csvEsc(f.Algorithm),
			csvEsc(f.PolicyRuleID), csvEsc(f.MigrationProfile),
			csvEsc(f.Status), f.CreatedAt.UTC().Format(time.RFC3339))
	}
}

// sarifSeverity maps Janus severity (1-5) to SARIF level strings.
func sarifSeverity(sev int32) string {
	switch {
	case sev >= 5:
		return "error"
	case sev >= 3:
		return "warning"
	default:
		return "note"
	}
}

// parseSARIFLocation extracts a SARIF physicalLocation from an asset reference.
// Asset refs may be plain file paths ("src/main.go") or include line hints
// ("src/main.go:42" or "src/main.go:42:7"). Network observations use
// "hostname:port" which produces an artifactLocation with no region.
func parseSARIFLocation(assetRef string) map[string]any {
	uri := assetRef
	loc := map[string]any{}

	// Try to parse "path:line" or "path:line:col" for source file findings.
	// Only treat as line number if the suffix is purely numeric.
	if idx := strings.LastIndex(assetRef, ":"); idx > 0 {
		maybeNum := assetRef[idx+1:]
		lineVal := 0
		for _, ch := range maybeNum {
			if ch < '0' || ch > '9' {
				lineVal = -1
				break
			}
			lineVal = lineVal*10 + int(ch-'0')
		}
		if lineVal > 0 {
			uri = assetRef[:idx]
			loc["region"] = map[string]any{"startLine": lineVal}
		}
	}

	loc["artifactLocation"] = map[string]any{"uri": uri, "uriBaseId": "%SRCROOT%"}
	return map[string]any{"physicalLocation": loc}
}

func (a *API) exportSARIF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	findings, err := a.store.Findings(r.Context(), 5000, TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}

	// Build SARIF rules from the unique policy_rule_ids seen in findings.
	ruleSet := make(map[string]struct{})
	for _, f := range findings {
		if f.PolicyRuleID != "" {
			ruleSet[f.PolicyRuleID] = struct{}{}
		}
	}
	sarifRules := make([]map[string]any, 0, len(ruleSet))
	for ruleID := range ruleSet {
		sarifRules = append(sarifRules, map[string]any{
			"id":      ruleID,
			"helpUri": "https://github.com/janus-cbom/janus/blob/main/docs/GUIDE.md",
		})
	}

	type sarifResult struct {
		RuleID     string           `json:"ruleId"`
		Level      string           `json:"level"`
		Message    map[string]any   `json:"message"`
		Locations  []map[string]any `json:"locations"`
		Properties map[string]any   `json:"properties,omitempty"`
	}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		sr := sarifResult{
			RuleID:    f.PolicyRuleID,
			Level:     sarifSeverity(f.Severity),
			Message:   map[string]any{"text": f.Title + ": " + f.Description},
			Locations: []map[string]any{parseSARIFLocation(f.AssetRef)},
		}
		if f.Algorithm != "" || f.Confidence > 0 {
			sr.Properties = map[string]any{
				"algorithm":  f.Algorithm,
				"confidence": f.Confidence,
				"status":     f.Status,
			}
		}
		results = append(results, sr)
	}

	sarif := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "Janus CryptoBOM",
				"version":        version.Version,
				"informationUri": "https://github.com/janus-cbom/janus",
				"rules":          sarifRules,
			}},
			"results": results,
			"originalUriBaseIds": map[string]any{
				"%SRCROOT%": map[string]any{"uri": "./"},
			},
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="janus-findings.sarif"`)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(sarif)
}

func csvEsc(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func metric(label string, value int64) string {
	return fmt.Sprintf("<div class=\"metric\"><div class=\"muted\">%s</div><strong>%d</strong></div>", esc(label), value)
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func (a *API) policies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active":    a.engine.ProfileVersion(),
		"available": a.engine.AvailableProfiles(),
	})
}

func (a *API) activePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !requireWriteRole(w, r) {
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.engine.SetActiveProfile(req.Version); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.wsHub.Broadcast("policy_switched", map[string]string{
		"active": a.engine.ProfileVersion(),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "active": a.engine.ProfileVersion()})
}

// cors echoes Access-Control-Allow-Origin only for an explicit allowlist: the
// configured dashboard origin(s) (JANUS_CORS_ORIGIN, comma-separated) plus the
// standard localhost dev origins. It never reflects an arbitrary Origin header
// back — a wildcard/reflected ACAO lets any site script the API (SEC). For a
// disallowed or absent Origin it falls back to the first configured origin so
// the header is deterministic. Credentials are not enabled (auth is via bearer
// token, not cookies), so this is defense-in-depth rather than the sole gate.
func cors(allowedOrigins string, next http.Handler) http.Handler {
	// Always-trusted local dev origins, preserved so a shared dev checkout keeps
	// working regardless of JANUS_CORS_ORIGIN.
	allowed := map[string]bool{
		"http://localhost:5173": true,
		"http://127.0.0.1:5173": true,
		"http://localhost:8080": true,
	}
	defaultOrigin := "http://localhost:5173"
	for i, o := range strings.Split(allowedOrigins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			allowed[o] = true
			if i == 0 {
				defaultOrigin = o
			}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", defaultOrigin)
		}
		// Responses vary by request Origin, so caches must key on it.
		w.Header().Add("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "content-type, authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// gauge writes one unlabeled gauge series in Prometheus text format.
func gauge(w io.Writer, name, help string, val int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n\n", name, help, name, name, val)
}

// normalizePath collapses dynamic path segments to route templates so the
// per-path metric label set stays bounded (OPS-006).
func normalizePath(p string) string {
	for _, prefix := range []string{
		"/api/findings/", "/api/hosts/", "/api/agents/", "/api/reports/",
		"/api/llm/jobs/", "/api/llm/verdicts/", "/api/llm/suggestions/", "/api/llm/provenance/", "/api/llm/batches/",
		"/api/waves/", "/api/policy/rules/", "/api/fleet/profiles/", "/api/compliance/exceptions/",
	} {
		if strings.HasPrefix(p, prefix) && len(p) > len(prefix) {
			return prefix + "*"
		}
	}
	return p
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	// /metrics bypasses JWT auth (scrapers use static config), so when a metrics
	// token is configured we enforce it here with a constant-time compare (SEC).
	if a.cfg.MetricsToken != "" {
		presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(presented), []byte(a.cfg.MetricsToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	overview, err := a.store.Overview(r.Context(), TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	gauge(w, "janus_assets_total", "Total tracked assets", overview.Assets)
	gauge(w, "janus_components_total", "Total cataloged CBOM components", overview.Components)
	gauge(w, "janus_critical_findings_total", "Total critical severity findings", overview.CriticalFindings)
	gauge(w, "janus_high_findings_total", "Total high severity findings", overview.HighFindings)
	gauge(w, "janus_open_migrations_total", "Total pending or active migrations", overview.OpenMigrations)

	connected := overview.Assets - overview.StalledAgents
	if connected < 0 {
		connected = 0
	}
	gauge(w, "janus_agents_connected", "Agents seen within the stall window", connected)

	// Labeled findings inventory (OPS-006). Replaces the old unlabeled
	// janus_findings_total; the sum across labels equals the previous value.
	if counts, err := a.store.FindingSeverityStatusCounts(r.Context()); err == nil {
		fmt.Fprint(w, "# HELP janus_findings_total Findings by severity and status.\n# TYPE janus_findings_total gauge\n")
		for _, c := range counts {
			fmt.Fprintf(w, "janus_findings_total{severity=\"%d\",status=\"%s\"} %d\n", c.Severity, c.Status, c.Count)
		}
		fmt.Fprint(w, "\n")
	}

	// DB connection-pool utilization (OPS-006).
	st := a.store.PoolStat()
	fmt.Fprint(w, "# HELP janus_db_pool_connections DB connection pool by state.\n# TYPE janus_db_pool_connections gauge\n")
	fmt.Fprintf(w, "janus_db_pool_connections{state=\"acquired\"} %d\n", st.Acquired)
	fmt.Fprintf(w, "janus_db_pool_connections{state=\"idle\"} %d\n", st.Idle)
	fmt.Fprintf(w, "janus_db_pool_connections{state=\"total\"} %d\n", st.Total)
	fmt.Fprintf(w, "janus_db_pool_connections{state=\"max\"} %d\n\n", st.Max)

	// LLM usage by model (FEAT-METRICS / LLM-023): calls, tokens, and average latency
	// give operators Prometheus visibility into LLM spend without scraping the API.
	// Cost is derivable as tokens × your provider's $/1k rate.
	if usage, err := a.store.GetLLMUsage(r.Context()); err == nil && usage != nil {
		fmt.Fprint(w, "# HELP janus_llm_calls_total LLM analysis calls by model.\n# TYPE janus_llm_calls_total counter\n")
		for _, m := range usage.ByModel {
			fmt.Fprintf(w, "janus_llm_calls_total{model=\"%s\"} %d\n", m.Model, m.Calls)
		}
		fmt.Fprint(w, "\n# HELP janus_llm_tokens_total LLM tokens by model and direction.\n# TYPE janus_llm_tokens_total counter\n")
		for _, m := range usage.ByModel {
			fmt.Fprintf(w, "janus_llm_tokens_total{model=\"%s\",direction=\"input\"} %d\n", m.Model, m.TokensIn)
			fmt.Fprintf(w, "janus_llm_tokens_total{model=\"%s\",direction=\"output\"} %d\n", m.Model, m.TokensOut)
		}
		fmt.Fprint(w, "\n# HELP janus_llm_avg_latency_ms Average LLM call latency by model.\n# TYPE janus_llm_avg_latency_ms gauge\n")
		for _, m := range usage.ByModel {
			fmt.Fprintf(w, "janus_llm_avg_latency_ms{model=\"%s\"} %d\n", m.Model, m.AvgLatencyMS)
		}
		fmt.Fprint(w, "\n# HELP janus_llm_jobs_total LLM analysis jobs by status.\n# TYPE janus_llm_jobs_total gauge\n")
		for status, count := range usage.JobsByStatus {
			fmt.Fprintf(w, "janus_llm_jobs_total{status=\"%s\"} %d\n", status, count)
		}
		fmt.Fprint(w, "\n")
	}

	// In-process request/webhook counters + latency histogram (OPS-006).
	metrics.WriteProcessMetrics(w)
}

// MetricsHandler exposes the Prometheus endpoint so main can also serve it on a
// dedicated listener (JANUS_METRICS_ADDR, OPS-006).
func (a *API) MetricsHandler() http.Handler { return http.HandlerFunc(a.metrics) }

func (a *API) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body store.AgentHeartbeat
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, err)
		return
	}
	if body.HostUUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_uuid is required"})
		return
	}
	if err := a.store.UpdateAgentHeartbeat(r.Context(), &body); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "host_uuid": body.HostUUID})
}

func (a *API) fleetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		var fc *store.FleetConfig
		var err error
		hostUUID := r.URL.Query().Get("host_uuid")
		if hostUUID != "" {
			fc, err = a.store.GetConfigForAgent(r.Context(), hostUUID)
		} else {
			fc, err = a.store.GetFleetConfig(r.Context())
		}
		if err != nil {
			writeError(w, err)
			return
		}
		// Never return the stored LLM API key in cleartext (CRED-02) — expose only that
		// one is set. (This column is legacy; live calls use the env config, see LLM-021.)
		if fc != nil && fc.LLMApiKey != "" {
			fc.LLMApiKey = maskedSecret
		}
		writeJSON(w, http.StatusOK, fc)
		return
	}
	if r.Method == http.MethodPost {
		if !requireWriteRole(w, r) {
			return
		}
		var fc store.FleetConfig
		if err := json.NewDecoder(r.Body).Decode(&fc); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		// If the client round-tripped the masked placeholder, keep the existing key
		// rather than overwriting it with the mask (CRED-02).
		if fc.LLMApiKey == maskedSecret {
			if existing, err := a.store.GetFleetConfig(r.Context()); err == nil {
				fc.LLMApiKey = existing.LLMApiKey
			}
		}
		if err := a.store.UpdateFleetConfig(r.Context(), &fc); err != nil {
			writeError(w, err)
			return
		}

		username, _ := r.Context().Value(UserContextKey).(string)
		if username == "" {
			username = "admin"
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "UPDATE_FLEET_CONFIG",
			Details:  fmt.Sprintf("Excluded dirs: %s, Min key size: %d, Schedule: %s", fc.ExcludeDirs, fc.MinKeySize, fc.ScanSchedule),
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (a *API) auditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	logs, err := a.store.GetAuditLogs(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// auditVerify (GET /api/audit-logs/verify, admin) re-walks the audit-log hash chain
// and reports whether it is intact — surfacing any tampering (FEAT-AUDIT-TAMPER).
func (a *API) auditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	res, err := a.store.VerifyAuditChain(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *API) agentDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		hostUUID := r.URL.Query().Get("host_uuid")
		if hostUUID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_uuid is required"})
			return
		}
		logs, err := a.store.GetAgentDiagnostics(r.Context(), hostUUID)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"host_uuid": hostUUID, "logs": logs})
		return
	}
	if r.Method == http.MethodPost {
		var body struct {
			HostUUID string `json:"host_uuid"`
			Logs     string `json:"logs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.HostUUID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_uuid is required"})
			return
		}
		if err := a.store.UpdateAgentDiagnostics(r.Context(), body.HostUUID, body.Logs); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// sanitizePolicyFilename strips path separators and invalid characters from policy version names.
func sanitizePolicyFilename(version string) string {
	// Allow only alphanumeric, dots, dashes, underscores. Replace others with underscore.
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, version)
}

func (a *API) createPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !requireWriteRole(w, r) {
		return
	}
	var req struct {
		Version                string  `json:"version"`
		MinimumRSAKeyBits      uint32  `json:"minimum_rsa_key_bits"`
		MinimumDHSafePrimeBits uint32  `json:"minimum_dh_safe_prime_bits"`
		RequireTLS13           bool    `json:"require_tls_13"`
		RequireHybridPQTLS13   bool    `json:"require_hybrid_pq_tls_13"`
		PreferredKEM           string  `json:"preferred_kem"`
		PreferredSignature     string  `json:"preferred_signature"`
		MinimumConfidence      float64 `json:"minimum_confidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "version is required"})
		return
	}
	// Validate version does not contain path traversal characters
	safeVersion := sanitizePolicyFilename(strings.ToLower(req.Version))
	if safeVersion != strings.ToLower(req.Version) || strings.Contains(req.Version, "..") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "version contains invalid characters"})
		return
	}

	p := policy.Profile{
		Version:                req.Version,
		MinimumRSAKeyBits:      req.MinimumRSAKeyBits,
		MinimumDHSafePrimeBits: req.MinimumDHSafePrimeBits,
		RequireTLS13:           req.RequireTLS13,
		RequireHybridPQTLS13:   req.RequireHybridPQTLS13,
		PreferredKEM:           req.PreferredKEM,
		PreferredSignature:     req.PreferredSignature,
		MinimumConfidence:      req.MinimumConfidence,
	}

	a.engine.AddProfile(p)

	filename := fmt.Sprintf("policies/%s.yaml", safeVersion)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("version: \"%s\"\n", p.Version))
	sb.WriteString(fmt.Sprintf("minimum_rsa_key_bits: %d\n", p.MinimumRSAKeyBits))
	sb.WriteString(fmt.Sprintf("minimum_dh_safe_prime_bits: %d\n", p.MinimumDHSafePrimeBits))
	sb.WriteString(fmt.Sprintf("require_tls_13: %t\n", p.RequireTLS13))
	sb.WriteString(fmt.Sprintf("require_hybrid_pq_tls_13: %t\n", p.RequireHybridPQTLS13))
	sb.WriteString(fmt.Sprintf("preferred_kem: \"%s\"\n", p.PreferredKEM))
	sb.WriteString(fmt.Sprintf("preferred_signature: \"%s\"\n", p.PreferredSignature))
	sb.WriteString(fmt.Sprintf("minimum_confidence: %.2f\n", p.MinimumConfidence))

	_ = os.MkdirAll("policies", 0700)
	if err := os.WriteFile(filename, []byte(sb.String()), 0600); err != nil {
		writeError(w, err)
		return
	}

	username, _ := r.Context().Value(UserContextKey).(string)
	if username == "" {
		username = "admin"
	}
	_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
		Username: username,
		Action:   "CREATE_POLICY_PROFILE",
		Details:  fmt.Sprintf("Created policy version %s", p.Version),
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "profile": p})
}

func (a *API) webhooks(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := a.store.GetWebhooks(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		if list == nil {
			list = []store.Webhook{} // return [] not null so clients can map/.length safely
		}
		writeJSON(w, http.StatusOK, list)
		return
	}
	if r.Method == http.MethodPost {
		if !requireWriteRole(w, r) {
			return
		}
		var wh store.Webhook
		if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if wh.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
			return
		}
		// Reject SSRF-prone destinations before persisting (HTTP-02).
		if err := validateWebhookURL(wh.URL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		wh.Active = true
		if err := a.store.InsertWebhook(r.Context(), &wh); err != nil {
			writeError(w, err)
			return
		}

		username, _ := r.Context().Value(UserContextKey).(string)
		if username == "" {
			username = "admin"
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "ADD_WEBHOOK",
			Details:  fmt.Sprintf("Added webhook URL: %s", wh.URL),
		})

		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
		return
	}
	if r.Method == http.MethodDelete {
		if !requireWriteRole(w, r) {
			return
		}
		webhookID := r.URL.Query().Get("id")
		if webhookID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
			return
		}
		if err := a.store.DeleteWebhook(r.Context(), webhookID); err != nil {
			writeError(w, err)
			return
		}

		username, _ := r.Context().Value(UserContextKey).(string)
		if username == "" {
			username = "admin"
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "DELETE_WEBHOOK",
			Details:  fmt.Sprintf("Deleted webhook ID: %s", webhookID),
		})

		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (a *API) retention(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rp, err := a.store.GetRetentionPolicy(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rp)
		return
	}
	if r.Method == http.MethodPost {
		if !requireWriteRole(w, r) {
			return
		}
		var req struct {
			RetentionDays int  `json:"retention_days"`
			AutoPurge     bool `json:"auto_purge"`
			TriggerPurge  bool `json:"trigger_purge"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}

		rp := store.RetentionPolicy{
			RetentionDays: req.RetentionDays,
			AutoPurge:     req.AutoPurge,
		}
		if err := a.store.UpdateRetentionPolicy(r.Context(), &rp); err != nil {
			writeError(w, err)
			return
		}

		var purged int64
		if req.TriggerPurge && req.RetentionDays > 0 {
			var err error
			purged, err = a.store.PurgeOldTelemetry(r.Context(), req.RetentionDays)
			if err != nil {
				writeError(w, err)
				return
			}
		}

		username, _ := r.Context().Value(UserContextKey).(string)
		if username == "" {
			username = "admin"
		}
		_ = a.store.InsertAuditLog(r.Context(), &store.AuditLog{
			Username: username,
			Action:   "UPDATE_RETENTION_POLICY",
			Details:  fmt.Sprintf("Updated retention to %d days. Triggered purge: %t (purged=%d)", req.RetentionDays, req.TriggerPurge, purged),
		})

		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "purged_records": purged})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (a *API) exportSIEM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	findings, err := a.store.Findings(r.Context(), 1000, TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-json-stream")
	encoder := json.NewEncoder(w)
	for _, f := range findings {
		payload := map[string]interface{}{
			"timestamp": time.Now().Format(time.RFC3339),
			"source":    "janus-siem-exporter",
			"event":     "crypto-compliance-finding",
			"severity":  f.Severity,
			"finding": map[string]interface{}{
				"finding_id":  f.FindingID,
				"asset_ref":   f.AssetRef,
				"rule_id":     f.PolicyRuleID,
				"algorithm":   f.Algorithm,
				"status":      f.Status,
				"description": f.Description,
			},
		}
		_ = encoder.Encode(payload)
	}
}

func (a *API) llmProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if a.cfg.LLM.APIKey() == "" {
		http.Error(w, `{"error":{"message":"LLM provider not configured. Set JANUS_LLM_API_KEY_FILE or JANUS_LLM_API_KEY_ENV on the server."}}`, http.StatusServiceUnavailable)
		return
	}

	// Forward request to the validated LLM provider base URL (SSRF-safe: set at startup via env, not from DB)
	targetURL := a.cfg.LLM.BaseURL + "/chat/completions"
	req, err := http.NewRequest(http.MethodPost, targetURL, r.Body)
	if err != nil {
		writeError(w, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.cfg.LLM.APIKey())

	timeout := time.Duration(a.cfg.LLM.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		writeError(w, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func (a *API) llmTestConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type testResult struct {
		OK                        bool   `json:"ok"`
		BaseURL                   string `json:"base_url,omitempty"`
		ModelAnalysis             string `json:"model_analysis,omitempty"`
		ModelRemediation          string `json:"model_remediation,omitempty"`
		ModelAnalysisAvailable    *bool  `json:"model_analysis_available,omitempty"`
		ModelRemediationAvailable *bool  `json:"model_remediation_available,omitempty"`
		Warning                   string `json:"warning,omitempty"`
		Error                     string `json:"error,omitempty"`
	}

	if a.cfg.LLM.APIKey() == "" {
		writeJSON(w, http.StatusOK, testResult{OK: false, Error: "LLM API key not configured"})
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.cfg.LLM.BaseURL+"/models", nil)
	if err != nil {
		writeJSON(w, http.StatusOK, testResult{OK: false, Error: err.Error()})
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.LLM.APIKey())

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusOK, testResult{OK: false, Error: err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		res := testResult{
			OK:               true,
			BaseURL:          a.cfg.LLM.BaseURL,
			ModelAnalysis:    a.cfg.LLM.ModelAnalysis,
			ModelRemediation: a.cfg.LLM.ModelRemediation,
		}
		// Model-compatibility check (LLM-004): confirm the configured models exist in
		// the provider's catalog. Advisory only — some OpenAI-compatible gateways omit
		// /models entries, so a miss is a warning, not a failure.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var catalog struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &catalog); err == nil && len(catalog.Data) > 0 {
			have := make(map[string]bool, len(catalog.Data))
			for _, m := range catalog.Data {
				have[m.ID] = true
			}
			aOK, rOK := have[a.cfg.LLM.ModelAnalysis], have[a.cfg.LLM.ModelRemediation]
			res.ModelAnalysisAvailable, res.ModelRemediationAvailable = &aOK, &rOK
			var missing []string
			if !aOK {
				missing = append(missing, "analysis model "+a.cfg.LLM.ModelAnalysis)
			}
			if !rOK && a.cfg.LLM.ModelRemediation != "" {
				missing = append(missing, "remediation model "+a.cfg.LLM.ModelRemediation)
			}
			if len(missing) > 0 {
				res.Warning = "provider catalog does not list: " + strings.Join(missing, ", ")
			}
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	writeJSON(w, http.StatusOK, testResult{
		OK:    false,
		Error: fmt.Sprintf("provider returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),
	})
}

func (a *API) fleetProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := a.store.GetConfigProfiles(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		// Do not leak stored LLM keys (CRED-02) — show presence only.
		for i := range list {
			if list[i].LLMApiKey != "" {
				list[i].LLMApiKey = maskedSecret
			}
		}
		writeJSON(w, http.StatusOK, list)
		return
	}
	if r.Method == http.MethodPost {
		if !requireWriteRole(w, r) {
			return
		}
		var cp store.ConfigProfile
		if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		// Never persist the masked placeholder as a real key (CRED-02).
		if cp.LLMApiKey == maskedSecret {
			cp.LLMApiKey = ""
		}
		if cp.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "profile name is required"})
			return
		}
		if err := a.store.CreateConfigProfile(r.Context(), &cp); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "profile_id": cp.ProfileID})
		return
	}
	if r.Method == http.MethodDelete {
		if !requireWriteRole(w, r) {
			return
		}
		profileID := r.URL.Query().Get("id")
		if profileID == "" {
			profileID = r.URL.Query().Get("profile_id")
		}
		if profileID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
			return
		}
		if err := a.store.DeleteConfigProfile(r.Context(), profileID); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (a *API) fleetProfileMapping(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := a.store.GetAgentProfileMappings(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}
	if r.Method == http.MethodPost {
		if !requireWriteRole(w, r) {
			return
		}
		var body struct {
			HostUUID  string `json:"host_uuid"`
			ProfileID string `json:"profile_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.HostUUID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_uuid is required"})
			return
		}
		if err := a.store.MapAgentToProfile(r.Context(), body.HostUUID, body.ProfileID); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "mapped", "host_uuid": body.HostUUID, "profile_id": body.ProfileID})
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// SetHSM configures the HSM client for the API.
func (a *API) SetHSM(client hsm.HSM) {
	a.hsmClient = client
}

// ---------------------------------------------------------------------------
// F1 — PQC Migration Simulator (Sandbox Mode)
// ---------------------------------------------------------------------------

func (a *API) sandboxSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		HostUUID      string `json:"host_uuid"`
		TargetService string `json:"target_service"`
		Algorithm     string `json:"algorithm"`
		ConfigPath    string `json:"config_path"`
		DryRun        bool   `json:"dry_run"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.HostUUID == "" || req.Algorithm == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_uuid and algorithm are required"})
		return
	}
	result, err := a.simulator.SimulateMigration(req.HostUUID, req.TargetService, req.Algorithm, req.ConfigPath, req.DryRun)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// F7 — Statistical Confidence Analysis
// ---------------------------------------------------------------------------

func (a *API) confidenceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	findings, err := a.store.Findings(r.Context(), 5000, TenantFromContext(r.Context()))
	if err != nil {
		writeError(w, err)
		return
	}
	report := a.confidence.AnalyzeFindingConfidence(findings)
	writeJSON(w, http.StatusOK, report)
}

// ---------------------------------------------------------------------------
// F13 — HSM Integration
// ---------------------------------------------------------------------------

func (a *API) hsmListKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.hsmClient == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "HSM not configured"})
		return
	}
	keys, err := a.hsmClient.ListKeys()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (a *API) hsmGenerateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.hsmClient == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "HSM not configured"})
		return
	}
	var req struct {
		Algorithm string `json:"algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Algorithm == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "algorithm is required"})
		return
	}
	keyID, err := a.hsmClient.GenerateKeyPair(req.Algorithm)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"key_id": keyID, "algorithm": req.Algorithm})
}

func (a *API) hsmSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.hsmClient == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "HSM not configured"})
		return
	}
	var req struct {
		KeyID string `json:"key_id"`
		Data  []byte `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.KeyID == "" || len(req.Data) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key_id and data are required"})
		return
	}
	signature, err := a.hsmClient.Sign(req.KeyID, req.Data)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"key_id":    req.KeyID,
		"signature": signature,
	})
}

func (a *API) hsmVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.hsmClient == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "HSM not configured"})
		return
	}
	var req struct {
		KeyID     string `json:"key_id"`
		Data      []byte `json:"data"`
		Signature []byte `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.KeyID == "" || len(req.Data) == 0 || len(req.Signature) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key_id, data, and signature are required"})
		return
	}
	valid, err := a.hsmClient.Verify(req.KeyID, req.Data, req.Signature)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"key_id": req.KeyID,
		"valid":  valid,
	})
}
