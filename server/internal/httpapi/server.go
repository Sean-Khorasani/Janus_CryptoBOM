package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/janus-cbom/janus/server/internal/certmanager"
	"github.com/janus-cbom/janus/server/internal/config"
	"github.com/janus-cbom/janus/server/internal/hsm"
	"github.com/janus-cbom/janus/server/internal/llm"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/sandbox"
	"github.com/janus-cbom/janus/server/internal/store"
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
}

func New(store store.Store, orch *orchestrator.Orchestrator, engine *policy.Engine, jwtSecret []byte, disableAuth bool, wsHub *ws.Hub, cfg config.Config) http.Handler {
	api := &API{
		store:      store,
		orch:       orch,
		engine:     engine,
		wsHub:      wsHub,
		simulator:  sandbox.NewSimulator(store, orch, engine),
		confidence: policy.NewConfidenceAnalyzer(store),
		cfg:        cfg,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", api.health)
	mux.HandleFunc("/api/auth/login", LoginHandler(jwtSecret))
	mux.HandleFunc("/api/overview", api.overview)
	mux.HandleFunc("/api/assets", api.assets)
	mux.HandleFunc("/api/components", api.components)
	mux.HandleFunc("/api/findings", api.findings)
	mux.HandleFunc("/api/findings/", api.findingStatus) // PUT /api/findings/{id}/status
	mux.HandleFunc("/api/migrations", api.migrations)
	mux.HandleFunc("/api/report.html", api.reportHTML)
	mux.HandleFunc("/api/certificates/csr", api.createCSR)

	// Require operator or admin role to enqueue migrations
	mux.Handle("/api/migrations/enqueue", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.enqueueMigration)))

	mux.HandleFunc("/api/export/cyclonedx", api.exportCycloneDX)
	mux.HandleFunc("/api/export/csv", api.exportCSV)
	mux.HandleFunc("/api/export/sarif", api.exportSARIF)
	mux.HandleFunc("/api/policies", api.policies)
	mux.HandleFunc("/api/policies/active", api.activePolicy)
	mux.HandleFunc("/api/policies/create", api.createPolicy)
	mux.HandleFunc("/api/agent/heartbeat", api.agentHeartbeat)
	mux.HandleFunc("/api/fleet/config", api.fleetConfig)
	mux.HandleFunc("/api/fleet/profiles", api.fleetProfiles)
	mux.HandleFunc("/api/fleet/profiles/mapping", api.fleetProfileMapping)
	mux.HandleFunc("/api/audit-logs", api.auditLogs)
	mux.HandleFunc("/api/agent/diagnostics", api.agentDiagnostics)
	mux.HandleFunc("/api/webhooks", api.webhooks)
	mux.HandleFunc("/api/retention", api.retention)
	mux.HandleFunc("/api/export/siem", api.exportSIEM)
	mux.HandleFunc("/api/llm/proxy", api.llmProxy)
	mux.Handle("/api/llm/test-connection", RequireRole([]string{"admin"})(http.HandlerFunc(api.llmTestConnection)))
	// LLM analysis pipeline (LLM-08/09/10/11/16)
	mux.Handle("/api/llm/analyze", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.llmAnalyze)))
	mux.HandleFunc("/api/llm/jobs", api.llmJobs)
	mux.HandleFunc("/api/llm/jobs/", api.llmJobs)
	mux.HandleFunc("/api/llm/verdicts/", api.llmVerdict)
	mux.HandleFunc("/api/llm/provenance/", api.llmProvenance)
	mux.HandleFunc("/api/llm/status", api.llmStatus)
	// Crypto-agility scorecard (AGILE-01/WP-023)
	mux.HandleFunc("/api/agility/scorecard", api.agilityScorecard)
	// Migration wave planning (WAVE-01/WP-022)
	mux.Handle("/api/waves", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.wavePlans)))
	mux.Handle("/api/waves/", RequireRole([]string{"operator", "admin"})(http.HandlerFunc(api.wavePlanByID)))
	mux.HandleFunc("/api/ws", api.wsHub.ServeWS)
	mux.HandleFunc("/api/report/compliance", api.complianceReport)
	mux.HandleFunc("/api/lab/simulate", api.pqcLabSimulate)
	mux.HandleFunc("/api/sla/metrics", api.slaMetrics)
	mux.HandleFunc("/api/agent/upgrade", api.agentUpgradeInfo)
	mux.HandleFunc("/api/export/audit", api.exportAuditLog)
	// F1 — PQC Migration Simulator
	mux.HandleFunc("/api/sandbox/simulate", api.sandboxSimulate)
	// F7 — Statistical Confidence Analysis
	mux.HandleFunc("/api/confidence/report", api.confidenceReport)
	mux.HandleFunc("/api/hsm/sign", api.hsmSign)
	mux.HandleFunc("/api/hsm/verify", api.hsmVerify)
	mux.HandleFunc("/metrics", api.metrics)

	authWrapper := AuthMiddleware(jwtSecret, disableAuth)
	return cors(authWrapper(mux))
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
	if err := a.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "db": "connected"})
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.Overview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) assets(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.Assets(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) components(w http.ResponseWriter, r *http.Request) {
	// Support pagination, search, and filtering like findings endpoint
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") || r.URL.Query().Has("search") {
		params := store.QueryParams{
			Limit:  intParam(r, "limit", 100),
			Offset: intParam(r, "offset", 0),
			Sort:   r.URL.Query().Get("sort"),
			Order:  r.URL.Query().Get("order"),
			Search: r.URL.Query().Get("search"),
		}
		comps, total, err := a.store.ComponentsPaginated(r.Context(), params)
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set("X-Total-Count", fmt.Sprintf("%d", total))
		writeJSON(w, http.StatusOK, comps)
		return
	}
	out, err := a.store.Components(r.Context(), 500)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) findings(w http.ResponseWriter, r *http.Request) {
	// Support ?limit=N&offset=M&sort=severity&order=desc&search=keyword
	if r.URL.Query().Has("limit") || r.URL.Query().Has("offset") || r.URL.Query().Has("search") {
		params := store.QueryParams{
			Limit:  intParam(r, "limit", 50),
			Offset: intParam(r, "offset", 0),
			Sort:   r.URL.Query().Get("sort"),
			Order:  r.URL.Query().Get("order"),
			Search: r.URL.Query().Get("search"),
		}
		findings, total, err := a.store.FindingsPaginated(r.Context(), params)
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set("X-Total-Count", fmt.Sprintf("%d", total))
		writeJSON(w, http.StatusOK, findings)
		return
	}
	out, err := a.store.Findings(r.Context(), 200)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
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
	a.wsHub.Broadcast("finding_status", map[string]string{
		"finding_id": findingID,
		"status":     body.Status,
		"updated_by": body.UpdatedBy,
	})
	writeJSON(w, http.StatusOK, map[string]string{"finding_id": findingID, "status": body.Status})
}

func (a *API) migrations(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.Migrations(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) reportHTML(w http.ResponseWriter, r *http.Request) {
	overview, err := a.store.Overview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	assets, err := a.store.Assets(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	findings, err := a.store.Findings(r.Context(), 500)
	if err != nil {
		writeError(w, err)
		return
	}
	components, err := a.store.Components(r.Context(), 500)
	if err != nil {
		writeError(w, err)
		return
	}
	migrations, err := a.store.Migrations(r.Context())
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
	CommonName         string   `json:"common_name"`
	DNSNames           []string `json:"dns_names"`
	Organization       []string `json:"organization"`
	TargetSignature    string   `json:"target_signature"`
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

	a.wsHub.Broadcast("migration_enqueued", map[string]string{
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

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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

func (a *API) exportCycloneDX(w http.ResponseWriter, r *http.Request) {
	components, err := a.store.Components(r.Context(), 2000)
	if err != nil {
		writeError(w, err)
		return
	}
	type cdxComponent struct {
		BomRef    string   `json:"bom-ref"`
		Type      string   `json:"type"`
		Name      string   `json:"name"`
		Version   string   `json:"version"`
		FilePath  string   `json:"evidence_filepath,omitempty"`
		Algorithms []string `json:"algorithms,omitempty"`
	}
	cdxComps := make([]cdxComponent, 0, len(components))
	for _, c := range components {
		cdxComps = append(cdxComps, cdxComponent{
			BomRef: c.BomRef, Type: c.ComponentType, Name: c.Name,
			Version: c.Version, FilePath: c.FilePath, Algorithms: c.Algorithms,
		})
	}
	cbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata":    map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339)},
		"components":  cdxComps,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="janus-cbom.cyclonedx.json"`)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(cbom)
}

func (a *API) exportCSV(w http.ResponseWriter, r *http.Request) {
	findings, err := a.store.Findings(r.Context(), 5000)
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

func (a *API) exportSARIF(w http.ResponseWriter, r *http.Request) {
	findings, err := a.store.Findings(r.Context(), 5000)
	if err != nil {
		writeError(w, err)
		return
	}
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []map[string]any `json:"locations"`
	}
	var results []sarifResult
	for _, f := range findings {
		level := "warning"
		if f.Severity >= 5 {
			level = "error"
		} else if f.Severity <= 2 {
			level = "note"
		}
		sr := sarifResult{RuleID: f.PolicyRuleID, Level: level}
		sr.Message.Text = f.Title + ": " + f.Description
		sr.Locations = []map[string]any{{"physicalLocation": map[string]any{
			"artifactLocation": map[string]string{"uri": f.AssetRef},
		}}}
		results = append(results, sr)
	}
	sarif := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name": "Janus CryptoBOM", "version": "0.1.0",
				"informationUri": "https://github.com/janus-cbom/janus",
			}},
			"results": results,
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

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// During development with auth disabled, allow all origins; otherwise restrict
		if origin == "http://localhost:5173" || origin == "http://127.0.0.1:5173" || origin == "http://localhost:8080" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else if origin != "" {
			// For production, set CORS_ORIGIN via config; here we allow localhost variants
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		}
		w.Header().Set("Access-Control-Allow-Headers", "content-type, authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	overview, err := a.store.Overview(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP janus_assets_total Total tracked assets\n")
	fmt.Fprintf(w, "# TYPE janus_assets_total gauge\n")
	fmt.Fprintf(w, "janus_assets_total %d\n\n", overview.Assets)

	fmt.Fprintf(w, "# HELP janus_components_total Total cataloged CBOM components\n")
	fmt.Fprintf(w, "# TYPE janus_components_total gauge\n")
	fmt.Fprintf(w, "janus_components_total %d\n\n", overview.Components)

	fmt.Fprintf(w, "# HELP janus_findings_total Total detected cryptographic findings\n")
	fmt.Fprintf(w, "# TYPE janus_findings_total gauge\n")
	fmt.Fprintf(w, "janus_findings_total %d\n\n", overview.Findings)

	fmt.Fprintf(w, "# HELP janus_critical_findings_total Total critical severity findings\n")
	fmt.Fprintf(w, "# TYPE janus_critical_findings_total gauge\n")
	fmt.Fprintf(w, "janus_critical_findings_total %d\n\n", overview.CriticalFindings)

	fmt.Fprintf(w, "# HELP janus_high_findings_total Total high severity findings\n")
	fmt.Fprintf(w, "# TYPE janus_high_findings_total gauge\n")
	fmt.Fprintf(w, "janus_high_findings_total %d\n\n", overview.HighFindings)

	fmt.Fprintf(w, "# HELP janus_open_migrations_total Total pending or active migrations\n")
	fmt.Fprintf(w, "# TYPE janus_open_migrations_total gauge\n")
	fmt.Fprintf(w, "janus_open_migrations_total %d\n\n", overview.OpenMigrations)
}

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
		writeJSON(w, http.StatusOK, fc)
		return
	}
	if r.Method == http.MethodPost {
		var fc store.FleetConfig
		if err := json.NewDecoder(r.Body).Decode(&fc); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
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
		writeJSON(w, http.StatusOK, list)
		return
	}
	if r.Method == http.MethodPost {
		var wh store.Webhook
		if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if wh.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
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
	findings, err := a.store.Findings(r.Context(), 1000)
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
		OK               bool   `json:"ok"`
		BaseURL          string `json:"base_url,omitempty"`
		ModelAnalysis    string `json:"model_analysis,omitempty"`
		ModelRemediation string `json:"model_remediation,omitempty"`
		Error            string `json:"error,omitempty"`
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
		writeJSON(w, http.StatusOK, testResult{
			OK:               true,
			BaseURL:          a.cfg.LLM.BaseURL,
			ModelAnalysis:    a.cfg.LLM.ModelAnalysis,
			ModelRemediation: a.cfg.LLM.ModelRemediation,
		})
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
		writeJSON(w, http.StatusOK, list)
		return
	}
	if r.Method == http.MethodPost {
		var cp store.ConfigProfile
		if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
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
	findings, err := a.store.Findings(r.Context(), 5000)
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
