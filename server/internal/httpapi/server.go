package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/janus-cbom/janus/server/internal/certmanager"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
)

type API struct {
	store  store.Store
	orch   *orchestrator.Orchestrator
	engine *policy.Engine
}

func New(store store.Store, orch *orchestrator.Orchestrator, engine *policy.Engine) http.Handler {
	api := &API{store: store, orch: orch, engine: engine}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", api.health)
	mux.HandleFunc("/api/overview", api.overview)
	mux.HandleFunc("/api/assets", api.assets)
	mux.HandleFunc("/api/components", api.components)
	mux.HandleFunc("/api/findings", api.findings)
	mux.HandleFunc("/api/findings/", api.findingStatus) // PUT /api/findings/{id}/status
	mux.HandleFunc("/api/migrations", api.migrations)
	mux.HandleFunc("/api/report.html", api.reportHTML)
	mux.HandleFunc("/api/certificates/csr", api.createCSR)
	mux.HandleFunc("/api/migrations/enqueue", api.enqueueMigration)
	mux.HandleFunc("/api/export/cyclonedx", api.exportCycloneDX)
	mux.HandleFunc("/api/export/csv", api.exportCSV)
	mux.HandleFunc("/api/export/sarif", api.exportSARIF)
	mux.HandleFunc("/api/policies", api.policies)
	mux.HandleFunc("/api/policies/active", api.activePolicy)
	mux.HandleFunc("/metrics", api.metrics)
	return cors(mux)
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
	cmd := a.orch.BuildCommand(req.HostUUID, req.TargetService, req.MigrationProfile, req.ConfigPath, req.PatchUnifiedDiff, hash, req.DryRun)
	a.orch.Enqueue(cmd)
	if err := a.store.InsertMigrationCommand(r.Context(), cmd); err != nil {
		writeError(w, err)
		return
	}
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "active": a.engine.ProfileVersion()})
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "content-type, authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT")
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
