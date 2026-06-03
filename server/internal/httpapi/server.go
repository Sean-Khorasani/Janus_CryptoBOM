package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/janus-cbom/janus/server/internal/certmanager"
	"github.com/janus-cbom/janus/server/internal/orchestrator"
	"github.com/janus-cbom/janus/server/internal/store"
)

type API struct {
	store store.Store
	orch  *orchestrator.Orchestrator
}

func New(store store.Store, orch *orchestrator.Orchestrator) http.Handler {
	api := &API{store: store, orch: orch}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", api.health)
	mux.HandleFunc("/api/overview", api.overview)
	mux.HandleFunc("/api/assets", api.assets)
	mux.HandleFunc("/api/components", api.components)
	mux.HandleFunc("/api/findings", api.findings)
	mux.HandleFunc("/api/migrations", api.migrations)
	mux.HandleFunc("/api/report.html", api.reportHTML)
	mux.HandleFunc("/api/certificates/csr", api.createCSR)
	mux.HandleFunc("/api/migrations/enqueue", api.enqueueMigration)
	return cors(mux)
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	out, err := a.store.Findings(r.Context(), 200)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
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
	cmd := a.orch.BuildCommand(req.HostUUID, req.TargetService, req.MigrationProfile, req.ConfigPath, req.PatchUnifiedDiff, req.DryRun)
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

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "content-type, authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
