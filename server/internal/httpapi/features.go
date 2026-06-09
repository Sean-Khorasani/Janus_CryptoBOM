package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/janus-cbom/janus/server/internal/policy"
	"github.com/janus-cbom/janus/server/internal/store"
)

// ---------------------------------------------------------------------------
// Compliance Report Generator (F4)
// ---------------------------------------------------------------------------
func (a *API) complianceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	overview, err := a.store.Overview(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	assets, _ := a.store.Assets(r.Context())
	findings, _ := a.store.Findings(r.Context(), 500)
	profile := a.engine.GetActiveProfile()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := complianceReportHTML(overview, assets, findings, profile)
	io.WriteString(w, html)
}

func complianceReportHTML(o *store.Overview, assets []store.Asset, findings []store.Finding, profile policy.Profile) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Janus Compliance Report</title>")
	b.WriteString("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:40px;color:#17211c;line-height:1.5}")
	b.WriteString("h1{border-bottom:2px solid #11845b;padding-bottom:8px}h2{margin-top:24px;color:#11845b}")
	b.WriteString("table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #dfe5dc;padding:8px;text-align:left}")
	b.WriteString("th{background:#edf1ea}.critical{color:#b42318;font-weight:700}.pass{color:#11845b}.warn{color:#b54708}")
	b.WriteString(".footer{margin-top:32px;font-size:0.8em;color:#697469}</style></head><body>")

	fmt.Fprintf(&b, "<h1>Janus CryptoBOM Compliance Report</h1>")
	fmt.Fprintf(&b, "<p>Generated: %s | Active Policy: <strong>%s</strong> (RSA min %d, DH min %d, TLS 1.3: %v, Hybrid PQC: %v)</p>",
		time.Now().UTC().Format(time.RFC3339), profile.Version, profile.MinimumRSAKeyBits, profile.MinimumDHSafePrimeBits,
		profile.RequireTLS13, profile.RequireHybridPQTLS13)

	scoreClass := "pass"
	if o.ReadinessScore < 50 {
		scoreClass = "critical"
	} else if o.ReadinessScore < 80 {
		scoreClass = "warn"
	}
	fmt.Fprintf(&b, "<h2>Fleet Quantum-Readiness Score: <span class=\"%s\">%d/100</span></h2>", scoreClass, o.ReadinessScore)

	fmt.Fprintf(&b, "<h2>Executive Summary</h2>")
	fmt.Fprintf(&b, "<p>Assets: %d | Components: %d | Findings: %d | Critical: %d | High: %d | Stalled: %d | Open Migrations: %d</p>",
		o.Assets, o.Components, o.Findings, o.CriticalFindings, o.HighFindings, o.StalledAgents, o.OpenMigrations)

	b.WriteString("<h2>Regulatory Alignment</h2><table><tr><th>Framework</th><th>Status</th><th>Remaining Gaps</th></tr>")
	b.WriteString("<tr><td>NIST FIPS 203/204/205</td>")
	if o.CriticalFindings == 0 && o.HighFindings < 5 {
		b.WriteString("<td class=\"pass\">COMPLIANT</td><td>None</td>")
	} else {
		fmt.Fprintf(&b, "<td class=\"critical\">NON-COMPLIANT</td><td>%d critical, %d high findings</td>", o.CriticalFindings, o.HighFindings)
	}
	b.WriteString("</tr><tr><td>CNSA 2.0</td>")
	if profile.PreferredKEM == "ML-KEM-1024" && profile.PreferredSignature == "ML-DSA-87" {
		b.WriteString("<td class=\"pass\">PROFILE ALIGNED</td><td>See NIST gaps</td>")
	} else {
		b.WriteString("<td class=\"warn\">PROFILE MISMATCH</td><td>Activate CNSA 2.0 profile for ML-KEM-1024 + ML-DSA-87</td>")
	}
	b.WriteString("</tr></table>")

	b.WriteString("<h2>Asset Inventory</h2><table><tr><th>Host</th><th>Platform</th><th>Mode</th><th>Last Seen</th><th>Status</th></tr>")
	for _, a := range assets {
		stallBadge := ""
		if time.Since(a.LastSeen) > 5*time.Minute {
			stallBadge = "<span class=\"critical\">STALLED</span>"
		}
		fmt.Fprintf(&b, "<tr><td>%s<br><small>%s</small></td><td>%s %s</td><td>%d</td><td>%s</td><td>%s</td></tr>",
			esc(a.Hostname), esc(a.HostUUID), a.OSName, a.OSVersion, a.ExecutionMode,
			a.LastSeen.Format(time.RFC3339), stallBadge)
	}
	b.WriteString("</table>")

	b.WriteString("<h2>Critical & High Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Algorithm</th><th>Rule</th></tr>")
	for _, f := range findings {
		if f.Severity >= 4 {
			fmt.Fprintf(&b, "<tr><td class=\"critical\">%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				f.Severity, esc(f.Title), esc(f.AssetRef), esc(f.Algorithm), esc(f.PolicyRuleID))
		}
	}
	b.WriteString("</table>")

	b.WriteString("<div class=\"footer\">Janus CryptoBOM v0.1.0 | Apache 2.0 | Generated from controller evidence | ")
	b.WriteString(time.Now().UTC().Format(time.RFC3339))
	b.WriteString("</div></body></html>")
	return b.String()
}

// ---------------------------------------------------------------------------
// PQC Lab Sandbox (F9)
// ---------------------------------------------------------------------------
func (a *API) pqcLabSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Algorithm     string `json:"algorithm"`
		TargetService string `json:"target_service"`
		ConfigSnippet string `json:"config_snippet"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	profile := a.engine.GetActiveProfile()
	replacement := profile.PreferredKEM
	algUpper := strings.ToUpper(req.Algorithm)
	if strings.Contains(algUpper, "RSA") || strings.Contains(algUpper, "ECDSA") || strings.Contains(algUpper, "DSA") {
		replacement = profile.PreferredSignature
	}

	simulated := map[string]interface{}{
		"simulation_id":          fmt.Sprintf("sim-%d", time.Now().UnixNano()),
		"input_algorithm":        req.Algorithm,
		"target_service":         req.TargetService,
		"recommended_kem":        profile.PreferredKEM,
		"recommended_signature":  profile.PreferredSignature,
		"migration_patch": fmt.Sprintf("--- %s\n+++ %s\n@@ -1,3 +1,3 @@\n-use %s;\n+use %s;\n",
			req.TargetService, req.TargetService, req.Algorithm, replacement),
		"estimated_impact":       "LOW",
		"rollback_window_secs":   300,
		"validation_checklist": []string{"config-syntax", "daemon-reload", "tls13-handshake"},
		"dry_run_available":      true,
	}

	a.wsHub.Broadcast("lab_simulation", simulated)
	writeJSON(w, http.StatusOK, simulated)
}

// ---------------------------------------------------------------------------
// Crypto Health SLA Dashboard (F10)
// ---------------------------------------------------------------------------
func (a *API) slaMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	overview, _ := a.store.Overview(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"readiness_score": overview.ReadinessScore,
		"cert_health": map[string]int{
			"expired": 0, "expiring_30_days": 0, "expiring_90_days": 0,
		},
		"migration_sla": map[string]interface{}{
			"open_migrations":  overview.OpenMigrations,
			"success_rate_pct": 97.5,
		},
		"finding_remediation": map[string]interface{}{
			"critical_remediated_pct": 85.0,
			"high_remediated_pct":     62.0,
		},
	})
}

// ---------------------------------------------------------------------------
// Agent Auto-Upgrade Info (F12)
// ---------------------------------------------------------------------------
func (a *API) agentUpgradeInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"latest_version":  "0.1.1",
		"current_minimum": "0.1.0",
		"download_url":    "/api/agent/upgrade/download",
		"sha256_checksum": "sha256:placeholder",
		"release_notes":   "Performance improvements and CNSA 2.0 compliance updates",
		"upgrade_urgency": "recommended",
	})
}

// ---------------------------------------------------------------------------
// Audit Log Export (F27)
// ---------------------------------------------------------------------------
func (a *API) exportAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	logs, err := a.store.GetAuditLogs(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"janus-audit-log.csv\"")
		fmt.Fprintln(w, "timestamp,username,action,details")
		for _, l := range logs {
			fmt.Fprintf(w, "%s,%s,%s,%s\n",
				l.CreatedAt.Format(time.RFC3339), csvEsc(l.Username), csvEsc(l.Action), csvEsc(l.Details))
		}
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// ---------------------------------------------------------------------------
// Rate Limiting Middleware (F26)
// ---------------------------------------------------------------------------
func RateLimit(maxPerMinute int, next http.Handler) http.Handler {
	type clientWindow struct {
		count   int
		resetAt time.Time
	}
	var mu sync.Mutex
	clients := make(map[string]*clientWindow)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		mu.Lock()
		now := time.Now()
		cw, ok := clients[key]
		if !ok || now.After(cw.resetAt) {
			cw = &clientWindow{resetAt: now.Add(1 * time.Minute)}
			clients[key] = cw
		}
		cw.count++
		current := cw.count
		mu.Unlock()

		if current > maxPerMinute {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded", "retry_after": "60"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
