use crate::proto::{CbomTelemetryPayload, CryptoAlgorithm, RiskSeverity};
use anyhow::{Context, Result};
use serde_json::json;
use std::fs;

pub fn write_html_report(path: &str, payload: &CbomTelemetryPayload) -> Result<()> {
    let mut findings = payload.findings.clone();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>Janus Agent CryptoBOM Report</title>");
    html.push_str("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#17211c;background:#f7f8f5}table{border-collapse:collapse;width:100%;background:#fff}th,td{border:1px solid #dfe5dc;padding:8px;text-align:left;vertical-align:top}th{background:#edf1ea}.metric{display:inline-block;background:#fff;border:1px solid #dfe5dc;border-radius:6px;padding:12px;margin:0 12px 12px 0}.sev5{color:#b42318;font-weight:700}.sev4{color:#b54708;font-weight:700}.muted{color:#697469}</style>");
    html.push_str("</head><body>");
    html.push_str("<h1>Janus Agent CryptoBOM Report</h1>");
    html.push_str(&format!(
        "<p class=\"muted\">Telemetry ID {} · Host {} · Scan {} to {}</p>",
        esc(&payload.telemetry_id),
        esc(&payload.host_uuid),
        payload.scan_started_unix,
        payload.scan_finished_unix
    ));
    html.push_str(&metric("Components", payload.components.len()));
    html.push_str(&metric("Findings", findings.len()));
    html.push_str(&metric("Network Observations", payload.network_observations.len()));
    html.push_str(&metric("Evidence Objects", payload.evidence.len()));

    html.push_str("<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Algorithm</th><th>Rule</th></tr></thead><tbody>");
    for f in &findings {
        html.push_str(&format!(
            "<tr><td class=\"sev{}\">{}</td><td>{}<br><span class=\"muted\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            f.severity,
            f.severity,
            esc(&f.title),
            esc(&f.description),
            esc(&f.asset_ref),
            esc(&f.algorithm),
            esc(&f.policy_rule_id)
        ));
    }
    html.push_str("</tbody></table>");

    html.push_str("<h2>CBOM Components</h2><table><thead><tr><th>Component</th><th>Type</th><th>Location</th><th>Algorithms</th></tr></thead><tbody>");
    for c in &payload.components {
        html.push_str(&format!(
            "<tr><td>{}<br><span class=\"muted\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&c.name),
            esc(&c.bom_ref),
            esc(&c.component_type),
            esc(&c.file_path),
            algorithms_html(&c.algorithms)
        ));
    }
    html.push_str("</tbody></table>");

    html.push_str("<h2>Network Observations</h2><table><thead><tr><th>Endpoint</th><th>Protocol</th><th>TLS</th><th>Cipher</th><th>Group</th><th>Signature</th></tr></thead><tbody>");
    for n in &payload.network_observations {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&n.endpoint),
            esc(&n.protocol),
            esc(&n.tls_version),
            esc(&n.cipher_suite),
            esc(&n.named_group),
            esc(&n.signature_algorithm)
        ));
    }
    html.push_str("</tbody></table>");
    html.push_str("</body></html>");

    fs::write(path, html).with_context(|| format!("write report {path}"))?;
    Ok(())
}

pub fn write_sarif_report(path: &str, payload: &CbomTelemetryPayload) -> Result<()> {
    let rules = vec![
        sarif_rule("JANUS-PQC-001", "Classical public-key cryptography is quantum-vulnerable"),
        sarif_rule("JANUS-PQC-002", "RSA key size below 2026 transition threshold"),
        sarif_rule("JANUS-CLASSICAL-003", "Deprecated hash detected"),
        sarif_rule("JANUS-PQC-004", "AES-128 used where long-term confidentiality may require AES-256"),
        sarif_rule("JANUS-NET-001", "Cleartext service observed"),
        sarif_rule("JANUS-NET-002", "TLS endpoint is not validated as TLS 1.3"),
        sarif_rule("JANUS-PQC-005", "TLS key exchange is classical-only"),
        sarif_rule("JANUS-PQC-006", "Certificate signature remains classical"),
    ];
    let results: Vec<_> = payload
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.policy_rule_id,
                "level": sarif_level(f.severity),
                "message": { "text": f.description },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.asset_ref },
                        "region": { "startLine": 1 }
                    }
                }],
                "properties": {
                    "janusFindingId": f.finding_id,
                    "algorithm": f.algorithm,
                    "migrationProfile": f.migration_profile,
                    "hostUuid": payload.host_uuid
                }
            })
        })
        .collect();
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Janus CryptoBOM Agent",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://example.invalid/janus-cbom",
                    "rules": rules
                }
            },
            "results": results,
            "properties": {
                "telemetryId": payload.telemetry_id,
                "hostUuid": payload.host_uuid,
                "scanStartedUnix": payload.scan_started_unix,
                "scanFinishedUnix": payload.scan_finished_unix
            }
        }]
    });
    fs::write(path, serde_json::to_string_pretty(&sarif)?)
        .with_context(|| format!("write SARIF report {path}"))?;
    Ok(())
}

fn sarif_rule(id: &str, name: &str) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "shortDescription": { "text": name },
        "help": { "text": "Review the Janus CryptoBOM finding evidence and apply the assigned PQC migration profile." }
    })
}

fn sarif_level(severity: i32) -> &'static str {
    if severity >= RiskSeverity::Critical as i32 {
        "error"
    } else if severity >= RiskSeverity::High as i32 {
        "error"
    } else if severity >= RiskSeverity::Medium as i32 {
        "warning"
    } else {
        "note"
    }
}

fn metric(label: &str, value: usize) -> String {
    format!("<div class=\"metric\"><div class=\"muted\">{}</div><strong>{}</strong></div>", esc(label), value)
}

fn algorithms_html(algorithms: &[CryptoAlgorithm]) -> String {
    if algorithms.is_empty() {
        return "<span class=\"muted\">none</span>".to_string();
    }
    algorithms
        .iter()
        .map(|a| {
            format!(
                "{} / {} / role={} / bits={}",
                esc(&a.name),
                esc(&a.family),
                a.role,
                a.key_bits
            )
        })
        .collect::<Vec<_>>()
        .join("<br>")
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
