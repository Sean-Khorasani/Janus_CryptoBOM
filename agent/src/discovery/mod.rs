pub mod binary;
pub mod cbom;
pub(crate) mod config_parse;
pub mod dependency;
pub(crate) mod network;
mod plugin;
mod runtime;
pub mod sidechannel;
pub mod source;
pub(crate) mod status;
#[cfg(target_os = "windows")]
mod windows;

pub use crate::proto::CbomTelemetryPayload;

use crate::{config::AgentConfig, proto::CryptoFinding};
use anyhow::Result;
use uuid::Uuid;

#[allow(dead_code)]
pub fn collect_static(cfg: &AgentConfig) -> Result<CbomTelemetryPayload> {
    let started = now_fn();
    let mut components = Vec::new();
    let mut evidence = Vec::new();

    status::set_phase("Static Source Analysis");
    let static_result = source::scan(cfg, false)?;
    components.extend(static_result.components);
    evidence.extend(static_result.evidence);

    let finished = now_fn();
    let cyclone_dx_json = cbom::render_cyclonedx(&components, &evidence, started, finished)?;
    Ok(CbomTelemetryPayload {
        telemetry_id: Uuid::new_v4().to_string(),
        host_uuid: "ci-cd-runner".to_string(),
        scan_started_unix: started,
        scan_finished_unix: finished,
        components,
        findings: Vec::new(),
        network_observations: Vec::new(),
        evidence,
        cyclone_dx_json,
    })
}

pub async fn collect(cfg: &AgentConfig, host_uuid: &str) -> Result<CbomTelemetryPayload> {
    let started = now_fn();
    let mut components = Vec::new();
    let mut evidence = Vec::new();
    let mut findings = Vec::new();

    status::log_event("Starting full cryptographic compliance sweep...");

    // Check once whether the server has LLM enabled before scanning.
    // This avoids per-match TCP timeouts when LLM is not configured server-side.
    let llm_available = check_llm_available(&cfg.http_endpoint()).await;

    status::set_phase("Static Source Analysis");
    let static_result = source::scan(cfg, llm_available)?;
    status::log_event(&format!(
        "Static source scan completed, cataloged {} components",
        static_result.components.len()
    ));
    components.extend(static_result.components);
    evidence.extend(static_result.evidence);

    status::set_phase("Binary PE/ELF Inspection");
    let binary_result = binary::scan(cfg)?;
    status::log_event(&format!(
        "Binary inspection completed, cataloged {} components",
        binary_result.components.len()
    ));
    components.extend(binary_result.components);
    evidence.extend(binary_result.evidence);

    status::set_phase("Dependency Analysis");
    let dependency_result = dependency::scan(cfg)?;
    status::log_event(&format!(
        "Package dependencies scan completed, cataloged {} components",
        dependency_result.components.len()
    ));
    components.extend(dependency_result.components);
    evidence.extend(dependency_result.evidence);

    status::set_phase("Side-Channel Analysis");
    let sidechannel_result = sidechannel::scan(cfg)?;
    status::log_event(&format!(
        "Side-channel analysis completed, generated {} findings",
        sidechannel_result.findings.len()
    ));
    evidence.extend(sidechannel_result.evidence);
    findings.extend(sidechannel_result.findings);

    let mut network_obs = Vec::new();
    if host_uuid != "ci-cd-runner" {
        if cfg.enable_runtime_discovery {
            status::set_phase("Runtime Discovery");
            let runtime_result = runtime::scan(cfg)?;
            status::log_event(&format!(
                "Runtime discovery completed, cataloged {} components",
                runtime_result.components.len()
            ));
            components.extend(runtime_result.components);
            evidence.extend(runtime_result.evidence);
        }

        #[cfg(target_os = "windows")]
        {
            status::set_phase("Windows Crypto Audit");
            let windows_result = windows::scan(cfg).await?;
            status::log_event(&format!(
                "Windows system registry policy scan completed, cataloged {} components",
                windows_result.components.len()
            ));
            components.extend(windows_result.components);
            evidence.extend(windows_result.evidence);
        }

        if cfg.enable_plugin_discovery {
            status::set_phase("Plugin Telemetry Intake");
            let plugin_result = plugin::scan(cfg).await?;
            status::log_event(&format!(
                "External plugins ingestion completed, cataloged {} components",
                plugin_result.components.len()
            ));
            components.extend(plugin_result.components);
            evidence.extend(plugin_result.evidence);
        }

        if cfg.enable_active_tls_probing {
            status::set_phase("Active TLS Handshake Probing");
            let network = network::scan(cfg).await?;
            status::log_event(&format!(
                "TLS handshake probing completed, cataloged {} components from {} observed endpoints",
                network.components.len(),
                network.observations.len()
            ));
            components.extend(network.components);
            evidence.extend(network.evidence);
            network_obs = network.observations;
        }
    }

    let finished = now_fn();
    status::log_event("Generating CycloneDX compliance SBOM output...");
    let cyclone_dx_json = cbom::render_cyclonedx(&components, &evidence, started, finished)?;
    status::log_event("Scan compliance payload fully prepared for secure upload.");
    Ok(CbomTelemetryPayload {
        telemetry_id: Uuid::new_v4().to_string(),
        host_uuid: host_uuid.to_string(),
        scan_started_unix: started,
        scan_finished_unix: finished,
        components,
        findings,
        network_observations: network_obs,
        evidence,
        cyclone_dx_json,
    })
}

#[derive(Default)]
pub(crate) struct ScanResult {
    pub(crate) components: Vec<crate::proto::CbomComponent>,
    pub(crate) evidence: Vec<crate::proto::Evidence>,
    pub(crate) findings: Vec<CryptoFinding>,
}

/// Check once per scan whether the controller's LLM proxy is enabled.
/// Returns false (skip LLM) on any error or if the server reports it disabled.
/// A single 3-second probe avoids per-match TCP hangs when LLM is not configured.
async fn check_llm_available(http_endpoint: &str) -> bool {
    let url = format!("{}/api/llm/status", http_endpoint.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_default();
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                return body
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            }
            false
        }
        _ => false,
    }
}

pub fn now_fn() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
