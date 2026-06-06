mod binary;
mod cbom;
mod dependency;
pub(crate) mod network;
mod plugin;
mod runtime;
mod source;
pub(crate) mod status;
mod windows;

use crate::{config::AgentConfig, proto::CbomTelemetryPayload};
use anyhow::Result;
use uuid::Uuid;

pub fn collect_static(cfg: &AgentConfig) -> Result<CbomTelemetryPayload> {
    let started = now();
    let mut components = Vec::new();
    let mut evidence = Vec::new();

    status::set_phase("Static Source Analysis");
    let static_result = source::scan(cfg, false)?;
    components.extend(static_result.components);
    evidence.extend(static_result.evidence);

    let finished = now();
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
    let started = now();
    let mut components = Vec::new();
    let mut evidence = Vec::new();

    status::log_event("Starting full cryptographic compliance sweep...");

    status::set_phase("Static Source Analysis");
    let static_result = source::scan(cfg, true)?;
    status::log_event(&format!("Static source scan completed, cataloged {} components", static_result.components.len()));
    components.extend(static_result.components);
    evidence.extend(static_result.evidence);

    status::set_phase("Binary PE/ELF Inspection");
    let binary_result = binary::scan(cfg)?;
    status::log_event(&format!("Binary inspection completed, cataloged {} components", binary_result.components.len()));
    components.extend(binary_result.components);
    evidence.extend(binary_result.evidence);

    status::set_phase("Dependency Analysis");
    let dependency_result = dependency::scan(cfg)?;
    status::log_event(&format!("Package dependencies scan completed, cataloged {} components", dependency_result.components.len()));
    components.extend(dependency_result.components);
    evidence.extend(dependency_result.evidence);

    let mut network_obs = Vec::new();
    if host_uuid != "ci-cd-runner" {
        status::set_phase("Runtime/Memory Scan");
        let runtime_result = runtime::scan(cfg)?;
        status::log_event(&format!("Runtime process memory scanning completed, cataloged {} components", runtime_result.components.len()));
        components.extend(runtime_result.components);
        evidence.extend(runtime_result.evidence);

        status::set_phase("Windows Crypto Audit");
        let windows_result = windows::scan(cfg).await?;
        status::log_event(&format!("Windows system registry policy scan completed, cataloged {} components", windows_result.components.len()));
        components.extend(windows_result.components);
        evidence.extend(windows_result.evidence);

        status::set_phase("Plugin Telemetry Intake");
        let plugin_result = plugin::scan(cfg).await?;
        status::log_event(&format!("External plugins ingestion completed, cataloged {} components", plugin_result.components.len()));
        components.extend(plugin_result.components);
        evidence.extend(plugin_result.evidence);

        status::set_phase("Active TLS Handshake Probing");
        let network = network::scan(cfg).await?;
        status::log_event(&format!("TLS handshake probing completed, cataloged {} components from {} observed endpoints", network.components.len(), network.observations.len()));
        components.extend(network.components);
        evidence.extend(network.evidence);
        network_obs = network.observations;
    }

    let finished = now();
    status::log_event("Generating CycloneDX compliance SBOM output...");
    let cyclone_dx_json = cbom::render_cyclonedx(&components, &evidence, started, finished)?;
    status::log_event("Scan compliance payload fully prepared for secure upload.");
    Ok(CbomTelemetryPayload {
        telemetry_id: Uuid::new_v4().to_string(),
        host_uuid: host_uuid.to_string(),
        scan_started_unix: started,
        scan_finished_unix: finished,
        components,
        findings: Vec::new(),
        network_observations: network_obs,
        evidence,
        cyclone_dx_json,
    })
}

#[derive(Default)]
struct ScanResult {
    components: Vec<crate::proto::CbomComponent>,
    evidence: Vec<crate::proto::Evidence>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
