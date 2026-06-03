mod binary;
mod cbom;
mod dependency;
mod network;
mod plugin;
mod runtime;
mod source;
mod windows;

use crate::{config::AgentConfig, proto::CbomTelemetryPayload};
use anyhow::Result;
use uuid::Uuid;

pub async fn collect(cfg: &AgentConfig, host_uuid: &str) -> Result<CbomTelemetryPayload> {
    let started = now();
    let mut components = Vec::new();
    let mut evidence = Vec::new();

    let static_result = source::scan(cfg)?;
    components.extend(static_result.components);
    evidence.extend(static_result.evidence);

    let binary_result = binary::scan(cfg)?;
    components.extend(binary_result.components);
    evidence.extend(binary_result.evidence);

    let dependency_result = dependency::scan(cfg)?;
    components.extend(dependency_result.components);
    evidence.extend(dependency_result.evidence);

    let runtime_result = runtime::scan(cfg)?;
    components.extend(runtime_result.components);
    evidence.extend(runtime_result.evidence);

    let windows_result = windows::scan(cfg).await?;
    components.extend(windows_result.components);
    evidence.extend(windows_result.evidence);

    let plugin_result = plugin::scan(cfg).await?;
    components.extend(plugin_result.components);
    evidence.extend(plugin_result.evidence);

    let network = network::scan(cfg).await?;
    evidence.extend(network.evidence);

    let finished = now();
    let cyclone_dx_json = cbom::render_cyclonedx(&components, &evidence, started, finished)?;
    Ok(CbomTelemetryPayload {
        telemetry_id: Uuid::new_v4().to_string(),
        host_uuid: host_uuid.to_string(),
        scan_started_unix: started,
        scan_finished_unix: finished,
        components,
        findings: Vec::new(),
        network_observations: network.observations,
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
