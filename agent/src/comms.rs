use crate::{
    config::AgentConfig,
    mutation::MutationEngine,
    proto::{
        janus_telemetry_client::JanusTelemetryClient, AgentRegistration, MigrationStatusReport,
    },
    storage::OfflineStore,
};
use anyhow::{Context, Result};
use tokio_stream::iter;

pub struct SyncSummary {
    pub registered: bool,
    pub uploaded: usize,
    pub commands: usize,
}

pub async fn sync_once(
    cfg: &AgentConfig,
    db: &OfflineStore,
    reg: &AgentRegistration,
    active: &MutationEngine,
) -> Result<SyncSummary> {
    let mut client = JanusTelemetryClient::connect(cfg.controller_endpoint.clone())
        .await
        .with_context(|| format!("connect {}", cfg.controller_endpoint))?;

    let ack = client
        .register_agent(reg.clone())
        .await
        .context("register agent")?
        .into_inner();
    if !ack.accepted {
        anyhow::bail!("controller rejected registration: {}", ack.message);
    }

    let payloads = db.pending_payloads(256).context("load pending telemetry")?;
    let payload_ids: Vec<String> = payloads.iter().map(|p| p.telemetry_id.clone()).collect();
    let response = client
        .stream_telemetry(iter(payloads))
        .await
        .context("stream telemetry")?;
    let mut command_stream = response.into_inner();

    let mut reports = Vec::<MigrationStatusReport>::new();
    while let Some(command) = command_stream.message().await.context("receive command")? {
        let report = active.execute(command).await;
        reports.push(report);
    }

    if !reports.is_empty() {
        client
            .report_migration_status(iter(reports.clone()))
            .await
            .context("report migration status")?;
    }

    for id in &payload_ids {
        db.delete_payload(id)?;
    }
    db.audit(
        "sync",
        &format!("uploaded={} commands={}", payload_ids.len(), reports.len()),
    )?;

    Ok(SyncSummary {
        registered: true,
        uploaded: payload_ids.len(),
        commands: reports.len(),
    })
}

