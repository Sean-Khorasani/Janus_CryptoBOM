use crate::{
    config::AgentConfig,
    mutation::MutationEngine,
    proto::{
        janus_telemetry_client::JanusTelemetryClient, AgentRegistration, MigrationStatusReport,
    },
    storage::OfflineStore,
};
use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tokio_stream::iter;

pub struct SyncSummary {
    pub registered: bool,
    pub uploaded: usize,
    pub commands: usize,
    pub scan_requested: bool,
}

#[derive(Debug, Deserialize)]
pub struct RemoteScanConfig {
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub scan_roots: Vec<String>,
    #[serde(default)]
    pub exclude_dirs: Vec<String>,
    #[serde(default)]
    pub include_extensions: Vec<String>,
    pub scan_interval_seconds: Option<u64>,
    pub max_file_bytes: Option<u64>,
    pub max_binary_bytes: Option<u64>,
    #[serde(default)]
    pub network_targets: Vec<String>,
    pub enable_runtime_discovery: Option<bool>,
    pub enable_process_memory_scraping: Option<bool>,
    pub enable_plugin_discovery: Option<bool>,
    pub enable_active_tls_probing: Option<bool>,
}

fn agent_token(host_uuid: &str, key: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())?;
    mac.update(host_uuid.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub async fn fetch_agent_config(
    addr: &str,
    host_uuid: &str,
    key: &str,
) -> Result<RemoteScanConfig> {
    Ok(reqwest::Client::new()
        .get(format!("{}/api/agent/config", addr.trim_end_matches('/')))
        .query(&[("host_uuid", host_uuid)])
        .header("X-Janus-Agent-Token", agent_token(host_uuid, key)?)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

pub async fn poll_scan_command(addr: &str, host_uuid: &str, key: &str) -> Result<bool> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/api/agent/scan-command",
            addr.trim_end_matches('/')
        ))
        .query(&[("host_uuid", host_uuid)])
        .header("X-Janus-Agent-Token", agent_token(host_uuid, key)?)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(false);
    }
    response.error_for_status()?;
    Ok(true)
}

pub async fn sync_once(
    cfg: &AgentConfig,
    db: &OfflineStore,
    reg: &AgentRegistration,
    active: &MutationEngine,
) -> Result<SyncSummary> {
    use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

    let mut endpoint = Channel::from_shared(cfg.controller_endpoint.clone())
        .with_context(|| format!("invalid controller endpoint: {}", cfg.controller_endpoint))?;

    if let Some(ref ca_path) = cfg.tls_ca_cert {
        let ca_pem =
            std::fs::read(ca_path).with_context(|| format!("read ca cert: {}", ca_path))?;
        let ca_cert = Certificate::from_pem(ca_pem);
        let mut tls_config = ClientTlsConfig::new().ca_certificate(ca_cert);

        if let (Some(ref client_cert_path), Some(ref client_key_path)) =
            (&cfg.tls_client_cert, &cfg.tls_client_key)
        {
            let cert_pem = std::fs::read(client_cert_path)
                .with_context(|| format!("read client cert: {}", client_cert_path))?;
            let key_pem = std::fs::read(client_key_path)
                .with_context(|| format!("read client key: {}", client_key_path))?;
            let identity = Identity::from_pem(cert_pem, key_pem);
            tls_config = tls_config.identity(identity);
        }

        endpoint = endpoint
            .tls_config(tls_config)
            .with_context(|| "failed to configure tls config for gRPC channel")?;
    }

    let channel = endpoint
        .connect()
        .await
        .with_context(|| format!("connect {}", cfg.controller_endpoint))?;

    let mut client = JanusTelemetryClient::new(channel);

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
    let mut scan_requested = false;
    while let Some(command) = command_stream.message().await.context("receive command")? {
        if command.target_service == "janus-agent" && command.migration_profile == "scan-now" {
            scan_requested = true;
            reports.push(MigrationStatusReport {
                command_id: command.command_id,
                host_uuid: reg.host_uuid.clone(),
                state: crate::proto::MigrationState::Applying as i32,
                success: false,
                error_vector: String::new(),
                output: "Scan command accepted; collection is starting".to_string(),
                validation_signatures: Vec::new(),
                observed_tls: None,
                reported_at_unix: crate::discovery::now_fn(),
            });
            continue;
        }
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
        commands: reports.len() + usize::from(scan_requested),
        scan_requested,
    })
}

pub async fn start_heartbeat_loop(
    http_endpoint: String,
    host_uuid: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        use crate::discovery::status::SharedScanState;
        use std::sync::atomic::Ordering;
        use std::time::Duration;
        use sysinfo::{ProcessesToUpdate, System};

        let mut sys = System::new_all();
        let pid_opt = sysinfo::get_current_pid().ok();

        loop {
            // Check for shutdown signal (--once mode completes)
            if shutdown_rx.has_changed().unwrap_or(false) && *shutdown_rx.borrow() {
                break;
            }
            let mut cpu_usage = 0.0;
            let mut mem_usage = 0.0;

            if let Some(pid) = pid_opt {
                sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
                if let Some(proc) = sys.process(pid) {
                    cpu_usage = proc.cpu_usage() as f64;
                    mem_usage = (proc.memory() as f64) / (1024.0 * 1024.0);
                }
            }

            let state = SharedScanState::global();
            let phase = state
                .current_phase
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let path = state
                .current_path
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let progress = state.scan_progress.load(Ordering::SeqCst);
            let total_files = state.total_files_scanned.load(Ordering::SeqCst);

            let body = serde_json::json!({
                "host_uuid": host_uuid,
                "scan_progress": progress,
                "current_scan_path": path,
                "cpu_usage": cpu_usage,
                "mem_usage": mem_usage,
                "status": phase,
                "total_files_scanned": total_files,
                "metrics_present": true
            });

            if let Ok(payload) = serde_json::to_string(&body) {
                if let Err(error) = post_heartbeat(&http_endpoint, &payload).await {
                    crate::discovery::status::log_event(&format!(
                        "Heartbeat delivery failed: {}",
                        error
                    ));
                }
            }

            let diag_logs = if let Ok(logs) = state.logs_buffer.lock() {
                logs.join("\n")
            } else {
                String::new()
            };

            if !diag_logs.is_empty() {
                match post_diagnostics(&http_endpoint, &host_uuid, &diag_logs).await {
                    Ok(_) => {
                        // Clear buffer after successful delivery to prevent retransmission
                        if let Ok(mut logs) = state.logs_buffer.lock() {
                            logs.clear();
                        }
                    }
                    Err(e) => {
                        // Keep logs for retry on next heartbeat
                        crate::discovery::status::log_event(&format!(
                            "Diagnostics upload failed: {}",
                            e
                        ));
                    }
                }
            }

            // Check shutdown more frequently (every 1s) for responsive --once termination
            let heartbeat_delay = if phase == "Idle" {
                Duration::from_secs(5)
            } else {
                Duration::from_secs(1)
            };
            tokio::select! {
                _ = tokio::time::sleep(heartbeat_delay) => {},
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
}

pub async fn publish_scan_state(addr: &str, host_uuid: &str) -> Result<()> {
    use crate::discovery::status::SharedScanState;
    use std::sync::atomic::Ordering;

    let state = SharedScanState::global();
    let body = serde_json::json!({
        "host_uuid": host_uuid,
        "scan_progress": state.scan_progress.load(Ordering::SeqCst),
        "current_scan_path": state.current_path.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        "cpu_usage": 0,
        "mem_usage": 0,
        "status": state.current_phase.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        "total_files_scanned": state.total_files_scanned.load(Ordering::SeqCst),
        "metrics_present": false
    });
    post_heartbeat(addr, &body.to_string()).await
}

async fn post_heartbeat(addr: &str, body: &str) -> anyhow::Result<()> {
    reqwest::Client::new()
        .post(format!(
            "{}/api/agent/heartbeat",
            addr.trim_end_matches('/')
        ))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_owned())
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn post_diagnostics(addr: &str, host_uuid: &str, logs: &str) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let host_port = addr
        .strip_prefix("http://")
        .unwrap_or(addr)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:8080");

    let mut stream = TcpStream::connect(host_port).await?;
    let payload = serde_json::json!({
        "host_uuid": host_uuid,
        "logs": logs
    })
    .to_string();

    let req = format!(
        "POST /api/agent/diagnostics HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        host_port,
        payload.len(),
        payload
    );
    stream.write_all(req.as_bytes()).await?;
    Ok(())
}
