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
    use tonic::transport::{Channel, ClientTlsConfig, Identity, Certificate};

    let mut endpoint = Channel::from_shared(cfg.controller_endpoint.clone())
        .with_context(|| format!("invalid controller endpoint: {}", cfg.controller_endpoint))?;

    if let Some(ref ca_path) = cfg.tls_ca_cert {
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("read ca cert: {}", ca_path))?;
        let ca_cert = Certificate::from_pem(ca_pem);
        let mut tls_config = ClientTlsConfig::new()
            .ca_certificate(ca_cert);

        if let (Some(ref client_cert_path), Some(ref client_key_path)) = (&cfg.tls_client_cert, &cfg.tls_client_key) {
            let cert_pem = std::fs::read(client_cert_path)
                .with_context(|| format!("read client cert: {}", client_cert_path))?;
            let key_pem = std::fs::read(client_key_path)
                .with_context(|| format!("read client key: {}", client_key_path))?;
            let identity = Identity::from_pem(cert_pem, key_pem);
            tls_config = tls_config.identity(identity);
        }

        endpoint = endpoint.tls_config(tls_config)
            .with_context(|| "failed to configure tls config for gRPC channel")?;
    }

    let channel = endpoint.connect().await
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

pub async fn start_heartbeat_loop(http_endpoint: String, host_uuid: String, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
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
            let phase = state.current_phase.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let path = state.current_path.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let progress = state.scan_progress.load(Ordering::SeqCst);
            let total_files = state.total_files_scanned.load(Ordering::SeqCst);

            let body = serde_json::json!({
                "host_uuid": host_uuid,
                "scan_progress": progress,
                "current_scan_path": path,
                "cpu_usage": cpu_usage,
                "mem_usage": mem_usage,
                "status": phase,
                "total_files_scanned": total_files
            });

            if let Ok(payload) = serde_json::to_string(&body) {
                let _ = post_heartbeat(&http_endpoint, &payload).await;
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
                        crate::discovery::status::log_event(&format!("Diagnostics upload failed: {}", e));
                    }
                }
            }

            // Dynamically fetch and update global scan exclusions
            if let Ok(dynamic_excs) = fetch_fleet_config(&http_endpoint, &host_uuid).await {
                if !dynamic_excs.is_empty() {
                    crate::discovery::status::set_exclusions(dynamic_excs);
                }
            }

            // Check shutdown more frequently (every 1s) for responsive --once termination
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {},
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
}

async fn post_heartbeat(addr: &str, body: &str) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let host_port = addr
        .strip_prefix("http://")
        .unwrap_or(addr)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:8080");

    let mut stream = TcpStream::connect(host_port).await?;
    let req = format!(
        "POST /api/agent/heartbeat HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        host_port,
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).await?;
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
    }).to_string();

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

async fn fetch_fleet_config(addr: &str, host_uuid: &str) -> anyhow::Result<Vec<String>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let host_port = addr
        .strip_prefix("http://")
        .unwrap_or(addr)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:8080");

    let mut stream = TcpStream::connect(host_port).await?;
    let req = format!(
        "GET /api/fleet/config?host_uuid={} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\r\n",
         host_uuid,
         host_port
    );
    stream.write_all(req.as_bytes()).await?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;

    let s = String::from_utf8_lossy(&resp);
    if let Some(body_start) = s.find("\r\n\r\n") {
        let body = &s[body_start + 4..];
        let val: serde_json::Value = serde_json::from_str(body)?;
        if let Some(exclude_str) = val.get("exclude_dirs").and_then(|v| v.as_str()) {
            let excs: Vec<String> = exclude_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            return Ok(excs);
        }
    }
    anyhow::bail!("Invalid HTTP response")
}

