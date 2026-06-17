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

// per_agent_token mirrors the server's agentauth.Token: hex HMAC-SHA256 over
// agentID\nmethod\npath\nts with the per-agent key (WP-029 P1).
fn per_agent_token(
    agent_id: &str,
    agent_key_hex: &str,
    method: &str,
    path: &str,
    ts: i64,
) -> Result<String> {
    let key = hex::decode(agent_key_hex.trim()).context("decode agent_key")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)?;
    mac.update(format!("{agent_id}\n{method}\n{path}\n{ts}").as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

// with_per_agent_auth attaches the X-Janus-Agent-{Id,Ts,Auth} headers when a per-agent
// identity is configured; otherwise the request is returned unchanged (legacy shared mode).
fn with_per_agent_auth(
    req: reqwest::RequestBuilder,
    agent_id: Option<&str>,
    agent_key: Option<&str>,
    method: &str,
    path: &str,
) -> reqwest::RequestBuilder {
    if let (Some(id), Some(key)) = (agent_id, agent_key) {
        if !id.is_empty() && !key.is_empty() {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if let Ok(tok) = per_agent_token(id, key, method, path, ts) {
                return req
                    .header("X-Janus-Agent-Id", id)
                    .header("X-Janus-Agent-Ts", ts.to_string())
                    .header("X-Janus-Agent-Auth", tok);
            }
        }
    }
    req
}

// with_grpc_agent_auth attaches janus-agent-{id,ts,auth} metadata to a tonic request when
// a per-agent identity is configured (WP-029 P1). The token binds to the fixed GRPC
// method/path the server's PerAgent*Interceptor expects (agentauth.GRPCMethod/GRPCPath).
// In legacy shared mode the request is returned unchanged.
fn with_grpc_agent_auth<T>(
    mut req: tonic::Request<T>,
    agent_id: Option<&str>,
    agent_key: Option<&str>,
) -> tonic::Request<T> {
    if let (Some(id), Some(key)) = (agent_id, agent_key) {
        if !id.is_empty() && !key.is_empty() {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if let Ok(tok) = per_agent_token(id, key, "GRPC", "janus.telemetry", ts) {
                if let (Ok(idv), Ok(tsv), Ok(tokv)) =
                    (id.parse(), ts.to_string().parse(), tok.parse())
                {
                    let md = req.metadata_mut();
                    md.insert("janus-agent-id", idv);
                    md.insert("janus-agent-ts", tsv);
                    md.insert("janus-agent-auth", tokv);
                }
            }
        }
    }
    req
}

// http_client builds a reqwest client that trusts the bundled Root CA (in addition to the
// system trust store) when tls_ca_cert is configured, so the agent can reach a controller
// served with a private PQC/ECDSA PKI over one-way TLS (WP-029 P2). Falls back to a default
// client if the CA file is missing/unreadable/unparseable — plain-HTTP and publicly-trusted
// deployments keep working unchanged.
fn http_client(ca_cert: Option<&str>) -> reqwest::Client {
    if let Some(path) = ca_cert {
        if let Ok(pem) = std::fs::read(path) {
            if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
                if let Ok(client) = reqwest::Client::builder()
                    .add_root_certificate(cert)
                    .build()
                {
                    return client;
                }
            }
        }
    }
    reqwest::Client::new()
}

pub async fn fetch_agent_config(
    addr: &str,
    host_uuid: &str,
    key: &str,
    agent_id: Option<&str>,
    agent_key: Option<&str>,
    ca_cert: Option<&str>,
) -> Result<RemoteScanConfig> {
    let req = http_client(ca_cert)
        .get(format!("{}/api/agent/config", addr.trim_end_matches('/')))
        .query(&[("host_uuid", host_uuid)])
        .header("X-Janus-Agent-Token", agent_token(host_uuid, key)?)
        .timeout(std::time::Duration::from_secs(3));
    let req = with_per_agent_auth(req, agent_id, agent_key, "GET", "/api/agent/config");
    Ok(req.send().await?.error_for_status()?.json().await?)
}

pub async fn poll_scan_command(
    addr: &str,
    host_uuid: &str,
    key: &str,
    agent_id: Option<&str>,
    agent_key: Option<&str>,
    ca_cert: Option<&str>,
) -> Result<bool> {
    let req = http_client(ca_cert)
        .get(format!(
            "{}/api/agent/scan-command",
            addr.trim_end_matches('/')
        ))
        .query(&[("host_uuid", host_uuid)])
        .header("X-Janus-Agent-Token", agent_token(host_uuid, key)?)
        .timeout(std::time::Duration::from_secs(3));
    let req = with_per_agent_auth(req, agent_id, agent_key, "GET", "/api/agent/scan-command");
    let response = req.send().await?;
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

    let aid = cfg.agent_id.as_deref();
    let akey = cfg.agent_key.as_deref();

    let ack = client
        .register_agent(with_grpc_agent_auth(
            tonic::Request::new(reg.clone()),
            aid,
            akey,
        ))
        .await
        .context("register agent")?
        .into_inner();
    if !ack.accepted {
        anyhow::bail!("controller rejected registration: {}", ack.message);
    }

    let payloads = db.pending_payloads(256).context("load pending telemetry")?;
    let payload_ids: Vec<String> = payloads.iter().map(|p| p.telemetry_id.clone()).collect();
    let response = client
        .stream_telemetry(with_grpc_agent_auth(
            tonic::Request::new(iter(payloads)),
            aid,
            akey,
        ))
        .await
        .context("stream telemetry")?;
    let mut command_stream = response.into_inner();

    let mut reports = Vec::<MigrationStatusReport>::new();
    let mut scan_requested = false;
    while let Some(command) = command_stream.message().await.context("receive command")? {
        // UX-001 scan-control verbs are addressed to "janus-agent" and never reach
        // the HMAC-signed mutation path. scan-now/scan-target trigger a scan;
        // pause/resume/cancel toggle the cooperative flags the scan loop checks.
        if command.target_service == "janus-agent" {
            let mut output = "";
            let mut handled = true;
            match command.migration_profile.as_str() {
                "scan-now" => {
                    crate::discovery::status::clear_cancel();
                    scan_requested = true;
                    output = "Scan command accepted; collection is starting";
                }
                "scan-target" => {
                    crate::discovery::status::clear_cancel();
                    if !command.config_path.is_empty() {
                        crate::discovery::status::set_scan_root_override(
                            command.config_path.clone(),
                        );
                    }
                    scan_requested = true;
                    output = "Targeted scan accepted; collection is starting";
                }
                "scan-pause" => {
                    crate::discovery::status::set_paused(true);
                    output = "Scan paused";
                }
                "scan-resume" => {
                    crate::discovery::status::set_paused(false);
                    output = "Scan resumed";
                }
                "scan-cancel" => {
                    crate::discovery::status::request_cancel();
                    output = "Scan cancellation requested";
                }
                _ => handled = false,
            }
            if handled {
                reports.push(MigrationStatusReport {
                    command_id: command.command_id,
                    host_uuid: reg.host_uuid.clone(),
                    state: crate::proto::MigrationState::Applying as i32,
                    success: true,
                    error_vector: String::new(),
                    output: output.to_string(),
                    validation_signatures: Vec::new(),
                    observed_tls: None,
                    reported_at_unix: crate::discovery::now_fn(),
                });
                continue;
            }
        }
        let report = active.execute(command).await;
        reports.push(report);
    }

    if !reports.is_empty() {
        client
            .report_migration_status(with_grpc_agent_auth(
                tonic::Request::new(iter(reports.clone())),
                aid,
                akey,
            ))
            .await
            .context("report migration status")?;
    }

    for id in &payload_ids {
        db.delete_payload(id)?;
    }
    db.audit(
        "sync",
        &format!(
            "host_uuid={} uploaded={} telemetry_ids=[{}] commands={}",
            reg.host_uuid,
            payload_ids.len(),
            payload_ids.join(","),
            reports.len()
        ),
    )?;
    // Emit the telemetry IDs so an upload can be correlated with the server-side
    // "telemetry received" log and the DB audit trail (OPS-004).
    if !payload_ids.is_empty() {
        eprintln!(
            "telemetry uploaded: host_uuid={} count={} telemetry_ids=[{}]",
            reg.host_uuid,
            payload_ids.len(),
            payload_ids.join(",")
        );
    }

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
    ca_cert: Option<String>,
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
                "files_skipped": state.files_skipped.load(Ordering::SeqCst),
                "metrics_present": true
            });

            if let Ok(payload) = serde_json::to_string(&body) {
                if let Err(error) =
                    post_heartbeat(&http_endpoint, &payload, ca_cert.as_deref()).await
                {
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
                match post_diagnostics(&http_endpoint, &host_uuid, &diag_logs, ca_cert.as_deref())
                    .await
                {
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

pub async fn publish_scan_state(addr: &str, host_uuid: &str, ca_cert: Option<&str>) -> Result<()> {
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
        "files_skipped": state.files_skipped.load(Ordering::SeqCst),
        "metrics_present": false
    });
    post_heartbeat(addr, &body.to_string(), ca_cert).await
}

async fn post_heartbeat(addr: &str, body: &str, ca_cert: Option<&str>) -> anyhow::Result<()> {
    http_client(ca_cert)
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

async fn post_diagnostics(
    addr: &str,
    host_uuid: &str,
    logs: &str,
    ca_cert: Option<&str>,
) -> anyhow::Result<()> {
    // reqwest (not a hand-rolled raw TCP request) so the diagnostics channel honors the
    // bundled Root CA over one-way TLS like the other HTTP endpoints (WP-029 P2).
    let payload = serde_json::json!({
        "host_uuid": host_uuid,
        "logs": logs
    })
    .to_string();
    http_client(ca_cert)
        .post(format!(
            "{}/api/agent/diagnostics",
            addr.trim_end_matches('/')
        ))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(payload)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-language parity (WP-029 P1): per_agent_token must produce the exact same
    // token as the server's agentauth.Token for the gRPC binding. The expected value
    // was generated from the Go agentauth package with the same key/inputs; if either
    // side's canonical string changes, this vector breaks and flags the mismatch.
    #[test]
    fn grpc_token_matches_server_vector() {
        let key_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let tok = per_agent_token("agent-7", key_hex, "GRPC", "janus.telemetry", 1_700_000_000)
            .expect("token");
        assert_eq!(
            tok,
            "3b1199d017cb9a112aa080df716724a6ae916918a5935cf07875014b41f2175d"
        );
    }

    #[test]
    fn per_agent_token_is_deterministic() {
        let k = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let a = per_agent_token("a1", k, "GET", "/api/agent/config", 42).unwrap();
        let b = per_agent_token("a1", k, "GET", "/api/agent/config", 42).unwrap();
        assert_eq!(a, b);
        // Distinct binding inputs yield distinct tokens.
        let c = per_agent_token("a1", k, "GRPC", "/api/agent/config", 42).unwrap();
        assert_ne!(a, c);
    }
}
