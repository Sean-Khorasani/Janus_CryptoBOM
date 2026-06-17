mod command_cert;
mod command_sig;
mod comms;
mod config;
mod discovery;
pub mod evidence;
mod host;
mod mutation;
mod policy;
mod proto;
mod report;
mod revocation;
mod storage;
mod version;

use anyhow::{Context, Result};
use clap::Parser;
use config::AgentConfig;
use proto::CbomTelemetryPayload;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "janus-agent")]
struct Args {
    #[arg(long, default_value = "janus-agent.toml")]
    config: String,

    #[arg(long)]
    once: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Commands {
    Check {
        #[arg(default_value = ".")]
        path: String,
        /// Only scan files changed between this git ref and HEAD (OPS-007 incremental
        /// CI gate). Falls back to a full scan if git is unavailable.
        #[arg(long, value_name = "GIT_REF")]
        changed_since: Option<String>,
    },
}

/// OPS-007: absolute paths of files changed between `git_ref` and HEAD under `scan_path`.
/// Returns None when git is unavailable (caller does a full scan); Some(list) — possibly
/// empty — otherwise. Deleted files are excluded.
fn changed_files_since(scan_path: &str, git_ref: &str) -> Option<Vec<String>> {
    use std::process::Command;
    let root_out = Command::new("git")
        .args(["-C", scan_path, "rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !root_out.status.success() {
        return None;
    }
    let root = String::from_utf8_lossy(&root_out.stdout).trim().to_string();
    let diff = Command::new("git")
        .args([
            "-C",
            scan_path,
            "diff",
            "--name-only",
            "--diff-filter=d",
            git_ref,
            "HEAD",
        ])
        .output()
        .ok()?;
    if !diff.status.success() {
        return None;
    }
    let files = String::from_utf8_lossy(&diff.stdout)
        .lines()
        .map(|l| {
            std::path::Path::new(&root)
                .join(l)
                .to_string_lossy()
                .to_string()
        })
        .filter(|p| std::path::Path::new(p).is_file())
        .collect();
    Some(files)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(Commands::Check {
        path,
        changed_since,
    }) = args.command
    {
        let mut cfg = if std::path::Path::new(&args.config).exists() {
            AgentConfig::load(&args.config).context("load config")?
        } else {
            AgentConfig::default()
        };
        cfg.scan_roots = vec![path.clone()];
        cfg.report_path = String::new();
        cfg.sarif_path = String::new();

        // OPS-007: restrict the scan to files changed since a git ref, if requested.
        if let Some(git_ref) = &changed_since {
            match changed_files_since(&path, git_ref) {
                Some(files) => {
                    eprintln!(
                        "--changed-since {}: scanning {} changed file(s)",
                        git_ref,
                        files.len()
                    );
                    cfg.scan_roots = files;
                }
                None => eprintln!(
                    "--changed-since {}: git unavailable; scanning full path",
                    git_ref
                ),
            }
        }

        // Run comprehensive offline scan: source + binary + dependency analysis
        let started = discovery::now_fn();
        let mut components = Vec::new();
        let mut evidence = Vec::new();

        // Static source analysis
        let source_result =
            discovery::source::scan(&cfg, false, None, true).context("source scan")?;
        components.extend(source_result.components);
        evidence.extend(source_result.evidence);

        // Binary PE/ELF/Mach-O inspection
        match discovery::binary::scan(&cfg) {
            Ok(result) => {
                components.extend(result.components);
                evidence.extend(result.evidence);
            }
            Err(e) => eprintln!("Binary scan skipped: {e}"),
        }

        // Dependency manifest analysis
        match discovery::dependency::scan(&cfg) {
            Ok(result) => {
                components.extend(result.components);
                evidence.extend(result.evidence);
            }
            Err(e) => eprintln!("Dependency scan skipped: {e}"),
        }

        let finished = discovery::now_fn();
        let cyclone_dx =
            discovery::cbom::render_cyclonedx(&components, &evidence, started, finished)
                .unwrap_or_default();

        let mut payload = CbomTelemetryPayload {
            telemetry_id: uuid::Uuid::new_v4().to_string(),
            host_uuid: "ci-cd-runner".to_string(),
            scan_started_unix: started,
            scan_finished_unix: finished,
            components,
            findings: Vec::new(),
            network_observations: Vec::new(),
            evidence,
            cyclone_dx_json: cyclone_dx,
        };
        policy::assess(&mut payload);

        if !payload.findings.is_empty() {
            for finding in &payload.findings {
                let severity_str = match finding.severity {
                    1 => "Info",
                    2 => "Low",
                    3 => "Medium",
                    4 => "High",
                    5 => "Critical",
                    _ => "Unspecified",
                };
                println!(
                    "Rule ID: {}, Title: {}, Severity: {}, Asset Ref: {}",
                    finding.policy_rule_id, finding.title, severity_str, finding.asset_ref
                );
            }
            std::process::exit(1);
        } else {
            println!("No vulnerable cryptography found. Check passed.");
            std::process::exit(0);
        }
    }

    let mut cfg = AgentConfig::load(&args.config).context("load config")?;
    let db = storage::OfflineStore::open(&cfg.cache_path).context("open offline cache")?;
    db.ensure_schema().context("ensure offline cache schema")?;
    db.perform_maintenance().ok();
    discovery::status::run_self_test(&cfg);

    if let Ok(prev) = db.get_stat("total_files_scanned") {
        if prev > 0 {
            discovery::status::PREVIOUS_TOTAL_FILES
                .store(prev, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let reg = host::registration(&cfg).context("build registration")?;
    let active = mutation::MutationEngine::new(cfg.clone());

    // Heartbeat loop with cancellation support for --once mode
    let (hb_shutdown_tx, hb_shutdown_rx) = tokio::sync::watch::channel(false);
    comms::start_heartbeat_loop(
        cfg.http_endpoint(),
        reg.host_uuid.clone(),
        cfg.tls_ca_cert.clone(),
        hb_shutdown_rx,
    )
    .await;

    loop {
        if let Ok(remote) = comms::fetch_agent_config(
            &cfg.http_endpoint(),
            &reg.host_uuid,
            &cfg.command_signing_key,
            cfg.agent_id.as_deref(),
            cfg.agent_key.as_deref(),
            cfg.tls_ca_cert.as_deref(),
        )
        .await
        {
            if remote.configured {
                if !remote.scan_roots.is_empty() {
                    cfg.scan_roots = remote.scan_roots;
                }
                cfg.exclude_dirs = remote.exclude_dirs;
                discovery::status::set_exclusions(cfg.exclude_dirs.clone());
                cfg.include_extensions = remote.include_extensions;
                if let Some(value) = remote.scan_interval_seconds.filter(|value| {
                    (config::MIN_SCAN_INTERVAL_SECONDS..=config::MAX_SCAN_INTERVAL_SECONDS)
                        .contains(value)
                }) {
                    cfg.scan_interval_seconds = value;
                }
                if let Some(value) = remote.max_file_bytes.filter(|value| {
                    (config::MIN_SCAN_BYTES..=config::MAX_SCAN_BYTES).contains(value)
                }) {
                    cfg.max_file_bytes = value;
                }
                if let Some(value) = remote.max_binary_bytes.filter(|value| {
                    (config::MIN_SCAN_BYTES..=config::MAX_SCAN_BYTES).contains(value)
                }) {
                    cfg.max_binary_bytes = value;
                }
                cfg.network_targets = remote.network_targets;
                if let Some(value) = remote.enable_runtime_discovery {
                    cfg.enable_runtime_discovery = value;
                }
                if let Some(value) = remote.enable_process_memory_scraping {
                    cfg.enable_process_memory_scraping = value && cfg.enable_runtime_discovery;
                }
                if let Some(value) = remote.enable_plugin_discovery {
                    cfg.enable_plugin_discovery = value;
                }
                if let Some(value) = remote.enable_active_tls_probing {
                    cfg.enable_active_tls_probing = value;
                }
            }
        }
        discovery::status::SharedScanState::global()
            .total_files_scanned
            .store(0, std::sync::atomic::Ordering::SeqCst);
        discovery::status::SharedScanState::global()
            .scan_progress
            .store(0, std::sync::atomic::Ordering::SeqCst);
        discovery::status::set_phase("Starting scan");
        let _ = comms::publish_scan_state(
            &cfg.http_endpoint(),
            &reg.host_uuid,
            cfg.tls_ca_cert.as_deref(),
        )
        .await;

        // Daemon scans are incremental: skip files unchanged since the last scan
        // (scan_state cache). The server retains findings for skipped files (OPS-007).
        let mut payload = discovery::collect(&cfg, &reg.host_uuid, Some(&db), false)
            .await
            .context("collect telemetry")?;

        let total_scanned = discovery::status::SharedScanState::global()
            .total_files_scanned
            .load(std::sync::atomic::Ordering::SeqCst);
        db.set_stat("total_files_scanned", total_scanned).ok();
        discovery::status::set_scan_complete(total_scanned);
        let _ = comms::publish_scan_state(
            &cfg.http_endpoint(),
            &reg.host_uuid,
            cfg.tls_ca_cert.as_deref(),
        )
        .await;

        // Policy assessment is server-side during upload; only assess locally for check/offline
        // (assessment runs server-side in StreamTelemetry to avoid duplication)
        if !cfg.report_path.is_empty() {
            policy::assess(&mut payload);
            report::write_html_report(&cfg.report_path, &payload).context("write local report")?;
        }
        if !cfg.sarif_path.is_empty() {
            if payload.findings.is_empty() {
                policy::assess(&mut payload);
            }
            report::write_sarif_report(&cfg.sarif_path, &payload).context("write SARIF report")?;
        }
        db.enqueue_payload(&payload).context("queue telemetry")?;

        let mut scan_requested = false;
        match comms::sync_once(&cfg, &db, &reg, &active).await {
            Ok(summary) => {
                scan_requested = summary.scan_requested;
                eprintln!(
                    "sync complete: registered={} uploaded={} commands={}",
                    summary.registered, summary.uploaded, summary.commands
                );
            }
            Err(err) => {
                eprintln!("sync deferred: {err:#}");
            }
        }
        discovery::status::set_phase("Idle");
        let _ = comms::publish_scan_state(
            &cfg.http_endpoint(),
            &reg.host_uuid,
            cfg.tls_ca_cert.as_deref(),
        )
        .await;

        if args.once {
            // Signal heartbeat loop to stop gracefully
            let _ = hb_shutdown_tx.send(true);
            break;
        }
        if scan_requested {
            continue;
        }
        let mut waited = 0;
        while waited < cfg.scan_interval_seconds {
            tokio::time::sleep(Duration::from_secs(5)).await;
            waited += 5;
            if comms::poll_scan_command(
                &cfg.http_endpoint(),
                &reg.host_uuid,
                &cfg.command_signing_key,
                cfg.agent_id.as_deref(),
                cfg.agent_key.as_deref(),
                cfg.tls_ca_cert.as_deref(),
            )
            .await
            .unwrap_or(false)
            {
                break;
            }
        }
    }

    Ok(())
}
