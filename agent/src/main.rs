mod comms;
mod config;
mod discovery;
mod host;
mod mutation;
mod policy;
mod proto;
mod report;
mod storage;

use anyhow::{Context, Result};
use clap::Parser;
use config::AgentConfig;
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
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(Commands::Check { path }) = args.command {
        let mut cfg = if std::path::Path::new(&args.config).exists() {
            AgentConfig::load(&args.config).context("load config")?
        } else {
            AgentConfig::default()
        };
        cfg.scan_roots = vec![path.clone()];
        cfg.report_path = String::new();
        cfg.sarif_path = String::new();

        let mut payload = discovery::collect_static(&cfg)
            .context("collect telemetry")?;
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
                    finding.policy_rule_id,
                    finding.title,
                    severity_str,
                    finding.asset_ref
                );
            }
            std::process::exit(1);
        } else {
            println!("No vulnerable cryptography found. Check passed.");
            std::process::exit(0);
        }
    }

    let cfg = AgentConfig::load(&args.config).context("load config")?;
    let db = storage::OfflineStore::open(&cfg.cache_path).context("open offline cache")?;
    db.ensure_schema().context("ensure offline cache schema")?;
    db.perform_maintenance().ok();
    discovery::status::run_self_test(&cfg);

    if let Ok(prev) = db.get_stat("total_files_scanned") {
        if prev > 0 {
            discovery::status::PREVIOUS_TOTAL_FILES.store(prev, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let reg = host::registration(&cfg).context("build registration")?;
    let active = mutation::MutationEngine::new(cfg.clone());

    comms::start_heartbeat_loop(cfg.http_endpoint(), reg.host_uuid.clone()).await;

    loop {
        discovery::status::SharedScanState::global().total_files_scanned.store(0, std::sync::atomic::Ordering::SeqCst);
        discovery::status::SharedScanState::global().scan_progress.store(0, std::sync::atomic::Ordering::SeqCst);

        let mut payload = discovery::collect(&cfg, &reg.host_uuid).await.context("collect telemetry")?;
        
        let total_scanned = discovery::status::SharedScanState::global().total_files_scanned.load(std::sync::atomic::Ordering::SeqCst);
        db.set_stat("total_files_scanned", total_scanned).ok();
        discovery::status::set_phase("Idle");

        policy::assess(&mut payload);
        if !cfg.report_path.is_empty() {
            report::write_html_report(&cfg.report_path, &payload).context("write local report")?;
        }
        if !cfg.sarif_path.is_empty() {
            report::write_sarif_report(&cfg.sarif_path, &payload).context("write SARIF report")?;
        }
        db.enqueue_payload(&payload).context("queue telemetry")?;

        match comms::sync_once(&cfg, &db, &reg, &active).await {
            Ok(summary) => {
                eprintln!(
                    "sync complete: registered={} uploaded={} commands={}",
                    summary.registered, summary.uploaded, summary.commands
                );
            }
            Err(err) => {
                eprintln!("sync deferred: {err:#}");
            }
        }

        if args.once {
            break;
        }
        tokio::time::sleep(Duration::from_secs(cfg.scan_interval_seconds)).await;
    }

    Ok(())
}
