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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
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
