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

    let reg = host::registration(&cfg).context("build registration")?;
    let active = mutation::MutationEngine::new(cfg.clone());

    loop {
        let mut payload = discovery::collect(&cfg, &reg.host_uuid).await.context("collect telemetry")?;
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
