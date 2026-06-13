use crate::{
    config::AgentConfig,
    proto::{AgentRegistration, ExecutionMode},
};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use sysinfo::System;
use uuid::Uuid;

pub fn registration(cfg: &AgentConfig) -> Result<AgentRegistration> {
    let host_uuid = load_or_create_uuid(&cfg.host_uuid_path)?;
    let hostname = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let mut sys = System::new_all();
    sys.refresh_all();
    let os_name = System::name().unwrap_or_else(|| std::env::consts::OS.to_string());
    let os_version = System::os_version().unwrap_or_default();
    let arch = std::env::consts::ARCH.to_string();
    let execution_mode = if cfg.passive() {
        ExecutionMode::Passive as i32
    } else {
        ExecutionMode::Active as i32
    };

    Ok(AgentRegistration {
        host_uuid,
        hostname,
        hardware_signatures: hardware_signatures(),
        os_name,
        os_version,
        arch,
        execution_mode,
        agent_version: crate::version::full(),
        capabilities: vec![
            "passive-static-source-scan".to_string(),
            "passive-binary-symbol-scan".to_string(),
            "dependency-manifest-scan".to_string(),
            "network-openssl-probe".to_string(),
            "runtime-metadata-inventory".to_string(),
            "signed-active-migration".to_string(),
        ],
        registered_at_unix: now(),
    })
}

fn load_or_create_uuid(path: &str) -> Result<String> {
    let p = Path::new(path);
    if p.exists() {
        return Ok(fs::read_to_string(p)?.trim().to_string());
    }
    if let Some(parent) = p.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("create host uuid directory {}", parent.display()))?;
    }
    let id = Uuid::new_v4().to_string();
    fs::write(p, &id).with_context(|| format!("write host uuid {}", p.display()))?;
    Ok(id)
}

fn hardware_signatures() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(hostname) = hostname::get() {
        out.push(hash_label(
            "hostname",
            hostname.to_string_lossy().as_bytes(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(machine_id) = fs::read("/etc/machine-id") {
            out.push(hash_label("machine-id", &machine_id));
        }
    }
    out.push(hash_label(
        "platform",
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH).as_bytes(),
    ));
    out
}

fn hash_label(label: &str, data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{label}:sha256:{}", hex::encode(h.finalize()))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
