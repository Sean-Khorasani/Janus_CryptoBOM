use super::ScanResult;
use crate::{
    config::{AgentConfig, PluginCommandConfig},
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::{process::Command, time::{timeout, Duration}};
use uuid::Uuid;

pub async fn scan(cfg: &AgentConfig) -> Result<ScanResult> {
    let mut out = ScanResult::default();
    for plugin in &cfg.plugin_commands {
        match run_plugin(plugin).await {
            Ok(raw) => ingest_plugin_output(&mut out, plugin, &raw),
            Err(err) => {
                let raw = format!("plugin {} failed: {err:#}", plugin.name);
                out.evidence.push(evidence(plugin, &raw, 0.25));
            }
        }
    }
    Ok(out)
}

async fn run_plugin(plugin: &PluginCommandConfig) -> Result<String> {
    let output = timeout(
        Duration::from_secs(plugin.timeout_seconds.max(1)),
        Command::new(&plugin.command).args(&plugin.args).output(),
    )
    .await??;
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(raw)
}

fn ingest_plugin_output(out: &mut ScanResult, plugin: &PluginCommandConfig, raw: &str) {
    out.evidence.push(evidence(plugin, raw, 0.64));
    let algorithms = extract_algorithms(raw, &plugin.name);
    if algorithms.is_empty() {
        return;
    }
    out.components.push(CbomComponent {
        bom_ref: format!("plugin:{}:{}", plugin.name, hash_short(raw)),
        name: plugin.name.clone(),
        version: String::new(),
        component_type: "agent-plugin-output".to_string(),
        purl: String::new(),
        file_path: plugin.command.clone(),
        language: "plugin".to_string(),
        algorithms,
        dependencies: Vec::new(),
        reachable: true,
    });
}

fn extract_algorithms(raw: &str, plugin_name: &str) -> Vec<CryptoAlgorithm> {
    let lower = raw.to_ascii_lowercase();
    let mut out = Vec::new();
    for (needle, name, family, role) in [
        ("ml-kem", "ML-KEM", "ML-KEM", CryptoRole::Kem),
        ("mlkem", "ML-KEM", "ML-KEM", CryptoRole::Kem),
        ("kyber", "ML-KEM", "ML-KEM", CryptoRole::Kem),
        ("ml-dsa", "ML-DSA", "ML-DSA", CryptoRole::Signature),
        ("mldsa", "ML-DSA", "ML-DSA", CryptoRole::Signature),
        ("dilithium", "ML-DSA", "ML-DSA", CryptoRole::Signature),
        ("slh-dsa", "SLH-DSA", "SLH-DSA", CryptoRole::Signature),
        ("sphincs", "SLH-DSA", "SLH-DSA", CryptoRole::Signature),
        ("rsa", "RSA", "RSA", CryptoRole::Signature),
        ("ecdsa", "ECDSA", "ECC", CryptoRole::Signature),
        ("ecdh", "ECDH", "ECC", CryptoRole::KeyExchange),
        ("diffie", "DH", "DH", CryptoRole::KeyExchange),
        ("sha1", "SHA-1", "hash", CryptoRole::Hash),
        ("sha256", "SHA-256", "hash", CryptoRole::Hash),
        ("aes", "AES", "AES", CryptoRole::Symmetric),
    ] {
        if lower.contains(needle) && !out.iter().any(|a: &CryptoAlgorithm| a.name == name && a.role == role as i32) {
            out.push(CryptoAlgorithm {
                name: name.to_string(),
                family: family.to_string(),
                role: role as i32,
                status: "plugin-observed".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: plugin_name.to_string(),
                source_file: plugin_name.to_string(),
                source_line: 0,
                source_column: 0,
                symbol: needle.to_string(),
                confidence: 0.6,
                quantum_vulnerable: false,
            });
        }
    }
    out
}

fn evidence(plugin: &PluginCommandConfig, raw: &str, confidence: f64) -> Evidence {
    Evidence {
        evidence_id: Uuid::new_v4().to_string(),
        source_type: "agent-plugin".to_string(),
        source_tool: plugin.name.clone(),
        target: format!("{} {}", plugin.command, plugin.args.join(" ")),
        collection_time_unix: now(),
        raw_artifact_sha256: sha256_hex(raw.as_bytes()),
        confidence,
        sensitivity_class: "metadata-only".to_string(),
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn hash_short(s: &str) -> String {
    sha256_hex(s.as_bytes()).chars().take(16).collect()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

