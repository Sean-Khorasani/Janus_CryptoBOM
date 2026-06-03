use crate::{
    config::AgentConfig,
    proto::{Evidence, NetworkObservation},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{net::TcpStream, process::Command, time::timeout};
use uuid::Uuid;

#[derive(Default)]
pub struct NetworkScanResult {
    pub observations: Vec<NetworkObservation>,
    pub evidence: Vec<Evidence>,
}

pub async fn scan(cfg: &AgentConfig) -> Result<NetworkScanResult> {
    let mut out = NetworkScanResult::default();
    for target in &cfg.network_targets {
        if target.ends_with(":80") {
            out.observations.push(NetworkObservation {
                endpoint: target.clone(),
                protocol: "http".to_string(),
                tls_version: String::new(),
                cipher_suite: String::new(),
                named_group: String::new(),
                signature_algorithm: String::new(),
                certificate_subject: String::new(),
                certificate_issuer: String::new(),
                certificate_not_after_unix: 0,
                pqc_hybrid: false,
                cleartext: true,
            });
            out.evidence.push(evidence(target, "cleartext-port-observed", target.as_bytes(), 0.8));
            continue;
        }

        if timeout(Duration::from_secs(3), TcpStream::connect(target)).await.is_err() {
            continue;
        }

        match openssl_probe(target).await {
            Ok((obs, raw)) => {
                out.observations.push(obs);
                out.evidence.push(evidence(target, "openssl-s-client", raw.as_bytes(), 0.78));
            }
            Err(err) => {
                let raw = format!("probe-error:{err}");
                out.evidence.push(evidence(target, "openssl-s-client-error", raw.as_bytes(), 0.3));
            }
        }
    }
    Ok(out)
}

async fn openssl_probe(target: &str) -> Result<(NetworkObservation, String)> {
    let host = target.split(':').next().unwrap_or(target);
    let output = Command::new("openssl")
        .args([
            "s_client",
            "-brief",
            "-tls1_3",
            "-groups",
            "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:P-256:P-384",
            "-servername",
            host,
            "-connect",
            target,
        ])
        .output()
        .await?;
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    let obs = parse_s_client(target, &raw);
    Ok((obs, raw))
}

fn parse_s_client(target: &str, raw: &str) -> NetworkObservation {
    let mut obs = NetworkObservation {
        endpoint: target.to_string(),
        protocol: "tls".to_string(),
        tls_version: String::new(),
        cipher_suite: String::new(),
        named_group: String::new(),
        signature_algorithm: String::new(),
        certificate_subject: String::new(),
        certificate_issuer: String::new(),
        certificate_not_after_unix: 0,
        pqc_hybrid: raw.to_ascii_uppercase().contains("MLKEM") || raw.to_ascii_uppercase().contains("ML-KEM"),
        cleartext: false,
    };
    for line in raw.lines().map(str::trim) {
        if let Some(v) = line.strip_prefix("Protocol version:") {
            obs.tls_version = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Ciphersuite:") {
            obs.cipher_suite = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Peer certificate:") {
            obs.certificate_subject = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Hash used:") {
            obs.signature_algorithm = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Signature type:") {
            let current = obs.signature_algorithm.clone();
            obs.signature_algorithm = format!("{current} {}", v.trim()).trim().to_string();
        } else if let Some(v) = line.strip_prefix("Server Temp Key:") {
            obs.named_group = v.trim().to_string();
            obs.pqc_hybrid = obs.pqc_hybrid || v.to_ascii_uppercase().contains("MLKEM") || v.to_ascii_uppercase().contains("ML-KEM");
        } else if line.contains("X25519MLKEM768") || line.contains("SecP256r1MLKEM768") || line.contains("SecP384r1MLKEM1024") {
            obs.named_group = line.to_string();
            obs.pqc_hybrid = true;
        }
    }
    obs
}

fn evidence(target: &str, tool: &str, raw: &[u8], confidence: f64) -> Evidence {
    let mut h = Sha256::new();
    h.update(raw);
    Evidence {
        evidence_id: Uuid::new_v4().to_string(),
        source_type: "network".to_string(),
        source_tool: tool.to_string(),
        target: target.to_string(),
        collection_time_unix: now(),
        raw_artifact_sha256: hex::encode(h.finalize()),
        confidence,
        sensitivity_class: "handshake-metadata".to_string(),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

