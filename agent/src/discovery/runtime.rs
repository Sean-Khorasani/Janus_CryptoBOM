use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use sysinfo::{ProcessesToUpdate, System};
use uuid::Uuid;

pub fn scan(_cfg: &AgentConfig) -> Result<ScanResult> {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut out = ScanResult::default();

    for (pid, process) in sys.processes() {
        let mut algorithms = Vec::new();
        let name = process.name().to_string_lossy().to_ascii_lowercase();
        let exe = process
            .exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let joined = format!("{} {}", name, exe.to_ascii_lowercase());
        for (needle, alg, family, role) in [
            ("openssl", "OpenSSL runtime", "OpenSSL", CryptoRole::Unspecified),
            ("nginx", "TLS termination", "TLS", CryptoRole::KeyExchange),
            ("apache", "TLS termination", "TLS", CryptoRole::KeyExchange),
            ("sshd", "SSH key exchange", "SSH", CryptoRole::KeyExchange),
            ("java", "JCA runtime", "JCA", CryptoRole::Unspecified),
            ("node", "Node crypto runtime", "node-crypto", CryptoRole::Unspecified),
        ] {
            if joined.contains(needle) {
                algorithms.push(CryptoAlgorithm {
                    name: alg.to_string(),
                    family: family.to_string(),
                    role: role as i32,
                    status: "process-metadata-observed".to_string(),
                    key_bits: 0,
                    curve: String::new(),
                    implementation_library: needle.to_string(),
                    source_file: exe.clone(),
                    source_line: 0,
                    source_column: 0,
                    symbol: process.name().to_string_lossy().to_string(),
                    confidence: 0.55,
                    quantum_vulnerable: false,
                });
            }
        }
        if algorithms.is_empty() {
            continue;
        }
        let target = format!("pid:{}:{}", pid, process.name().to_string_lossy());
        out.evidence.push(Evidence {
            evidence_id: Uuid::new_v4().to_string(),
            source_type: "runtime-process".to_string(),
            source_tool: "janus-agent-process-metadata".to_string(),
            target: target.clone(),
            collection_time_unix: now(),
            raw_artifact_sha256: hash(&target),
            confidence: 0.55,
            sensitivity_class: "metadata-only".to_string(),
        });
        out.components.push(CbomComponent {
            bom_ref: target,
            name: process.name().to_string_lossy().to_string(),
            version: String::new(),
            component_type: "process".to_string(),
            purl: String::new(),
            file_path: exe,
            language: "runtime".to_string(),
            algorithms,
            dependencies: Vec::new(),
            reachable: true,
        });
    }

    #[cfg(target_os = "linux")]
    scan_linux_maps(&mut out);

    Ok(out)
}

#[cfg(target_os = "linux")]
fn scan_linux_maps(out: &mut ScanResult) {
    use std::fs;
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name().to_string_lossy().to_string();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let maps = entry.path().join("maps");
            let text = match fs::read_to_string(&maps) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let mut libs = Vec::new();
            for line in text.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.contains("libssl") || lower.contains("libcrypto") || lower.contains("boringssl") || lower.contains("libgnutls") {
                    if let Some(path) = line.split_whitespace().last() {
                        libs.push(path.to_string());
                    }
                }
            }
            libs.sort();
            libs.dedup();
            for lib in libs {
                out.components.push(CbomComponent {
                    bom_ref: format!("pid:{pid}:library:{lib}"),
                    name: lib.rsplit('/').next().unwrap_or(&lib).to_string(),
                    version: String::new(),
                    component_type: "loaded-library".to_string(),
                    purl: String::new(),
                    file_path: lib.clone(),
                    language: "native".to_string(),
                    algorithms: vec![CryptoAlgorithm {
                        name: "loaded-crypto-library".to_string(),
                        family: "runtime-library".to_string(),
                        role: CryptoRole::Unspecified as i32,
                        status: "process-map-observed".to_string(),
                        key_bits: 0,
                        curve: String::new(),
                        implementation_library: lib.clone(),
                        source_file: lib.clone(),
                        source_line: 0,
                        source_column: 0,
                        symbol: "process-map".to_string(),
                        confidence: 0.7,
                        quantum_vulnerable: false,
                    }],
                    dependencies: Vec::new(),
                    reachable: true,
                });
            }
        }
    }
}

fn hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

