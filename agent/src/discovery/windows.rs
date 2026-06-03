use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::{process::Command, time::{timeout, Duration}};
use uuid::Uuid;

#[cfg(target_os = "windows")]
pub async fn scan(_cfg: &AgentConfig) -> Result<ScanResult> {
    let mut out = ScanResult::default();
    for (name, args, source_type) in [
        ("certutil", vec!["-store", "-user", "My"], "windows-user-cert-store"),
        ("certutil", vec!["-store", "-user", "Root"], "windows-user-root-store"),
        ("certutil", vec!["-store", "My"], "windows-machine-cert-store"),
        ("certutil", vec!["-store", "Root"], "windows-machine-root-store"),
        ("netsh", vec!["http", "show", "sslcert"], "windows-http-sys-tls-bindings"),
        ("certutil", vec!["-csplist"], "windows-cng-provider-inventory"),
        ("reg", vec!["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL", "/s"], "windows-schannel-policy"),
    ] {
        if let Ok(raw) = run(name, &args).await {
            ingest_command_output(&mut out, source_type, name, &args, &raw);
        }
    }
    Ok(out)
}

#[cfg(not(target_os = "windows"))]
pub async fn scan(_cfg: &AgentConfig) -> Result<ScanResult> {
    Ok(ScanResult::default())
}

async fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = timeout(
        Duration::from_secs(20),
        Command::new(program).args(args).output(),
    )
    .await??;
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(raw)
}

fn ingest_command_output(
    out: &mut ScanResult,
    source_type: &str,
    program: &str,
    args: &[&str],
    raw: &str,
) {
    let target = format!("{} {}", program, args.join(" "));
    out.evidence.push(Evidence {
        evidence_id: Uuid::new_v4().to_string(),
        source_type: source_type.to_string(),
        source_tool: "janus-agent-windows-collector".to_string(),
        target: target.clone(),
        collection_time_unix: now(),
        raw_artifact_sha256: sha256_hex(raw.as_bytes()),
        confidence: 0.78,
        sensitivity_class: "metadata-only".to_string(),
    });

    let mut components = parse_certutil_store(source_type, raw);
    if components.is_empty() {
        components = parse_capabilities(source_type, raw);
    }
    if components.is_empty() && raw.to_ascii_lowercase().contains("ip:port") {
        components.push(CbomComponent {
            bom_ref: format!("windows:http-sys:{}", hash_short(raw)),
            name: "HTTP.sys TLS binding inventory".to_string(),
            version: String::new(),
            component_type: "windows-tls-binding".to_string(),
            purl: String::new(),
            file_path: target,
            language: "windows".to_string(),
            algorithms: vec![CryptoAlgorithm {
                name: "TLS certificate binding".to_string(),
                family: "windows-http-sys".to_string(),
                role: CryptoRole::CertPublicKey as i32,
                status: "binding-observed".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: "HTTP.sys".to_string(),
                source_file: "netsh http show sslcert".to_string(),
                source_line: 0,
                source_column: 0,
                symbol: "sslcert".to_string(),
                confidence: 0.62,
                quantum_vulnerable: false,
            }],
            dependencies: Vec::new(),
            reachable: true,
        });
    }
    if components.is_empty() && source_type == "windows-schannel-policy" {
        components.push(parse_schannel_policy(raw));
    }
    out.components.extend(components);
}

fn parse_certutil_store(source_type: &str, raw: &str) -> Vec<CbomComponent> {
    let mut components = Vec::new();
    let mut subject = String::new();
    let mut issuer = String::new();
    let mut algorithms = Vec::<CryptoAlgorithm>::new();

    for line in raw.lines().map(str::trim) {
        if line.starts_with("================ Certificate") {
            flush_cert(source_type, &mut components, &mut subject, &mut issuer, &mut algorithms);
            continue;
        }
        if let Some(v) = value_after_colon(line, "Subject") {
            subject = v;
        } else if let Some(v) = value_after_colon(line, "Issuer") {
            issuer = v;
        } else if let Some(v) = value_after_colon(line, "Public Key Algorithm") {
            algorithms.push(algorithm_from_windows_line(
                &v,
                CryptoRole::CertPublicKey,
                0,
                "certutil",
            ));
        } else if let Some(v) = value_after_colon(line, "Public Key Length") {
            let bits = first_number(&v);
            if let Some(last) = algorithms.last_mut() {
                last.key_bits = bits;
                if last.name.is_empty() && bits > 0 {
                    last.name = format!("public-key-{bits}");
                }
            }
        } else if let Some(v) = value_after_colon(line, "Signature Algorithm") {
            algorithms.push(algorithm_from_windows_line(
                &v,
                CryptoRole::CertSignature,
                0,
                "certutil",
            ));
        }
    }
    flush_cert(source_type, &mut components, &mut subject, &mut issuer, &mut algorithms);
    components
}

fn parse_capabilities(source_type: &str, raw: &str) -> Vec<CbomComponent> {
    let mut algorithms = Vec::new();
    let lower = raw.to_ascii_lowercase();
    for (needle, name, family, role) in [
        ("rsa", "RSA", "RSA", CryptoRole::Signature),
        ("ecdsa", "ECDSA", "ECC", CryptoRole::Signature),
        ("ecdh", "ECDH", "ECC", CryptoRole::KeyExchange),
        ("sha1", "SHA-1", "hash", CryptoRole::Hash),
        ("sha256", "SHA-256", "hash", CryptoRole::Hash),
        ("aes", "AES", "AES", CryptoRole::Symmetric),
    ] {
        if lower.contains(needle) {
            algorithms.push(CryptoAlgorithm {
                name: name.to_string(),
                family: family.to_string(),
                role: role as i32,
                status: "windows-provider-capability".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: "Windows CNG/CAPI".to_string(),
                source_file: source_type.to_string(),
                source_line: 0,
                source_column: 0,
                symbol: needle.to_string(),
                confidence: 0.58,
                quantum_vulnerable: false,
            });
        }
    }
    if algorithms.is_empty() {
        return Vec::new();
    }
    vec![CbomComponent {
        bom_ref: format!("windows:provider-capabilities:{}", hash_short(raw)),
        name: "Windows cryptographic provider capabilities".to_string(),
        version: String::new(),
        component_type: "windows-crypto-provider".to_string(),
        purl: String::new(),
        file_path: source_type.to_string(),
        language: "windows".to_string(),
        algorithms,
        dependencies: Vec::new(),
        reachable: true,
    }]
}

fn parse_schannel_policy(raw: &str) -> CbomComponent {
    let lower = raw.to_ascii_lowercase();
    let mut algorithms = Vec::new();
    for (needle, name, family, role) in [
        ("tls 1.0", "TLS 1.0", "TLS", CryptoRole::KeyExchange),
        ("tls 1.1", "TLS 1.1", "TLS", CryptoRole::KeyExchange),
        ("tls 1.2", "TLS 1.2", "TLS", CryptoRole::KeyExchange),
        ("tls 1.3", "TLS 1.3", "TLS", CryptoRole::KeyExchange),
        ("rc4", "RC4", "legacy", CryptoRole::Symmetric),
        ("triple des", "3DES", "legacy", CryptoRole::Symmetric),
        ("diffie-hellman", "DH", "DH", CryptoRole::KeyExchange),
        ("ecc", "ECC", "ECC", CryptoRole::KeyExchange),
        ("rsa", "RSA", "RSA", CryptoRole::Signature),
        ("sha", "SHA", "hash", CryptoRole::Hash),
    ] {
        if lower.contains(needle) {
            algorithms.push(CryptoAlgorithm {
                name: name.to_string(),
                family: family.to_string(),
                role: role as i32,
                status: "windows-schannel-policy-observed".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: "Schannel".to_string(),
                source_file: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL".to_string(),
                source_line: 0,
                source_column: 0,
                symbol: needle.to_string(),
                confidence: 0.66,
                quantum_vulnerable: false,
            });
        }
    }
    CbomComponent {
        bom_ref: format!("windows:schannel-policy:{}", hash_short(raw)),
        name: "Windows Schannel policy".to_string(),
        version: String::new(),
        component_type: "windows-schannel-policy".to_string(),
        purl: String::new(),
        file_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL".to_string(),
        language: "windows-registry".to_string(),
        algorithms,
        dependencies: Vec::new(),
        reachable: true,
    }
}

fn flush_cert(
    source_type: &str,
    components: &mut Vec<CbomComponent>,
    subject: &mut String,
    issuer: &mut String,
    algorithms: &mut Vec<CryptoAlgorithm>,
) {
    if subject.is_empty() && issuer.is_empty() && algorithms.is_empty() {
        return;
    }
    let name = if subject.is_empty() {
        "Windows certificate".to_string()
    } else {
        subject.clone()
    };
    components.push(CbomComponent {
        bom_ref: format!("windows:cert:{}:{}", source_type, hash_short(&format!("{subject}{issuer}{:?}", algorithms.len()))),
        name,
        version: String::new(),
        component_type: "certificate".to_string(),
        purl: String::new(),
        file_path: source_type.to_string(),
        language: "windows-cert-store".to_string(),
        algorithms: std::mem::take(algorithms),
        dependencies: if issuer.is_empty() { Vec::new() } else { vec![issuer.clone()] },
        reachable: true,
    });
    subject.clear();
    issuer.clear();
}

fn algorithm_from_windows_line(
    line: &str,
    role: CryptoRole,
    key_bits: u32,
    library: &str,
) -> CryptoAlgorithm {
    let lower = line.to_ascii_lowercase();
    let (name, family) = if lower.contains("sha1") || lower.contains("sha-1") {
        ("SHA-1".to_string(), "hash".to_string())
    } else if lower.contains("sha256") || lower.contains("sha-256") {
        ("SHA-256".to_string(), "hash".to_string())
    } else if lower.contains("sha384") || lower.contains("sha-384") {
        ("SHA-384".to_string(), "hash".to_string())
    } else if lower.contains("ecdsa") || lower.contains("ecc") || lower.contains("ecpublickey") {
        ("ECDSA/ECC".to_string(), "ECC".to_string())
    } else if lower.contains("rsa") {
        ("RSA".to_string(), "RSA".to_string())
    } else {
        (line.to_string(), "windows-crypto".to_string())
    };
    CryptoAlgorithm {
        name,
        family,
        role: role as i32,
        status: "windows-cert-store-observed".to_string(),
        key_bits,
        curve: String::new(),
        implementation_library: library.to_string(),
        source_file: "certutil".to_string(),
        source_line: 0,
        source_column: 0,
        symbol: line.to_string(),
        confidence: 0.74,
        quantum_vulnerable: false,
    }
}

fn value_after_colon(line: &str, key: &str) -> Option<String> {
    line.strip_prefix(key)
        .and_then(|v| v.strip_prefix(':'))
        .map(|v| v.trim().to_string())
}

fn first_number(s: &str) -> u32 {
    let digits: String = s
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().unwrap_or(0)
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
