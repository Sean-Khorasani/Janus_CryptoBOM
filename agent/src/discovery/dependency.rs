use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use uuid::Uuid;
use walkdir::WalkDir;

const CRYPTO_PACKAGES: &[(&str, &str)] = &[
    ("openssl", "OpenSSL"),
    ("ring", "ring"),
    ("rustls", "rustls"),
    ("boring", "BoringSSL"),
    ("crypto", "generic crypto"),
    ("cryptography", "Python cryptography"),
    ("pyopenssl", "pyOpenSSL"),
    ("bouncycastle", "Bouncy Castle"),
    ("javax.crypto", "Java Cryptography Architecture"),
    ("node-forge", "node-forge"),
    ("crypto-js", "crypto-js"),
    ("libsodium", "libsodium"),
];

pub fn scan(cfg: &AgentConfig) -> Result<ScanResult> {
    let mut out = ScanResult::default();
    for root in &cfg.scan_roots {
        for entry in WalkDir::new(root).into_iter().filter_entry(|e| include_entry(e.path(), cfg)) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_file() || !is_manifest(entry.path()) {
                continue;
            }
            let raw = match fs::read(entry.path()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if raw.len() as u64 > cfg.max_file_bytes {
                continue;
            }
            let text = String::from_utf8_lossy(&raw);
            let deps = parse_dependencies(entry.path(), &text);
            let mut algorithms = Vec::new();
            for dep in deps.keys() {
                let dep_l = dep.to_ascii_lowercase();
                for (needle, lib) in CRYPTO_PACKAGES {
                    if dep_l.contains(needle) {
                        algorithms.push(CryptoAlgorithm {
                            name: "library-crypto-capability".to_string(),
                            family: "dependency".to_string(),
                            role: CryptoRole::Unspecified as i32,
                            status: "declared-dependency".to_string(),
                            key_bits: 0,
                            curve: String::new(),
                            implementation_library: lib.to_string(),
                            source_file: entry.path().display().to_string(),
                            source_line: 0,
                            source_column: 0,
                            symbol: dep.clone(),
                            confidence: 0.68,
                            quantum_vulnerable: false,
                        });
                    }
                }
            }
            if deps.is_empty() && algorithms.is_empty() {
                continue;
            }
            let path = entry.path().display().to_string();
            out.evidence.push(Evidence {
                evidence_id: Uuid::new_v4().to_string(),
                source_type: "dependency-manifest".to_string(),
                source_tool: "janus-agent-dependency-parser".to_string(),
                target: path.clone(),
                collection_time_unix: now(),
                raw_artifact_sha256: sha256_hex(&raw),
                confidence: 0.76,
                sensitivity_class: "metadata-only".to_string(),
            });
            out.components.push(CbomComponent {
                bom_ref: format!("manifest:{}", path.replace('\\', "/")),
                name: entry.path().file_name().unwrap_or_default().to_string_lossy().to_string(),
                version: String::new(),
                component_type: "manifest".to_string(),
                purl: String::new(),
                file_path: path,
                language: manifest_type(entry.path()).to_string(),
                algorithms,
                dependencies: deps
                    .iter()
                    .map(|(name, version)| format!("{name}@{version}"))
                    .collect(),
                reachable: true,
            });
        }
    }
    Ok(out)
}

fn include_entry(path: &Path, cfg: &AgentConfig) -> bool {
    let s = path.to_string_lossy();
    !cfg.exclude_dirs.iter().any(|d| s.contains(d))
}

fn is_manifest(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|s| s.to_str()).unwrap_or_default(),
        "go.mod" | "package.json" | "package-lock.json" | "requirements.txt" | "pyproject.toml" | "pom.xml" | "Cargo.toml" | "Cargo.lock"
    )
}

fn manifest_type(path: &Path) -> &'static str {
    match path.file_name().and_then(|s| s.to_str()).unwrap_or_default() {
        "go.mod" => "go",
        "package.json" | "package-lock.json" => "npm",
        "requirements.txt" | "pyproject.toml" => "python",
        "pom.xml" => "maven",
        "Cargo.toml" | "Cargo.lock" => "cargo",
        _ => "unknown",
    }
}

fn parse_dependencies(path: &Path, text: &str) -> BTreeMap<String, String> {
    match path.file_name().and_then(|s| s.to_str()).unwrap_or_default() {
        "package.json" | "package-lock.json" => parse_npm(text),
        "go.mod" => parse_go_mod(text),
        "requirements.txt" => parse_requirements(text),
        "Cargo.toml" | "Cargo.lock" => parse_cargo(text),
        "pom.xml" => parse_maven(text),
        _ => BTreeMap::new(),
    }
}

fn parse_npm(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
            if let Some(obj) = v.get(key).and_then(|x| x.as_object()) {
                for (name, version) in obj {
                    out.insert(name.clone(), version.as_str().unwrap_or("").to_string());
                }
            }
        }
        if let Some(obj) = v.get("packages").and_then(|x| x.as_object()) {
            for (path, meta) in obj {
                if let Some(name) = path.strip_prefix("node_modules/") {
                    out.insert(name.to_string(), meta.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string());
                }
            }
        }
    }
    out
}

fn parse_go_mod(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with("require ") && !line.ends_with('(') {
            let parts: Vec<_> = line.trim_start_matches("require ").split_whitespace().collect();
            if parts.len() >= 2 {
                out.insert(parts[0].to_string(), parts[1].to_string());
            }
        } else if line.contains('/') && line.split_whitespace().count() >= 2 {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts[1].starts_with('v') {
                out.insert(parts[0].to_string(), parts[1].to_string());
            }
        }
    }
    out
}

fn parse_requirements(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (name, version) = line.split_once("==").unwrap_or((line, ""));
        out.insert(name.to_string(), version.to_string());
    }
    out
}

fn parse_cargo(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut in_deps = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with("[dependencies") || line.starts_with("[dev-dependencies") || line.starts_with("[build-dependencies") {
            in_deps = true;
            continue;
        }
        if line.starts_with('[') {
            in_deps = false;
        }
        if in_deps {
            if let Some((name, version)) = line.split_once('=') {
                out.insert(name.trim().to_string(), version.trim().trim_matches('"').to_string());
            }
        }
        if line.starts_with("name = ") {
            let name = line.trim_start_matches("name = ").trim_matches('"').to_string();
            out.entry(name).or_default();
        }
        if line.starts_with("version = ") {
            if let Some((last, _)) = out.iter().next_back().map(|(k, v)| (k.clone(), v.clone())) {
                if out.get(&last).map(|v| v.is_empty()).unwrap_or(false) {
                    out.insert(last, line.trim_start_matches("version = ").trim_matches('"').to_string());
                }
            }
        }
    }
    out
}

fn parse_maven(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut current_artifact = None::<String>;
    for line in text.lines().map(str::trim) {
        if let Some(v) = tag_value(line, "artifactId") {
            current_artifact = Some(v);
        }
        if let Some(v) = tag_value(line, "version") {
            if let Some(name) = current_artifact.take() {
                out.insert(name, v);
            }
        }
    }
    out
}

fn tag_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    line.strip_prefix(&open)
        .and_then(|s| s.strip_suffix(&close))
        .map(ToString::to_string)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

