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

const CRYPTO_PACKAGES: &[(&str, &str, f64)] = &[
    // Rust
    ("ring", "ring", 0.95),
    ("rustls", "rustls", 0.95),
    ("boring", "BoringSSL", 0.90),
    ("aws-lc-rs", "AWS-LC", 0.90),
    ("p256", "RustCrypto p256", 0.85),
    ("rsa", "RustCrypto rsa", 0.85),
    ("aes", "RustCrypto aes", 0.85),
    ("ed25519", "RustCrypto ed25519", 0.85),
    // Python
    ("cryptography", "Python cryptography", 0.90),
    ("pyopenssl", "pyOpenSSL", 0.90),
    ("pycryptodome", "PyCryptodome", 0.90),
    ("pycrypto", "PyCrypto", 0.85),
    ("paramiko", "Paramiko (SSH)", 0.75),
    // Java
    ("bouncycastle", "Bouncy Castle", 0.90),
    ("javax.crypto", "Java Cryptography Architecture", 0.90),
    ("tink", "Google Tink", 0.90),
    // JavaScript/Node
    ("node-forge", "node-forge", 0.85),
    ("crypto-js", "crypto-js", 0.85),
    ("jose", "jose (JWT/JWE)", 0.85),
    ("jsonwebtoken", "jsonwebtoken", 0.85),
    ("jwks-rsa", "jwks-rsa", 0.80),
    ("bcrypt", "bcrypt", 0.85),
    ("argon2", "argon2", 0.85),
    // C/C++ and Rust (OpenSSL is shared across ecosystems)
    ("openssl", "OpenSSL", 0.90),
    ("libsodium", "libsodium", 0.90),
    ("wolfssl", "wolfSSL", 0.90),
    ("mbedtls", "Mbed TLS", 0.90),
    ("botan", "Botan", 0.90),
    ("libressl", "LibreSSL", 0.90),
    // Go
    ("crypto", "Go crypto stdlib", 0.70),
    ("golang.org/x/crypto", "Go x/crypto", 0.90),
    ("github.com/square/go-jose", "go-jose", 0.85),
    ("github.com/golang-jwt", "golang-jwt", 0.85),
    // FHE (Fully Homomorphic Encryption) libraries
    ("tfhe-rs", "TFHE-rs", 0.95),
    ("concrete", "Concrete (Zama)", 0.95),
    ("openfhe", "OpenFHE", 0.90),
    ("seal", "Microsoft SEAL", 0.90),
    ("lattigo", "Lattigo", 0.95),
    ("helib", "HElib", 0.90),
    ("palisade", "PALISADE", 0.85),
    ("tfhe", "TFHE", 0.90),
    // General
    ("age", "age encryption", 0.80),
    ("gpgme", "GPGME", 0.85),
    ("gnupg", "GnuPG", 0.85),
];

/// Dependency needles that identify FHE (Fully Homomorphic Encryption) libraries.
const FHE_NEEDLES: &[&str] = &[
    "tfhe-rs", "concrete", "openfhe", "seal", "lattigo", "helib", "palisade", "tfhe",
];

pub fn scan(cfg: &AgentConfig) -> Result<ScanResult> {
    let mut out = ScanResult::default();
    for root in &cfg.scan_roots {
        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| include_entry(e.path(), cfg))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            super::status::update_progress("Dependency Analysis", entry.path());
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
            let mut has_fhe = false;
            for dep in deps.keys() {
                let dep_l = dep.to_ascii_lowercase();
                for (needle, lib, confidence) in CRYPTO_PACKAGES {
                    if dep_l.contains(needle) {
                        let is_fhe = FHE_NEEDLES.iter().any(|fhe| dep_l.contains(fhe));
                        if is_fhe {
                            has_fhe = true;
                        }
                        let algo_status = if is_fhe {
                            "fhe-capability-detected".to_string()
                        } else {
                            "declared-dependency".to_string()
                        };
                        let algo_family = if is_fhe {
                            "homomorphic-encryption".to_string()
                        } else {
                            "dependency".to_string()
                        };
                        algorithms.push(CryptoAlgorithm {
                            name: "library-crypto-capability".to_string(),
                            family: algo_family,
                            role: CryptoRole::Unspecified as i32,
                            status: algo_status,
                            key_bits: 0,
                            curve: String::new(),
                            implementation_library: lib.to_string(),
                            source_file: entry.path().display().to_string(),
                            source_line: 0,
                            source_column: 0,
                            symbol: dep.clone(),
                            confidence: if is_lockfile(entry.path()) {
                                *confidence
                            } else {
                                confidence * 0.75
                            },
                            quantum_vulnerable: false,
                            context_snippet: String::new(),
                        });
                        break; // only first matching package descriptor
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
            let component_type = if has_fhe { "fhe-library" } else { "manifest" };
            out.components.push(CbomComponent {
                bom_ref: format!("manifest:{}", path.replace('\\', "/")),
                name: entry
                    .path()
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                version: String::new(),
                component_type: component_type.to_string(),
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

/// Check whether a path should be included in scanning, using path-component matching
/// so that excluding "target" only matches the directory "target/", not "custom-target/".
fn include_entry(path: &Path, cfg: &AgentConfig) -> bool {
    !path.components().any(|comp| {
        let comp_str = comp.as_os_str().to_string_lossy();
        cfg.exclude_dirs.iter().any(|d| comp_str == d.as_str())
    })
}

fn is_lockfile(path: &Path) -> bool {
    matches!(
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default(),
        "Cargo.lock" | "package-lock.json" | "go.sum" | "poetry.lock" | "Pipfile.lock"
    )
}

fn is_manifest(path: &Path) -> bool {
    matches!(
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default(),
        "go.mod"
            | "go.sum"
            | "package.json"
            | "package-lock.json"
            | "requirements.txt"
            | "pyproject.toml"
            | "pom.xml"
            | "Cargo.toml"
            | "Cargo.lock"
            | "poetry.lock"
            | "Pipfile.lock"
    )
}

fn manifest_type(path: &Path) -> &'static str {
    match path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
    {
        "go.mod" | "go.sum" => "go",
        "package.json" | "package-lock.json" => "npm",
        "requirements.txt" | "pyproject.toml" | "poetry.lock" | "Pipfile.lock" => "python",
        "pom.xml" => "maven",
        "Cargo.toml" | "Cargo.lock" => "cargo",
        _ => "unknown",
    }
}

fn parse_dependencies(path: &Path, text: &str) -> BTreeMap<String, String> {
    match path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
    {
        "package.json" | "package-lock.json" => parse_npm(text),
        "go.mod" => parse_go_mod(text),
        "go.sum" => parse_go_sum(text),
        "requirements.txt" => parse_requirements(text),
        "poetry.lock" => parse_poetry_lock(text),
        "Pipfile.lock" => parse_pipfile_lock(text),
        "Cargo.toml" | "Cargo.lock" => parse_cargo(text),
        "pom.xml" => parse_maven(text),
        _ => BTreeMap::new(),
    }
}

fn parse_npm(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        for key in [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ] {
            if let Some(obj) = v.get(key).and_then(|x| x.as_object()) {
                for (name, version) in obj {
                    out.insert(name.clone(), version.as_str().unwrap_or("").to_string());
                }
            }
        }
        if let Some(obj) = v.get("packages").and_then(|x| x.as_object()) {
            for (path, meta) in obj {
                if let Some(name) = path.strip_prefix("node_modules/") {
                    out.insert(
                        name.to_string(),
                        meta.get("version")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                    );
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
            let parts: Vec<_> = line
                .trim_start_matches("require ")
                .split_whitespace()
                .collect();
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
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (name, version) = line.split_once("==").unwrap_or((line, ""));
        out.insert(name.to_string(), version.to_string());
    }
    out
}

fn parse_cargo(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut in_deps = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with("[dependencies")
            || line.starts_with("[dev-dependencies")
            || line.starts_with("[build-dependencies")
        {
            in_deps = true;
            continue;
        }
        if line.starts_with('[') {
            in_deps = false;
        }
        if in_deps {
            if let Some((name, version)) = line.split_once('=') {
                out.insert(
                    name.trim().to_string(),
                    version.trim().trim_matches('"').to_string(),
                );
            }
        }
        if line.starts_with("name = ") {
            let name = line
                .trim_start_matches("name = ")
                .trim_matches('"')
                .to_string();
            out.entry(name).or_default();
        }
        if line.starts_with("version = ") {
            if let Some((last, _)) = out.iter().next_back().map(|(k, v)| (k.clone(), v.clone())) {
                if out.get(&last).map(|v| v.is_empty()).unwrap_or(false) {
                    out.insert(
                        last,
                        line.trim_start_matches("version = ")
                            .trim_matches('"')
                            .to_string(),
                    );
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

/// Parse go.sum — each line: `module version h1:hash`
fn parse_go_sum(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            // Only keep non-go.mod entries (actual package downloads)
            if !parts[1].ends_with("/go.mod") {
                out.entry(parts[0].to_string())
                    .or_insert_with(|| parts[1].to_string());
            }
        }
    }
    out
}

/// Parse poetry.lock — TOML-like: `[[package]]` blocks with `name` and `version` keys
fn parse_poetry_lock(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line == "[[package]]" {
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                out.insert(name, version);
            }
        } else if let Some(rest) = line.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            current_version = Some(rest.trim_matches('"').to_string());
        }
    }
    if let (Some(name), Some(version)) = (current_name, current_version) {
        out.insert(name, version);
    }
    out
}

/// Parse Pipfile.lock — JSON with `{"default": {"package": {"version": "==x.y.z"}}, "develop": {...}}`
fn parse_pipfile_lock(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        for section in &["default", "develop"] {
            if let Some(obj) = v.get(section).and_then(|x| x.as_object()) {
                for (pkg, meta) in obj {
                    let version = meta
                        .get("version")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .trim_start_matches("==")
                        .to_string();
                    out.insert(pkg.clone(), version);
                }
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
