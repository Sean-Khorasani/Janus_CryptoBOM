use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use uuid::Uuid;
use walkdir::WalkDir;

struct Pattern {
    regex: Regex,
    name: &'static str,
    family: &'static str,
    role: CryptoRole,
}

fn strip_comments_and_strings(text: &str, ext: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut string_char = '\0';
    let mut is_escaped = false;
    
    let mut in_triple_string = false;
    let mut triple_char = '\0';
    
    let mut in_xml_comment = false;

    let is_c_like = matches!(ext, "rs" | "go" | "js" | "jsx" | "ts" | "tsx" | "java" | "kt" | "cs" | "c" | "h" | "cpp" | "hpp" | "swift" | "m" | "mm" | "scala" | "php");
    let is_script = matches!(ext, "py" | "rb" | "sh" | "yaml" | "yml" | "toml" | "conf" | "cnf");
    let is_xml = matches!(ext, "xml");

    while i < chars.len() {
        let c = chars[i];
        
        if c == '\n' || c == '\r' {
            in_line_comment = false;
            if in_string && string_char != '`' {
                in_string = false;
                string_char = '\0';
            }
            out.push(c);
            i += 1;
            continue;
        }

        if in_line_comment {
            out.push(' ');
            i += 1;
            continue;
        }

        if in_block_comment {
            if is_c_like && i + 1 < chars.len() && chars[i] == '*' && chars[i+1] == '/' {
                out.push(' ');
                out.push(' ');
                i += 2;
                in_block_comment = false;
            } else {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        if in_xml_comment {
            if i + 2 < chars.len() && chars[i] == '-' && chars[i+1] == '-' && chars[i+2] == '>' {
                out.push(' ');
                out.push(' ');
                out.push(' ');
                i += 3;
                in_xml_comment = false;
            } else {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        if in_triple_string {
            let tc = triple_char;
            if i + 2 < chars.len() && chars[i] == tc && chars[i+1] == tc && chars[i+2] == tc {
                out.push(' ');
                out.push(' ');
                out.push(' ');
                i += 3;
                in_triple_string = false;
                triple_char = '\0';
            } else {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        if in_string {
            if is_escaped {
                out.push(' ');
                i += 1;
                is_escaped = false;
            } else if c == '\\' {
                out.push(' ');
                i += 1;
                is_escaped = true;
            } else if c == string_char {
                out.push(' ');
                i += 1;
                in_string = false;
                string_char = '\0';
            } else {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        if is_c_like && i + 1 < chars.len() && chars[i] == '/' && chars[i+1] == '*' {
            in_block_comment = true;
            out.push(' ');
            out.push(' ');
            i += 2;
            continue;
        }

        if is_xml && i + 3 < chars.len() && chars[i] == '<' && chars[i+1] == '!' && chars[i+2] == '-' && chars[i+3] == '-' {
            in_xml_comment = true;
            out.push(' ');
            out.push(' ');
            out.push(' ');
            out.push(' ');
            i += 4;
            continue;
        }

        if is_c_like && i + 1 < chars.len() && chars[i] == '/' && chars[i+1] == '/' {
            in_line_comment = true;
            out.push(' ');
            out.push(' ');
            i += 2;
            continue;
        }

        if is_script && c == '#' {
            in_line_comment = true;
            out.push(' ');
            i += 1;
            continue;
        }

        if ext == "py" && i + 2 < chars.len() {
            let tc = chars[i];
            if (tc == '"' || tc == '\'') && chars[i+1] == tc && chars[i+2] == tc {
                in_triple_string = true;
                triple_char = tc;
                out.push(' ');
                out.push(' ');
                out.push(' ');
                i += 3;
                continue;
            }
        }

        if c == '"' || c == '\'' || (is_c_like && c == '`') {
            in_string = true;
            string_char = c;
            out.push(' ');
            i += 1;
            continue;
        }

        out.push(c);
        i += 1;
    }
    
    out
}

pub fn scan(cfg: &AgentConfig) -> Result<ScanResult> {
    let patterns = patterns()?;
    let mut out = ScanResult::default();
    for root in &cfg.scan_roots {
        for entry in WalkDir::new(root).into_iter().filter_entry(|e| include_entry(e.path(), cfg)) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_file() || !is_source(entry.path()) {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.len() > cfg.max_file_bytes {
                continue;
            }
            let raw = match fs::read(entry.path()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let text = String::from_utf8_lossy(&raw);
            let ext = entry.path().extension().and_then(|s| s.to_str()).unwrap_or_default().to_ascii_lowercase();
            let stripped = strip_comments_and_strings(&text, &ext);
            let mut algorithms = Vec::new();
            
            // Zip lines to perform line-by-line comparison
            for (line_idx, (line, stripped_line)) in text.lines().zip(stripped.lines()).enumerate() {
                for pat in &patterns {
                    if let Some(m) = pat.regex.find(stripped_line) {
                        algorithms.push(CryptoAlgorithm {
                            name: pat.name.to_string(),
                            family: pat.family.to_string(),
                            role: pat.role as i32,
                            status: "observed".to_string(),
                            key_bits: infer_key_bits(pat.name, line),
                            curve: infer_curve(line),
                            implementation_library: infer_library(line),
                            source_file: entry.path().display().to_string(),
                            source_line: (line_idx + 1) as u32,
                            source_column: (m.start() + 1) as u32,
                            symbol: m.as_str().to_string(),
                            confidence: 0.90,
                            quantum_vulnerable: false,
                        });
                    } else if let Some(m) = pat.regex.find(line) {
                        algorithms.push(CryptoAlgorithm {
                            name: pat.name.to_string(),
                            family: pat.family.to_string(),
                            role: pat.role as i32,
                            status: "observed".to_string(),
                            key_bits: infer_key_bits(pat.name, line),
                            curve: infer_curve(line),
                            implementation_library: infer_library(line),
                            source_file: entry.path().display().to_string(),
                            source_line: (line_idx + 1) as u32,
                            source_column: (m.start() + 1) as u32,
                            symbol: m.as_str().to_string(),
                            confidence: 0.30,
                            quantum_vulnerable: false,
                        });
                    }
                }
            }
            if algorithms.is_empty() {
                continue;
            }
            let file_hash = sha256_hex(&raw);
            let path = entry.path().display().to_string();
            let evidence_id = Uuid::new_v4().to_string();
            out.evidence.push(Evidence {
                evidence_id,
                source_type: "source-code".to_string(),
                source_tool: "janus-agent-static-patterns".to_string(),
                target: path.clone(),
                collection_time_unix: now(),
                raw_artifact_sha256: file_hash,
                confidence: 0.90,
                sensitivity_class: "metadata-only".to_string(),
            });
            out.components.push(CbomComponent {
                bom_ref: format!("file:{}", path.replace('\\', "/")),
                name: entry
                    .path()
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                version: String::new(),
                component_type: "file".to_string(),
                purl: String::new(),
                file_path: path,
                language: language(entry.path()),
                algorithms,
                dependencies: Vec::new(),
                reachable: true,
            });
        }
    }
    Ok(out)
}

fn patterns() -> Result<Vec<Pattern>> {
    let defs = [
        (r"\bRSA(_|\b|\.|::|With|with)", "RSA", "RSA", CryptoRole::Signature),
        (r"\bECDSA\b|\becdsa\b", "ECDSA", "ECC", CryptoRole::Signature),
        (r"\bECDH(E)?\b|\becdh\b", "ECDHE", "ECC", CryptoRole::KeyExchange),
        (r"\bDiffieHellman\b|\bDH_generate\b|\bdiffie[-_]?hellman\b", "DH", "DH", CryptoRole::KeyExchange),
        (r"\bML[-_]?KEM[-_]?(512|768|1024)?\b|\bKyber\b", "ML-KEM", "ML-KEM", CryptoRole::Kem),
        (r"\bML[-_]?DSA[-_]?(44|65|87)?\b|\bDilithium\b", "ML-DSA", "ML-DSA", CryptoRole::Signature),
        (r"\bSLH[-_]?DSA\b|\bSPHINCS\+?\b", "SLH-DSA", "SLH-DSA", CryptoRole::Signature),
        (r"\bAES[-_]?128\b|\bAES_128\b", "AES-128", "AES", CryptoRole::Symmetric),
        (r"\bAES[-_]?256\b|\bAES_256\b", "AES-256", "AES", CryptoRole::Symmetric),
        (r"\bDES\b|\b3DES\b|\bRC4\b", "legacy-symmetric", "legacy", CryptoRole::Symmetric),
        (r"\bMD5\b", "MD5", "hash", CryptoRole::Hash),
        (r"\bSHA1\b|\bSHA-1\b", "SHA-1", "hash", CryptoRole::Hash),
        (r"\bSHA384\b|\bSHA-384\b", "SHA-384", "hash", CryptoRole::Hash),
        (r"\bSHA512\b|\bSHA-512\b", "SHA-512", "hash", CryptoRole::Hash),
        (r"\bSecureRandom\b|\brand\.Reader\b|\bgetrandom\b|\bBCryptGenRandom\b", "secure-random", "random", CryptoRole::Random),
    ];
    defs.iter()
        .map(|(re, name, family, role)| {
            Ok(Pattern {
                regex: Regex::new(re)?,
                name,
                family,
                role: *role,
            })
        })
        .collect()
}

fn include_entry(path: &Path, cfg: &AgentConfig) -> bool {
    let s = path.to_string_lossy();
    !cfg.exclude_dirs.iter().any(|d| s.contains(d))
}

fn is_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()).unwrap_or_default(),
        "rs" | "go" | "js" | "jsx" | "ts" | "tsx" | "py" | "java" | "kt" | "cs" | "c" | "h" | "cpp" | "hpp" | "rb" | "php" | "swift" | "m" | "mm" | "scala" | "sh" | "yaml" | "yml" | "toml" | "xml" | "conf" | "cnf"
    )
}

fn language(path: &Path) -> String {
    match path.extension().and_then(|s| s.to_str()).unwrap_or_default() {
        "rs" => "rust",
        "go" => "go",
        "js" | "jsx" | "ts" | "tsx" => "javascript",
        "py" => "python",
        "java" | "kt" | "scala" => "jvm",
        "cs" => ".net",
        "c" | "h" | "cpp" | "hpp" => "native",
        "conf" | "cnf" | "yaml" | "yml" | "toml" | "xml" => "config",
        _ => "unknown",
    }
    .to_string()
}

fn infer_library(line: &str) -> String {
    let l = line.to_ascii_lowercase();
    for lib in ["openssl", "boringssl", "crypto", "javax.crypto", "cryptography", "bcrypt", "commoncrypto", "ring", "rustls"] {
        if l.contains(lib) {
            return lib.to_string();
        }
    }
    String::new()
}

fn infer_key_bits(name: &str, line: &str) -> u32 {
    if name == "AES-128" {
        return 128;
    }
    if name == "AES-256" {
        return 256;
    }
    for bits in [1024_u32, 2048, 3072, 4096] {
        if line.contains(&bits.to_string()) {
            return bits;
        }
    }
    0
}

fn infer_curve(line: &str) -> String {
    let l = line.to_ascii_lowercase();
    for curve in ["p-256", "prime256v1", "secp256r1", "p-384", "secp384r1", "x25519", "x448"] {
        if l.contains(curve) {
            return curve.to_string();
        }
    }
    String::new()
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

