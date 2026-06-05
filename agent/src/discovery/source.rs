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

fn analyze_snippet_llm_sync(http_endpoint: &str, name: &str, source_file: &str, snippet: &str) -> Result<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let host_port = http_endpoint
        .strip_prefix("http://")
        .unwrap_or(http_endpoint)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:8080");

    let prompt = format!(
        "You are a cryptography security expert. Analyze the following code snippet which contains a reference to the cryptographic algorithm '{}'. Classify the usage intent into exactly one of the following categories: 'protect', 'verify', 'negotiate', 'test'. Reply with a JSON object exactly matching this format: {{\"intent\": \"one-of-the-categories\", \"confidence\": 0.9}}\nCode Snippet (from {}):\n{}",
        name, source_file, snippet
    );

    let body_json = serde_json::json!({
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.0
    }).to_string();

    let mut stream = TcpStream::connect(host_port)?;
    let req = format!(
        "POST /api/llm/proxy HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        host_port,
        body_json.len(),
        body_json
    );
    stream.write_all(req.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    if let Some(idx) = response.find("\r\n\r\n") {
        let body = &response[idx + 4..];
        let val: serde_json::Value = serde_json::from_str(body)?;
        
        if let Some(choices) = val.get("choices") {
            if let Some(content) = choices[0]["message"]["content"].as_str() {
                let clean = content.replace("```json", "").replace("```", "").trim().to_string();
                let parsed: serde_json::Value = serde_json::from_str(&clean)?;
                if let Some(intent) = parsed.get("intent").and_then(|i| i.as_str()) {
                    return Ok(intent.to_string());
                }
            }
        }
    }
    
    anyhow::bail!("failed to parse LLM response")
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
            super::status::update_progress("Static Source Analysis", entry.path());
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
            
            let is_test_file = is_test_path(entry.path());
            let text_lines: Vec<&str> = text.lines().collect();
            let stripped_lines: Vec<&str> = stripped.lines().collect();
            // Only match against comment/string-stripped lines to avoid false positives
            for (line_idx, (line, stripped_line)) in text_lines.iter().zip(stripped_lines.iter()).enumerate() {
                for pat in &patterns {
                    if let Some(m) = pat.regex.find(stripped_line) {
                        let intent = infer_usage_intent(line);
                        let base_confidence: f64 = if is_test_file {
                            0.20 // test code is low-confidence
                        } else {
                            match intent.as_str() {
                                "verify" | "parse" => 0.50,
                                "negotiate" => 0.70,
                                _ => 0.90, // protect / unknown
                            }
                        };
                        let start_idx = line_idx.saturating_sub(5);
                        let end_idx = (line_idx + 6).min(text_lines.len());
                        let snippet = text_lines[start_idx..end_idx].join("\n");

                        let mut algo_status = if is_test_file { "test-only".to_string() } else { intent.clone() };
                        let mut algo_conf = base_confidence;

                        // Try calling LLM proxy
                        if !is_test_file && base_confidence > 0.0 {
                            if let Ok(llm_intent) = analyze_snippet_llm_sync(&cfg.http_endpoint(), pat.name, &entry.path().display().to_string(), &snippet) {
                                algo_status = llm_intent;
                                algo_conf = 0.95; // LLM confidence boost
                            }
                        }

                        algorithms.push(CryptoAlgorithm {
                            name: pat.name.to_string(),
                            family: pat.family.to_string(),
                            role: pat.role as i32,
                            status: algo_status,
                            key_bits: infer_key_bits(pat.name, line),
                            curve: infer_curve(line),
                            implementation_library: infer_library(line),
                            source_file: entry.path().display().to_string(),
                            source_line: (line_idx + 1) as u32,
                            source_column: (m.start() + 1) as u32,
                            symbol: m.as_str().to_string(),
                            confidence: algo_conf,
                            quantum_vulnerable: false,
                            context_snippet: snippet,
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
    if cfg.exclude_dirs.iter().any(|d| s.contains(d)) {
        return false;
    }
    if super::status::get_exclusions().iter().any(|d| s.contains(d)) {
        return false;
    }
    true
}

fn is_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()).unwrap_or_default(),
        "rs" | "go" | "js" | "jsx" | "ts" | "tsx" | "py" | "java" | "kt" | "cs" | "c" | "h" | "cpp" | "hpp" | "rb" | "php" | "swift" | "m" | "mm" | "scala" | "sh" | "yaml" | "yml" | "toml" | "xml" | "conf" | "cnf"
    )
}

/// Detect test files by naming conventions across languages.
fn is_test_path(path: &Path) -> bool {
    let s = path.to_string_lossy().to_ascii_lowercase();
    let name = path.file_stem().and_then(|n| n.to_str()).unwrap_or_default().to_ascii_lowercase();
    // Directory-level test markers
    if s.contains("__tests__") || s.contains("test_fixtures") || s.contains("testdata") {
        return true;
    }
    // File-level test markers by language convention
    name.ends_with("_test")       // Go, Rust
        || name.starts_with("test_") // Python
        || name.ends_with(".test")   // JS/TS
        || name.ends_with(".spec")   // JS/TS
        || name.ends_with("tests")   // General
        || name.contains("_test_")   // Embedded tests
}

/// Infer usage intent from surrounding code context.
/// Returns one of: "protect", "verify", "parse", "negotiate", "observed".
fn infer_usage_intent(line: &str) -> String {
    let l = line.to_ascii_lowercase();
    // Verification / read-only patterns
    if l.contains("verify") || l.contains("check") || l.contains("validate")
        || l.contains("parse") || l.contains("decode") || l.contains("unmarshal")
        || l.contains("deserialize") || l.contains("read") || l.contains("load_cert")
        || l.contains("x509_check") || l.contains("certificate_verify")
    {
        return "verify".to_string();
    }
    // Negotiation / capability listing patterns
    if l.contains("cipher_list") || l.contains("ciphersuite") || l.contains("supported")
        || l.contains("preferred") || l.contains("available") || l.contains("offered")
        || l.contains("set_ciphers") || l.contains("cipher_suites")
    {
        return "negotiate".to_string();
    }
    // Active protection patterns
    if l.contains("sign") || l.contains("encrypt") || l.contains("generate_key")
        || l.contains("new_key") || l.contains("keygen") || l.contains("seal")
        || l.contains("wrap_key") || l.contains("derive")
    {
        return "protect".to_string();
    }
    "observed".to_string()
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

