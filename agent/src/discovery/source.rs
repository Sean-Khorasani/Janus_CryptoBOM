use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
    prompts::{PromptRegistry, PromptTemplate},
};
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, sync::OnceLock};
use uuid::Uuid;
use walkdir::WalkDir;

/// Describes how a crypto finding was detected, ordered from least to most confident.
///
/// The variant is stored in `Evidence.source_type` so downstream tools can weight
/// findings appropriately without parsing free-form text.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum DetectionMethod {
    /// Regex match inside a test file — pattern may be illustrative rather than production use.
    RegexMatchTestFile,
    /// Pure regex pattern match in non-test production code; intent not confirmed by context.
    RegexMatch,
    /// Algorithm name found inside a string literal passed to a known crypto API call
    /// (e.g. `Cipher.getInstance("RSA")`, `createHash('md5')`) — the string IS the
    /// algorithm selection, so this is stronger than a bare identifier match.
    StringApiContext,
    /// Regex match in non-test code where surrounding context (comment/string stripping +
    /// intent classification) confirms active crypto use.
    ContextConfirmed,
    /// Two or more independent patterns flagged the same source line, corroborating each other.
    MultiPatternCorroborated,
}

impl DetectionMethod {
    /// Baseline confidence for this detection method.
    ///
    /// These are floor values; callers may lower the score for context such as
    /// verify/parse intent but should not raise it above the next tier.
    fn confidence_floor(self) -> f64 {
        match self {
            Self::RegexMatchTestFile => 0.20,
            Self::RegexMatch => 0.60,
            Self::StringApiContext => 0.78,
            Self::ContextConfirmed => 0.80,
            Self::MultiPatternCorroborated => 0.88,
        }
    }

    /// Short label stored in `Evidence.source_type` so downstream tools can filter by method.
    fn source_type_label(self) -> &'static str {
        match self {
            Self::RegexMatchTestFile => "regex-match-test",
            Self::RegexMatch => "regex-match",
            Self::StringApiContext => "string-api-context",
            Self::ContextConfirmed => "context-confirmed",
            Self::MultiPatternCorroborated => "multi-pattern",
        }
    }

    /// Classify a single line's detection method given test-file status, intent, and match count.
    fn classify(is_test_file: bool, intent: &str, match_count: usize) -> Self {
        if is_test_file {
            return Self::RegexMatchTestFile;
        }
        if match_count >= 2 {
            return Self::MultiPatternCorroborated;
        }
        // A recognized, non-default intent means context validation confirmed the use.
        match intent {
            "protect" | "verify" | "negotiate" => Self::ContextConfirmed,
            _ => Self::RegexMatch,
        }
    }
}

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
    // In config formats the quoted value IS the signal (`ciphers = "ECDHE-RSA-..."`);
    // blanking strings there erases exactly what we scan for. Only strip comments.
    let strip_strings = !matches!(ext, "yaml" | "yml" | "toml" | "conf" | "cnf" | "xml");

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

        if strip_strings && (c == '"' || c == '\'' || (is_c_like && c == '`')) {
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

fn default_classify_template() -> PromptTemplate {
    PromptTemplate {
        prompt: concat!(
            "You are a cryptography security expert. Analyze the following code snippet ",
            "which contains a reference to the cryptographic algorithm '{{algorithm}}'. ",
            "Classify the usage intent into exactly one of the following categories: ",
            "'protect', 'verify', 'negotiate', 'test'. ",
            "Reply with a JSON object exactly matching this format: ",
            "{\"intent\": \"one-of-the-categories\", \"confidence\": 0.9}\n",
            "Code Snippet (from {{source_file}}):\n{{snippet}}"
        ).to_string(),
        model: "gpt-4o-mini".to_string(),
        temperature: 0.0,
        version: None,
    }
}

fn default_remediate_template() -> PromptTemplate {
    PromptTemplate {
        prompt: concat!(
            "You are a cryptography security expert. Rewrite the following code snippet from ",
            "'{{source_file}}' to migrate from the quantum-vulnerable algorithm '{{algorithm}}' ",
            "to a secure post-quantum or modern standard (e.g., ML-KEM, ML-DSA, SHA-256). ",
            "The response must return ONLY a unified diff patch. ",
            "Do not include markdown code block formatting (like ```diff), just the raw diff text. ",
            "Remediation patch target file: {{source_file}}\nCode Snippet:\n{{snippet}}"
        ).to_string(),
        model: "gpt-4o-mini".to_string(),
        temperature: 0.0,
        version: None,
    }
}

fn analyze_snippet_llm_sync(http_endpoint: &str, tmpl: &PromptTemplate, name: &str, source_file: &str, snippet: &str) -> Result<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let host_port = http_endpoint
        .strip_prefix("http://")
        .unwrap_or(http_endpoint)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:8080");
    let prompt = tmpl.render(&[("algorithm", name), ("source_file", source_file), ("snippet", snippet)]);

    let body_json = serde_json::json!({
        "model": tmpl.model,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": tmpl.temperature
    }).to_string();

    let addr: std::net::SocketAddr = host_port.parse()
        .or_else(|_| std::net::ToSocketAddrs::to_socket_addrs(&host_port).map(|mut i| i.next().unwrap()))
        .map_err(|e| anyhow::anyhow!("resolve {}: {}", host_port, e))?;
    let mut stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
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

pub fn generate_remediation_patch_llm(
    http_endpoint: &str,
    tmpl: &PromptTemplate,
    name: &str,
    source_file: &str,
    snippet: &str,
) -> Result<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let host_port = http_endpoint
        .strip_prefix("http://")
        .unwrap_or(http_endpoint)
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:8080");

    let prompt = tmpl.render(&[("algorithm", name), ("source_file", source_file), ("snippet", snippet)]);

    let body_json = serde_json::json!({
        "model": tmpl.model,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.0
    }).to_string();

    let addr: std::net::SocketAddr = host_port.parse()
        .or_else(|_| std::net::ToSocketAddrs::to_socket_addrs(&host_port).map(|mut i| i.next().unwrap()))
        .map_err(|e| anyhow::anyhow!("resolve {}: {}", host_port, e))?;
    let mut stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
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
                let clean = content
                    .replace("```diff", "")
                    .replace("```patch", "")
                    .replace("```", "")
                    .trim()
                    .to_string();
                return Ok(clean);
            }
        }
    }

    anyhow::bail!("failed to parse LLM patch response")
}

pub fn scan(cfg: &AgentConfig, use_llm: bool) -> Result<ScanResult> {
    let patterns = patterns()?;
    let mut out = ScanResult::default();

    // Load prompt templates once per scan (not per match) to avoid repeated disk reads.
    let classify_tmpl = if use_llm {
        PromptRegistry::new(&cfg.prompts_dir).load_or_default("classify-intent", default_classify_template())
    } else {
        default_classify_template()
    };
    let remediate_tmpl = if use_llm {
        PromptRegistry::new(&cfg.prompts_dir).load_or_default("remediate-patch", default_remediate_template())
    } else {
        default_remediate_template()
    };

    // Candidate patches are collected and written once next to the report —
    // a passive scan must never write into the scanned tree.
    let mut pending_patches: Vec<String> = Vec::new();
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

            // Track the strongest DetectionMethod seen and all pattern names matched in this
            // file, for the single per-file Evidence record that summarises provenance.
            let mut file_strongest_method = DetectionMethod::RegexMatchTestFile;
            let mut file_pattern_names: Vec<&str> = Vec::new();

            // Only match against comment/string-stripped lines to avoid false positives.
            // We first count matches per line so MultiPatternCorroborated can be detected.
            for (line_idx, (line, stripped_line)) in text_lines.iter().zip(stripped_lines.iter()).enumerate() {
                // Collect all pattern hits on this stripped line.
                let mut line_hits: Vec<(&Pattern, regex::Match<'_>)> = Vec::new();
                for pat in &patterns {
                    if let Some(m) = pat.regex.find(stripped_line) {
                        // "DSA" must not fire inside ML-DSA / SLH-DSA tokens.
                        if pat.name == "DSA" && is_pq_prefixed(stripped_line, m.start()) {
                            continue;
                        }
                        line_hits.push((pat, m));
                    }
                }
                // Second pass over the RAW line: algorithm names inside string literals
                // passed to crypto APIs (`Cipher.getInstance("RSA")`) — the dominant
                // selection idiom in JCA/Node/Python, invisible to the stripped pass.
                let string_hits = string_literal_hits(line);
                if line_hits.is_empty() && string_hits.is_empty() {
                    continue;
                }

                // Intent from the stripped line so comments cannot steer classification.
                let intent = infer_usage_intent(stripped_line);
                let match_count = line_hits.len();

                let start_idx = line_idx.saturating_sub(5);
                let end_idx = (line_idx + 6).min(text_lines.len());
                let snippet = text_lines[start_idx..end_idx].join("\n");

                for (pat, m) in line_hits {
                    let method = DetectionMethod::classify(is_test_file, &intent, match_count);

                    // Intent-adjusted confidence: lower the floor for passive/observing intents.
                    let algo_conf = if is_test_file {
                        method.confidence_floor()
                    } else {
                        intent_adjusted_confidence(method, &intent)
                    };

                    let algo_status = if is_test_file {
                        "test-only".to_string()
                    } else {
                        intent.clone()
                    };

                    // Attempt LLM intent classification when requested. The LLM may only
                    // relabel intent within the closed enum and may only LOWER confidence,
                    // never raise it above the deterministic tier — snippets are untrusted
                    // input (a scanned repo can prompt-inject the classifier), so its output
                    // is an annotation, not an authority.
                    let (algo_status, algo_conf) = if use_llm && !is_test_file {
                        match analyze_snippet_llm_sync(
                            &cfg.http_endpoint(),
                            &classify_tmpl,
                            pat.name,
                            &entry.path().display().to_string(),
                            &snippet,
                        ) {
                            Ok(llm_intent) if is_known_intent(&llm_intent) => {
                                let llm_conf =
                                    intent_adjusted_confidence(method, &llm_intent).min(algo_conf);
                                (llm_intent, llm_conf)
                            }
                            _ => (algo_status, algo_conf),
                        }
                    } else {
                        (algo_status, algo_conf)
                    };

                    let is_qv = is_quantum_vulnerable(pat.name);

                    if is_qv && !is_test_file {
                        let path_str = entry.path().display().to_string();
                        let line_num = line_idx + 1;
                        let patch = if use_llm {
                            match generate_remediation_patch_llm(
                                &cfg.http_endpoint(),
                                &remediate_tmpl,
                                pat.name,
                                &path_str,
                                &snippet,
                            ) {
                                Ok(p) => p,
                                Err(_) => build_static_patch(&path_str, line_num, line, pat.name),
                            }
                        } else {
                            build_static_patch(&path_str, line_num, line, pat.name)
                        };
                        pending_patches.push(patch);
                    }

                    // Update per-file strongest method for the Evidence summary.
                    if method > file_strongest_method {
                        file_strongest_method = method;
                    }
                    if !file_pattern_names.contains(&pat.name) {
                        file_pattern_names.push(pat.name);
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
                        quantum_vulnerable: is_qv,
                        context_snippet: snippet.clone(),
                    });
                }

                for (s_name, s_family, s_role, s_col, s_symbol) in &string_hits {
                    // Skip if the identifier pass already reported this algorithm here.
                    if algorithms
                        .iter()
                        .any(|a| a.name == *s_name && a.source_line == (line_idx + 1) as u32)
                    {
                        continue;
                    }
                    let method = if is_test_file {
                        DetectionMethod::RegexMatchTestFile
                    } else {
                        DetectionMethod::StringApiContext
                    };
                    let algo_conf = if is_test_file {
                        method.confidence_floor()
                    } else {
                        intent_adjusted_confidence(method, &intent)
                    };
                    let algo_status = if is_test_file {
                        "test-only".to_string()
                    } else {
                        intent.clone()
                    };
                    let is_qv = is_quantum_vulnerable(s_name);
                    if is_qv && !is_test_file {
                        let path_str = entry.path().display().to_string();
                        pending_patches.push(build_static_patch(&path_str, line_idx + 1, line, s_name));
                    }
                    if method > file_strongest_method {
                        file_strongest_method = method;
                    }
                    if !file_pattern_names.contains(s_name) {
                        file_pattern_names.push(*s_name);
                    }
                    algorithms.push(CryptoAlgorithm {
                        name: s_name.to_string(),
                        family: s_family.to_string(),
                        role: *s_role as i32,
                        status: algo_status,
                        key_bits: infer_key_bits(s_name, line),
                        curve: infer_curve(line),
                        implementation_library: infer_library(line),
                        source_file: entry.path().display().to_string(),
                        source_line: (line_idx + 1) as u32,
                        source_column: (s_col + 1) as u32,
                        symbol: s_symbol.clone(),
                        confidence: algo_conf,
                        quantum_vulnerable: is_qv,
                        context_snippet: snippet.clone(),
                    });
                }
            }
            if algorithms.is_empty() {
                continue;
            }
            let file_hash = sha256_hex(&raw);
            let path = entry.path().display().to_string();
            let evidence_id = Uuid::new_v4().to_string();
            // source_tool encodes which patterns triggered so reviewers can trace provenance.
            let source_tool = format!(
                "janus-source-scanner/regex:{}",
                file_pattern_names.join(",")
            );
            out.evidence.push(Evidence {
                evidence_id,
                source_type: file_strongest_method.source_type_label().to_string(),
                source_tool,
                target: path.clone(),
                collection_time_unix: now(),
                raw_artifact_sha256: file_hash,
                confidence: file_strongest_method.confidence_floor(),
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
    if !pending_patches.is_empty() {
        let report_dir = Path::new(&cfg.report_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let _ = fs::write(report_dir.join("remediation.patch"), pending_patches.join("\n"));
    }
    Ok(out)
}

fn patterns() -> Result<Vec<Pattern>> {
    let defs = [
        (r"\bRSA(_|\b|\.|::|With|with)", "RSA", "RSA", CryptoRole::Signature),
        (r"\bECDSA\b|\becdsa\b", "ECDSA", "ECC", CryptoRole::Signature),
        (r"\bECDH(E)?\b|\becdh\b", "ECDHE", "ECC", CryptoRole::KeyExchange),
        (r"\bDiffieHellman\b|\bDH_generate|\bdiffie[-_]?hellman\b", "DH", "DH", CryptoRole::KeyExchange),
        (r"\bDSA(?:_|\b)", "DSA", "DSA", CryptoRole::Signature),
        (r"(?i)\bed25519(?:_|\b)|\bEdDSA\b|\bed448(?:_|\b)", "Ed25519", "ECC", CryptoRole::Signature),
        (r"(?i)\bx25519(?:_|\b)|\bcurve25519(?:_|\b)|\bx448(?:_|\b)", "X25519", "ECC", CryptoRole::KeyExchange),
        // IANA-registered hybrid PQ groups (TLS 4587/4588/4589) and SSH hybrid KEX names —
        // recognized so hybrid deployments inventory as PQ-capable, not as classical ECC.
        (
            r"(?i)\b(x25519mlkem768|secp256r1mlkem768|secp384r1mlkem1024|mlkem768x25519-sha256|mlkem768nistp256-sha256|mlkem1024nistp384-sha384|x25519kyber768draft00|sntrup761x25519-sha512)\b",
            "PQ-hybrid-KEX",
            "hybrid-pqc",
            CryptoRole::KeyExchange,
        ),
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
        // FHE (Fully Homomorphic Encryption) pattern families
        (r"\bFHE\b", "FHE", "homomorphic-encryption", CryptoRole::Unspecified),
        (r"\bHomomorphicEncrypt(ion)?\b", "HomomorphicEncryption", "homomorphic-encryption", CryptoRole::Unspecified),
        (r"\bCKKS\b", "CKKS", "homomorphic-encryption", CryptoRole::Unspecified),
        (r"\bBGV\b", "BGV", "homomorphic-encryption", CryptoRole::Unspecified),
        (r"\bBFV\b", "BFV", "homomorphic-encryption", CryptoRole::Unspecified),
        (r"\bTFHE\b", "TFHE", "homomorphic-encryption", CryptoRole::Unspecified),
        (r"\bGSW\b", "GSW", "homomorphic-encryption", CryptoRole::Unspecified),
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
    // Use path-component matching so excluding "target" only matches the directory, not "custom-target"
    if path.components().any(|comp| {
        let comp_str = comp.as_os_str().to_string_lossy();
        cfg.exclude_dirs.iter().any(|d| comp_str == d.as_str()) ||
            super::status::get_exclusions().iter().any(|d| comp_str == d.as_str())
    }) {
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
    let name = path.file_stem().and_then(|n| n.to_str()).unwrap_or_default().to_ascii_lowercase();
    // Directory-level test markers: exact path-component match (covers Rust `tests/`,
    // which the previous substring checks missed, without matching e.g. "contest").
    if path.components().any(|c| {
        let c = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            c.as_str(),
            "test" | "tests" | "__tests__" | "testdata" | "test_fixtures" | "spec" | "specs"
        )
    }) {
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
///
/// Keywords are matched on word boundaries — substring matching mislabeled
/// `design`→sign, `thread`→read, `checksum`→check, silently distorting confidence.
fn infer_usage_intent(line: &str) -> String {
    static RES: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    let (verify_re, negotiate_re, protect_re) = RES.get_or_init(|| {
        (
            Regex::new(r"(?i)\b(verif(?:y|ied|ies|ication)|checks?|validat(?:e|ed|es|ion)|parse[sd]?|decode[sd]?|unmarshal|deserializ(?:e|ed)|load_cert|x509_check|certificate_verify)\b").unwrap(),
            Regex::new(r"(?i)\b(cipher_?list|cipher_?suites?|supported|preferred|available|offered|set_ciphers|groups_list|sigalgs)\b").unwrap(),
            Regex::new(r"(?i)\b(sign(?:s|ed|ing|ature)?|encrypt(?:s|ed|ion)?|generate_?key|new_?key|keygen|seal|wrap_?key|deriv(?:e|ed|ation))\b").unwrap(),
        )
    });
    if verify_re.is_match(line) {
        return "verify".to_string();
    }
    if negotiate_re.is_match(line) {
        return "negotiate".to_string();
    }
    if protect_re.is_match(line) {
        return "protect".to_string();
    }
    "observed".to_string()
}

/// Closed intent vocabulary — LLM output outside this set is discarded (injection defense).
fn is_known_intent(intent: &str) -> bool {
    matches!(intent, "protect" | "verify" | "parse" | "negotiate" | "test" | "observed")
}

/// Confidence for a detection method adjusted by usage intent. Passive/observing
/// intents lower the floor; nothing here can exceed the method's deterministic tier.
fn intent_adjusted_confidence(method: DetectionMethod, intent: &str) -> f64 {
    match intent {
        "verify" | "parse" => method.confidence_floor() * 0.70,
        "negotiate" => method.confidence_floor() * 0.85,
        "test" => DetectionMethod::RegexMatchTestFile.confidence_floor(),
        _ => method.confidence_floor(),
    }
}

/// Algorithms whose findings are flagged quantum-vulnerable (or classically weak for
/// MD5/SHA-1/legacy-symmetric) and receive candidate remediation patches.
fn is_quantum_vulnerable(name: &str) -> bool {
    matches!(
        name,
        "RSA" | "ECDSA" | "ECDH" | "ECDHE" | "DH" | "DSA" | "Ed25519" | "X25519" | "MD5"
            | "SHA-1" | "legacy-symmetric"
    )
}

/// True when the text immediately before `start` is an ML-/SLH- prefix, i.e. the
/// match is the tail of a post-quantum algorithm token (ML-DSA, SLH-DSA).
fn is_pq_prefixed(line: &str, start: usize) -> bool {
    let pre = line[..start].to_ascii_lowercase();
    pre.ends_with("ml-") || pre.ends_with("ml_") || pre.ends_with("slh-") || pre.ends_with("slh_")
}

/// Scan a RAW (unstripped) line for algorithm names inside string literals, gated on
/// the line also containing a known crypto-API call. This is how JCA, Node `crypto`,
/// Python `hashlib`/`cryptography`, and OpenSSL EVP select algorithms — entirely
/// invisible to the stripped-identifier pass.
/// Returns (canonical name, family, role, byte column, matched token).
fn string_literal_hits(raw_line: &str) -> Vec<(&'static str, &'static str, CryptoRole, usize, String)> {
    static RES: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    let (api_re, quoted_re, token_re) = RES.get_or_init(|| {
        (
            Regex::new(r#"(?ix)\b(getInstance|MessageDigest|KeyPairGenerator|KeyFactory|KeyAgreement|createHash|createHmac|createCipheriv|createSign|createVerify|createDiffieHellman|generateKeyPair(?:Sync)?|hashlib|EVP_(?:get_digestbyname|MD_fetch|CIPHER_fetch|PKEY)|SSL_CTX_set1?_(?:groups|sigalgs|curves)|set_ciphers|HashAlgorithmName|SignatureAlgorithm|CryptoConfig|algorithms?\s*[:=])"#).unwrap(),
            Regex::new(r#"["'`]([^"'`]{1,120})["'`]"#).unwrap(),
            Regex::new(r"(?i)\b(rsa|ecdsa|ecdhe?|dsa|ed25519|x25519|curve25519|md5|sha-?1|des(?:ede)?|3des|rc4)\b").unwrap(),
        )
    });
    let mut hits = Vec::new();
    if !api_re.is_match(raw_line) {
        return hits;
    }
    for q in quoted_re.captures_iter(raw_line) {
        let content = q.get(1).unwrap();
        for t in token_re.find_iter(content.as_str()) {
            if is_pq_prefixed(content.as_str(), t.start()) {
                continue;
            }
            let mapped = match t.as_str().to_ascii_lowercase().as_str() {
                "rsa" => ("RSA", "RSA", CryptoRole::Signature),
                "ecdsa" => ("ECDSA", "ECC", CryptoRole::Signature),
                "ecdh" | "ecdhe" => ("ECDHE", "ECC", CryptoRole::KeyExchange),
                "dsa" => ("DSA", "DSA", CryptoRole::Signature),
                "ed25519" => ("Ed25519", "ECC", CryptoRole::Signature),
                "x25519" | "curve25519" => ("X25519", "ECC", CryptoRole::KeyExchange),
                "md5" => ("MD5", "hash", CryptoRole::Hash),
                "sha1" | "sha-1" => ("SHA-1", "hash", CryptoRole::Hash),
                "des" | "desede" | "3des" | "rc4" => {
                    ("legacy-symmetric", "legacy", CryptoRole::Symmetric)
                }
                _ => continue,
            };
            if hits.iter().any(|(n, ..)| *n == mapped.0) {
                continue;
            }
            hits.push((
                mapped.0,
                mapped.1,
                mapped.2,
                content.start() + t.start(),
                t.as_str().to_string(),
            ));
        }
    }
    hits
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

/// Build a minimal unified-diff patch for a quantum-vulnerable line using
/// static replacement heuristics (no LLM required).
fn build_static_patch(path_str: &str, line_num: usize, line: &str, name: &str) -> String {
    // Role-aware target selection: signature use migrates to ML-DSA, key
    // establishment to ML-KEM (RSA is ambiguous — decide from line context).
    let l = line.to_ascii_lowercase();
    let signing_context = l.contains("sign") || l.contains("certificate") || l.contains("cert");
    let replacement = match name {
        "MD5" | "SHA-1" => line
            .replace("MD5", "SHA256")
            .replace("SHA-1", "SHA256")
            .replace("SHA1", "SHA256")
            .replace("md5", "sha256")
            .replace("sha1", "sha256"),
        "ECDSA" | "DSA" | "Ed25519" => line.replace(name, "MLDSA65"),
        "ECDHE" | "ECDH" | "DH" | "X25519" => line.replace(name, "MLKEM768"),
        "RSA" if signing_context => line.replace(name, "MLDSA65"),
        _ => line.replace(name, "MLKEM768"),
    };
    format!(
        "# janus candidate patch (heuristic, review required — never auto-applied)\n--- {path_str}\n+++ {path_str}\n@@ -{line_num},1 +{line_num},1 @@\n-{}\n+{}\n",
        line.trim_end(),
        replacement.trim_end()
    )
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

#[cfg(test)]
mod detection_method_tests {
    use super::DetectionMethod;

    #[test]
    fn test_file_always_yields_lowest_tier() {
        // Test-file flag overrides both intent and match count.
        assert_eq!(
            DetectionMethod::classify(true, "protect", 5),
            DetectionMethod::RegexMatchTestFile
        );
        assert_eq!(
            DetectionMethod::classify(true, "", 1),
            DetectionMethod::RegexMatchTestFile
        );
    }

    #[test]
    fn multi_pattern_fires_at_two_or_more_matches() {
        assert_eq!(
            DetectionMethod::classify(false, "", 2),
            DetectionMethod::MultiPatternCorroborated
        );
        assert_eq!(
            DetectionMethod::classify(false, "protect", 3),
            DetectionMethod::MultiPatternCorroborated
        );
        // Single match with intent does NOT reach MultiPatternCorroborated.
        assert_ne!(
            DetectionMethod::classify(false, "protect", 1),
            DetectionMethod::MultiPatternCorroborated
        );
    }

    #[test]
    fn known_intents_yield_context_confirmed() {
        for intent in &["protect", "verify", "negotiate"] {
            assert_eq!(
                DetectionMethod::classify(false, intent, 1),
                DetectionMethod::ContextConfirmed,
                "intent={intent}"
            );
        }
    }

    #[test]
    fn unknown_or_test_intent_yields_regex_match() {
        for intent in &["", "test", "unknown", "other"] {
            assert_eq!(
                DetectionMethod::classify(false, intent, 1),
                DetectionMethod::RegexMatch,
                "intent={intent}"
            );
        }
    }

    #[test]
    fn confidence_floors_match_spec() {
        assert!((DetectionMethod::RegexMatchTestFile.confidence_floor() - 0.20).abs() < 1e-9);
        assert!((DetectionMethod::RegexMatch.confidence_floor() - 0.60).abs() < 1e-9);
        assert!((DetectionMethod::StringApiContext.confidence_floor() - 0.78).abs() < 1e-9);
        assert!((DetectionMethod::ContextConfirmed.confidence_floor() - 0.80).abs() < 1e-9);
        assert!((DetectionMethod::MultiPatternCorroborated.confidence_floor() - 0.88).abs() < 1e-9);
    }

    #[test]
    fn ordering_is_strongest_last() {
        assert!(DetectionMethod::RegexMatchTestFile < DetectionMethod::RegexMatch);
        assert!(DetectionMethod::RegexMatch < DetectionMethod::StringApiContext);
        assert!(DetectionMethod::StringApiContext < DetectionMethod::ContextConfirmed);
        assert!(DetectionMethod::ContextConfirmed < DetectionMethod::MultiPatternCorroborated);
    }
}

#[cfg(test)]
mod detection_quality_tests {
    use super::*;

    #[test]
    fn intent_uses_word_boundaries() {
        // Substring matching mislabeled these before.
        assert_eq!(infer_usage_intent("let design = rsa_thing();"), "observed");
        assert_eq!(infer_usage_intent("thread.spawn(rsa_task)"), "observed");
        assert_eq!(infer_usage_intent("compute checksum with md5"), "observed");
        // Real intents still classify.
        assert_eq!(infer_usage_intent("rsa.sign(payload)"), "protect");
        assert_eq!(infer_usage_intent("cert.verify(sig)"), "verify");
        assert_eq!(infer_usage_intent("set_ciphers(list)"), "negotiate");
    }

    #[test]
    fn string_literal_api_idioms_are_detected() {
        let hits = string_literal_hits(r#"Cipher.getInstance("RSA/ECB/PKCS1Padding")"#);
        assert!(hits.iter().any(|(n, ..)| *n == "RSA"), "JCA getInstance: {hits:?}");
        let hits = string_literal_hits(r#"const h = crypto.createHash('md5');"#);
        assert!(hits.iter().any(|(n, ..)| *n == "MD5"), "node createHash: {hits:?}");
        let hits = string_literal_hits(r#"hashlib.new("sha1")"#);
        assert!(hits.iter().any(|(n, ..)| *n == "SHA-1"));
        // No API context on the line → no string findings (FP guard).
        assert!(string_literal_hits(r#"log.info("uses RSA somewhere")"#).is_empty());
        // PQ names inside strings must not fire the classical DSA rule.
        assert!(string_literal_hits(r#"KeyPairGenerator.getInstance("ML-DSA-65")"#).is_empty());
    }

    #[test]
    fn config_files_keep_string_values() {
        let stripped = strip_comments_and_strings("ciphers = \"ECDHE-RSA-AES128\" # legacy\n", "toml");
        assert!(stripped.contains("ECDHE-RSA-AES128"), "{stripped}");
        assert!(!stripped.contains("legacy"));
    }

    #[test]
    fn dsa_not_flagged_inside_pq_names() {
        assert!(is_pq_prefixed("ML-DSA-65", 3));
        assert!(is_pq_prefixed("SLH_DSA", 4));
        assert!(!is_pq_prefixed("use DSA here", 4));
    }

    #[test]
    fn hybrid_groups_and_missing_qv_algos_have_patterns() {
        let pats = patterns().unwrap();
        let find = |line: &str| -> Vec<&str> {
            pats.iter().filter(|p| p.regex.is_match(line)).map(|p| p.name).collect()
        };
        assert!(find("ssh-ed25519 AAAA").contains(&"Ed25519"));
        assert!(find("kex: X25519").contains(&"X25519"));
        let hybrid = find("curve_pref = X25519MLKEM768");
        assert!(hybrid.contains(&"PQ-hybrid-KEX"), "{hybrid:?}");
        // Hybrid token must not double-report as classical X25519 or ML-KEM.
        assert!(!hybrid.contains(&"X25519"));
        assert!(!hybrid.contains(&"ML-KEM"));
        assert!(find("DSA_generate_parameters").contains(&"DSA"));
        assert!(!is_quantum_vulnerable("PQ-hybrid-KEX"));
        assert!(is_quantum_vulnerable("Ed25519"));
    }

    #[test]
    fn llm_intent_validation_is_closed_enum() {
        assert!(is_known_intent("verify"));
        assert!(!is_known_intent("ignore-previous-instructions"));
        // LLM-supplied "test" intent down-ranks to the test-file floor.
        let c = intent_adjusted_confidence(DetectionMethod::ContextConfirmed, "test");
        assert!((c - 0.20).abs() < 1e-9);
    }

    #[test]
    fn static_patch_is_role_aware() {
        let p = build_static_patch("a.go", 3, "cert := RSA_sign(key)", "RSA");
        assert!(p.contains("MLDSA65"), "signing RSA should target ML-DSA: {p}");
        let p = build_static_patch("a.go", 3, "shared := RSA_encrypt(pub)", "RSA");
        assert!(p.contains("MLKEM768"), "key transport RSA should target ML-KEM: {p}");
        assert!(p.starts_with("# janus candidate patch"));
    }

    #[test]
    fn rust_tests_dir_is_test_path() {
        assert!(is_test_path(Path::new("crate/tests/integration.rs")));
        assert!(is_test_path(Path::new("pkg/__tests__/x.spec.ts")));
        assert!(!is_test_path(Path::new("src/contest/scanner.rs")));
    }
}

/// Labeled detection corpus with measured precision/recall (DETECTION-IMPROVEMENTS.md §2.2-3).
/// A file counts as a POSITIVE when the scan yields a quantum-vulnerable finding with
/// status != test-only and confidence >= 0.5. The corpus was authored adversarially
/// against known FP/FN classes; extend it whenever detection logic changes and record
/// the printed numbers in the analysis doc.
#[cfg(test)]
mod detection_corpus {
    use super::*;
    use crate::config::AgentConfig;

    // (relative path, content, expect_qv_finding)
    const CORPUS: &[(&str, &str, bool)] = &[
        // True positives — must be flagged
        ("app/Jca.java", r#"Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");"#, true),
        ("app/hash.js", r#"const h = crypto.createHash('md5');"#, true),
        ("app/sign.go", "sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)", true),
        ("app/kex.c", "DH_generate_key(dh);", true),
        ("app/legacy.py", r#"h = hashlib.new("sha1")"#, true),
        ("conf/tls.conf", "ciphers = \"ECDHE-RSA-AES256-GCM-SHA384\"\n", true),
        ("app/sshkey.rs", "let sig = ed25519_sign(&msg, &key);", true),
        ("app/kx.ts", "const shared = x25519_derive(base, peer);", true),
        // True negatives — must NOT be flagged (each targets a known FP class)
        ("app/comment.go", "// RSA is no longer used here\nfunc nothing() {}", false),
        ("app/log.js", r#"log.info("uses RSA somewhere");"#, false),
        ("tests/rsa_test.go", "k, _ := rsa.GenerateKey(rand.Reader, 2048)", false),
        ("app/pq.rs", "let kp = ML_DSA_keygen();", false),
        ("conf/hybrid.conf", "Groups = X25519MLKEM768\n", false),
        ("app/aes.go", "alg := AES_256", false),
    ];

    #[test]
    fn corpus_precision_recall() {
        let dir = std::env::temp_dir().join(format!("janus-corpus-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for (rel, content, _) in CORPUS {
            let p = dir.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, content).unwrap();
        }
        let cfg = AgentConfig {
            scan_roots: vec![dir.display().to_string()],
            report_path: dir.join("report.html").display().to_string(),
            ..AgentConfig::default()
        };
        let result = scan(&cfg, false).unwrap();

        let flagged: Vec<String> = result
            .components
            .iter()
            .filter(|c| {
                c.algorithms.iter().any(|a| {
                    a.quantum_vulnerable && a.status != "test-only" && a.confidence >= 0.5
                })
            })
            .map(|c| c.file_path.replace('\\', "/"))
            .collect();
        let is_flagged =
            |rel: &str| flagged.iter().any(|f| f.ends_with(&rel.replace('\\', "/")));

        let (mut tp, mut fp_, mut fn_) = (0u32, 0u32, 0u32);
        for (rel, _, expect) in CORPUS {
            match (expect, is_flagged(rel)) {
                (true, true) => tp += 1,
                (true, false) => {
                    fn_ += 1;
                    eprintln!("FN: {rel}");
                }
                (false, true) => {
                    fp_ += 1;
                    eprintln!("FP: {rel}");
                }
                (false, false) => {}
            }
        }
        let precision = tp as f64 / (tp + fp_).max(1) as f64;
        let recall = tp as f64 / (tp + fn_).max(1) as f64;
        eprintln!(
            "detection corpus v1: files={} tp={tp} fp={fp_} fn={fn_} precision={precision:.3} recall={recall:.3}",
            CORPUS.len()
        );

        // The hybrid-PQ config must inventory as hybrid-pqc, never as classical X25519.
        let hybrid = result
            .components
            .iter()
            .find(|c| c.file_path.replace('\\', "/").ends_with("conf/hybrid.conf"))
            .expect("hybrid.conf must produce an inventory component");
        assert!(hybrid.algorithms.iter().any(|a| a.family == "hybrid-pqc"));
        assert!(hybrid.algorithms.iter().all(|a| !a.quantum_vulnerable));

        let _ = fs::remove_dir_all(&dir);
        assert!(precision >= 0.99, "precision regressed: {precision}");
        assert!(recall >= 0.99, "recall regressed: {recall}");
    }
}

