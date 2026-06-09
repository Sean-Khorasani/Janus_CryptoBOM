use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CryptoFinding, RiskSeverity},
};
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use uuid::Uuid;
use walkdir::WalkDir;

/// A pattern that signals a potential side-channel / constant-time violation.
struct SidePattern {
    regex: Regex,
    severity: RiskSeverity,
    title: &'static str,
    description: &'static str,
}

/// Scan source files for side-channel leakage patterns and return findings.
pub fn scan(cfg: &AgentConfig) -> Result<ScanResult> {
    let patterns = build_side_patterns()?;
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

            super::status::update_progress("Side-Channel Analysis", entry.path());

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
            let ext = entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let stripped = strip_comments(&text, &ext);

            let text_lines: Vec<&str> = text.lines().collect();
            let stripped_lines: Vec<&str> = stripped.lines().collect();

            for (line_idx, stripped_line) in stripped_lines.iter().enumerate() {
                if stripped_line.trim().is_empty() {
                    continue;
                }
                for pat in &patterns {
                    if let Some(m) = pat.regex.find(stripped_line) {
                        let start = line_idx.saturating_sub(3);
                        let end = (line_idx + 4).min(text_lines.len());
                        let snippet = text_lines[start..end].join("\n");

                        let file_hash = sha256_hex(&raw);
                        let evidence_id = Uuid::new_v4().to_string();

                        let asset_ref = format!(
                            "{}#L{}",
                            entry.path().display(),
                            line_idx + 1
                        );

                        out.evidence.push(crate::proto::Evidence {
                            evidence_id: evidence_id.clone(),
                            source_type: "side-channel-analysis".to_string(),
                            source_tool: "janus-agent-sidechannel".to_string(),
                            target: entry.path().display().to_string(),
                            collection_time_unix: now(),
                            raw_artifact_sha256: file_hash,
                            confidence: 0.85,
                            sensitivity_class: "security".to_string(),
                        });

                        out.findings.push(CryptoFinding {
                            finding_id: Uuid::new_v4().to_string(),
                            severity: pat.severity as i32,
                            title: pat.title.to_string(),
                            description: format!(
                                "{} — matched pattern `{}` on line {} of {}",
                                pat.description,
                                m.as_str(),
                                line_idx + 1,
                                entry.path().display()
                            ),
                            asset_ref,
                            algorithm: "side-channel".to_string(),
                            policy_rule_id: format!("sidechannel-{}", pat.title.replace(' ', "-").to_ascii_lowercase()),
                            evidence_ids: vec![evidence_id],
                            migration_profile: String::new(),
                        });
                    }
                }
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Side-channel pattern definitions
// ---------------------------------------------------------------------------

fn build_side_patterns() -> Result<Vec<SidePattern>> {
    let defs: [(&str, RiskSeverity, &str, &str); 8] = [
        // CRITICAL — branching directly on raw key bytes
        (
            r"\bif\s*\(.*\b(key|secret|private_key|master_key|secret_key)\s*\[",
            RiskSeverity::Critical,
            "Branch-On-Key-Byte",
            "Branching directly on a raw key byte enables timing side-channel attacks that can recover the key.",
        ),
        // CRITICAL — switch on secret-derived value
        (
            r"\bswitch\s*\(.*\b(mac|hash|signature|ciphertext|auth_tag|digest|key_byte|secret_byte)\s*\[",
            RiskSeverity::Critical,
            "Switch-On-Secret",
            "A switch statement branches on a secret-derived value — control flow depends on cryptographic secrets.",
        ),
        // HIGH — non-constant-time comparison of hashes/MACs
        (
            r"(?i)\b(mac|hmac|tag|auth_tag|signature|digest|computed_hash|expected_hash)\s*(==|!=)\s*(mac|hmac|tag|auth_tag|signature|digest|computed_hash|expected_hash)",
            RiskSeverity::High,
            "NonConstantTime-Compare",
            "Comparison of MAC/hash/digest values using `==` instead of a constant-time comparison function.",
        ),
        // HIGH — likely non-constant-time memory comparison
        (
            r"(?i)\b(memcmp|strcmp|strncmp|Compare|SequenceEqual)\s*\([^)]*",
            RiskSeverity::High,
            "NonConstantTime-Memcmp",
            "Use of memory comparison function that may not execute in constant time (e.g. memcmp, strcmp).",
        ),
        // HIGH — equality comparison with early return / branch (single-line pattern)
        (
            r"(?i)\bif\b[^{;{]*==[^{;{]*\b(return|break)\b",
            RiskSeverity::High,
            "EarlyExit-Compare",
            "Comparison with early exit on the result — a classic non-constant-time timing leak vector.",
        ),
        // MEDIUM — table lookup indexed by secret data
        (
            r"(?i)[a-z_]*box\[[a-z_]*\b(mac|hash|cipher|digest|key_byte|secret|signature)\b",
            RiskSeverity::Medium,
            "Secret-Indexed-Table",
            "Table lookup indexed by a secret-derived value; cache timing can leak the index.",
        ),
        // MEDIUM — array access with secret-derived index
        (
            r"(?i)\b(key|secret|hash|digest)\s*\[[^]]+\]\s*as\s+usize",
            RiskSeverity::Medium,
            "Secret-Array-Index",
            "Using a secret-derived byte as an array index — cache-timing side channel.",
        ),
        // LOW — potential timing leak (e.g. `==` on any crypto field)
        (
            r"(?i)\b(ciphertext|plaintext|encrypted|decrypted)\s*(==|!=)\s*\w+",
            RiskSeverity::Low,
            "Potential-Timing-Leak",
            "Direct equality comparison involving ciphertext or encrypted data — potential timing side-channel.",
        ),
    ];

    defs.iter()
        .map(|(re, sev, title, desc)| {
            Ok(SidePattern {
                regex: Regex::new(re)?,
                severity: *sev,
                title,
                description: desc,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// File filtering helpers (mirror source.rs)
// ---------------------------------------------------------------------------

fn include_entry(path: &Path, cfg: &AgentConfig) -> bool {
    !path.components().any(|comp| {
        let comp_str = comp.as_os_str().to_string_lossy();
        cfg.exclude_dirs.iter().any(|d| comp_str == d.as_str())
    })
}

fn is_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()).unwrap_or_default(),
        "rs" | "go" | "js" | "jsx" | "ts" | "tsx" | "py" | "java" | "kt" | "cs"
            | "c" | "h" | "cpp" | "hpp" | "rb" | "php" | "swift" | "m" | "mm"
            | "scala" | "sh"
    )
}

// ---------------------------------------------------------------------------
// Comment / string stripping (mirrors source.rs logic)
// ---------------------------------------------------------------------------

fn strip_comments(text: &str, ext: &str) -> String {
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

    let is_c_like = matches!(
        ext,
        "rs" | "go"
            | "js" | "jsx" | "ts" | "tsx"
            | "java" | "kt" | "cs"
            | "c" | "h" | "cpp" | "hpp"
            | "swift" | "m" | "mm" | "scala" | "php"
    );
    let is_script = matches!(ext, "py" | "rb" | "sh");
    let is_xml = ext == "xml";

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
            if is_c_like && i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '/' {
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
            if i + 2 < chars.len() && chars[i] == '-' && chars[i + 1] == '-' && chars[i + 2] == '>'
            {
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
            if i + 2 < chars.len()
                && chars[i] == tc
                && chars[i + 1] == tc
                && chars[i + 2] == tc
            {
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

        if is_c_like && i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '*' {
            in_block_comment = true;
            out.push(' ');
            out.push(' ');
            i += 2;
            continue;
        }

        if is_xml
            && i + 3 < chars.len()
            && chars[i] == '<'
            && chars[i + 1] == '!'
            && chars[i + 2] == '-'
            && chars[i + 3] == '-'
        {
            in_xml_comment = true;
            out.push(' ');
            out.push(' ');
            out.push(' ');
            out.push(' ');
            i += 4;
            continue;
        }

        if is_c_like && i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '/' {
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
            if (tc == '"' || tc == '\'') && chars[i + 1] == tc && chars[i + 2] == tc {
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

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

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
