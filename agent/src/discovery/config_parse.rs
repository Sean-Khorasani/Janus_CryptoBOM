//! Structural configuration parsing for crypto posture (WP-014).
//!
//! Where the generic source scanner matches regex patterns line-by-line, this
//! module understands the *structure* of well-known security configuration
//! formats — it knows that nginx `ssl_protocols` is a protocol directive and
//! `ssl_ciphers` a cipher list, that OpenSSH `KexAlgorithms` selects key
//! exchange, and that an OpenSSL `CipherString` configures the default suite.
//! Directive-aware parsing yields higher-confidence, correctly-attributed
//! findings than a bare identifier match, and lets us recognize PQC-hybrid
//! groups (X25519MLKEM768, sntrup761x25519) as *not* quantum-vulnerable.
//!
//! Supported formats: nginx, OpenSSH sshd_config/ssh_config, OpenSSL openssl.cnf.
//! Anything else returns `None` and falls back to the regex scanner.

use crate::proto::{CryptoAlgorithm, CryptoRole};
use std::path::Path;

/// The structured config formats this module understands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigFormat {
    Nginx,
    Ssh,
    OpenSsl,
}

impl ConfigFormat {
    pub fn label(self) -> &'static str {
        match self {
            Self::Nginx => "nginx",
            Self::Ssh => "ssh",
            Self::OpenSsl => "openssl",
        }
    }
}

/// Result of a structural config scan: the recognized format and the findings.
pub struct ConfigScan {
    pub format: ConfigFormat,
    pub algorithms: Vec<CryptoAlgorithm>,
}

/// Recognize the config format from filename first, then a content sniff.
/// Returns `None` for files that are not one of the supported structured formats,
/// so the caller can fall back to the generic regex scanner.
pub fn recognize(path: &Path, text: &str) -> Option<ConfigFormat> {
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if fname == "sshd_config" || fname == "ssh_config" {
        return Some(ConfigFormat::Ssh);
    }
    if fname == "openssl.cnf" || fname == "openssl.conf" {
        return Some(ConfigFormat::OpenSsl);
    }
    if fname.contains("nginx") {
        return Some(ConfigFormat::Nginx);
    }

    // Content sniff for files without a canonical name. Require a directive that
    // is distinctive to the format to avoid misclassifying generic .conf files.
    let lower = text.to_ascii_lowercase();
    if lower.contains("ssl_protocols")
        || lower.contains("ssl_ciphers")
        || lower.contains("ssl_ecdh_curve")
    {
        return Some(ConfigFormat::Nginx);
    }
    if directive_present(text, "KexAlgorithms") || directive_present(text, "HostKeyAlgorithms") {
        return Some(ConfigFormat::Ssh);
    }
    if lower.contains("cipherstring") || lower.contains("minprotocol") {
        return Some(ConfigFormat::OpenSsl);
    }
    None
}

/// Parse a recognized config file into structured crypto findings.
pub fn scan(path: &Path, text: &str) -> Option<ConfigScan> {
    let format = recognize(path, text)?;
    let file = path.display().to_string();
    let mut algorithms = Vec::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line = strip_inline_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let lineno = (idx + 1) as u32;
        match format {
            ConfigFormat::Nginx => parse_nginx_line(line, raw_line, &file, lineno, &mut algorithms),
            ConfigFormat::Ssh => parse_ssh_line(line, raw_line, &file, lineno, &mut algorithms),
            ConfigFormat::OpenSsl => {
                parse_openssl_line(line, raw_line, &file, lineno, &mut algorithms)
            }
        }
    }

    Some(ConfigScan { format, algorithms })
}

/// True for extensionless config files that the generic `is_source` extension
/// gate would otherwise skip but the structural parser recognizes by filename
/// (e.g. `sshd_config`, `ssh_config`). Extension-bearing configs (.conf/.cnf)
/// already pass the source gate.
pub fn is_known_config_path(path: &Path) -> bool {
    matches!(
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default(),
        "sshd_config" | "ssh_config"
    )
}

/// The source_type label written into Evidence for structural config findings.
pub fn source_type_label() -> &'static str {
    "structural-config"
}

/// Structural directive matches are high-confidence: the directive context proves
/// the token is an active crypto selection, not an incidental identifier.
pub const CONFIG_CONFIDENCE: f64 = 0.90;

// ----------------------------------------------------------------------------
// nginx
// ----------------------------------------------------------------------------

fn parse_nginx_line(
    line: &str,
    raw: &str,
    file: &str,
    lineno: u32,
    out: &mut Vec<CryptoAlgorithm>,
) {
    if let Some(val) = directive_value(line, "ssl_protocols") {
        for proto in val.split_whitespace() {
            push_protocol(proto, raw, file, lineno, out);
        }
    } else if let Some(val) = directive_value(line, "ssl_ciphers") {
        let cleaned = val.trim_matches(|c| c == '"' || c == '\'' || c == ';');
        for token in split_cipher_list(cleaned) {
            push_cipher_token(&token, raw, file, lineno, out);
        }
    } else if let Some(val) = directive_value(line, "ssl_ecdh_curve") {
        for token in val.trim_end_matches(';').split(':') {
            push_kex_token(token.trim(), raw, file, lineno, out);
        }
    }
}

// ----------------------------------------------------------------------------
// OpenSSH
// ----------------------------------------------------------------------------

fn parse_ssh_line(line: &str, raw: &str, file: &str, lineno: u32, out: &mut Vec<CryptoAlgorithm>) {
    if let Some(val) = ssh_directive_value(line, "KexAlgorithms") {
        for token in split_csv(val) {
            push_kex_token(&token, raw, file, lineno, out);
        }
    } else if let Some(val) = ssh_directive_value(line, "Ciphers") {
        for token in split_csv(val) {
            push_cipher_token(&token, raw, file, lineno, out);
        }
    } else if let Some(val) = ssh_directive_value(line, "MACs") {
        for token in split_csv(val) {
            push_mac_token(&token, raw, file, lineno, out);
        }
    } else if let Some(val) = ssh_directive_value(line, "HostKeyAlgorithms") {
        for token in split_csv(val) {
            push_sig_token(&token, raw, file, lineno, out);
        }
    }
}

// ----------------------------------------------------------------------------
// OpenSSL
// ----------------------------------------------------------------------------

fn parse_openssl_line(
    line: &str,
    raw: &str,
    file: &str,
    lineno: u32,
    out: &mut Vec<CryptoAlgorithm>,
) {
    if let Some(val) = eq_directive_value(line, "MinProtocol") {
        push_protocol(val.trim(), raw, file, lineno, out);
    } else if let Some(val) = eq_directive_value(line, "CipherString") {
        for token in split_cipher_list(val.trim()) {
            push_cipher_token(&token, raw, file, lineno, out);
        }
    } else if let Some(val) =
        eq_directive_value(line, "Groups").or_else(|| eq_directive_value(line, "Curves"))
    {
        for token in val.trim().split(':') {
            push_kex_token(token.trim(), raw, file, lineno, out);
        }
    }
}

// ----------------------------------------------------------------------------
// Token classification
// ----------------------------------------------------------------------------

fn push_protocol(proto: &str, raw: &str, file: &str, lineno: u32, out: &mut Vec<CryptoAlgorithm>) {
    let p = proto.trim().trim_end_matches(';');
    let upper = p.to_ascii_uppercase();
    let weak = matches!(
        upper.as_str(),
        "SSLV2" | "SSLV3" | "TLSV1" | "TLSV1.0" | "TLSV1.1"
    );
    if upper.starts_with("SSLV") || upper.starts_with("TLSV") {
        out.push(make(
            p,
            "tls-protocol",
            CryptoRole::Unspecified,
            // Legacy protocols are a classical weakness, not a quantum one.
            false,
            weak,
            raw,
            file,
            lineno,
        ));
    }
}

fn push_cipher_token(
    token: &str,
    raw: &str,
    file: &str,
    lineno: u32,
    out: &mut Vec<CryptoAlgorithm>,
) {
    let t = token.to_ascii_uppercase();
    if t.is_empty() {
        return;
    }
    // Key-exchange / authentication components inside a cipher suite name.
    if t.contains("ECDHE") || t.contains("ECDH") {
        push_unique(
            out,
            make(
                token,
                "ECC",
                CryptoRole::KeyExchange,
                true,
                false,
                raw,
                file,
                lineno,
            ),
        );
    }
    if t.contains("DHE") || t.starts_with("DH-") || t.contains("EDH") {
        push_unique(
            out,
            make(
                token,
                "DH",
                CryptoRole::KeyExchange,
                true,
                false,
                raw,
                file,
                lineno,
            ),
        );
    }
    if t.contains("RSA") {
        push_unique(
            out,
            make(
                token,
                "RSA",
                CryptoRole::Signature,
                true,
                false,
                raw,
                file,
                lineno,
            ),
        );
    }
    if t.contains("ECDSA") {
        push_unique(
            out,
            make(
                token,
                "ECC",
                CryptoRole::Signature,
                true,
                false,
                raw,
                file,
                lineno,
            ),
        );
    }
    if t.contains("3DES") || t.contains("DES-CBC3") {
        push_unique(
            out,
            make(
                token,
                "legacy",
                CryptoRole::Symmetric,
                false,
                true,
                raw,
                file,
                lineno,
            ),
        );
    }
    if t.contains("RC4") {
        push_unique(
            out,
            make(
                token,
                "legacy",
                CryptoRole::Symmetric,
                false,
                true,
                raw,
                file,
                lineno,
            ),
        );
    }
    if t.contains("AES128") || t.contains("AES-128") || t.contains("AES_128") {
        push_unique(
            out,
            make(
                token,
                "AES",
                CryptoRole::Symmetric,
                false,
                false,
                raw,
                file,
                lineno,
            ),
        );
    }
    if t.ends_with("SHA") || t.contains("-SHA-") || t.ends_with("SHA1") {
        push_unique(
            out,
            make(
                token,
                "hash",
                CryptoRole::Hash,
                false,
                true,
                raw,
                file,
                lineno,
            ),
        );
    }
}

fn push_kex_token(token: &str, raw: &str, file: &str, lineno: u32, out: &mut Vec<CryptoAlgorithm>) {
    let t = token.trim();
    if t.is_empty() {
        return;
    }
    let lower = t.to_ascii_lowercase();
    // PQC-hybrid groups are the migration target — NOT quantum-vulnerable.
    let hybrid = lower.contains("mlkem")
        || lower.contains("ml-kem")
        || lower.contains("kyber")
        || lower.contains("sntrup761");
    if hybrid {
        out.push(make(
            t,
            "hybrid-pqc",
            CryptoRole::KeyExchange,
            false,
            false,
            raw,
            file,
            lineno,
        ));
        return;
    }
    // Classical key-exchange groups/curves are quantum-vulnerable.
    let classical = lower.contains("x25519")
        || lower.contains("curve25519")
        || lower.starts_with("ecdh")
        || lower.contains("secp")
        || lower.contains("prime256")
        || lower.starts_with("ffdhe")
        || lower.contains("diffie");
    if classical {
        out.push(make(
            t,
            "ECC",
            CryptoRole::KeyExchange,
            true,
            false,
            raw,
            file,
            lineno,
        ));
    }
}

fn push_mac_token(token: &str, raw: &str, file: &str, lineno: u32, out: &mut Vec<CryptoAlgorithm>) {
    let lower = token.to_ascii_lowercase();
    // Weak MAC hashes: MD5 and SHA-1.
    if lower.contains("md5") || lower.contains("sha1") {
        out.push(make(
            token,
            "hash",
            CryptoRole::Hash,
            false,
            true,
            raw,
            file,
            lineno,
        ));
    }
}

fn push_sig_token(token: &str, raw: &str, file: &str, lineno: u32, out: &mut Vec<CryptoAlgorithm>) {
    let lower = token.to_ascii_lowercase();
    if lower.contains("ssh-rsa") || lower.contains("rsa-sha") {
        out.push(make(
            token,
            "RSA",
            CryptoRole::Signature,
            true,
            false,
            raw,
            file,
            lineno,
        ));
    } else if lower.contains("ecdsa") {
        out.push(make(
            token,
            "ECC",
            CryptoRole::Signature,
            true,
            false,
            raw,
            file,
            lineno,
        ));
    } else if lower.contains("ed25519") {
        // Ed25519 is classical (quantum-vulnerable) but strong against classical attack.
        out.push(make(
            token,
            "ECC",
            CryptoRole::Signature,
            true,
            false,
            raw,
            file,
            lineno,
        ));
    }
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn make(
    name: &str,
    family: &str,
    role: CryptoRole,
    quantum_vulnerable: bool,
    weak: bool,
    raw: &str,
    file: &str,
    lineno: u32,
) -> CryptoAlgorithm {
    // "negotiate" status reflects that this is a negotiated/config-selected
    // primitive; weak legacy items are flagged but still negotiation-context.
    let status = if weak { "negotiate-weak" } else { "negotiate" };
    CryptoAlgorithm {
        name: name.to_string(),
        family: family.to_string(),
        role: role as i32,
        status: status.to_string(),
        key_bits: 0,
        curve: String::new(),
        implementation_library: String::new(),
        source_file: file.to_string(),
        source_line: lineno,
        source_column: 1,
        symbol: name.to_string(),
        confidence: CONFIG_CONFIDENCE,
        quantum_vulnerable,
        context_snippet: raw.trim().to_string(),
    }
}

/// Avoid emitting the same (name, line, family, role) twice from overlapping
/// cipher-token rules. Role is part of the key so that, e.g., the ECDHE
/// key-exchange and ECDSA signature components of one suite are both kept.
fn push_unique(out: &mut Vec<CryptoAlgorithm>, alg: CryptoAlgorithm) {
    if out.iter().any(|a| {
        a.name == alg.name
            && a.source_line == alg.source_line
            && a.family == alg.family
            && a.role == alg.role
    }) {
        return;
    }
    out.push(alg);
}

/// `directive value...;` (nginx style). Returns the value if the line starts
/// with the directive keyword followed by whitespace.
fn directive_value<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(directive)?;
    let rest = rest.strip_prefix(|c: char| c.is_whitespace())?;
    Some(rest.trim().trim_end_matches(';').trim())
}

/// `Directive value` (OpenSSH style — case-insensitive keyword, space-separated).
fn ssh_directive_value<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    let mut parts = line.splitn(2, char::is_whitespace);
    let key = parts.next()?;
    if !key.eq_ignore_ascii_case(directive) {
        return None;
    }
    parts.next().map(|v| v.trim())
}

/// `Key = value` (OpenSSL ini style — case-insensitive key).
fn eq_directive_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (k, v) = line.split_once('=')?;
    if !k.trim().eq_ignore_ascii_case(key) {
        return None;
    }
    Some(v.trim())
}

fn directive_present(text: &str, directive: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        l.len() >= directive.len()
            && l[..directive.len()].eq_ignore_ascii_case(directive)
            && l[directive.len()..].starts_with(char::is_whitespace)
    })
}

fn split_cipher_list(s: &str) -> Vec<String> {
    s.split([':', ' ', ','])
        .map(|t| t.trim().to_string())
        .filter(|t| {
            !t.is_empty() && !t.starts_with('!') && !t.starts_with('-') && !t.starts_with('+')
        })
        .collect()
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

fn strip_inline_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn names(scan: &ConfigScan) -> Vec<String> {
        scan.algorithms.iter().map(|a| a.name.clone()).collect()
    }

    #[test]
    fn recognizes_by_filename() {
        assert_eq!(
            recognize(Path::new("/etc/ssh/sshd_config"), ""),
            Some(ConfigFormat::Ssh)
        );
        assert_eq!(
            recognize(Path::new("/etc/ssl/openssl.cnf"), ""),
            Some(ConfigFormat::OpenSsl)
        );
        assert_eq!(
            recognize(Path::new("/etc/nginx/nginx.conf"), ""),
            Some(ConfigFormat::Nginx)
        );
        assert_eq!(
            recognize(Path::new("/app/random.conf"), "key = value\n"),
            None
        );
    }

    #[test]
    fn recognizes_by_content_sniff() {
        assert_eq!(
            recognize(
                Path::new("site.conf"),
                "server {\n  ssl_protocols TLSv1.2;\n}"
            ),
            Some(ConfigFormat::Nginx)
        );
        assert_eq!(
            recognize(Path::new("custom"), "KexAlgorithms curve25519-sha256\n"),
            Some(ConfigFormat::Ssh)
        );
    }

    #[test]
    fn nginx_flags_legacy_protocols_and_classical_kex() {
        let cfg = "ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA;\n";
        let scan = scan(Path::new("nginx.conf"), cfg).unwrap();
        let n = names(&scan);
        // Legacy protocols flagged as weak.
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.name == "TLSv1" && a.status == "negotiate-weak"));
        // ECDHE + RSA from the cipher are quantum-vulnerable.
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.family == "ECC" && a.quantum_vulnerable));
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.family == "RSA" && a.quantum_vulnerable));
        // DHE recognized as DH key exchange.
        assert!(scan.algorithms.iter().any(|a| a.family == "DH"));
        // SHA1 suffix flagged weak.
        assert!(
            scan.algorithms.iter().any(|a| a.family == "hash"),
            "expected a hash finding in {n:?}"
        );
    }

    #[test]
    fn ssh_distinguishes_hybrid_from_classical_kex() {
        let cfg = "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256\n";
        let scan = scan(Path::new("sshd_config"), cfg).unwrap();
        // Hybrid PQC groups are NOT quantum-vulnerable.
        let hybrids: Vec<_> = scan
            .algorithms
            .iter()
            .filter(|a| a.family == "hybrid-pqc")
            .collect();
        assert_eq!(
            hybrids.len(),
            2,
            "expected 2 hybrid groups, got {:?}",
            names(&scan)
        );
        assert!(hybrids.iter().all(|a| !a.quantum_vulnerable));
        // Classical curve25519 IS quantum-vulnerable.
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.name.contains("curve25519") && a.quantum_vulnerable));
    }

    #[test]
    fn ssh_flags_weak_macs_and_rsa_hostkeys() {
        let cfg = "MACs hmac-sha1,hmac-md5,hmac-sha2-256\nHostKeyAlgorithms ssh-rsa,ssh-ed25519\n";
        let scan = scan(Path::new("sshd_config"), cfg).unwrap();
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.name.contains("sha1") && !a.quantum_vulnerable));
        assert!(scan.algorithms.iter().any(|a| a.name.contains("md5")));
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.name == "ssh-rsa" && a.family == "RSA"));
    }

    #[test]
    fn openssl_parses_cipherstring_and_groups() {
        let cfg = "[system_default_sect]\nMinProtocol = TLSv1.2\nCipherString = ECDHE-ECDSA-AES256-GCM-SHA384\nGroups = X25519MLKEM768:x25519\n";
        let scan = scan(Path::new("openssl.cnf"), cfg).unwrap();
        // Hybrid group recognized, classical x25519 flagged QV.
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.family == "hybrid-pqc" && !a.quantum_vulnerable));
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.name == "x25519" && a.quantum_vulnerable));
        // ECDSA from the cipher string.
        assert!(scan
            .algorithms
            .iter()
            .any(|a| a.family == "ECC" && a.role == CryptoRole::Signature as i32));
    }

    #[test]
    fn all_findings_are_high_confidence_and_negotiation_context() {
        let cfg = "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n";
        let scan = scan(Path::new("nginx.conf"), cfg).unwrap();
        assert!(!scan.algorithms.is_empty());
        for a in &scan.algorithms {
            assert!(
                a.confidence >= 0.85,
                "structural findings should be high-confidence"
            );
            assert!(
                a.status.starts_with("negotiate"),
                "structural findings are negotiation-context"
            );
            assert!(!a.context_snippet.is_empty());
        }
    }

    #[test]
    fn comments_are_ignored() {
        let cfg = "# ssl_protocols TLSv1;\nssl_protocols TLSv1.3;\n";
        let scan = scan(Path::new("nginx.conf"), cfg).unwrap();
        // The commented TLSv1 must not be flagged; only TLSv1.3 (strong) appears.
        assert!(!scan.algorithms.iter().any(|a| a.name == "TLSv1"));
    }
}
