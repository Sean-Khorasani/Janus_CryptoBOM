use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use uuid::Uuid;
use walkdir::WalkDir;

use object::{Object, ObjectSection};

const SYMBOLS: &[(&str, &str, CryptoRole)] = &[
    (
        "EVP_EncryptInit",
        "OpenSSL EVP symmetric encryption",
        CryptoRole::Symmetric,
    ),
    (
        "EVP_DecryptInit",
        "OpenSSL EVP symmetric decryption",
        CryptoRole::Symmetric,
    ),
    (
        "RSA_public_encrypt",
        "OpenSSL RSA public encryption",
        CryptoRole::KeyExchange,
    ),
    (
        "RSA_private_decrypt",
        "OpenSSL RSA private decryption",
        CryptoRole::KeyExchange,
    ),
    ("RSA_sign", "OpenSSL RSA signature", CryptoRole::Signature),
    (
        "ECDSA_sign",
        "OpenSSL ECDSA signature",
        CryptoRole::Signature,
    ),
    (
        "ECDH_compute_key",
        "OpenSSL ECDH key exchange",
        CryptoRole::KeyExchange,
    ),
    (
        "DH_generate_key",
        "OpenSSL DH key exchange",
        CryptoRole::KeyExchange,
    ),
    (
        "SSL_CTX_set_cipher_list",
        "OpenSSL TLS cipher configuration",
        CryptoRole::KeyExchange,
    ),
    (
        "SSL_CTX_set1_groups_list",
        "OpenSSL TLS group configuration",
        CryptoRole::KeyExchange,
    ),
    (
        "BCryptEncrypt",
        "Windows CNG encryption",
        CryptoRole::Symmetric,
    ),
    (
        "BCryptSecretAgreement",
        "Windows CNG secret agreement",
        CryptoRole::KeyExchange,
    ),
    (
        "CryptEncrypt",
        "Windows CAPI encryption",
        CryptoRole::Symmetric,
    ),
    ("CCCrypt", "macOS CommonCrypto", CryptoRole::Symmetric),
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
            super::status::update_progress("Binary PE/ELF Inspection", entry.path());
            if !entry.file_type().is_file() {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.len() == 0 || metadata.len() > cfg.max_binary_bytes {
                continue;
            }
            let raw = match fs::read(entry.path()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !is_binary_candidate(entry.path(), &raw) {
                continue;
            }
            let mut algorithms = Vec::new();
            let mut parsed_ok = false;
            // Optional static disassembly of the code section (LLM-007), gated by the
            // binary-analysis policy. Static decode only — no execution, no sandbox.
            let mut disasm_summary = String::new();

            if let Ok(binary_file) = object::File::parse(&*raw) {
                parsed_ok = true;
                if cfg.binary_llm_policy.allow_hexdump_window {
                    disasm_summary = disassemble_text_section(&binary_file);
                }

                // Enumerate imports
                if let Ok(imports) = binary_file.imports() {
                    for import in imports {
                        let symbol_name = String::from_utf8_lossy(import.name());
                        let library_name = String::from_utf8_lossy(import.library());
                        for (sym, description, role) in SYMBOLS {
                            if symbol_name == *sym {
                                let mut desc = description.to_string();
                                if !library_name.is_empty() {
                                    desc = format!("{} (imported from {})", desc, library_name);
                                }
                                algorithms.push(CryptoAlgorithm {
                                    name: algorithm_name(sym),
                                    family: family_name(sym),
                                    role: *role as i32,
                                    status: "binary-import-observed".to_string(),
                                    key_bits: 0,
                                    curve: String::new(),
                                    implementation_library: desc,
                                    source_file: entry.path().display().to_string(),
                                    source_line: 0,
                                    source_column: 0,
                                    symbol: sym.to_string(),
                                    confidence: 0.90, // Structural import is high confidence
                                    quantum_vulnerable: false,

                                    context_snippet: String::new(),
                                });
                            }
                        }
                    }
                }

                // Enumerate exports
                if let Ok(exports) = binary_file.exports() {
                    for export in exports {
                        if let Ok(name) = std::str::from_utf8(export.name()) {
                            for (sym, description, role) in SYMBOLS {
                                if name == *sym {
                                    algorithms.push(CryptoAlgorithm {
                                        name: algorithm_name(sym),
                                        family: family_name(sym),
                                        role: *role as i32,
                                        status: "binary-export-observed".to_string(),
                                        key_bits: 0,
                                        curve: String::new(),
                                        implementation_library: format!(
                                            "{} (exported)",
                                            description
                                        ),
                                        source_file: entry.path().display().to_string(),
                                        source_line: 0,
                                        source_column: 0,
                                        symbol: sym.to_string(),
                                        confidence: 0.90, // Structural export is high confidence
                                        quantum_vulnerable: false,
                                        context_snippet: String::new(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Fallback to raw string search if not parseable
            if !parsed_ok {
                for (symbol, description, role) in SYMBOLS {
                    if contains_ascii(&raw, symbol.as_bytes()) {
                        algorithms.push(CryptoAlgorithm {
                            name: algorithm_name(symbol),
                            family: family_name(symbol),
                            role: *role as i32,
                            status: "binary-symbol-observed".to_string(),
                            key_bits: 0,
                            curve: String::new(),
                            implementation_library: description.to_string(),
                            source_file: entry.path().display().to_string(),
                            source_line: 0,
                            source_column: 0,
                            symbol: symbol.to_string(),
                            confidence: 0.30, // Regex fallback is low confidence
                            quantum_vulnerable: false,

                            context_snippet: String::new(),
                        });
                    }
                }
            }

            if algorithms.is_empty() {
                continue;
            }
            // Attach the disassembly summary (if collected) to the first finding as
            // instruction-level evidence for downstream binary-analysis reports (LLM-007).
            if !disasm_summary.is_empty() {
                algorithms[0].context_snippet = disasm_summary;
            }
            let path = entry.path().display().to_string();
            out.evidence.push(Evidence {
                evidence_id: Uuid::new_v4().to_string(),
                source_type: "binary".to_string(),
                source_tool: "janus-agent-symbol-scanner".to_string(),
                target: path.clone(),
                collection_time_unix: now(),
                raw_artifact_sha256: sha256_hex(&raw),
                confidence: 0.74,
                sensitivity_class: "metadata-only".to_string(),
            });
            out.components.push(CbomComponent {
                bom_ref: format!("binary:{}", path.replace('\\', "/")),
                name: entry
                    .path()
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                version: String::new(),
                component_type: binary_type(&raw).to_string(),
                purl: String::new(),
                file_path: path,
                language: "binary".to_string(),
                algorithms,
                dependencies: Vec::new(),
                // WP-014: presence of a crypto symbol in an import/export table
                // does not prove it is exercised at runtime. Do not claim proven
                // reachability from static binary inspection.
                reachable: false,
            });
        }
    }
    Ok(out)
}

fn include_entry(path: &Path, cfg: &AgentConfig) -> bool {
    !path.components().any(|comp| {
        let comp_str = comp.as_os_str().to_string_lossy();
        cfg.exclude_dirs.iter().any(|d| comp_str == d.as_str())
    })
}

fn is_binary_candidate(path: &Path, raw: &[u8]) -> bool {
    if raw.len() < 4 {
        return false;
    }
    matches!(binary_type(raw), "ELF" | "PE" | "Mach-O")
        || matches!(
            path.extension()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
            "exe" | "dll" | "so" | "dylib" | "bin" | "jar" | "war" | "ear" | "class"
        )
}

fn binary_type(raw: &[u8]) -> &'static str {
    if raw.starts_with(&[0x7f, b'E', b'L', b'F']) {
        "ELF"
    } else if raw.starts_with(b"MZ") {
        "PE"
    } else if raw.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || raw.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || raw.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || raw.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        "Mach-O"
    } else {
        "binary"
    }
}

fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn algorithm_name(symbol: &str) -> String {
    if symbol.contains("RSA") {
        "RSA".to_string()
    } else if symbol.contains("ECDSA") {
        "ECDSA".to_string()
    } else if symbol.contains("ECDH") || symbol.contains("SecretAgreement") {
        "ECDH".to_string()
    } else if symbol.contains("DH_") {
        "DH".to_string()
    } else if symbol.contains("SSL_CTX") {
        "TLS configuration".to_string()
    } else {
        "cryptographic API".to_string()
    }
}

fn family_name(symbol: &str) -> String {
    if symbol.contains("RSA") {
        "RSA".to_string()
    } else if symbol.contains("ECDSA") || symbol.contains("ECDH") {
        "ECC".to_string()
    } else if symbol.contains("DH_") {
        "DH".to_string()
    } else {
        "library-api".to_string()
    }
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

/// disassemble_text_section statically decodes a bounded window of the binary's executable
/// code (`.text`) into human-readable x86/x64 instructions for binary-analysis evidence
/// (LLM-007). Returns "" for non-x86 architectures or when no code section is present. This is
/// static byte decoding only — no execution, hence no sandbox is required.
fn disassemble_text_section(file: &object::File<'_>) -> String {
    let bitness: u32 = match file.architecture() {
        object::Architecture::X86_64 => 64,
        object::Architecture::I386 => 32,
        _ => return String::new(),
    };
    let section = match file.section_by_name(".text") {
        Some(s) => s,
        None => return String::new(),
    };
    let data = match section.data() {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    let window = &data[..data.len().min(64)];
    disassemble(window, section.address(), bitness, 12).join("\n")
}

/// disassemble statically decodes up to `max` x86/x64 instructions from `code` (starting
/// instruction pointer `rip`, `bitness` 32 or 64) and returns "address  mnemonic operands"
/// lines. Pure decode; never executes the bytes.
fn disassemble(code: &[u8], rip: u64, bitness: u32, max: usize) -> Vec<String> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
    let mut decoder = Decoder::with_ip(bitness, code, rip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instr = Instruction::default();
    let mut out = Vec::new();
    while decoder.can_decode() && out.len() < max {
        decoder.decode_out(&mut instr);
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        out.push(format!("{:016X}  {}", instr.ip(), text));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // LLM-007 static disassembly: decode known x86-64 machine code into mnemonics. No execution.
    #[test]
    fn disassembles_known_x64_bytes() {
        // 48 89 E5 = `mov rbp, rsp`; C3 = `ret`.
        let code = [0x48u8, 0x89, 0xE5, 0xC3];
        let out = disassemble(&code, 0x1000, 64, 8);
        assert_eq!(out.len(), 2, "expected two instructions, got {out:?}");
        let first = out[0].to_lowercase();
        assert!(
            first.contains("mov") && first.contains("rbp"),
            "got {}",
            out[0]
        );
        assert!(out[1].to_lowercase().contains("ret"), "got {}", out[1]);
        // The starting IP is rendered.
        assert!(out[0].starts_with("0000000000001000"), "got {}", out[0]);
    }

    #[test]
    fn empty_code_yields_no_instructions() {
        assert!(disassemble(&[], 0, 64, 8).is_empty());
    }
}
