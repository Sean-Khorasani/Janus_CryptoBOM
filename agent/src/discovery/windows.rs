use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::{
    process::Command,
    time::{timeout, Duration},
};
use uuid::Uuid;

#[cfg(target_os = "windows")]
pub async fn scan(cfg: &AgentConfig) -> Result<ScanResult> {
    let mut out = ScanResult::default();
    for (name, args, source_type) in [
        // CNG algorithm registration: ML-KEM/ML-DSA appear in the Microsoft Primitive
        // Provider's per-interface Functions lists on PQ-capable builds (verified on
        // Windows 11 25H2 build 26200: UM\00000008 lists ML-KEM, UM\00000005 ML-DSA).
        ("reg", vec!["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Providers\\Microsoft Primitive Provider\\UM", "/s", "/v", "Functions"], "windows-cng-pq-capability"),
        // OS build + SChannel group/curve order: PQ primitives being present does NOT
        // mean TLS negotiates hybrid groups — the curve list is the enablement signal.
        ("powershell", vec!["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$v = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; $c = ''; try { $c = (Get-TlsEccCurve) -join ',' } catch {}; [PSCustomObject]@{ Build = $v.CurrentBuildNumber; UBR = $v.UBR; DisplayVersion = $v.DisplayVersion; Curves = $c } | ConvertTo-Json -Compress"], "windows-tls-group-policy"),
        ("certutil", vec!["-store", "-user", "My"], "windows-user-cert-store"),
        ("certutil", vec!["-store", "-user", "Root"], "windows-user-root-store"),
        ("certutil", vec!["-store", "My"], "windows-machine-cert-store"),
        ("certutil", vec!["-store", "Root"], "windows-machine-root-store"),
        ("netsh", vec!["http", "show", "sslcert"], "windows-http-sys-tls-bindings"),
        ("certutil", vec!["-csplist"], "windows-cng-provider-inventory"),
        ("reg", vec!["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL", "/s"], "windows-schannel-policy"),
        ("reg", vec!["query", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography", "/s"], "windows-gpo-cryptography"),
        ("reg", vec!["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002", "/v", "Functions"], "windows-cng-ssl-ciphers"),
        ("powershell", vec!["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-NetTCPConnection -State Listen | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; $path = if ($p) { $p.Path } else { \"\" }; [PSCustomObject]@{ LocalPort = $_.LocalPort; OwningProcess = $_.OwningProcess; ProcessPath = $path } } | ConvertTo-Json -Compress"], "windows-listening-ports"),
        ("powershell", vec!["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-Process -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Modules | Where-Object { $_.ModuleName -like '*bcrypt*' -or $_.ModuleName -like '*ncrypt*' -or $_.ModuleName -like '*libcrypto*' -or $_.ModuleName -like '*openssl*' } | ForEach-Object { [PSCustomObject]@{ ProcessName = $_.ProcessName; ModuleName = $_.ModuleName; ModulePath = $_.FileName } } } catch {} } | ConvertTo-Json -Compress"], "windows-loaded-crypto-modules"),
    ] {
        if let Ok(raw) = run(name, &args).await {
            ingest_command_output(&mut out, source_type, name, &args, &raw);
        }
    }
    carve_key_artifacts(cfg, &mut out);
    // W4: when SChannel is PQ-capable-but-disabled, emit the reviewable remediation
    // recipe next to the report. Generated only — applying it is an operator decision.
    let pq_disabled = out.components.iter().find(|c| {
        c.component_type == "windows-tls-group-policy"
            && c.algorithms
                .iter()
                .any(|a| a.status == "schannel-pq-group-disabled")
    });
    if let Some(c) = pq_disabled {
        let curves = c
            .algorithms
            .first()
            .map(|a| a.curve.clone())
            .unwrap_or_default();
        let recipe = schannel_pq_recipe(&c.version, &curves);
        let report_dir = std::path::Path::new(&cfg.report_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let _ = std::fs::write(report_dir.join("schannel-pq-remediation.ps1"), recipe);
    }
    Ok(out)
}

/// Reviewable PowerShell recipe enabling the IANA-registered hybrid group
/// X25519MLKEM768 in SChannel's curve order. Dry-run by default; -Apply gated;
/// preconditions checked; rollback is the inverse cmdlet. Never executed by the agent.
fn schannel_pq_recipe(build: &str, current_curves: &str) -> String {
    format!(
        r#"# janus remediation recipe: enable SChannel hybrid PQ key exchange
# Finding: schannel-pq-group-disabled (build {build}; curve order: {current_curves})
# REVIEW REQUIRED — run without arguments for a dry run; -Apply to make the change.
# Rollback: Disable-TlsEccCurve -Name X25519MLKEM768
param([switch]$Apply)
$ErrorActionPreference = 'Stop'

# Precondition 1: CNG must expose ML-KEM (PQ-capable OS build).
$cap = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Primitive Provider\UM" /s /v Functions 2>$null
if (-not ($cap | Select-String -SimpleMatch 'ML-KEM')) {{
    Write-Error 'CNG does not register ML-KEM on this build — OS update required before enabling hybrid TLS groups.'
}}
# Precondition 2: group must not already be enabled.
$curves = Get-TlsEccCurve
if ($curves -contains 'X25519MLKEM768') {{
    Write-Output 'X25519MLKEM768 already enabled — nothing to do.'
    exit 0
}}
Write-Output "Current curve order: $($curves -join ', ')"
Write-Output 'Planned change: Enable-TlsEccCurve -Name X25519MLKEM768 -Position 0'
if ($Apply) {{
    Enable-TlsEccCurve -Name X25519MLKEM768 -Position 0
    Write-Output "New curve order: $((Get-TlsEccCurve) -join ', ')"
    Write-Output 'Validate with an outbound TLS 1.3 handshake to a hybrid-capable peer, then monitor negotiation failures; rollback: Disable-TlsEccCurve -Name X25519MLKEM768'
}} else {{
    Write-Output 'Dry run only. Re-run with -Apply after review.'
}}
"#
    )
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

    // Typed source types dispatch directly — the generic capability needle-matcher
    // below would otherwise swallow them (e.g. the CNG PQ registry output contains
    // "RSA_SIGN"/"ECDSA" and would misparse as a provider-capability component).
    let mut components = match source_type {
        "windows-cng-pq-capability" => vec![parse_cng_pq_capability(raw)],
        "windows-tls-group-policy" => vec![parse_tls_group_policy(raw)],
        _ => parse_certutil_store(source_type, raw),
    };
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

                context_snippet: String::new(),
            }],
            dependencies: Vec::new(),
            reachable: true,
        });
    }
    if components.is_empty() && source_type == "windows-schannel-policy" {
        components.push(parse_schannel_policy(raw));
    }
    if components.is_empty() && source_type == "windows-gpo-cryptography" {
        components.push(parse_gpo_cryptography(raw));
    }
    if components.is_empty() && source_type == "windows-cng-ssl-ciphers" {
        components.push(parse_cng_ssl_ciphers(raw));
    }
    if components.is_empty() && source_type == "windows-listening-ports" {
        components.extend(parse_listening_ports(raw));
    }
    if components.is_empty() && source_type == "windows-loaded-crypto-modules" {
        components.extend(parse_loaded_crypto_modules(raw));
    }
    out.components.extend(components);
}

/// CNG PQ primitive capability: positive findings for each PQ algorithm registered in
/// the provider Functions lists, and an explicit NEGATIVE-evidence finding when none
/// are present (so "scanned, absent" is distinguishable from "not scanned").
fn parse_cng_pq_capability(raw: &str) -> CbomComponent {
    let lower = raw.to_ascii_lowercase();
    let mut algorithms = Vec::new();
    for (needle, name, family) in [
        ("ml-kem", "ML-KEM", "ML-KEM"),
        ("ml-dsa", "ML-DSA", "ML-DSA"),
        ("slh-dsa", "SLH-DSA", "SLH-DSA"),
        ("xmss", "XMSS", "hash-based"),
        ("lms", "LMS", "hash-based"),
    ] {
        if lower.contains(needle) {
            algorithms.push(CryptoAlgorithm {
                name: name.to_string(),
                family: family.to_string(),
                role: CryptoRole::Unspecified as i32,
                status: "cng-pq-primitive-available".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: "Microsoft Primitive Provider".to_string(),
                source_file: "HKLM\\...\\Cryptography\\Providers\\Microsoft Primitive Provider\\UM"
                    .to_string(),
                source_line: 0,
                source_column: 0,
                symbol: needle.to_string(),
                confidence: 0.92,
                quantum_vulnerable: false,
                context_snippet: String::new(),
            });
        }
    }
    if algorithms.is_empty() {
        algorithms.push(CryptoAlgorithm {
            name: "PQ primitives absent".to_string(),
            family: "negative-evidence".to_string(),
            role: CryptoRole::Unspecified as i32,
            status: "cng-pq-primitive-absent".to_string(),
            key_bits: 0,
            curve: String::new(),
            implementation_library: "Microsoft Primitive Provider".to_string(),
            source_file: "HKLM\\...\\Cryptography\\Providers\\Microsoft Primitive Provider\\UM".to_string(),
            source_line: 0,
            source_column: 0,
            symbol: "ml-kem|ml-dsa|slh-dsa".to_string(),
            confidence: 0.85,
            quantum_vulnerable: false,
            context_snippet: "CNG provider Functions lists contain no PQ algorithms; OS upgrade required before SChannel PQ enablement".to_string(),
        });
    }
    CbomComponent {
        bom_ref: format!("windows:cng-pq-capability:{}", hash_short(raw)),
        name: "Windows CNG PQ primitive capability".to_string(),
        version: String::new(),
        component_type: "windows-cng-pq-capability".to_string(),
        purl: String::new(),
        file_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Providers".to_string(),
        language: "windows-registry".to_string(),
        algorithms,
        dependencies: Vec::new(),
        reachable: true,
    }
}

/// SChannel negotiation surface: the curve/group order decides whether TLS actually
/// offers hybrid PQ key exchange. Classical-only lists are the QV finding even when
/// the CNG primitives exist ("PQ-capable but not PQ-enabled").
fn parse_tls_group_policy(raw: &str) -> CbomComponent {
    let val: serde_json::Value = serde_json::from_str(raw.trim()).unwrap_or_default();
    let build = val
        .get("Build")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let display = val
        .get("DisplayVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let curves = val.get("Curves").and_then(|v| v.as_str()).unwrap_or("");
    let curves_l = curves.to_ascii_lowercase();
    let pq_enabled = curves_l.contains("mlkem");
    let algorithm = if pq_enabled {
        CryptoAlgorithm {
            name: "PQ-hybrid-KEX".to_string(),
            family: "hybrid-pqc".to_string(),
            role: CryptoRole::KeyExchange as i32,
            status: "schannel-pq-group-enabled".to_string(),
            key_bits: 0,
            curve: curves.to_string(),
            implementation_library: "Schannel".to_string(),
            source_file: "Get-TlsEccCurve".to_string(),
            source_line: 0,
            source_column: 0,
            symbol: "X25519MLKEM768".to_string(),
            confidence: 0.92,
            quantum_vulnerable: false,
            context_snippet: format!("build {build} {display}: curve order = {curves}"),
        }
    } else {
        CryptoAlgorithm {
            name: "classical-only TLS groups".to_string(),
            family: "ECC".to_string(),
            role: CryptoRole::KeyExchange as i32,
            status: "schannel-pq-group-disabled".to_string(),
            key_bits: 0,
            curve: curves.to_string(),
            implementation_library: "Schannel".to_string(),
            source_file: "Get-TlsEccCurve".to_string(),
            source_line: 0,
            source_column: 0,
            symbol: curves.to_string(),
            confidence: 0.88,
            quantum_vulnerable: true,
            context_snippet: format!(
                "build {build} {display}: SChannel offers only classical groups ({curves}); remediation: add X25519MLKEM768 to the ECC curve order (Group Policy: SSL Configuration Settings > ECC Curve Order) on PQ-capable builds"
            ),
        }
    };
    CbomComponent {
        bom_ref: format!("windows:tls-group-policy:{}", hash_short(raw)),
        name: "Windows SChannel TLS group policy".to_string(),
        version: build,
        component_type: "windows-tls-group-policy".to_string(),
        purl: String::new(),
        file_path: "Get-TlsEccCurve".to_string(),
        language: "windows".to_string(),
        algorithms: vec![algorithm],
        dependencies: Vec::new(),
        reachable: true,
    }
}

/// Key/cert artifact carving over scan roots: records hash + metadata ONLY (file name,
/// size, header type) — never key material. PEM headers are classified from the first
/// bytes; PFX/JKS by extension.
#[allow(dead_code)] // invoked from the Windows-only scan(); parsers stay cross-platform for tests
fn carve_key_artifacts(cfg: &AgentConfig, out: &mut ScanResult) {
    use std::path::Path;
    for root in &cfg.scan_roots {
        for entry in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                !e.path().components().any(|comp| {
                    let comp_str = comp.as_os_str().to_string_lossy();
                    cfg.exclude_dirs.iter().any(|d| comp_str == d.as_str())
                })
            })
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let ext = entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !matches!(
                ext.as_str(),
                "pfx" | "p12" | "pem" | "jks" | "key" | "der" | "crt" | "cer"
            ) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() > cfg.max_file_bytes {
                continue;
            }
            let Ok(raw) = std::fs::read(entry.path()) else {
                continue;
            };
            let header = classify_key_artifact(&ext, &raw);
            let path = entry.path().display().to_string();
            out.evidence.push(Evidence {
                evidence_id: Uuid::new_v4().to_string(),
                source_type: "windows-key-artifact".to_string(),
                source_tool: "janus-agent-artifact-carver".to_string(),
                target: path.clone(),
                collection_time_unix: now(),
                raw_artifact_sha256: sha256_hex(&raw),
                confidence: 0.90,
                sensitivity_class: "restricted-key-artifact".to_string(),
            });
            out.components.push(CbomComponent {
                bom_ref: format!("artifact:{}", hash_short(&path)),
                name: Path::new(&path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                version: String::new(),
                component_type: "key-artifact".to_string(),
                purl: String::new(),
                file_path: path,
                language: "artifact".to_string(),
                algorithms: vec![CryptoAlgorithm {
                    name: header.to_string(),
                    family: "key-artifact".to_string(),
                    role: CryptoRole::Unspecified as i32,
                    status: "artifact-carved-metadata-only".to_string(),
                    key_bits: 0,
                    curve: String::new(),
                    implementation_library: String::new(),
                    source_file: format!("size:{}", meta.len()),
                    source_line: 0,
                    source_column: 0,
                    symbol: ext.clone(),
                    confidence: 0.90,
                    // Unencrypted private key material on disk is a finding regardless
                    // of algorithm; encrypted containers and certs are inventory-only.
                    quantum_vulnerable: matches!(
                        header,
                        "pem-private-key" | "pem-private-key-legacy-format"
                    ),
                    context_snippet: String::new(),
                }],
                dependencies: Vec::new(),
                reachable: true,
            });
        }
    }
}

/// Classify a key artifact from extension + leading bytes; never returns key content.
#[allow(dead_code)] // exercised by unit tests on all platforms; runtime use is Windows-only
fn classify_key_artifact(ext: &str, raw: &[u8]) -> &'static str {
    let head = String::from_utf8_lossy(&raw[..raw.len().min(80)]).to_string();
    if head.contains("BEGIN RSA PRIVATE KEY")
        || head.contains("BEGIN EC PRIVATE KEY")
        || head.contains("BEGIN DSA PRIVATE KEY")
    {
        return "pem-private-key-legacy-format";
    }
    if head.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        return "pem-private-key-encrypted";
    }
    if head.contains("BEGIN PRIVATE KEY") || head.contains("BEGIN OPENSSH PRIVATE KEY") {
        return "pem-private-key";
    }
    if head.contains("BEGIN CERTIFICATE") {
        return "pem-certificate";
    }
    match ext {
        "pfx" | "p12" => "pkcs12-container",
        "jks" => "java-keystore",
        "der" | "crt" | "cer" => "der-or-cert",
        "key" => "key-file-unrecognized-header",
        _ => "unrecognized",
    }
}

fn parse_certutil_store(source_type: &str, raw: &str) -> Vec<CbomComponent> {
    let mut components = Vec::new();
    let mut subject = String::new();
    let mut issuer = String::new();
    let mut algorithms = Vec::<CryptoAlgorithm>::new();

    for line in raw.lines().map(str::trim) {
        if line.starts_with("================ Certificate") {
            flush_cert(
                source_type,
                &mut components,
                &mut subject,
                &mut issuer,
                &mut algorithms,
            );
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
                if last.family == "RSA" && bits > 0 && bits < 2048 {
                    last.status = "weak-key".to_string();
                }
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
    flush_cert(
        source_type,
        &mut components,
        &mut subject,
        &mut issuer,
        &mut algorithms,
    );
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

                context_snippet: String::new(),
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
                source_file:
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"
                        .to_string(),
                source_line: 0,
                source_column: 0,
                symbol: needle.to_string(),
                confidence: 0.66,
                quantum_vulnerable: false,

                context_snippet: String::new(),
            });
        }
    }
    CbomComponent {
        bom_ref: format!("windows:schannel-policy:{}", hash_short(raw)),
        name: "Windows Schannel policy".to_string(),
        version: String::new(),
        component_type: "windows-schannel-policy".to_string(),
        purl: String::new(),
        file_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"
            .to_string(),
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
        bom_ref: format!(
            "windows:cert:{}:{}",
            source_type,
            hash_short(&format!("{subject}{issuer}{:?}", algorithms.len()))
        ),
        name,
        version: String::new(),
        // Self-signed (subject == issuer) certificates are trust anchors or local
        // dev certs — chain analysis treats them as chain heads.
        component_type: if !subject.is_empty() && subject == issuer {
            "certificate-self-signed".to_string()
        } else {
            "certificate".to_string()
        },
        purl: String::new(),
        file_path: source_type.to_string(),
        language: "windows-cert-store".to_string(),
        algorithms: std::mem::take(algorithms),
        dependencies: if issuer.is_empty() {
            Vec::new()
        } else {
            vec![issuer.clone()]
        },
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
    // (name, family, quantum_vulnerable). Cert public keys and signatures over
    // RSA/ECC/DSA are the inventory's core QV findings; PQ algorithms (RFC 9881
    // ML-DSA OID arc 2.16.840.1.101.3.4.3.x, RFC 9909 SLH-DSA) classify as safe.
    let (name, family, qv) = if lower.contains("ml-dsa") || lower.contains("2.16.840.1.101.3.4.3.1")
    {
        ("ML-DSA".to_string(), "ML-DSA".to_string(), false)
    } else if lower.contains("slh-dsa") {
        ("SLH-DSA".to_string(), "SLH-DSA".to_string(), false)
    } else if lower.contains("ml-kem") {
        ("ML-KEM".to_string(), "ML-KEM".to_string(), false)
    } else if lower.contains("ed25519") {
        ("Ed25519".to_string(), "ECC".to_string(), true)
    } else if lower.contains("ecdsa") || lower.contains("ecc") || lower.contains("ecpublickey") {
        // Signature algorithm lines are hash+key combos ("sha256ECDSA") — the
        // public-key component decides quantum vulnerability, so it wins over
        // the hash branches below.
        ("ECDSA/ECC".to_string(), "ECC".to_string(), true)
    } else if lower.contains("rsa") {
        ("RSA".to_string(), "RSA".to_string(), true)
    } else if lower.contains("dsa") {
        ("DSA".to_string(), "DSA".to_string(), true)
    } else if lower.contains("md5") {
        ("MD5".to_string(), "hash".to_string(), true)
    } else if lower.contains("sha1") || lower.contains("sha-1") {
        ("SHA-1".to_string(), "hash".to_string(), true)
    } else if lower.contains("sha256") || lower.contains("sha-256") {
        ("SHA-256".to_string(), "hash".to_string(), false)
    } else if lower.contains("sha384") || lower.contains("sha-384") {
        ("SHA-384".to_string(), "hash".to_string(), false)
    } else {
        (line.to_string(), "windows-crypto".to_string(), false)
    };
    // RSA below 2048 bits is classically weak, independent of the quantum question.
    let status = if family == "RSA" && key_bits > 0 && key_bits < 2048 {
        "weak-key".to_string()
    } else {
        "windows-cert-store-observed".to_string()
    };
    let curve = [
        "p256", "p-256", "p384", "p-384", "p521", "p-521", "nistp256", "nistp384", "nistp521",
    ]
    .iter()
    .find(|c| lower.contains(*c))
    .map(|c| c.to_string())
    .unwrap_or_default();
    CryptoAlgorithm {
        name,
        family,
        role: role as i32,
        status,
        key_bits,
        curve,
        implementation_library: library.to_string(),
        source_file: "certutil".to_string(),
        source_line: 0,
        source_column: 0,
        symbol: line.to_string(),
        confidence: 0.74,
        quantum_vulnerable: qv,
        context_snippet: String::new(),
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

fn parse_gpo_cryptography(raw: &str) -> CbomComponent {
    let mut algorithms = Vec::new();

    let mut has_fips = false;
    let mut has_pin_rules = false;
    let mut has_ecc_curves = false;

    for line in raw.lines() {
        let line_lower = line.to_ascii_lowercase();
        if line_lower.contains("fips") {
            has_fips = true;
        }
        if line_lower.contains("pinrules") {
            has_pin_rules = true;
        }
        if line_lower.contains("ecccurves") {
            has_ecc_curves = true;
        }
    }

    if has_fips {
        algorithms.push(CryptoAlgorithm {
            name: "FIPS mode".to_string(),
            family: "FIPS".to_string(),
            role: CryptoRole::Unspecified as i32,
            status: "windows-gpo-policy-observed".to_string(),
            key_bits: 0,
            curve: String::new(),
            implementation_library: "Windows Cryptography".to_string(),
            source_file: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography".to_string(),
            source_line: 0,
            source_column: 0,
            symbol: "FIPS".to_string(),
            confidence: 0.85,
            quantum_vulnerable: false,

            context_snippet: String::new(),
        });
    }

    if has_pin_rules {
        algorithms.push(CryptoAlgorithm {
            name: "Pin Rules".to_string(),
            family: "policy".to_string(),
            role: CryptoRole::Unspecified as i32,
            status: "windows-gpo-policy-observed".to_string(),
            key_bits: 0,
            curve: String::new(),
            implementation_library: "Windows Cryptography".to_string(),
            source_file: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography".to_string(),
            source_line: 0,
            source_column: 0,
            symbol: "PinRules".to_string(),
            confidence: 0.85,
            quantum_vulnerable: false,

            context_snippet: String::new(),
        });
    }

    if has_ecc_curves {
        algorithms.push(CryptoAlgorithm {
            name: "ECC Curves Policy".to_string(),
            family: "ECC".to_string(),
            role: CryptoRole::Unspecified as i32,
            status: "windows-gpo-policy-observed".to_string(),
            key_bits: 0,
            curve: String::new(),
            implementation_library: "Windows Cryptography".to_string(),
            source_file: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography".to_string(),
            source_line: 0,
            source_column: 0,
            symbol: "ECCCurves".to_string(),
            confidence: 0.85,
            quantum_vulnerable: false,

            context_snippet: String::new(),
        });
    }

    if algorithms.is_empty() {
        algorithms.push(CryptoAlgorithm {
            name: "Group Policy Cryptography Audit".to_string(),
            family: "policy".to_string(),
            role: CryptoRole::Unspecified as i32,
            status: "windows-gpo-policy-scanned".to_string(),
            key_bits: 0,
            curve: String::new(),
            implementation_library: "Windows Cryptography".to_string(),
            source_file: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography".to_string(),
            source_line: 0,
            source_column: 0,
            symbol: "Microsoft\\Cryptography".to_string(),
            confidence: 0.80,
            quantum_vulnerable: false,

            context_snippet: String::new(),
        });
    }

    CbomComponent {
        bom_ref: format!("windows:gpo-cryptography:{}", hash_short(raw)),
        name: "Windows Cryptography Group Policy".to_string(),
        version: String::new(),
        component_type: "windows-gpo-cryptography".to_string(),
        purl: String::new(),
        file_path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography".to_string(),
        language: "windows-registry".to_string(),
        algorithms,
        dependencies: Vec::new(),
        reachable: true,
    }
}

fn parse_cng_ssl_ciphers(raw: &str) -> CbomComponent {
    let lower = raw.to_ascii_lowercase();
    let mut algorithms = Vec::new();

    for (needle, name, family, role) in [
        (
            "rsa",
            "RSA cipher suites enabled",
            "RSA",
            CryptoRole::KeyExchange,
        ),
        (
            "3des",
            "3DES cipher suites enabled",
            "legacy",
            CryptoRole::Symmetric,
        ),
        (
            "rc4",
            "RC4 cipher suites enabled",
            "legacy",
            CryptoRole::Symmetric,
        ),
        (
            "aes128",
            "AES128 cipher suites enabled",
            "AES",
            CryptoRole::Symmetric,
        ),
        (
            "aes256",
            "AES256 cipher suites enabled",
            "AES",
            CryptoRole::Symmetric,
        ),
        (
            "ecdhe",
            "ECDHE cipher suites enabled",
            "ECC",
            CryptoRole::KeyExchange,
        ),
    ] {
        if lower.contains(needle) {
            algorithms.push(CryptoAlgorithm {
                name: name.to_string(),
                family: family.to_string(),
                role: role as i32,
                status: "windows-cng-cipher-observed".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: "Windows CNG".to_string(),
                source_file: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002".to_string(),
                source_line: 0,
                source_column: 0,
                symbol: needle.to_string(),
                confidence: 0.85,
                quantum_vulnerable: needle == "rsa" || needle == "ecdhe",

                context_snippet: String::new(),
            });
        }
    }

    if algorithms.is_empty() {
        algorithms.push(CryptoAlgorithm {
            name: "Default OS Cipher Suites".to_string(),
            family: "policy".to_string(),
            role: CryptoRole::Unspecified as i32,
            status: "windows-cng-cipher-scanned".to_string(),
            key_bits: 0,
            curve: String::new(),
            implementation_library: "Windows CNG".to_string(),
            source_file: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002".to_string(),
            source_line: 0,
            source_column: 0,
            symbol: "Functions".to_string(),
            confidence: 0.80,
            quantum_vulnerable: false,

            context_snippet: String::new(),
        });
    }

    CbomComponent {
        bom_ref: format!("windows:cng-ssl-ciphers:{}", hash_short(raw)),
        name: "Windows CNG SSL Ciphers".to_string(),
        version: String::new(),
        component_type: "windows-cng-ciphers".to_string(),
        purl: String::new(),
        file_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002".to_string(),
        language: "windows-registry".to_string(),
        algorithms,
        dependencies: Vec::new(),
        reachable: true,
    }
}

fn parse_listening_ports(raw: &str) -> Vec<CbomComponent> {
    let mut components = Vec::new();
    let val: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let items = if val.is_array() {
        val.as_array().unwrap().clone()
    } else {
        vec![val]
    };

    let mut algorithms = Vec::new();
    for item in items {
        let port = item.get("LocalPort").and_then(|v| v.as_u64()).unwrap_or(0);
        let pid = item
            .get("OwningProcess")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let path = item
            .get("ProcessPath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if port > 0 {
            let impl_lib = if path.is_empty() {
                format!("PID {}", pid)
            } else {
                format!("PID {} ({})", pid, path)
            };
            algorithms.push(CryptoAlgorithm {
                name: format!("TCP Port {}", port),
                family: "network-socket".to_string(),
                role: CryptoRole::Unspecified as i32,
                status: "listening-socket-observed".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: impl_lib,
                source_file: if path.is_empty() {
                    "Get-NetTCPConnection".to_string()
                } else {
                    path.to_string()
                },
                source_line: 0,
                source_column: 0,
                symbol: format!("port:{}", port),
                confidence: 0.90,
                quantum_vulnerable: false,
                context_snippet: String::new(),
            });
        }
    }

    if !algorithms.is_empty() {
        components.push(CbomComponent {
            bom_ref: format!("windows:listening-ports:{}", hash_short(raw)),
            name: "Windows Active Listening Sockets".to_string(),
            version: String::new(),
            component_type: "windows-listening-ports".to_string(),
            purl: String::new(),
            file_path: "Get-NetTCPConnection".to_string(),
            language: "windows".to_string(),
            algorithms,
            dependencies: Vec::new(),
            reachable: true,
        });
    }
    components
}

fn parse_loaded_crypto_modules(raw: &str) -> Vec<CbomComponent> {
    let mut components = Vec::new();
    let val: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let items = if val.is_array() {
        val.as_array().unwrap().clone()
    } else {
        vec![val]
    };

    for item in items {
        let process_name = item
            .get("ProcessName")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let module_name = item
            .get("ModuleName")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let module_path = item
            .get("ModulePath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !process_name.is_empty() && !module_name.is_empty() {
            components.push(CbomComponent {
                bom_ref: format!("windows:loaded-module:{}:{}", process_name, module_name),
                name: format!("Loaded DLL {} in {}", module_name, process_name),
                version: String::new(),
                component_type: "windows-loaded-dll".to_string(),
                purl: String::new(),
                file_path: module_path.to_string(),
                language: "windows".to_string(),
                algorithms: vec![CryptoAlgorithm {
                    name: module_name.to_string(),
                    family: "windows-dll".to_string(),
                    role: CryptoRole::Unspecified as i32,
                    status: "loaded-dll-observed".to_string(),
                    key_bits: 0,
                    curve: String::new(),
                    implementation_library: format!("Process {}", process_name),
                    source_file: module_path.to_string(),
                    source_line: 0,
                    source_column: 0,
                    symbol: process_name.to_string(),
                    confidence: 0.95,
                    quantum_vulnerable: module_name.to_ascii_lowercase().contains("openssl")
                        || module_name.to_ascii_lowercase().contains("libcrypto"),
                    context_snippet: String::new(),
                }],
                dependencies: Vec::new(),
                reachable: true,
            });
        }
    }
    components
}

#[cfg(test)]
mod windows_pq_tests {
    use super::*;

    // Captured verbatim from Windows 11 25H2 build 26200.8655 on 2026-06-12.
    const CNG_PQ_REG: &str = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Primitive Provider\UM\00000008
    Functions    REG_MULTI_SZ    ML-KEM

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Primitive Provider\UM\00000005
    Functions    REG_MULTI_SZ    RSA_SIGN\0ECDSA_P256\0ECDSA_P384\0ECDSA_P521\0ECDSA\0ML-DSA
";

    #[test]
    fn cng_pq_capability_detects_mlkem_and_mldsa() {
        let c = parse_cng_pq_capability(CNG_PQ_REG);
        let names: Vec<&str> = c.algorithms.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"ML-KEM"), "{names:?}");
        assert!(names.contains(&"ML-DSA"), "{names:?}");
        assert!(c.algorithms.iter().all(|a| !a.quantum_vulnerable));
    }

    #[test]
    fn cng_pq_capability_emits_negative_evidence_when_absent() {
        let c = parse_cng_pq_capability("Functions    REG_MULTI_SZ    RSA_SIGN\0ECDSA\n");
        assert_eq!(c.algorithms.len(), 1);
        assert_eq!(c.algorithms[0].status, "cng-pq-primitive-absent");
        assert_eq!(c.algorithms[0].family, "negative-evidence");
    }

    #[test]
    fn tls_group_policy_classical_only_is_qv_finding() {
        // Captured shape from this machine: PQ primitives present, SChannel classical.
        let c = parse_tls_group_policy(
            r#"{"Build":"26200","UBR":8655,"DisplayVersion":"25H2","Curves":"curve25519,NistP256,NistP384"}"#,
        );
        assert_eq!(c.algorithms.len(), 1);
        let a = &c.algorithms[0];
        assert_eq!(a.status, "schannel-pq-group-disabled");
        assert!(a.quantum_vulnerable);
        assert!(a.context_snippet.contains("X25519MLKEM768"));
        assert_eq!(c.version, "26200");
    }

    #[test]
    fn tls_group_policy_hybrid_enabled_is_safe() {
        let c = parse_tls_group_policy(
            r#"{"Build":"26300","UBR":1,"DisplayVersion":"26H1","Curves":"X25519MLKEM768,curve25519,NistP256"}"#,
        );
        let a = &c.algorithms[0];
        assert_eq!(a.status, "schannel-pq-group-enabled");
        assert!(!a.quantum_vulnerable);
        assert_eq!(a.family, "hybrid-pqc");
    }

    #[test]
    fn cert_algorithms_flag_quantum_vulnerable() {
        let a = algorithm_from_windows_line(
            "RSA (2048 Bits)",
            CryptoRole::CertPublicKey,
            2048,
            "certutil",
        );
        assert!(a.quantum_vulnerable);
        assert_eq!(a.status, "windows-cert-store-observed");
        let a = algorithm_from_windows_line("RSA", CryptoRole::CertPublicKey, 1024, "certutil");
        assert_eq!(a.status, "weak-key");
        let a = algorithm_from_windows_line(
            "sha256ECDSA P-384",
            CryptoRole::CertSignature,
            0,
            "certutil",
        );
        assert!(a.quantum_vulnerable);
        assert_eq!(a.curve, "p-384");
        let a = algorithm_from_windows_line("ML-DSA-65", CryptoRole::CertSignature, 0, "certutil");
        assert!(!a.quantum_vulnerable);
        assert_eq!(a.name, "ML-DSA");
    }

    #[test]
    fn schannel_recipe_is_gated_and_reversible() {
        let r = schannel_pq_recipe("26200", "curve25519,NistP256,NistP384");
        assert!(
            r.contains("param([switch]$Apply)"),
            "must be dry-run by default"
        );
        assert!(r.contains("Disable-TlsEccCurve"), "must document rollback");
        assert!(
            r.contains("ML-KEM"),
            "must check CNG capability precondition"
        );
        assert!(r.contains("X25519MLKEM768"));
        assert!(r.starts_with("# janus remediation recipe"));
    }

    #[test]
    fn key_artifact_classification_is_metadata_only() {
        assert_eq!(
            classify_key_artifact("pem", b"-----BEGIN RSA PRIVATE KEY-----\nMII..."),
            "pem-private-key-legacy-format"
        );
        assert_eq!(
            classify_key_artifact("pem", b"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
            "pem-private-key-encrypted"
        );
        assert_eq!(
            classify_key_artifact("pem", b"-----BEGIN CERTIFICATE-----"),
            "pem-certificate"
        );
        assert_eq!(
            classify_key_artifact("pfx", &[0x30, 0x82]),
            "pkcs12-container"
        );
        assert_eq!(
            classify_key_artifact("key", b"random bytes"),
            "key-file-unrecognized-header"
        );
    }
}
