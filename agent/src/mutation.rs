use crate::{
    config::AgentConfig,
    proto::{MigrationCommand, MigrationState, MigrationStatusReport},
};
use anyhow::{Context, Result};
use diffy::{apply, Patch};
use subtle::ConstantTimeEq;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use crate::discovery::network::{extract_named_group, parse_x509_der};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::process::Command;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct MutationEngine {
    cfg: AgentConfig,
}

impl MutationEngine {
    pub fn new(cfg: AgentConfig) -> Self {
        Self { cfg }
    }

    pub async fn execute(&self, cmd: MigrationCommand) -> MigrationStatusReport {
        let result = self.execute_inner(&cmd).await;
        match result {
            Ok(output) => {
                let mut rep = report(&cmd, MigrationState::Succeeded, true, "", &output);
                if !cmd.dry_run {
                    rep.observed_tls = verify_post_migration(&cmd.target_service, &self.cfg).await;
                }
                rep
            }
            Err(err) => report(&cmd, MigrationState::Failed, false, &format!("{err:#}"), ""),
        }
    }

    async fn execute_inner(&self, cmd: &MigrationCommand) -> Result<String> {
        if self.cfg.passive() {
            anyhow::bail!("agent is in passive mode; active mutation is disabled");
        }
        if !self.verify(cmd) {
            anyhow::bail!("migration command signature verification failed");
        }
        if !self
            .cfg
            .active
            .allowed_services
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&cmd.target_service))
        {
            anyhow::bail!("target service {} is not allowed", cmd.target_service);
        }
        if cmd.target_service.eq_ignore_ascii_case("windows-trust-store") {
            return self.apply_windows_trust_store(cmd).await;
        }
        if cmd.target_service.eq_ignore_ascii_case("windows-schannel-policy") {
            return self.apply_windows_schannel_policy(cmd).await;
        }
        let config_path = self.checked_config_path(&cmd.config_path)?;
        let original = fs::read_to_string(&config_path)
            .with_context(|| format!("read {}", config_path.display()))?;

        // Config file checksum verification (drift detection)
        if let Some(expected_checksum_entry) = cmd.validation_checklist.iter().find(|val| val.starts_with("checksum=")) {
            let expected_sha = expected_checksum_entry.trim_start_matches("checksum=");
            if !expected_sha.is_empty() {
                let mut h = Sha256::new();
                h.update(original.as_bytes());
                let actual_sha = hex::encode(h.finalize());
                if actual_sha != expected_sha {
                    anyhow::bail!(
                        "config file checksum mismatch (detected drift): expected {}, found {}",
                        expected_sha,
                        actual_sha
                    );
                }
            }
        }

        let patch = Patch::from_str(&cmd.patch_unified_diff).context("parse unified diff")?;
        let patched = apply(&original, &patch).context("apply unified diff")?;

        if cmd.dry_run {
            return Ok(format!(
                "dry-run accepted: service={} config={} profile={} target_kem={} target_signature={}",
                cmd.target_service,
                config_path.display(),
                cmd.migration_profile,
                cmd.target_kem,
                cmd.target_signature
            ));
        }

        fs::create_dir_all(&self.cfg.active.backup_dir).context("create backup directory")?;
        let backup_path = self.backup_path(&config_path, cmd);
        fs::write(&backup_path, &original).with_context(|| format!("write backup {}", backup_path.display()))?;
        fs::write(&config_path, patched).with_context(|| format!("write patched {}", config_path.display()))?;

        if let Err(err) = self.validate(&cmd.target_service, &config_path).await {
            let _ = fs::write(&config_path, &original);
            anyhow::bail!("validation failed and rollback restored backup: {err:#}");
        }

        if let Err(err) = self.reload(&cmd.target_service).await {
            let _ = fs::write(&config_path, &original);
            anyhow::bail!("reload failed and rollback restored backup: {err:#}");
        }

        if !cmd.dry_run && !self.cfg.network_targets.is_empty() {
            let has_tls_targets = self.cfg.network_targets.iter().any(|t| !t.ends_with(":80"));
            if has_tls_targets {
                if verify_post_migration(&cmd.target_service, &self.cfg).await.is_none() {
                    let _ = fs::write(&config_path, &original);
                    let _ = self.reload(&cmd.target_service).await;
                    anyhow::bail!("post-migration TLS handshake verification failed; rollback restored backup");
                }
            }
        }

        Ok(format!(
            "migration applied: service={} config={} backup={}",
            cmd.target_service,
            config_path.display(),
            backup_path.display()
        ))
    }

    fn verify(&self, cmd: &MigrationCommand) -> bool {
        let mut mac = HmacSha256::new_from_slice(self.cfg.command_signing_key.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(canonical_command(cmd).as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        expected
            .as_bytes()
            .ct_eq(cmd.signed_directive.as_slice())
            .into()
    }

    fn checked_config_path(&self, raw: &str) -> Result<PathBuf> {
        let path = PathBuf::from(raw);
        let canonical = path.canonicalize().with_context(|| format!("canonicalize {raw}"))?;
        
        if let Some(ext) = canonical.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_ascii_lowercase();
            if ["exe", "dll", "bat", "sh", "cmd", "bin", "msi", "com", "vbs", "ps1"].contains(&ext_lower.as_str()) {
                anyhow::bail!("mutation blocked: target file extension '.{}' is restricted", ext);
            }
        }

        for root in &self.cfg.active.allowed_config_roots {
            let root = PathBuf::from(root).canonicalize().with_context(|| format!("canonicalize root {root}"))?;
            if canonical.starts_with(root) {
                return Ok(canonical);
            }
        }
        anyhow::bail!("{raw} is outside allowed_config_roots")
    }

    fn backup_path(&self, config_path: &Path, cmd: &MigrationCommand) -> PathBuf {
        let safe_name = config_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "_");
        PathBuf::from(&self.cfg.active.backup_dir)
            .join(format!("{}.{}.bak", safe_name, cmd.command_id))
    }

    async fn validate(&self, service: &str, config_path: &Path) -> Result<String> {
        let (program, args): (&str, Vec<String>) = match service.to_ascii_lowercase().as_str() {
            "nginx" => ("nginx", vec!["-t".into(), "-c".into(), config_path.display().to_string()]),
            "apache" => ("apachectl", vec!["configtest".into()]),
            "ssh" => ("sshd", vec!["-t".into(), "-f".into(), config_path.display().to_string()]),
            other => anyhow::bail!("no validator for service {other}"),
        };
        run(program, &args).await
    }

    async fn reload(&self, service: &str) -> Result<String> {
        let (program, args): (&str, Vec<String>) = match service.to_ascii_lowercase().as_str() {
            "nginx" => ("nginx", vec!["-s".into(), "reload".into()]),
            "apache" => ("apachectl", vec!["graceful".into()]),
            "ssh" if cfg!(target_os = "windows") => ("powershell", vec!["Restart-Service".into(), "sshd".into()]),
            "ssh" => ("systemctl", vec!["reload".into(), "sshd".into()]),
            other => anyhow::bail!("no reloader for service {other}"),
        };
        run(program, &args).await
    }

    async fn apply_windows_trust_store(&self, cmd: &MigrationCommand) -> Result<String> {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = cmd;
            anyhow::bail!("windows-trust-store mutation is only available on Windows");
        }

        #[cfg(target_os = "windows")]
        {
            let store = normalize_windows_store(&cmd.config_path)?;
            if !cmd.patch_unified_diff.contains("BEGIN CERTIFICATE") {
                anyhow::bail!("windows-trust-store command requires PEM certificate payload in patch_unified_diff");
            }
            if cmd.dry_run {
                return Ok(format!(
                    "dry-run accepted: import certificate into Windows store {store}"
                ));
            }

            fs::create_dir_all(&self.cfg.active.backup_dir).context("create backup directory")?;
            let cert_path = PathBuf::from(&self.cfg.active.backup_dir)
                .join(format!("janus-cert-{}.cer", cmd.command_id));
            fs::write(&cert_path, &cmd.patch_unified_diff)
                .with_context(|| format!("write certificate payload {}", cert_path.display()))?;

            let import_script = format!(
                "$cert = Import-Certificate -FilePath '{}' -CertStoreLocation 'Cert:\\{}'; $cert.Thumbprint",
                ps_escape(&cert_path.display().to_string()),
                ps_escape(&store)
            );
            let thumbprint = run(
                "powershell",
                &[
                    "-NoProfile".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-Command".into(),
                    import_script,
                ],
            )
            .await?
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or_default()
            .to_string();

            if thumbprint.is_empty() {
                anyhow::bail!("certificate import did not return a thumbprint");
            }

            let validate_script = format!(
                "if (Test-Path 'Cert:\\{}\\{}') {{ 'present' }} else {{ exit 20 }}",
                ps_escape(&store),
                ps_escape(&thumbprint)
            );
            if let Err(err) = run(
                "powershell",
                &[
                    "-NoProfile".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-Command".into(),
                    validate_script,
                ],
            )
            .await
            {
                let _ = rollback_windows_cert(&store, &thumbprint).await;
                anyhow::bail!("certificate validation failed and rollback was attempted: {err:#}");
            }

            if !self.cfg.network_targets.is_empty() {
                let has_tls_targets = self.cfg.network_targets.iter().any(|t| !t.ends_with(":80"));
                if has_tls_targets {
                    if verify_post_migration(&cmd.target_service, &self.cfg).await.is_none() {
                        let _ = rollback_windows_cert(&store, &thumbprint).await;
                        anyhow::bail!("post-migration TLS handshake verification failed; certificate import rolled back");
                    }
                }
            }

            Ok(format!(
                "certificate imported into Windows store {} with thumbprint {}",
                store, thumbprint
            ))
        }
    }

    async fn apply_windows_schannel_policy(&self, cmd: &MigrationCommand) -> Result<String> {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = cmd;
            anyhow::bail!("windows-schannel-policy mutation is only available on Windows");
        }

        #[cfg(target_os = "windows")]
        {
            let changes: Vec<RegistryDwordChange> =
                serde_json::from_str(&cmd.patch_unified_diff).context("parse Schannel JSON payload")?;
            if changes.is_empty() {
                anyhow::bail!("Schannel JSON payload must include at least one registry change");
            }
            for change in &changes {
                validate_schannel_change(change)?;
            }
            if cmd.dry_run {
                return Ok(format!("dry-run accepted: {} Schannel registry changes", changes.len()));
            }

            let mut rollback = Vec::<RegistryDwordRollback>::new();
            for change in &changes {
                rollback.push(read_registry_dword(change).await.unwrap_or_else(|_| RegistryDwordRollback {
                    path: change.path.clone(),
                    name: change.name.clone(),
                    existed: false,
                    value: 0,
                }));
            }

            for change in &changes {
                if let Err(err) = write_registry_dword(change).await {
                    let _ = rollback_registry_dwords(&rollback).await;
                    anyhow::bail!("Schannel registry update failed and rollback was attempted: {err:#}");
                }
            }

            if !self.cfg.network_targets.is_empty() {
                let has_tls_targets = self.cfg.network_targets.iter().any(|t| !t.ends_with(":80"));
                if has_tls_targets {
                    if verify_post_migration(&cmd.target_service, &self.cfg).await.is_none() {
                        let _ = rollback_registry_dwords(&rollback).await;
                        anyhow::bail!("post-migration TLS handshake verification failed; Schannel registry update rolled back");
                    }
                }
            }

            Ok(format!("applied {} Schannel registry changes", changes.len()))
        }
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Deserialize)]
struct RegistryDwordChange {
    path: String,
    name: String,
    value: u32,
}

#[cfg(target_os = "windows")]
struct RegistryDwordRollback {
    path: String,
    name: String,
    existed: bool,
    value: u32,
}

#[cfg(target_os = "windows")]
fn validate_schannel_change(change: &RegistryDwordChange) -> Result<()> {
    let path_upper = change.path.to_ascii_uppercase();
    if !path_upper.starts_with("HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SECURITYPROVIDERS\\SCHANNEL") {
        anyhow::bail!("registry path is outside Schannel policy: {}", change.path);
    }
    if change.name != "Enabled" && change.name != "DisabledByDefault" {
        anyhow::bail!("only Enabled and DisabledByDefault DWORD values are supported");
    }
    if change.value > 1 {
        anyhow::bail!("Schannel DWORD value must be 0 or 1");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn read_registry_dword(change: &RegistryDwordChange) -> Result<RegistryDwordRollback> {
    let output = run(
        "reg",
        &[
            "query".into(),
            change.path.clone(),
            "/v".into(),
            change.name.clone(),
        ],
    )
    .await?;

    // Use regex for robust parsing across Windows versions and locales
    // Output format: "    Name    REG_DWORD    0x1"
    let re = regex::Regex::new(r"REG_DWORD\s+0x([0-9a-fA-F]+)").expect("valid regex");
    let value = re.captures(&output)
        .and_then(|caps| caps.get(1))
        .and_then(|m| u32::from_str_radix(m.as_str(), 16).ok())
        .unwrap_or(0);

    let existed = output.contains("REG_DWORD");
    Ok(RegistryDwordRollback {
        path: change.path.clone(),
        name: change.name.clone(),
        existed,
        value,
    })
}

#[cfg(target_os = "windows")]
async fn write_registry_dword(change: &RegistryDwordChange) -> Result<String> {
    run(
        "reg",
        &[
            "add".into(),
            change.path.clone(),
            "/v".into(),
            change.name.clone(),
            "/t".into(),
            "REG_DWORD".into(),
            "/d".into(),
            change.value.to_string(),
            "/f".into(),
        ],
    )
    .await
}

#[cfg(target_os = "windows")]
async fn rollback_registry_dwords(rollback: &[RegistryDwordRollback]) -> Result<()> {
    for item in rollback.iter().rev() {
        if item.existed {
            let _ = run(
                "reg",
                &[
                    "add".into(),
                    item.path.clone(),
                    "/v".into(),
                    item.name.clone(),
                    "/t".into(),
                    "REG_DWORD".into(),
                    "/d".into(),
                    item.value.to_string(),
                    "/f".into(),
                ],
            )
            .await;
        } else {
            let _ = run(
                "reg",
                &[
                    "delete".into(),
                    item.path.clone(),
                    "/v".into(),
                    item.name.clone(),
                    "/f".into(),
                ],
            )
            .await;
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn rollback_windows_cert(store: &str, thumbprint: &str) -> Result<String> {
    let script = format!(
        "if (Test-Path 'Cert:\\{}\\{}') {{ Remove-Item -Path 'Cert:\\{}\\{}' -Force; 'removed' }} else {{ 'already-absent' }}",
        ps_escape(store),
        ps_escape(thumbprint),
        ps_escape(store),
        ps_escape(thumbprint)
    );
    run(
        "powershell",
        &[
            "-NoProfile".into(),
            "-ExecutionPolicy".into(),
            "Bypass".into(),
            "-Command".into(),
            script,
        ],
    )
    .await
}

#[cfg(target_os = "windows")]
fn normalize_windows_store(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_matches('\\').replace('/', "\\");
    let allowed = [
        "CurrentUser\\Root",
        "CurrentUser\\CA",
        "CurrentUser\\My",
        "LocalMachine\\Root",
        "LocalMachine\\CA",
        "LocalMachine\\My",
    ];
    if allowed.iter().any(|v| v.eq_ignore_ascii_case(&trimmed)) {
        return Ok(trimmed);
    }
    anyhow::bail!("Windows certificate store {} is not allowed", raw)
}

#[cfg(target_os = "windows")]
fn ps_escape(s: &str) -> String {
    s.replace('\'', "''")
}

async fn run(program: &str, args: &[String]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("execute {program}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        anyhow::bail!("{program} failed with {}: {combined}", output.status);
    }
    Ok(combined)
}

fn canonical_command(cmd: &MigrationCommand) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        cmd.command_id,
        cmd.host_uuid,
        cmd.target_service,
        cmd.migration_profile,
        cmd.target_kem,
        cmd.target_signature,
        cmd.config_path,
        cmd.rollback_window_seconds,
        cmd.patch_unified_diff,
        cmd.issued_at_unix,
        cmd.dry_run
    )
}

fn report(
    cmd: &MigrationCommand,
    state: MigrationState,
    success: bool,
    error_vector: &str,
    output: &str,
) -> MigrationStatusReport {
    MigrationStatusReport {
        command_id: cmd.command_id.clone(),
        host_uuid: cmd.host_uuid.clone(),
        state: state as i32,
        success,
        error_vector: error_vector.to_string(),
        output: output.to_string(),
        validation_signatures: vec![
            format!("target_kem={}", cmd.target_kem),
            format!("target_signature={}", cmd.target_signature),
            format!("profile={}", cmd.migration_profile),
        ],
        observed_tls: None,
        reported_at_unix: now(),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn verify_post_migration(_service: &str, cfg: &AgentConfig) -> Option<crate::proto::NetworkObservation> {
    if cfg.network_targets.is_empty() {
        return None;
    }
    
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    #[derive(Debug)]
    struct NoCertificateVerification;
    impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _e: &rustls::pki_types::CertificateDer<'_>,
            _i: &[rustls::pki_types::CertificateDer<'_>],
            _s: &rustls::pki_types::ServerName<'_>,
            _o: &[u8],
            _n: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &rustls::pki_types::CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &rustls::pki_types::CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
    }

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config_arc = Arc::new(config);

    for target in &cfg.network_targets {
        if target.ends_with(":80") {
            continue;
        }
        
        let host = target.split(':').next().unwrap_or(target);
        let stream_res = tokio::time::timeout(
            Duration::from_millis(1500),
            tokio::net::TcpStream::connect(target)
        ).await;
        
        let mut stream = match stream_res {
            Ok(Ok(s)) => s,
            _ => continue,
        };
        
        let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
            Ok(sn) => sn,
            _ => continue,
        };
        
        let mut conn = match rustls::ClientConnection::new(config_arc.clone(), server_name) {
            Ok(c) => c,
            _ => continue,
        };
        
        let mut raw_bytes = Vec::new();
        let mut buf = [0u8; 4096];
        let mut handshake_failed = false;
        
        while conn.is_handshaking() {
            if conn.wants_write() {
                let mut wr = Vec::new();
                if conn.write_tls(&mut wr).is_err() {
                    handshake_failed = true;
                    break;
                }
                use tokio::io::AsyncWriteExt;
                if stream.write_all(&wr).await.is_err() {
                    handshake_failed = true;
                    break;
                }
            }
            if conn.wants_read() {
                use tokio::io::AsyncReadExt;
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        raw_bytes.extend_from_slice(&buf[..n]);
                        if conn.read_tls(&mut std::io::Cursor::new(&buf[..n])).is_err() {
                            handshake_failed = true;
                            break;
                        }
                        if conn.process_new_packets().is_err() {
                            handshake_failed = true;
                            break;
                        }
                    }
                    _ => {
                        handshake_failed = true;
                        break;
                    }
                }
            }
        }
        
        if handshake_failed {
            continue;
        }

        let protocol = conn.protocol_version()
            .map(|v| format!("{:?}", v))
            .unwrap_or_else(|| "unknown".to_string());
            
        let cipher_suite = conn.negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_default();

        let mut cert_subject = String::new();
        let mut cert_issuer = String::new();
        let mut cert_not_after = 0;

        if let Some(certs) = conn.peer_certificates() {
            if let Some(first_cert) = certs.first() {
                let (subj, iss, not_after, _) = parse_x509_der(first_cert.as_ref());
                cert_subject = subj;
                cert_issuer = iss;
                cert_not_after = not_after;
            }
        }

        let mut pqc_hybrid = false;
        let mut named_group = String::new();
        if let Some(group_id) = extract_named_group(&raw_bytes) {
            let (name, hybrid) = match group_id {
                4588 => ("X25519MLKEM768".to_string(), true),
                4605 => ("SecP256r1MLKEM768".to_string(), true),
                4590 => ("X448MLKEM1024".to_string(), true),
                29 => ("X25519".to_string(), false),
                23 => ("secp256r1".to_string(), false),
                24 => ("secp384r1".to_string(), false),
                g => (format!("Unknown group (0x{:04x})", g), false),
            };
            named_group = name;
            pqc_hybrid = hybrid;
        }

        return Some(crate::proto::NetworkObservation {
            endpoint: target.to_string(),
            protocol: "tls".to_string(),
            tls_version: protocol,
            cipher_suite,
            named_group,
            signature_algorithm: String::new(),
            certificate_subject: cert_subject,
            certificate_issuer: cert_issuer,
            certificate_not_after_unix: cert_not_after,
            pqc_hybrid,
            cleartext: false,
        });
    }
    None
}
