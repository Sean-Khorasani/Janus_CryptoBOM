use crate::discovery::network::{extract_named_group, parse_x509_der};
use crate::{
    config::AgentConfig,
    proto::{MigrationCommand, MigrationState, MigrationStatusReport},
};
use anyhow::{Context, Result};
use diffy::{apply, Patch};
use hmac::{Hmac, Mac};
#[cfg(target_os = "windows")]
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
};
use subtle::ConstantTimeEq;
use tokio::process::Command;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct MutationEngine {
    cfg: AgentConfig,
    adapter_command_dir: Option<PathBuf>,
}

impl MutationEngine {
    pub fn new(cfg: AgentConfig) -> Self {
        Self {
            cfg,
            adapter_command_dir: None,
        }
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
        ensure_supported_service(&cmd.target_service)?;
        if cmd
            .target_service
            .eq_ignore_ascii_case("windows-trust-store")
        {
            return self.apply_windows_trust_store(cmd).await;
        }
        if cmd
            .target_service
            .eq_ignore_ascii_case("windows-schannel-policy")
        {
            return self.apply_windows_schannel_policy(cmd).await;
        }
        let config_path = self.checked_config_path(&cmd.config_path)?;
        let original = fs::read_to_string(&config_path)
            .with_context(|| format!("read {}", config_path.display()))?;

        // Config file checksum verification (drift detection)
        if let Some(expected_checksum_entry) = cmd
            .validation_checklist
            .iter()
            .find(|val| val.starts_with("checksum="))
        {
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
        atomic_write(&backup_path, original.as_bytes(), Some(&config_path))
            .with_context(|| format!("write backup {}", backup_path.display()))?;
        atomic_write(&config_path, patched.as_bytes(), Some(&config_path))
            .with_context(|| format!("write patched {}", config_path.display()))?;

        if let Err(err) = self.validate(&cmd.target_service, &config_path).await {
            rollback_file(&config_path, &backup_path)?;
            anyhow::bail!("validation failed and rollback restored backup: {err:#}");
        }

        if let Err(err) = self.reload(&cmd.target_service).await {
            rollback_file(&config_path, &backup_path)?;
            self.reload(&cmd.target_service)
                .await
                .context("reload restored configuration after rollback")?;
            anyhow::bail!("reload failed and rollback restored backup: {err:#}");
        }

        if !cmd.dry_run && !self.cfg.network_targets.is_empty() {
            let has_tls_targets = self.cfg.network_targets.iter().any(|t| !t.ends_with(":80"));
            if has_tls_targets
                && verify_post_migration(&cmd.target_service, &self.cfg)
                    .await
                    .is_none()
            {
                rollback_file(&config_path, &backup_path)?;
                self.reload(&cmd.target_service)
                    .await
                    .context("reload restored configuration after rollback")?;
                anyhow::bail!(
                    "post-migration TLS handshake verification failed; rollback restored backup"
                );
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
        let canonical = path
            .canonicalize()
            .with_context(|| format!("canonicalize {raw}"))?;

        if let Some(ext) = canonical.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_ascii_lowercase();
            if [
                "exe", "dll", "bat", "sh", "cmd", "bin", "msi", "com", "vbs", "ps1",
            ]
            .contains(&ext_lower.as_str())
            {
                anyhow::bail!(
                    "mutation blocked: target file extension '.{}' is restricted",
                    ext
                );
            }
        }

        for root in &self.cfg.active.allowed_config_roots {
            let root = PathBuf::from(root)
                .canonicalize()
                .with_context(|| format!("canonicalize root {root}"))?;
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
        let config_path = config_path.display().to_string();
        let candidates: Vec<(&str, Vec<String>)> = match service.to_ascii_lowercase().as_str() {
            "nginx" => vec![("nginx", vec!["-t".into(), "-c".into(), config_path])],
            "apache" => vec![
                ("apachectl", vec!["configtest".into()]),
                ("apache2ctl", vec!["configtest".into()]),
                ("httpd", vec!["-t".into()]),
            ],
            "ssh" => vec![("sshd", vec!["-t".into(), "-f".into(), config_path])],
            other => anyhow::bail!("no validator for service {other}"),
        };
        self.run_adapter_candidates(&candidates).await
    }

    async fn reload(&self, service: &str) -> Result<String> {
        let candidates: Vec<(&str, Vec<String>)> = match service.to_ascii_lowercase().as_str() {
            "nginx" => vec![
                ("nginx", vec!["-s".into(), "reload".into()]),
                ("systemctl", vec!["reload".into(), "nginx".into()]),
                ("service", vec!["nginx".into(), "reload".into()]),
            ],
            "apache" => vec![
                ("apachectl", vec!["graceful".into()]),
                ("apache2ctl", vec!["graceful".into()]),
                ("systemctl", vec!["reload".into(), "apache2".into()]),
                ("systemctl", vec!["reload".into(), "httpd".into()]),
            ],
            "ssh" if cfg!(target_os = "windows") => {
                vec![("powershell", vec!["Restart-Service".into(), "sshd".into()])]
            }
            "ssh" => vec![
                ("systemctl", vec!["reload".into(), "sshd".into()]),
                ("systemctl", vec!["reload".into(), "ssh".into()]),
                ("service", vec!["sshd".into(), "reload".into()]),
                ("service", vec!["ssh".into(), "reload".into()]),
            ],
            other => anyhow::bail!("no reloader for service {other}"),
        };
        self.run_adapter_candidates(&candidates).await
    }

    async fn run_adapter_candidates(&self, candidates: &[(&str, Vec<String>)]) -> Result<String> {
        let mut failures = Vec::new();
        for (program, args) in candidates {
            match self.run_adapter(program, args).await {
                Ok(output) => return Ok(output),
                Err(err) => failures.push(format!("{program}: {err:#}")),
            }
        }
        anyhow::bail!("no adapter command succeeded: {}", failures.join("; "))
    }

    async fn run_adapter(&self, program: &str, args: &[String]) -> Result<String> {
        let program = self
            .adapter_command_dir
            .as_ref()
            .map(|dir| dir.join(program).display().to_string())
            .unwrap_or_else(|| program.to_string());
        run(&program, args).await
    }

    #[cfg(test)]
    fn with_adapter_command_dir(mut self, dir: PathBuf) -> Self {
        self.adapter_command_dir = Some(dir);
        self
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
                    if verify_post_migration(&cmd.target_service, &self.cfg)
                        .await
                        .is_none()
                    {
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
            let changes: Vec<RegistryDwordChange> = serde_json::from_str(&cmd.patch_unified_diff)
                .context("parse Schannel JSON payload")?;
            if changes.is_empty() {
                anyhow::bail!("Schannel JSON payload must include at least one registry change");
            }
            for change in &changes {
                validate_schannel_change(change)?;
            }
            if cmd.dry_run {
                return Ok(format!(
                    "dry-run accepted: {} Schannel registry changes",
                    changes.len()
                ));
            }

            let mut rollback = Vec::<RegistryDwordRollback>::new();
            for change in &changes {
                rollback.push(read_registry_dword(change).await.unwrap_or_else(|_| {
                    RegistryDwordRollback {
                        path: change.path.clone(),
                        name: change.name.clone(),
                        existed: false,
                        value: 0,
                    }
                }));
            }

            for change in &changes {
                if let Err(err) = write_registry_dword(change).await {
                    let _ = rollback_registry_dwords(&rollback).await;
                    anyhow::bail!(
                        "Schannel registry update failed and rollback was attempted: {err:#}"
                    );
                }
            }

            if !self.cfg.network_targets.is_empty() {
                let has_tls_targets = self.cfg.network_targets.iter().any(|t| !t.ends_with(":80"));
                if has_tls_targets {
                    if verify_post_migration(&cmd.target_service, &self.cfg)
                        .await
                        .is_none()
                    {
                        let _ = rollback_registry_dwords(&rollback).await;
                        anyhow::bail!("post-migration TLS handshake verification failed; Schannel registry update rolled back");
                    }
                }
            }

            Ok(format!(
                "applied {} Schannel registry changes",
                changes.len()
            ))
        }
    }
}

fn ensure_supported_service(service: &str) -> Result<()> {
    match service.to_ascii_lowercase().as_str() {
        "nginx" | "apache" | "ssh" | "windows-trust-store" | "windows-schannel-policy" => Ok(()),
        other => anyhow::bail!("no migration adapter for service {other}"),
    }
}

fn atomic_write(path: &Path, contents: &[u8], permission_source: Option<&Path>) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let temp_path = parent.join(format!(
        ".{}.janus-{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .with_context(|| format!("create {}", temp_path.display()))?;
        if let Some(source) = permission_source {
            let permissions = fs::metadata(source)
                .with_context(|| format!("read metadata {}", source.display()))?
                .permissions();
            file.set_permissions(permissions)
                .with_context(|| format!("set permissions {}", temp_path.display()))?;
        }
        file.write_all(contents)
            .with_context(|| format!("write {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temp_path.display()))?;
        drop(file);
        fs::rename(&temp_path, path).with_context(|| format!("replace {}", path.display()))?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn rollback_file(config_path: &Path, backup_path: &Path) -> Result<()> {
    let original = fs::read(backup_path)
        .with_context(|| format!("read rollback backup {}", backup_path.display()))?;
    atomic_write(config_path, &original, Some(backup_path))
        .with_context(|| format!("restore {}", config_path.display()))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("open directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
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
    if !path_upper
        .starts_with("HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SECURITYPROVIDERS\\SCHANNEL")
    {
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
    let value = re
        .captures(&output)
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
    let validation_checklist =
        serde_json::to_string(&cmd.validation_checklist).unwrap_or_else(|_| "[]".to_string());
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        cmd.command_id,
        cmd.host_uuid,
        cmd.target_service,
        cmd.migration_profile,
        cmd.target_kem,
        cmd.target_signature,
        cmd.config_path,
        validation_checklist,
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

async fn verify_post_migration(
    _service: &str,
    cfg: &AgentConfig,
) -> Option<crate::proto::NetworkObservation> {
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
            tokio::net::TcpStream::connect(target),
        )
        .await;

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

        let protocol = conn
            .protocol_version()
            .map(|v| format!("{:?}", v))
            .unwrap_or_else(|| "unknown".to_string());

        let cipher_suite = conn
            .negotiated_cipher_suite()
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

#[cfg(test)]
mod tests {
    use super::{atomic_write, canonical_command, rollback_file, MutationEngine};
    use crate::{
        config::AgentConfig,
        proto::{MigrationCommand, MigrationState},
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::{fs, path::PathBuf};

    const ORIGINAL: &str = "original\n";
    const PATCH: &str = "--- original\n+++ modified\n@@ -1 +1 @@\n-original\n+mutated\n";
    #[cfg(unix)]
    const FAKE_ADAPTER: &str = include_str!("../../tests/linux-migration/fake-service-adapter.sh");

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("janus-mutation-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn atomic_write_replaces_content_without_leaving_temp_files() {
        let dir = TestDir::new();
        let target = dir.0.join("service.conf");
        fs::write(&target, "original").expect("write original");

        atomic_write(&target, b"replacement", Some(&target)).expect("atomic replace");

        assert_eq!(
            fs::read_to_string(&target).expect("read target"),
            "replacement"
        );
        assert_eq!(
            fs::read_dir(&dir.0).expect("read directory").count(),
            1,
            "temporary files must be removed"
        );
    }

    #[test]
    fn rollback_restores_backup_content() {
        let dir = TestDir::new();
        let target = dir.0.join("service.conf");
        let backup = dir.0.join("service.conf.command.bak");
        fs::write(&target, "mutated").expect("write mutated target");
        fs::write(&backup, "original").expect("write backup");

        rollback_file(&target, &backup).expect("restore backup");

        assert_eq!(fs::read_to_string(target).expect("read target"), "original");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new();
        let target = dir.0.join("service.conf");
        fs::write(&target, "original").expect("write original");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640))
            .expect("set target permissions");

        atomic_write(&target, b"replacement", Some(&target)).expect("atomic replace");

        let mode = fs::metadata(target)
            .expect("read metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640);
    }

    fn active_engine(dir: &TestDir, service: &str) -> MutationEngine {
        let cfg = AgentConfig {
            execution_mode: "active".to_string(),
            command_signing_key: "test-signing-key-long-enough".to_string(),
            active: crate::config::ActiveConfig {
                allowed_services: vec![service.to_string()],
                allowed_config_roots: vec![dir.0.display().to_string()],
                backup_dir: dir.0.join("backups").display().to_string(),
            },
            ..Default::default()
        };
        MutationEngine::new(cfg).with_adapter_command_dir(dir.0.join("bin"))
    }

    fn signed_command(
        engine: &MutationEngine,
        service: &str,
        config: &std::path::Path,
    ) -> MigrationCommand {
        let mut cmd = MigrationCommand {
            command_id: format!("test-{}", uuid::Uuid::new_v4()),
            host_uuid: "test-host".to_string(),
            target_service: service.to_string(),
            migration_profile: "test-profile".to_string(),
            target_kem: "ML-KEM-768".to_string(),
            target_signature: "ML-DSA-65".to_string(),
            config_path: config.display().to_string(),
            validation_checklist: vec![],
            rollback_window_seconds: 60,
            patch_unified_diff: PATCH.to_string(),
            signed_directive: vec![],
            issued_at_unix: 1,
            dry_run: false,
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(engine.cfg.command_signing_key.as_bytes())
            .expect("create test HMAC");
        mac.update(canonical_command(&cmd).as_bytes());
        cmd.signed_directive = hex::encode(mac.finalize().into_bytes()).into_bytes();
        cmd
    }

    #[cfg(unix)]
    fn install_fake(dir: &TestDir, program: &str, mode: &str, config: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let bin = dir.0.join("bin");
        fs::create_dir_all(&bin).expect("create fake executable directory");
        let executable = bin.join(program);
        fs::write(&executable, FAKE_ADAPTER).expect("write fake adapter");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("make fake adapter executable");
        fs::write(bin.join(format!("{program}.mode")), mode).expect("write fake adapter mode");
        fs::write(
            bin.join(format!("{program}.config")),
            config.display().to_string(),
        )
        .expect("write fake adapter config path");
        executable
    }

    #[cfg(unix)]
    fn adapter_programs(service: &str) -> (&'static str, &'static str) {
        match service {
            "nginx" => ("nginx", "nginx"),
            "apache" => ("apachectl", "apachectl"),
            "ssh" => ("sshd", "systemctl"),
            _ => panic!("unsupported test service"),
        }
    }

    #[tokio::test]
    async fn unsupported_service_fails_before_any_mutation() {
        let dir = TestDir::new();
        let config = dir.0.join("service.conf");
        fs::write(&config, ORIGINAL).expect("write original config");
        let engine = active_engine(&dir, "unsupported-service");
        let cmd = signed_command(&engine, "unsupported-service", &config);

        let report = engine.execute(cmd).await;

        assert_eq!(report.state, MigrationState::Failed as i32);
        assert!(report.error_vector.contains("no migration adapter"));
        assert_eq!(fs::read_to_string(config).expect("read config"), ORIGINAL);
        assert!(
            !dir.0.join("backups").exists(),
            "backup must not be created"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn linux_adapter_validation_failures_restore_original_configs() {
        for service in ["nginx", "apache", "ssh"] {
            let dir = TestDir::new();
            let config = dir.0.join(format!("{service}.conf"));
            fs::write(&config, ORIGINAL).expect("write original config");
            let (validator, reloader) = adapter_programs(service);
            install_fake(&dir, validator, "validation-fail", &config);
            if reloader != validator {
                install_fake(&dir, reloader, "success", &config);
            }
            let engine = active_engine(&dir, service);
            let cmd = signed_command(&engine, service, &config);

            let report = engine.execute(cmd).await;

            assert_eq!(report.state, MigrationState::Failed as i32, "{service}");
            assert!(
                report
                    .error_vector
                    .contains("validation failed and rollback restored backup"),
                "{service}: {}",
                report.error_vector
            );
            assert_eq!(
                fs::read_to_string(&config).expect("read restored config"),
                ORIGINAL,
                "{service}"
            );
            assert!(
                dir.0
                    .join("bin")
                    .join(format!("{validator}.validation-observed"))
                    .exists(),
                "{service}: validator must observe the patched config before failing"
            );
            assert!(
                !dir.0
                    .join("bin")
                    .join(format!("{reloader}.reload-count"))
                    .exists(),
                "{service}: validation failure must not invoke reload"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn linux_adapter_reload_failures_restore_original_configs_and_reload_them() {
        for service in ["nginx", "apache", "ssh"] {
            let dir = TestDir::new();
            let config = dir.0.join(format!("{service}.conf"));
            fs::write(&config, ORIGINAL).expect("write original config");
            let (validator, reloader) = adapter_programs(service);
            install_fake(&dir, validator, "success", &config);
            install_fake(&dir, reloader, "reload-fail-once", &config);
            let engine = active_engine(&dir, service);
            let cmd = signed_command(&engine, service, &config);

            let report = engine.execute(cmd).await;

            assert_eq!(report.state, MigrationState::Failed as i32, "{service}");
            assert!(
                report
                    .error_vector
                    .contains("reload failed and rollback restored backup"),
                "{service}: {}",
                report.error_vector
            );
            assert_eq!(
                fs::read_to_string(&config).expect("read restored config"),
                ORIGINAL,
                "{service}"
            );
            assert_eq!(
                fs::read_to_string(dir.0.join("bin").join(format!("{reloader}.reload-count")))
                    .expect("read reload count")
                    .trim(),
                if service == "ssh" { "3" } else { "2" },
                "{service}: failed reload and rollback reload must both run"
            );
            assert_eq!(
                fs::read_to_string(
                    dir.0
                        .join("bin")
                        .join(format!("{reloader}.reload-observed"))
                )
                .expect("read reload observations"),
                if service == "ssh" {
                    "mutated\nmutated\noriginal\n"
                } else {
                    "mutated\noriginal\n"
                },
                "{service}: reloads must observe patched then restored config"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn apache_adapter_discovers_debian_command_name() {
        let dir = TestDir::new();
        let config = dir.0.join("apache.conf");
        fs::write(&config, "mutated\n").expect("write validated config");
        install_fake(&dir, "apache2ctl", "success", &config);
        let engine = active_engine(&dir, "apache");

        engine
            .validate("apache", &config)
            .await
            .expect("discover apache2ctl validator");
        engine
            .reload("apache")
            .await
            .expect("discover apache2ctl reloader");
    }
}
