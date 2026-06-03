use crate::{
    config::AgentConfig,
    proto::{MigrationCommand, MigrationState, MigrationStatusReport},
};
use anyhow::{Context, Result};
use diffy::{apply, Patch};
use hmac::digest::subtle::ConstantTimeEq;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
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
            Ok(output) => report(&cmd, MigrationState::Succeeded, true, "", &output),
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
            let _ = fs::write(&config_path, original);
            anyhow::bail!("validation failed and rollback restored backup: {err:#}");
        }

        if let Err(err) = self.reload(&cmd.target_service).await {
            let _ = fs::write(&config_path, original);
            anyhow::bail!("reload failed and rollback restored backup: {err:#}");
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
    let value = output
        .lines()
        .find(|line| line.contains("REG_DWORD"))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    Ok(RegistryDwordRollback {
        path: change.path.clone(),
        name: change.name.clone(),
        existed: true,
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
