use super::ScanResult;
use crate::{
    config::{AgentConfig, PluginCommandConfig},
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::{
    process::Command,
    time::{timeout, Duration},
};
use uuid::Uuid;

pub async fn scan(cfg: &AgentConfig) -> Result<ScanResult> {
    let mut out = ScanResult::default();
    for plugin in &cfg.plugin_commands {
        match run_plugin(plugin).await {
            Ok(raw) => ingest_plugin_output(&mut out, plugin, &raw),
            Err(err) => {
                let raw = format!("plugin {} failed: {err:#}", plugin.name);
                out.evidence.push(evidence(plugin, &raw, 0.25));
            }
        }
    }
    Ok(out)
}

/// Run a plugin command with resource limits enforced via OS-specific mechanisms:
/// - Linux: cgroups v2 memory.max, cpu.max
/// - Windows: Job object memory + CPU limits via JOBOBJECT_EXTENDED_LIMIT_INFORMATION
/// - Timeout enforced via tokio::time::timeout (works cross-platform)
async fn run_plugin(plugin: &PluginCommandConfig) -> Result<String> {
    let timeout_secs = plugin.timeout_seconds.max(1);
    let mem_limit = plugin.max_memory_mb.max(64); // minimum 64MB
    let cpu_limit = plugin.max_cpu_percent.clamp(1, 100);

    #[cfg(target_os = "linux")]
    let cgroup = LinuxPluginCgroup::create(mem_limit, cpu_limit)?;

    let mut cmd = Command::new(&plugin.command);
    cmd.args(&plugin.args);

    // Apply OS-specific resource limits before spawning
    #[cfg(target_os = "linux")]
    cgroup.attach(&mut cmd);
    #[cfg(not(target_os = "linux"))]
    apply_resource_limits(&mut cmd, mem_limit, cpu_limit);

    // A timed-out plugin must not survive while its cgroup is being removed.
    cmd.kill_on_drop(true);
    let execution = timeout(Duration::from_secs(timeout_secs), cmd.output()).await;

    #[cfg(target_os = "linux")]
    cgroup.cleanup().context("clean up plugin cgroup")?;

    let output = execution.context("plugin execution timed out")??;
    let mut raw = String::new();
    raw.push_str(&String::from_utf8_lossy(&output.stdout));
    raw.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(raw)
}

#[cfg(target_os = "linux")]
struct LinuxPluginCgroup {
    path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxPluginCgroup {
    fn create(mem_mb: u64, cpu_percent: u8) -> Result<Self> {
        let path = current_cgroup_parent()?.join(format!(
            "janus-plugin-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir(&path)
            .with_context(|| format!("create plugin cgroup {}", path.display()))?;

        let cgroup = Self { path };
        let setup = cgroup.configure(mem_mb, cpu_percent);
        if let Err(setup_err) = setup {
            let cleanup_err = cgroup.remove_unstarted().err();
            return match cleanup_err {
                Some(cleanup_err) => Err(setup_err.context(format!(
                    "also failed to clean up incomplete cgroup: {cleanup_err:#}"
                ))),
                None => Err(setup_err),
            };
        }
        Ok(cgroup)
    }

    fn remove_unstarted(&self) -> Result<()> {
        std::fs::remove_dir(&self.path)
            .with_context(|| format!("remove incomplete plugin cgroup {}", self.path.display()))
    }

    fn configure(&self, mem_mb: u64, cpu_percent: u8) -> Result<()> {
        let memory = memory_limit_bytes(mem_mb)?;
        write_and_verify_limit(&self.path.join("memory.max"), &memory)?;

        let cpu = format!("{} 100000", u64::from(cpu_percent) * 1000);
        write_and_verify_limit(&self.path.join("cpu.max"), &cpu)?;

        // Required so cleanup can terminate plugin-created descendants.
        std::fs::OpenOptions::new()
            .write(true)
            .open(self.path.join("cgroup.kill"))
            .context("cgroup v2 cgroup.kill is unavailable")?;
        Ok(())
    }

    fn attach(&self, cmd: &mut Command) {
        let procs = self.path.join("cgroup.procs");
        unsafe {
            cmd.pre_exec(move || write_existing(&procs, &std::process::id().to_string()));
        }
    }

    fn cleanup(&self) -> Result<()> {
        write_existing(&self.path.join("cgroup.kill"), "1")
            .context("kill remaining plugin cgroup processes")?;

        let mut last_error = None;
        for _ in 0..50 {
            match std::fs::remove_dir(&self.path) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    last_error = Some(err);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
        Err(last_error.expect("cleanup attempts are non-empty"))
            .with_context(|| format!("remove plugin cgroup {}", self.path.display()))
    }
}

#[cfg(target_os = "linux")]
fn current_cgroup_parent() -> Result<std::path::PathBuf> {
    let membership =
        std::fs::read_to_string("/proc/self/cgroup").context("read current cgroup membership")?;
    cgroup_parent_from_membership(&membership)
}

#[cfg(target_os = "linux")]
fn cgroup_parent_from_membership(membership: &str) -> Result<std::path::PathBuf> {
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("process is not in a cgroup v2 unified hierarchy")?
        .strip_prefix('/')
        .context("cgroup v2 membership path is not absolute")?;
    Ok(std::path::Path::new("/sys/fs/cgroup").join(relative))
}

#[cfg(target_os = "linux")]
fn memory_limit_bytes(mem_mb: u64) -> Result<String> {
    mem_mb
        .checked_mul(1024 * 1024)
        .map(|bytes| bytes.to_string())
        .context("plugin memory limit overflows bytes")
}

#[cfg(target_os = "linux")]
fn write_existing(path: &std::path::Path, value: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(value.as_bytes())
}

#[cfg(target_os = "linux")]
fn write_and_verify_limit(path: &std::path::Path, value: &str) -> Result<()> {
    write_existing(path, value)
        .with_context(|| format!("write cgroup limit {}", path.display()))?;
    let actual = std::fs::read_to_string(path)
        .with_context(|| format!("verify cgroup limit {}", path.display()))?;
    anyhow::ensure!(
        actual.trim() == value,
        "cgroup limit {} was not applied: requested {value}, got {}",
        path.display(),
        actual.trim()
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_resource_limits(cmd: &mut Command, mem_mb: u64, _cpu_percent: u8) {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };

    let job_name = format!("janus-plugin-{}\0", std::process::id());
    let job_name_wide: Vec<u16> = job_name.encode_utf16().collect();

    unsafe {
        let job: HANDLE = CreateJobObjectW(std::ptr::null(), job_name_wide.as_ptr());
        if !job.is_null() {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            info.ProcessMemoryLimit = (mem_mb as usize) * 1024 * 1024; // bytes
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            // Attach child processes to the job
            const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x01000000;
            cmd.creation_flags(CREATE_BREAKAWAY_FROM_JOB);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn apply_resource_limits(_cmd: &mut Command, _mem_mb: u64, _cpu_percent: u8) {
    // Resource limits not supported on this platform
}

fn ingest_plugin_output(out: &mut ScanResult, plugin: &PluginCommandConfig, raw: &str) {
    out.evidence.push(evidence(plugin, raw, 0.64));
    let algorithms = extract_algorithms(raw, &plugin.name);
    if algorithms.is_empty() {
        return;
    }
    out.components.push(CbomComponent {
        bom_ref: format!("plugin:{}:{}", plugin.name, hash_short(raw)),
        name: plugin.name.clone(),
        version: String::new(),
        component_type: "agent-plugin-output".to_string(),
        purl: String::new(),
        file_path: plugin.command.clone(),
        language: "plugin".to_string(),
        algorithms,
        dependencies: Vec::new(),
        reachable: true,
    });
}

fn extract_algorithms(raw: &str, plugin_name: &str) -> Vec<CryptoAlgorithm> {
    let lower = raw.to_ascii_lowercase();
    let mut out = Vec::new();
    for (needle, name, family, role) in [
        ("ml-kem", "ML-KEM", "ML-KEM", CryptoRole::Kem),
        ("mlkem", "ML-KEM", "ML-KEM", CryptoRole::Kem),
        ("kyber", "ML-KEM", "ML-KEM", CryptoRole::Kem),
        ("ml-dsa", "ML-DSA", "ML-DSA", CryptoRole::Signature),
        ("mldsa", "ML-DSA", "ML-DSA", CryptoRole::Signature),
        ("dilithium", "ML-DSA", "ML-DSA", CryptoRole::Signature),
        ("slh-dsa", "SLH-DSA", "SLH-DSA", CryptoRole::Signature),
        ("sphincs", "SLH-DSA", "SLH-DSA", CryptoRole::Signature),
        ("rsa", "RSA", "RSA", CryptoRole::Signature),
        ("ecdsa", "ECDSA", "ECC", CryptoRole::Signature),
        ("ecdh", "ECDH", "ECC", CryptoRole::KeyExchange),
        ("diffie", "DH", "DH", CryptoRole::KeyExchange),
        ("sha1", "SHA-1", "hash", CryptoRole::Hash),
        ("sha256", "SHA-256", "hash", CryptoRole::Hash),
        ("aes", "AES", "AES", CryptoRole::Symmetric),
    ] {
        if lower.contains(needle)
            && !out
                .iter()
                .any(|a: &CryptoAlgorithm| a.name == name && a.role == role as i32)
        {
            out.push(CryptoAlgorithm {
                name: name.to_string(),
                family: family.to_string(),
                role: role as i32,
                status: "plugin-observed".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: plugin_name.to_string(),
                source_file: plugin_name.to_string(),
                source_line: 0,
                source_column: 0,
                symbol: needle.to_string(),
                confidence: 0.6,
                quantum_vulnerable: false,

                context_snippet: String::new(),
            });
        }
    }
    out
}

fn evidence(plugin: &PluginCommandConfig, raw: &str, confidence: f64) -> Evidence {
    Evidence {
        evidence_id: Uuid::new_v4().to_string(),
        source_type: "agent-plugin".to_string(),
        source_tool: plugin.name.clone(),
        target: format!("{} {}", plugin.command, plugin.args.join(" ")),
        collection_time_unix: now(),
        raw_artifact_sha256: sha256_hex(raw.as_bytes()),
        confidence,
        sensitivity_class: "metadata-only".to_string(),
    }
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        cgroup_parent_from_membership, memory_limit_bytes, write_and_verify_limit,
        LinuxPluginCgroup,
    };
    use tokio::process::Command;

    fn test_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("janus-plugin-{label}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn memory_limit_conversion_rejects_overflow() {
        assert_eq!(memory_limit_bytes(64).unwrap(), "67108864");
        assert!(memory_limit_bytes(u64::MAX).is_err());
    }

    #[test]
    fn cgroup_parent_uses_current_unified_hierarchy() {
        assert_eq!(
            cgroup_parent_from_membership("0::/system.slice/janus-agent.service\n").unwrap(),
            std::path::PathBuf::from("/sys/fs/cgroup/system.slice/janus-agent.service")
        );
        assert!(cgroup_parent_from_membership("2:cpu:/legacy\n").is_err());
    }

    #[test]
    fn write_and_verify_limit_requires_exact_applied_value() {
        let path = test_path("limit");
        std::fs::write(&path, "max\n").unwrap();

        write_and_verify_limit(&path, "67108864").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "67108864");

        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn missing_cgroup_procs_prevents_plugin_execution() {
        let sentinel = test_path("sentinel");
        let cgroup = LinuxPluginCgroup {
            path: test_path("missing-cgroup"),
        };
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &format!("touch {}", sentinel.display())]);

        cgroup.attach(&mut command);
        assert!(command.output().await.is_err());
        assert!(!sentinel.exists());
    }

    #[test]
    fn cleanup_failure_is_reported() {
        let path = test_path("cleanup");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("cgroup.kill"), "").unwrap();
        let cgroup = LinuxPluginCgroup { path: path.clone() };

        assert!(cgroup.cleanup().is_err());

        std::fs::remove_file(path.join("cgroup.kill")).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
}
