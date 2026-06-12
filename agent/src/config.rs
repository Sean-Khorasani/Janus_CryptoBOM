use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path};

const ENV_CONTROLLER_ENDPOINT: &str = "JANUS_CONTROLLER_ENDPOINT";
const ENV_HTTP_CONTROLLER_ENDPOINT: &str = "JANUS_HTTP_CONTROLLER_ENDPOINT";
const ENV_CACHE_PATH: &str = "JANUS_CACHE_PATH";
const ENV_HOST_UUID_PATH: &str = "JANUS_HOST_UUID_PATH";
const ENV_REPORT_PATH: &str = "JANUS_REPORT_PATH";
const ENV_SARIF_PATH: &str = "JANUS_SARIF_PATH";
const ENV_EXECUTION_MODE: &str = "JANUS_EXECUTION_MODE";
const ENV_SCAN_ROOTS: &str = "JANUS_SCAN_ROOTS";
const ENV_COMMAND_SIGNING_KEY: &str = "JANUS_COMMAND_SIGNING_KEY";
const ENV_COMMAND_SIGNING_KEY_FILE: &str = "JANUS_COMMAND_SIGNING_KEY_FILE";

pub const DEFAULT_SCAN_INTERVAL_SECONDS: u64 = 15 * 60;
pub const MIN_SCAN_INTERVAL_SECONDS: u64 = 10;
pub const MAX_SCAN_INTERVAL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_BINARY_BYTES: u64 = 16 * 1024 * 1024;
pub const MIN_SCAN_BYTES: u64 = 1024;
pub const MAX_SCAN_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentConfig {
    pub controller_endpoint: String,
    pub http_controller_endpoint: Option<String>,
    pub tls_ca_cert: Option<String>,
    pub tls_client_cert: Option<String>,
    pub tls_client_key: Option<String>,
    pub execution_mode: String,
    pub cache_path: String,
    pub host_uuid_path: String,
    #[serde(default = "default_report_path")]
    pub report_path: String,
    #[serde(default = "default_sarif_path")]
    pub sarif_path: String,
    pub scan_interval_seconds: u64,
    pub max_file_bytes: u64,
    pub max_binary_bytes: u64,
    pub command_signing_key: String,
    pub scan_roots: Vec<String>,
    pub exclude_dirs: Vec<String>,
    #[serde(default)]
    pub include_extensions: Vec<String>,
    pub network_targets: Vec<String>,
    #[serde(default)]
    pub enable_runtime_discovery: bool,
    #[serde(default)]
    pub enable_process_memory_scraping: bool,
    #[serde(default)]
    pub enable_plugin_discovery: bool,
    #[serde(default)]
    pub enable_active_tls_probing: bool,
    #[serde(default)]
    pub plugin_dirs: Vec<String>,
    #[serde(default)]
    pub plugin_commands: Vec<PluginCommandConfig>,
    #[serde(default = "default_intercept_mode")]
    pub intercept_mode: String,
    /// Directory containing versioned prompt YAML templates.
    /// Defaults to "config/prompts" relative to the working directory.
    #[serde(default = "default_prompts_dir")]
    pub prompts_dir: String,
    /// LLM-07: Per-agent binary analysis LLM policy.
    /// Off by default — must be explicitly opted in per agent.
    #[serde(default)]
    pub binary_llm_policy: BinaryLLMPolicy,
    pub active: ActiveConfig,
}

/// LLM-07: Controls opt-in LLM-assisted binary analysis.
/// Binary analysis via LLM requires explicit operator consent because it involves
/// sending bounded binary context (strings, imports, hexdump windows) to an external
/// provider. Disabled by default to prevent accidental data exposure.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BinaryLLMPolicy {
    /// Master switch — must be true for any LLM binary analysis to occur.
    #[serde(default)]
    pub enabled: bool,
    /// Allow sending extracted strings from PE/ELF/Mach-O to LLM (bounded).
    #[serde(default)]
    pub allow_string_extraction: bool,
    /// Allow sending import/export table entries to LLM.
    #[serde(default = "default_true")]
    pub allow_import_table: bool,
    /// Allow sending a hexdump window (bounded) around a suspicious pattern.
    #[serde(default)]
    pub allow_hexdump_window: bool,
    /// Maximum bytes to send per binary section/window to LLM (default 1024).
    #[serde(default = "default_binary_llm_max_bytes")]
    pub max_context_bytes: usize,
    /// Require explicit operator consent logged to audit trail before first use.
    #[serde(default = "default_true")]
    pub require_audit_consent: bool,
}

fn default_true() -> bool {
    true
}

fn default_binary_llm_max_bytes() -> usize {
    1024
}

impl Default for BinaryLLMPolicy {
    fn default() -> Self {
        BinaryLLMPolicy {
            enabled: false,
            allow_string_extraction: false,
            allow_import_table: true,
            allow_hexdump_window: false,
            max_context_bytes: 1024,
            require_audit_consent: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginCommandConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_plugin_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_plugin_max_memory")]
    pub max_memory_mb: u64,
    #[serde(default = "default_plugin_max_cpu")]
    pub max_cpu_percent: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActiveConfig {
    pub allowed_services: Vec<String>,
    pub allowed_config_roots: Vec<String>,
    pub backup_dir: String,
}

fn default_report_path() -> String {
    "janus-agent-report.html".to_string()
}

fn default_sarif_path() -> String {
    "janus-agent.sarif".to_string()
}

fn default_intercept_mode() -> String {
    "passive".to_string()
}

fn default_prompts_dir() -> String {
    std::env::var("JANUS_PROMPTS_DIR").unwrap_or_else(|_| "config/prompts".to_string())
}

fn default_plugin_timeout() -> u64 {
    30
}

fn default_plugin_max_memory() -> u64 {
    512
}

fn default_plugin_max_cpu() -> u8 {
    50
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            controller_endpoint: "localhost:9443".to_string(),
            http_controller_endpoint: None,
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
            execution_mode: "passive".to_string(),
            cache_path: "janus-agent.sqlite3".to_string(),
            host_uuid_path: "janus-host-id".to_string(),
            report_path: "".to_string(),
            sarif_path: "".to_string(),
            scan_interval_seconds: DEFAULT_SCAN_INTERVAL_SECONDS,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_binary_bytes: DEFAULT_MAX_BINARY_BYTES,
            command_signing_key: String::new(), // must be set explicitly — no insecure default
            scan_roots: vec![".".to_string()],
            exclude_dirs: vec![],
            include_extensions: vec![],
            network_targets: vec![],
            enable_runtime_discovery: false,
            enable_process_memory_scraping: false,
            enable_plugin_discovery: false,
            enable_active_tls_probing: false,
            plugin_dirs: vec![],
            plugin_commands: vec![],
            intercept_mode: "passive".to_string(),
            prompts_dir: default_prompts_dir(),
            binary_llm_policy: BinaryLLMPolicy::default(),
            active: ActiveConfig {
                allowed_services: vec![],
                allowed_config_roots: vec![],
                backup_dir: "backup".to_string(),
            },
        }
    }
}

impl AgentConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        let mut cfg: AgentConfig = toml::from_str(&raw).context("parse TOML")?;
        cfg.apply_environment_overrides()?;
        if cfg.command_signing_key.starts_with("dpapi:")
            || cfg.command_signing_key.starts_with("plain:")
        {
            if let Ok(decrypted) = crate::storage::unprotect(&cfg.command_signing_key) {
                if let Ok(dec_str) = String::from_utf8(decrypted) {
                    cfg.command_signing_key = dec_str;
                }
            }
        }
        cfg.load_plugin_manifests()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn passive(&self) -> bool {
        !self.execution_mode.eq_ignore_ascii_case("active")
    }

    fn validate(&self) -> Result<()> {
        if self.controller_endpoint.is_empty() {
            anyhow::bail!("controller_endpoint is required");
        }
        if self.scan_roots.is_empty() {
            anyhow::bail!("at least one scan_root is required");
        }
        if !(MIN_SCAN_INTERVAL_SECONDS..=MAX_SCAN_INTERVAL_SECONDS)
            .contains(&self.scan_interval_seconds)
        {
            anyhow::bail!(
                "scan_interval_seconds must be between {} and {}",
                MIN_SCAN_INTERVAL_SECONDS,
                MAX_SCAN_INTERVAL_SECONDS
            );
        }
        if !(MIN_SCAN_BYTES..=MAX_SCAN_BYTES).contains(&self.max_file_bytes)
            || !(MIN_SCAN_BYTES..=MAX_SCAN_BYTES).contains(&self.max_binary_bytes)
        {
            anyhow::bail!(
                "max_file_bytes and max_binary_bytes must be between {} and {}",
                MIN_SCAN_BYTES,
                MAX_SCAN_BYTES
            );
        }
        if self.command_signing_key.is_empty() {
            anyhow::bail!("command_signing_key is required — generate a 32-byte random key and set it in agent config");
        }
        if self.command_signing_key.len() < 16 {
            anyhow::bail!("command_signing_key must be at least 16 bytes (recommended: 32 bytes)");
        }
        if self.enable_process_memory_scraping && !self.enable_runtime_discovery {
            anyhow::bail!(
                "enable_process_memory_scraping requires enable_runtime_discovery = true"
            );
        }
        Ok(())
    }

    fn apply_environment_overrides(&mut self) -> Result<()> {
        override_string(ENV_CONTROLLER_ENDPOINT, &mut self.controller_endpoint)?;
        if let Some(value) = environment_value(ENV_HTTP_CONTROLLER_ENDPOINT)? {
            self.http_controller_endpoint = Some(value);
        }
        override_string(ENV_CACHE_PATH, &mut self.cache_path)?;
        override_string(ENV_HOST_UUID_PATH, &mut self.host_uuid_path)?;
        override_string(ENV_REPORT_PATH, &mut self.report_path)?;
        override_string(ENV_SARIF_PATH, &mut self.sarif_path)?;
        override_string(ENV_EXECUTION_MODE, &mut self.execution_mode)?;

        if let Some(value) = environment_value(ENV_SCAN_ROOTS)? {
            self.scan_roots = value
                .split(',')
                .map(str::trim)
                .filter(|root| !root.is_empty())
                .map(str::to_string)
                .collect();
        }

        override_string(ENV_COMMAND_SIGNING_KEY, &mut self.command_signing_key)?;
        if let Some(path) = environment_value(ENV_COMMAND_SIGNING_KEY_FILE)? {
            self.command_signing_key = fs::read_to_string(&path)
                .with_context(|| format!("read {ENV_COMMAND_SIGNING_KEY_FILE} {}", path))?
                .trim_end_matches(['\r', '\n'])
                .to_string();
        }
        Ok(())
    }

    fn load_plugin_manifests(&mut self) -> Result<()> {
        for dir in &self.plugin_dirs {
            let root = Path::new(dir);
            if !root.exists() {
                continue;
            }
            for entry in
                fs::read_dir(root).with_context(|| format!("read plugin dir {}", root.display()))?
            {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let manifest = entry.path().join("plugin.toml");
                if !manifest.exists() {
                    continue;
                }
                let raw = fs::read_to_string(&manifest)
                    .with_context(|| format!("read plugin manifest {}", manifest.display()))?;
                let mut plugin: PluginCommandConfig = toml::from_str(&raw)
                    .with_context(|| format!("parse {}", manifest.display()))?;
                if plugin.name.is_empty() {
                    plugin.name = entry.file_name().to_string_lossy().to_string();
                }
                let plugin_root = entry.path();
                for arg in &mut plugin.args {
                    let candidate = plugin_root.join(&arg);
                    if candidate.exists() {
                        *arg = candidate.canonicalize()?.display().to_string();
                    }
                }
                self.plugin_commands.push(plugin);
            }
        }
        Ok(())
    }

    pub fn http_endpoint(&self) -> String {
        if let Some(ref ep) = self.http_controller_endpoint {
            return ep.clone();
        }
        if self.controller_endpoint.contains(":9443") {
            self.controller_endpoint.replace(":9443", ":8080")
        } else {
            "http://127.0.0.1:8080".to_string()
        }
    }
}

fn environment_value(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => anyhow::bail!("{name} contains non-Unicode data"),
    }
}

fn override_string(name: &str, target: &mut String) -> Result<()> {
    if let Some(value) = environment_value(name)? {
        *target = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        sync::{Mutex, MutexGuard},
    };
    use uuid::Uuid;

    const OVERRIDE_ENVIRONMENT: [&str; 10] = [
        ENV_CONTROLLER_ENDPOINT,
        ENV_HTTP_CONTROLLER_ENDPOINT,
        ENV_CACHE_PATH,
        ENV_HOST_UUID_PATH,
        ENV_REPORT_PATH,
        ENV_SARIF_PATH,
        ENV_EXECUTION_MODE,
        ENV_SCAN_ROOTS,
        ENV_COMMAND_SIGNING_KEY,
        ENV_COMMAND_SIGNING_KEY_FILE,
    ];
    static ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

    struct EnvironmentGuard {
        _lock: MutexGuard<'static, ()>,
        original: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvironmentGuard {
        fn clean() -> Self {
            let lock = ENVIRONMENT_LOCK.lock().expect("lock environment");
            let original = OVERRIDE_ENVIRONMENT
                .iter()
                .map(|name| (*name, env::var_os(name)))
                .collect();
            for name in OVERRIDE_ENVIRONMENT {
                env::remove_var(name);
            }
            Self {
                _lock: lock,
                original,
            }
        }

        fn set(&self, name: &str, value: impl AsRef<std::ffi::OsStr>) {
            env::set_var(name, value);
        }
    }

    impl Drop for EnvironmentGuard {
        fn drop(&mut self) {
            for (name, value) in &self.original {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }
    }

    struct TestFiles {
        root: std::path::PathBuf,
    }

    impl TestFiles {
        fn new() -> Self {
            let root = env::temp_dir().join(format!("janus-config-test-{}", Uuid::new_v4()));
            fs::create_dir_all(&root).expect("create test directory");
            Self { root }
        }

        fn write(&self, name: &str, content: &str) -> std::path::PathBuf {
            let path = self.root.join(name);
            fs::write(&path, content).expect("write test file");
            path
        }

        fn config(&self, mut cfg: AgentConfig) -> std::path::PathBuf {
            cfg.plugin_dirs.clear();
            let raw = toml::to_string(&cfg).expect("serialize config");
            self.write("agent.toml", &raw)
        }
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn valid_config() -> AgentConfig {
        AgentConfig {
            command_signing_key: "toml-signing-key".to_string(),
            ..AgentConfig::default()
        }
    }

    #[test]
    fn discovery_opt_ins_default_to_disabled() {
        let cfg = AgentConfig::default();

        assert!(cfg.passive());
        assert!(!cfg.enable_runtime_discovery);
        assert!(!cfg.enable_process_memory_scraping);
        assert!(!cfg.enable_plugin_discovery);
        assert!(!cfg.enable_active_tls_probing);
    }

    #[test]
    fn discovery_stages_require_explicit_opt_in() {
        let env = EnvironmentGuard::clean();
        let files = TestFiles::new();
        let mut cfg = valid_config();
        cfg.enable_runtime_discovery = true;
        cfg.enable_process_memory_scraping = true;
        cfg.enable_plugin_discovery = true;
        cfg.enable_active_tls_probing = true;
        let config_path = files.config(cfg);

        let cfg = AgentConfig::load(config_path).expect("load explicit discovery opt-ins");

        assert!(cfg.passive());
        assert!(cfg.enable_runtime_discovery);
        assert!(cfg.enable_process_memory_scraping);
        assert!(cfg.enable_plugin_discovery);
        assert!(cfg.enable_active_tls_probing);
        drop(env);
    }

    #[test]
    fn missing_discovery_opt_ins_deserialize_as_disabled() {
        let raw = r#"
controller_endpoint = "http://127.0.0.1:9443"
execution_mode = "passive"
cache_path = "janus-agent.sqlite3"
host_uuid_path = "janus-host-id"
scan_interval_seconds = 900
max_file_bytes = 2097152
max_binary_bytes = 16777216
command_signing_key = "local-development-command-signing-key"
scan_roots = ["."]
exclude_dirs = []
network_targets = []

[active]
allowed_services = []
allowed_config_roots = []
backup_dir = ".janus-backups"
"#;

        let cfg: AgentConfig = toml::from_str(raw).expect("deserialize legacy config");

        assert!(!cfg.enable_runtime_discovery);
        assert!(!cfg.enable_process_memory_scraping);
        assert!(!cfg.enable_plugin_discovery);
        assert!(!cfg.enable_active_tls_probing);
    }

    #[test]
    fn process_memory_scraping_requires_runtime_discovery() {
        let env = EnvironmentGuard::clean();
        let files = TestFiles::new();
        let mut cfg = valid_config();
        cfg.enable_process_memory_scraping = true;
        let config_path = files.config(cfg);

        let error =
            AgentConfig::load(config_path).expect_err("invalid discovery opt-ins must fail");

        assert!(error
            .to_string()
            .contains("enable_process_memory_scraping requires enable_runtime_discovery"));
        drop(env);
    }

    #[test]
    fn scan_limits_reject_values_outside_the_supported_contract() {
        let env = EnvironmentGuard::clean();
        let files = TestFiles::new();
        let mut cfg = valid_config();
        cfg.scan_interval_seconds = MIN_SCAN_INTERVAL_SECONDS - 1;
        let config_path = files.config(cfg);

        let error = AgentConfig::load(config_path).expect_err("short interval must fail");

        assert!(error
            .to_string()
            .contains("scan_interval_seconds must be between"));
        drop(env);
    }

    #[test]
    fn environment_values_override_toml_values() {
        let env = EnvironmentGuard::clean();
        let files = TestFiles::new();
        let config_path = files.config(valid_config());

        env.set(ENV_CONTROLLER_ENDPOINT, "http://controller:50051");
        env.set(ENV_HTTP_CONTROLLER_ENDPOINT, "http://controller:8080");
        env.set(ENV_CACHE_PATH, "/var/lib/janus/cache.sqlite3");
        env.set(ENV_HOST_UUID_PATH, "/var/lib/janus/host-id");
        env.set(ENV_REPORT_PATH, "/var/lib/janus/report.html");
        env.set(ENV_SARIF_PATH, "/var/lib/janus/report.sarif");
        env.set(ENV_EXECUTION_MODE, "active");
        env.set(ENV_SCAN_ROOTS, " /srv/one, /srv/two ,,/srv/three ");
        env.set(ENV_COMMAND_SIGNING_KEY, "environment-signing-key");

        let cfg = AgentConfig::load(config_path).expect("load overridden config");

        assert_eq!(cfg.controller_endpoint, "http://controller:50051");
        assert_eq!(
            cfg.http_controller_endpoint.as_deref(),
            Some("http://controller:8080")
        );
        assert_eq!(cfg.cache_path, "/var/lib/janus/cache.sqlite3");
        assert_eq!(cfg.host_uuid_path, "/var/lib/janus/host-id");
        assert_eq!(cfg.report_path, "/var/lib/janus/report.html");
        assert_eq!(cfg.sarif_path, "/var/lib/janus/report.sarif");
        assert_eq!(cfg.execution_mode, "active");
        assert_eq!(cfg.scan_roots, ["/srv/one", "/srv/two", "/srv/three"]);
        assert_eq!(cfg.command_signing_key, "environment-signing-key");
    }

    #[test]
    fn signing_key_file_takes_precedence_and_strips_line_endings() {
        let env = EnvironmentGuard::clean();
        let files = TestFiles::new();
        let config_path = files.config(valid_config());
        let key_path = files.write("signing-key", "file-signing-key  \r\n");

        env.set(ENV_COMMAND_SIGNING_KEY, "environment-signing-key");
        env.set(ENV_COMMAND_SIGNING_KEY_FILE, &key_path);

        let cfg = AgentConfig::load(config_path).expect("load file signing key");

        assert_eq!(cfg.command_signing_key, "file-signing-key  ");
    }

    #[test]
    fn overrides_are_applied_before_validation() {
        let env = EnvironmentGuard::clean();
        let files = TestFiles::new();
        let mut cfg = valid_config();
        cfg.controller_endpoint.clear();
        cfg.command_signing_key.clear();
        cfg.scan_roots.clear();
        let config_path = files.config(cfg);

        env.set(ENV_CONTROLLER_ENDPOINT, "http://controller:50051");
        env.set(ENV_COMMAND_SIGNING_KEY, "environment-signing-key");
        env.set(ENV_SCAN_ROOTS, "/srv/source");

        AgentConfig::load(config_path).expect("environment repairs invalid TOML values");
    }

    #[test]
    fn empty_scan_roots_override_is_rejected() {
        let env = EnvironmentGuard::clean();
        let files = TestFiles::new();
        let config_path = files.config(valid_config());

        env.set(ENV_SCAN_ROOTS, " , , ");

        let error = AgentConfig::load(config_path).expect_err("empty scan roots must fail");

        assert!(error
            .to_string()
            .contains("at least one scan_root is required"));
    }

    #[test]
    fn missing_signing_key_file_is_reported() {
        let env = EnvironmentGuard::clean();
        let files = TestFiles::new();
        let config_path = files.config(valid_config());
        let missing = files.root.join("missing-key");

        env.set(ENV_COMMAND_SIGNING_KEY_FILE, &missing);

        let error = AgentConfig::load(config_path).expect_err("missing key file must fail");

        assert!(error
            .to_string()
            .contains("read JANUS_COMMAND_SIGNING_KEY_FILE"));
    }
}
