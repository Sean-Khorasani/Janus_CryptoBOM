use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

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
    pub network_targets: Vec<String>,
    #[serde(default)]
    pub plugin_dirs: Vec<String>,
    #[serde(default)]
    pub plugin_commands: Vec<PluginCommandConfig>,
    pub active: ActiveConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginCommandConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_plugin_timeout")]
    pub timeout_seconds: u64,
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

fn default_plugin_timeout() -> u64 {
    30
}

impl AgentConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        let mut cfg: AgentConfig = toml::from_str(&raw).context("parse TOML")?;
        if cfg.command_signing_key.starts_with("dpapi:") || cfg.command_signing_key.starts_with("plain:") {
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
        if self.scan_interval_seconds == 0 {
            anyhow::bail!("scan_interval_seconds must be non-zero");
        }
        if self.command_signing_key.len() < 16 {
            anyhow::bail!("command_signing_key must be at least 16 bytes");
        }
        Ok(())
    }

    fn load_plugin_manifests(&mut self) -> Result<()> {
        for dir in &self.plugin_dirs {
            let root = Path::new(dir);
            if !root.exists() {
                continue;
            }
            for entry in fs::read_dir(root).with_context(|| format!("read plugin dir {}", root.display()))? {
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
                let mut plugin: PluginCommandConfig =
                    toml::from_str(&raw).with_context(|| format!("parse {}", manifest.display()))?;
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
