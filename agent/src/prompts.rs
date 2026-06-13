use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

/// A versioned prompt template loaded from a TOML file.
///
/// Templates use `{{varname}}` placeholders; `render()` substitutes them.
/// Model and temperature come from the file, enabling per-task tuning
/// without recompiling the agent.
#[derive(Clone, Deserialize)]
pub struct PromptTemplate {
    pub prompt: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_temperature")]
    pub temperature: f64,
    /// Schema version for forward compatibility (kept for auditing, not used by runtime).
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<String>,
}

fn default_model() -> String {
    "gpt-4o-mini".to_string()
}
fn default_temperature() -> f64 {
    0.0
}

impl PromptTemplate {
    /// Load a template from a TOML file on disk.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read prompt template {}: {}", path.display(), e))?;
        toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse prompt template {}: {}", path.display(), e))
    }

    /// Substitute `{{key}}` placeholders. Unknown keys are left as-is.
    pub fn render(&self, vars: &[(&str, &str)]) -> String {
        let mut out = self.prompt.clone();
        for (key, value) in vars {
            out = out.replace(&format!("{{{{{}}}}}", key), value);
        }
        out
    }
}

/// Loads prompt templates from a directory (one TOML file per task).
pub struct PromptRegistry {
    dir: String,
}

impl PromptRegistry {
    pub fn new(dir: impl Into<String>) -> Self {
        Self { dir: dir.into() }
    }

    /// Load a template by task name (looks for `<dir>/<name>.toml`).
    /// Returns an error if the file is missing or malformed.
    #[allow(dead_code)]
    pub fn load(&self, name: &str) -> Result<PromptTemplate> {
        let path = Path::new(&self.dir).join(format!("{}.toml", name));
        PromptTemplate::load(&path)
    }

    /// Load a template or fall back to `default` if the file is missing or unreadable.
    pub fn load_or_default(&self, name: &str, default: PromptTemplate) -> PromptTemplate {
        let path = Path::new(&self.dir).join(format!("{}.toml", name));
        if path.exists() {
            match PromptTemplate::load(&path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!(
                        "[prompts] warn: failed to parse {}: {} — using built-in fallback",
                        path.display(),
                        e
                    );
                    default
                }
            }
        } else {
            default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_template(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn render_substitutes_placeholders() {
        let t = PromptTemplate {
            prompt: "Hello {{name}}, algorithm is {{algorithm}}".to_string(),
            model: "gpt-4o-mini".to_string(),
            temperature: 0.0,
            version: None,
        };
        let rendered = t.render(&[("name", "world"), ("algorithm", "RSA")]);
        assert_eq!(rendered, "Hello world, algorithm is RSA");
    }

    #[test]
    fn load_parses_toml_with_multiline_prompt() {
        let dir = std::env::temp_dir().join("janus_prompts_test_load");
        fs::create_dir_all(&dir).unwrap();
        let path = write_template(
            &dir,
            "t.toml",
            "model = \"gpt-4o\"\ntemperature = 0.2\nprompt = \"\"\"\nLine one\nLine two\n\"\"\"\n",
        );
        let t = PromptTemplate::load(&path).unwrap();
        assert!(t.prompt.contains("Line one"));
        assert_eq!(t.model, "gpt-4o");
        assert!((t.temperature - 0.2).abs() < 1e-6);
    }

    #[test]
    fn load_uses_defaults_for_missing_optional_fields() {
        let dir = std::env::temp_dir().join("janus_prompts_test_defaults");
        fs::create_dir_all(&dir).unwrap();
        let path = write_template(&dir, "t.toml", "prompt = \"Hello\"\n");
        let t = PromptTemplate::load(&path).unwrap();
        assert_eq!(t.model, "gpt-4o-mini");
        assert_eq!(t.temperature, 0.0);
    }

    #[test]
    fn registry_falls_back_on_missing_file() {
        let reg = PromptRegistry::new("/nonexistent/dir");
        let fallback = PromptTemplate {
            prompt: "fallback".to_string(),
            model: "gpt-4o-mini".to_string(),
            temperature: 0.0,
            version: None,
        };
        let t = reg.load_or_default("classify-intent", fallback);
        assert_eq!(t.prompt, "fallback");
    }
}
