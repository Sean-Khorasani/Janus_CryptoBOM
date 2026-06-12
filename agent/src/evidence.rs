use serde::{Deserialize, Serialize};

/// Sensitivity classification for evidence data (RESEARCH.md §4.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityLabel {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl Default for SensitivityLabel {
    fn default() -> Self {
        SensitivityLabel::Internal
    }
}

/// The source of an evidence item — which discovery module produced it
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    SourceCodePattern,
    ConfigFile,
    BinaryImport,
    TlsHandshake,
    DependencyManifest,
    ProcessMemory,
    WindowsRegistry,
    SideChannelPattern,
}

/// A bounded, privacy-safe evidence package sent to LLM analysis.
/// NEVER contains raw file contents. Context snippets are capped at MAX_CONTEXT_BYTES.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedEvidencePackage {
    pub finding_id: String,
    pub evidence_source: EvidenceSource,
    pub algorithm_detected: String,
    pub detection_method: String,
    pub confidence_floor: f64,
    /// Relative file path (sanitized, no absolute paths)
    pub file_path: Option<String>,
    /// Source line range [start, end], source evidence only
    pub line_range: Option<[u32; 2]>,
    /// Algorithm name + up to 2 lines of context. CAPPED at MAX_CONTEXT_BYTES.
    pub context_snippet: Option<String>,
    /// LLM intent labels from prior classification (e.g. "protect", "negotiate")
    pub intent_labels: Vec<String>,
    pub sensitivity: SensitivityLabel,
    pub collection_timestamp: String, // ISO 8601
}

pub const MAX_CONTEXT_BYTES: usize = 512;

impl BoundedEvidencePackage {
    /// Build a source-code evidence package. Trims context_snippet to MAX_CONTEXT_BYTES.
    pub fn from_source(
        finding_id: impl Into<String>,
        algorithm: impl Into<String>,
        detection_method: impl Into<String>,
        confidence_floor: f64,
        file_path: impl Into<String>,
        line_range: [u32; 2],
        context_snippet: impl Into<String>,
        intent_labels: Vec<String>,
    ) -> Self {
        let raw_snippet = context_snippet.into();
        let trimmed = if raw_snippet.len() > MAX_CONTEXT_BYTES {
            raw_snippet[..MAX_CONTEXT_BYTES].to_string()
        } else {
            raw_snippet
        };
        BoundedEvidencePackage {
            finding_id: finding_id.into(),
            evidence_source: EvidenceSource::SourceCodePattern,
            algorithm_detected: algorithm.into(),
            detection_method: detection_method.into(),
            confidence_floor,
            file_path: Some(file_path.into()),
            line_range: Some(line_range),
            context_snippet: Some(trimmed),
            intent_labels,
            sensitivity: SensitivityLabel::Internal,
            collection_timestamp: now_iso8601(),
        }
    }

    /// Build a TLS service evidence package (no code snippet).
    pub fn from_tls(
        finding_id: impl Into<String>,
        algorithm: impl Into<String>,
        detection_method: impl Into<String>,
        confidence_floor: f64,
        service_address: impl Into<String>,
    ) -> Self {
        BoundedEvidencePackage {
            finding_id: finding_id.into(),
            evidence_source: EvidenceSource::TlsHandshake,
            algorithm_detected: algorithm.into(),
            detection_method: detection_method.into(),
            confidence_floor,
            file_path: Some(service_address.into()),
            line_range: None,
            context_snippet: None,
            intent_labels: vec!["negotiate".to_string()],
            sensitivity: SensitivityLabel::Internal,
            collection_timestamp: now_iso8601(),
        }
    }

    /// Build a dependency manifest evidence package.
    pub fn from_dependency(
        finding_id: impl Into<String>,
        algorithm: impl Into<String>,
        package_name: impl Into<String>,
        package_version: impl Into<String>,
        manifest_path: impl Into<String>,
    ) -> Self {
        let snippet = format!("{}:{}", package_name.into(), package_version.into());
        BoundedEvidencePackage {
            finding_id: finding_id.into(),
            evidence_source: EvidenceSource::DependencyManifest,
            algorithm_detected: algorithm.into(),
            detection_method: "dependency_manifest_match".to_string(),
            confidence_floor: 0.90,
            file_path: Some(manifest_path.into()),
            line_range: None,
            context_snippet: Some(snippet),
            intent_labels: vec![],
            sensitivity: SensitivityLabel::Internal,
            collection_timestamp: now_iso8601(),
        }
    }

    /// Build a binary import evidence package (no code snippet — binary analysis only).
    pub fn from_binary_import(
        finding_id: impl Into<String>,
        algorithm: impl Into<String>,
        binary_path: impl Into<String>,
        import_symbol: impl Into<String>,
    ) -> Self {
        let snippet = import_symbol.into();
        let trimmed = if snippet.len() > MAX_CONTEXT_BYTES {
            snippet[..MAX_CONTEXT_BYTES].to_string()
        } else {
            snippet
        };
        BoundedEvidencePackage {
            finding_id: finding_id.into(),
            evidence_source: EvidenceSource::BinaryImport,
            algorithm_detected: algorithm.into(),
            detection_method: "binary_import_table".to_string(),
            confidence_floor: 0.70,
            file_path: Some(binary_path.into()),
            line_range: None,
            context_snippet: Some(trimmed),
            intent_labels: vec![],
            sensitivity: SensitivityLabel::Internal,
            collection_timestamp: now_iso8601(),
        }
    }

    /// Validate that this package does not exceed size limits.
    /// Returns Err if context_snippet exceeds MAX_CONTEXT_BYTES.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref s) = self.context_snippet {
            if s.len() > MAX_CONTEXT_BYTES {
                return Err(format!(
                    "context_snippet exceeds MAX_CONTEXT_BYTES ({} > {})",
                    s.len(),
                    MAX_CONTEXT_BYTES
                ));
            }
        }
        if self.confidence_floor < 0.0 || self.confidence_floor > 1.0 {
            return Err(format!(
                "confidence_floor out of range: {}",
                self.confidence_floor
            ));
        }
        Ok(())
    }
}

/// Returns current time as a simple ISO 8601 UTC timestamp (seconds precision).
fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple ISO 8601 UTC seconds — sufficient for evidence timestamps
    format!("{}Z", secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_snippet_is_capped_at_max_bytes() {
        let long_snippet = "x".repeat(MAX_CONTEXT_BYTES + 100);
        let pkg = BoundedEvidencePackage::from_source(
            "finding-1",
            "RSA-2048",
            "RegexMatch",
            0.6,
            "src/crypto.rs",
            [10, 12],
            long_snippet,
            vec![],
        );
        let s = pkg.context_snippet.unwrap();
        assert_eq!(s.len(), MAX_CONTEXT_BYTES);
    }

    #[test]
    fn validate_rejects_oversized_snippet() {
        let mut pkg = BoundedEvidencePackage::from_source(
            "f1",
            "AES-128",
            "RegexMatch",
            0.6,
            "a.rs",
            [1, 2],
            "ok",
            vec![],
        );
        pkg.context_snippet = Some("x".repeat(MAX_CONTEXT_BYTES + 1));
        assert!(pkg.validate().is_err());
    }

    #[test]
    fn validate_accepts_valid_package() {
        let pkg =
            BoundedEvidencePackage::from_tls("f1", "RSA-2048", "TlsHandshake", 0.9, "host:443");
        assert!(pkg.validate().is_ok());
    }

    #[test]
    fn from_dependency_sets_correct_source() {
        let pkg = BoundedEvidencePackage::from_dependency(
            "f2",
            "SHA-1",
            "openssl",
            "1.0.2k",
            "package.json",
        );
        assert_eq!(pkg.evidence_source, EvidenceSource::DependencyManifest);
        assert!((pkg.confidence_floor - 0.90).abs() < 1e-9);
    }

    #[test]
    fn validate_rejects_confidence_out_of_range() {
        let mut pkg =
            BoundedEvidencePackage::from_tls("f1", "RSA-2048", "TlsHandshake", 0.9, "host:443");
        pkg.confidence_floor = 1.5;
        assert!(pkg.validate().is_err());
    }

    #[test]
    fn binary_snippet_is_capped() {
        let long_sym = "EVP_EncryptInit_".repeat(100);
        let pkg = BoundedEvidencePackage::from_binary_import(
            "f3",
            "AES-128",
            "/bin/app",
            long_sym,
        );
        let s = pkg.context_snippet.unwrap();
        assert!(s.len() <= MAX_CONTEXT_BYTES);
    }

    #[test]
    fn sensitivity_default_is_internal() {
        let pkg =
            BoundedEvidencePackage::from_tls("f1", "RSA-2048", "TlsHandshake", 0.9, "host:443");
        assert_eq!(pkg.sensitivity, SensitivityLabel::Internal);
    }
}
