use crate::proto::{CbomComponent, Evidence};
use anyhow::Result;
use serde_json::{json, Value};

pub fn render_cyclonedx(
    components: &[CbomComponent],
    evidence: &[Evidence],
    started: i64,
    finished: i64,
) -> Result<String> {
    let mut cdx_components = Vec::<Value>::new();
    for component in components {
        let crypto_properties: Vec<Value> = component
            .algorithms
            .iter()
            .flat_map(|alg| {
                [
                    json!({"name": "janus:crypto:algorithm", "value": &alg.name}),
                    json!({"name": "janus:crypto:family", "value": &alg.family}),
                    json!({"name": "janus:crypto:role", "value": alg.role.to_string()}),
                    json!({"name": "janus:crypto:status", "value": &alg.status}),
                    json!({"name": "janus:crypto:library", "value": &alg.implementation_library}),
                    json!({"name": "janus:crypto:quantumVulnerable", "value": alg.quantum_vulnerable.to_string()}),
                ]
            })
            .collect();
        cdx_components.push(json!({
            "type": cyclonedx_type(&component.component_type),
            "bom-ref": component.bom_ref,
            "name": component.name,
            "version": component.version,
            "purl": null_if_empty(&component.purl),
            "properties": crypto_properties,
            "evidence": {
                "identity": {
                    "field": "file_path",
                    "confidence": 0.7,
                    "methods": [{"technique": "source-code-analysis", "confidence": 0.7, "value": component.file_path}]
                }
            }
        }));
    }

    // CycloneDX 1.6 cryptographic-asset components (WP-021): model each algorithm as a
    // standards-compliant crypto asset with cryptoProperties, in addition to the file/library
    // components above. Consumers that understand CBOM read these; the janus:crypto:* property
    // mirror on the parent component is retained for back-compat.
    for component in components {
        for alg in component.algorithms.iter() {
            if alg.name.is_empty() {
                continue;
            }
            let mut algo_props = json!({
                "primitive": cdx_primitive(&alg.family, &alg.name),
                "parameterSetIdentifier": alg.name,
                "executionEnvironment": "software-plain-ram",
                "implementationPlatform": "generic",
            });
            if let Some(level) = cdx_nist_pq_level(&alg.name, alg.quantum_vulnerable) {
                algo_props["nistQuantumSecurityLevel"] = json!(level);
            }
            cdx_components.push(json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto:{}:{}", component.bom_ref, alg.name),
                "name": alg.name,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": algo_props,
                }
            }));
        }
    }

    let evidence_props: Vec<Value> = evidence
        .iter()
        .map(|e| {
            json!({
                "name": format!("janus:evidence:{}", e.evidence_id),
                "value": format!("{}:{}:{}:{}", e.source_type, e.source_tool, e.target, e.raw_artifact_sha256)
            })
        })
        .collect();

    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "version": 1,
        "metadata": {
            "timestamp": unix_to_iso(finished),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "janus-agent",
                    "version": env!("CARGO_PKG_VERSION")
                }]
            },
            "properties": [
                {"name": "janus:scanStartedUnix", "value": started.to_string()},
                {"name": "janus:scanFinishedUnix", "value": finished.to_string()}
            ]
        },
        "components": cdx_components,
        "dependencies": dependencies(components),
        "properties": evidence_props
    });
    Ok(serde_json::to_string(&bom)?)
}

fn cyclonedx_type(component_type: &str) -> &'static str {
    match component_type {
        "file" | "manifest" => "file",
        "process" | "loaded-library" => "application",
        "ELF" | "PE" | "Mach-O" | "binary" => "file",
        _ => "library",
    }
}

fn null_if_empty(s: &str) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s.to_string())
    }
}

fn dependencies(components: &[CbomComponent]) -> Vec<Value> {
    components
        .iter()
        .map(|c| {
            json!({
                "ref": c.bom_ref,
                "dependsOn": c.dependencies
            })
        })
        .collect()
}

/// Format a unix timestamp (seconds) as an RFC 3339 / ISO 8601 UTC string, which CycloneDX
/// and SARIF both require for `timestamp` fields (WP-021). Falls back to the epoch on the
/// (practically impossible) out-of-range error so the export stays schema-valid.
fn unix_to_iso(ts: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(ts)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Map a crypto algorithm family/name to a CycloneDX 1.6 cryptographic-algorithm `primitive`.
/// Returns "unknown" when it cannot be classified (a valid enum value), never an invalid one.
fn cdx_primitive(family: &str, name: &str) -> &'static str {
    let f = family.to_ascii_lowercase();
    let n = name.to_ascii_lowercase();
    let hay = format!("{f} {n}");
    let has = |s: &str| hay.contains(s);
    if has("ml-kem") || has("kyber") || has("ecdh") || has("dh") || has("x25519") || has("x448") {
        if has("ml-kem") || has("kyber") {
            return "kem";
        }
        return "key-agree";
    }
    if has("ml-dsa")
        || has("dilithium")
        || has("slh-dsa")
        || has("sphincs")
        || has("ecdsa")
        || has("eddsa")
        || has("ed25519")
        || has("dsa")
        || has("rsa-pss")
        || has("signature")
    {
        return "signature";
    }
    if has("rsa") {
        return "pke";
    }
    if has("aes") || has("3des") || has("des") || has("blowfish") || has("rc4") || has("chacha") {
        return "block-cipher";
    }
    if has("sha") || has("md5") || has("blake") || has("hash") {
        return "hash";
    }
    if has("hmac") || has("mac") {
        return "mac";
    }
    "unknown"
}

/// Conservative NIST post-quantum security level (0–6) for the algorithm, or None when it
/// cannot be claimed. Quantum-vulnerable asymmetric algorithms are level 0; PQC and strong
/// symmetric algorithms map by parameter set. Unknown → None (field omitted) to avoid
/// over-claiming.
fn cdx_nist_pq_level(name: &str, quantum_vulnerable: bool) -> Option<u8> {
    let n = name.to_ascii_uppercase();
    if n.contains("1024") || n.contains("-87") || n.contains("AES-256") || n.contains("AES256") {
        return Some(5);
    }
    if n.contains("768") || n.contains("-65") || n.contains("AES-192") {
        return Some(3);
    }
    if n.contains("512") || n.contains("-44") || n.contains("AES-128") || n.contains("AES128") {
        return Some(1);
    }
    if quantum_vulnerable {
        return Some(0);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{CbomComponent, CryptoAlgorithm};

    fn alg(name: &str, family: &str, quantum_vulnerable: bool) -> CryptoAlgorithm {
        CryptoAlgorithm {
            name: name.to_string(),
            family: family.to_string(),
            quantum_vulnerable,
            ..Default::default()
        }
    }

    // CycloneDX 1.6 conformance (WP-021): the rendered BOM must use the standard envelope,
    // an RFC 3339 metadata timestamp, a urn:uuid serial, and a cryptographic-asset component
    // carrying cryptoProperties for each algorithm.
    #[test]
    fn cyclonedx_is_schema_conformant() {
        use time::format_description::well_known::Rfc3339;
        let comp = CbomComponent {
            bom_ref: "comp-1".to_string(),
            name: "libssl".to_string(),
            component_type: "library".to_string(),
            algorithms: vec![
                alg("RSA-2048", "RSA", true),
                alg("ML-DSA-65", "ML-DSA", false),
            ],
            ..Default::default()
        };
        let out = render_cyclonedx(&[comp], &[], 1_700_000_000, 1_700_000_500).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();

        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.6");
        assert!(
            v["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"),
            "serialNumber must be a urn:uuid"
        );
        // metadata.timestamp must be RFC 3339 (parses cleanly), not a bare unix int.
        let ts = v["metadata"]["timestamp"].as_str().unwrap();
        assert!(
            time::OffsetDateTime::parse(ts, &Rfc3339).is_ok(),
            "metadata.timestamp {ts:?} must be RFC 3339"
        );

        // Exactly one cryptographic-asset component per algorithm, each with cryptoProperties.
        let crypto_assets: Vec<&Value> = v["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["type"] == "cryptographic-asset")
            .collect();
        assert_eq!(crypto_assets.len(), 2, "one crypto-asset per algorithm");
        for ca in &crypto_assets {
            assert_eq!(ca["cryptoProperties"]["assetType"], "algorithm");
            assert!(ca["cryptoProperties"]["algorithmProperties"]["primitive"].is_string());
        }
        // RSA (quantum-vulnerable) → primitive pke, NIST PQ level 0.
        let rsa = crypto_assets
            .iter()
            .find(|c| c["name"] == "RSA-2048")
            .unwrap();
        let rsa_props = &rsa["cryptoProperties"]["algorithmProperties"];
        assert_eq!(rsa_props["primitive"], "pke");
        assert_eq!(rsa_props["nistQuantumSecurityLevel"], 0);
        // ML-DSA-65 → signature primitive, PQ level 3.
        let mldsa = crypto_assets
            .iter()
            .find(|c| c["name"] == "ML-DSA-65")
            .unwrap();
        let mldsa_props = &mldsa["cryptoProperties"]["algorithmProperties"];
        assert_eq!(mldsa_props["primitive"], "signature");
        assert_eq!(mldsa_props["nistQuantumSecurityLevel"], 3);
    }
}
