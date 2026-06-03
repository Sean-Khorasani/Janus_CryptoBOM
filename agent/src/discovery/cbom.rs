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

fn unix_to_iso(ts: i64) -> String {
    format!("{ts}")
}
