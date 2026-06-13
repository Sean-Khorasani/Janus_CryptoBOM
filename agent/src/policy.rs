use crate::proto::{
    CbomComponent, CbomTelemetryPayload, CryptoAlgorithm, CryptoFinding, CryptoRole,
    NetworkObservation, RiskSeverity,
};
use uuid::Uuid;

pub fn assess(payload: &mut CbomTelemetryPayload) {
    let components = payload.components.clone();
    for component in &components {
        for alg in &component.algorithms {
            assess_algorithm(payload, component, alg);
        }
    }
    let network = payload.network_observations.clone();
    for obs in &network {
        assess_network(payload, obs);
    }
}

fn find_evidence_ids(payload: &CbomTelemetryPayload, asset_ref: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut clean_ref = asset_ref.to_string();
    if let Some(idx) = asset_ref.find(':') {
        clean_ref = asset_ref[idx + 1..].to_string();
    }
    let clean_ref_normalized = clean_ref.replace('/', "\\");

    for ev in &payload.evidence {
        let ev_target_normalized = ev.target.replace('/', "\\");
        if ev.target == asset_ref
            || ev_target_normalized == clean_ref_normalized
            || (clean_ref_normalized.len() > 4
                && ev_target_normalized.contains(&clean_ref_normalized))
            || (ev_target_normalized.len() > 4
                && clean_ref_normalized.contains(&ev_target_normalized))
        {
            ids.push(ev.evidence_id.clone());
        }
    }
    ids
}

fn assess_algorithm(
    payload: &mut CbomTelemetryPayload,
    component: &CbomComponent,
    alg: &CryptoAlgorithm,
) {
    let name = alg.name.to_ascii_uppercase();
    let family = alg.family.to_ascii_uppercase();
    let classical_public_key = contains_any(&name, &["RSA", "ECDSA", "ECDH", "ECDHE", "DH", "DSA"])
        || contains_any(&family, &["RSA", "ECC", "ECDH", "DIFFIE", "DSA"]);

    if public_key_role(alg.role) && classical_public_key {
        let mut severity = RiskSeverity::High;
        let mut title; // = "Classical public-key cryptography is quantum-vulnerable".to_string();
        let mut desc = format!(
            "{} uses {} for role {}. Migrate to hybrid/PQC profile X25519MLKEM768 and ML-DSA where supported.",
            component.bom_ref, alg.name, alg.role
        );
        let mut rule; // = "JANUS-PQC-001";
                      // let mut profile = "hybrid-tls13-mlkem-mldsa"; toreview and todel
        let profile;
        let evidence_ids = find_evidence_ids(payload, &component.bom_ref);

        if alg.role == CryptoRole::CertSignature as i32
            || alg.role == CryptoRole::Signature as i32
            || alg.role == CryptoRole::CertPublicKey as i32
        {
            title = "Classical public-key signature cryptography is quantum-vulnerable".to_string();
            desc = format!(
                "{} uses {} for {}. Migrate to PQC signature standard ML-DSA-65 or SLH-DSA.",
                component.bom_ref,
                alg.name,
                role_name(alg.role)
            );
            rule = "JANUS-PQC-001";
            profile = "certificate-signature-modernization";
            if name.contains("RSA") && alg.key_bits > 0 && alg.key_bits < 3072 {
                severity = RiskSeverity::Critical;
                title = "RSA key size below 2026 transition threshold".to_string();
                desc = format!(
                    "{} uses RSA-{}; minimum transitional threshold is RSA-3072. Migrate to signature standard ML-DSA-65.",
                    component.bom_ref, alg.key_bits
                );
                rule = "JANUS-PQC-002";
            }
        } else {
            title = "Classical key exchange / KEM cryptography is quantum-vulnerable".to_string();
            desc = format!(
                "{} uses {} for {}. Migrate to hybrid/PQC key establishment standard X25519MLKEM768 (ML-KEM).",
                component.bom_ref, alg.name, role_name(alg.role)
            );
            rule = "JANUS-PQC-007";
            profile = "hybrid-tls13-key-exchange";
        }

        push_finding(
            payload,
            severity,
            &title,
            &desc,
            &component.bom_ref,
            &alg.name,
            rule,
            profile,
            evidence_ids,
        );
        return;
    }

    if name.contains("MD5") || name.contains("SHA1") || name.contains("SHA-1") {
        let evidence_ids = find_evidence_ids(payload, &component.bom_ref);
        push_finding(
            payload,
            RiskSeverity::High,
            "Deprecated hash detected",
            &format!(
                "{} references {}. Replace with SHA-384/SHA-512/SHA-3 according to protocol context.",
                component.bom_ref, alg.name
            ),
            &component.bom_ref,
            &alg.name,
            "JANUS-CLASSICAL-003",
            "hash-modernization",
            evidence_ids,
        );
    }

    if name.contains("AES-128") && alg.role == CryptoRole::Symmetric as i32 {
        let evidence_ids = find_evidence_ids(payload, &component.bom_ref);
        push_finding(
            payload,
            RiskSeverity::Medium,
            "AES-128 used where long-term confidentiality may require AES-256",
            &format!(
                "{} references AES-128. Review confidentiality lifetime and upgrade long-retention data paths to AES-256.",
                component.bom_ref
            ),
            &component.bom_ref,
            &alg.name,
            "JANUS-PQC-004",
            "symmetric-margin-upgrade",
            evidence_ids,
        );
    }

    let name_upper = alg.name.to_ascii_uppercase();
    let family_upper = alg.family.to_ascii_uppercase();
    if name_upper.contains("TLS 1.0")
        || name_upper.contains("TLS 1.1")
        || name_upper.contains("RC4")
        || name_upper.contains("3DES")
        || family_upper.contains("TLS 1.0")
        || family_upper.contains("TLS 1.1")
        || family_upper.contains("RC4")
        || family_upper.contains("3DES")
    {
        let evidence_ids = find_evidence_ids(payload, &component.bom_ref);
        push_finding(
            payload,
            RiskSeverity::High,
            "Weak Schannel/TLS Policy enabled in Registry",
            &format!("Weak registry cipher or protocol enabled: {}", alg.name),
            &component.bom_ref,
            &alg.name,
            "JANUS-CLASSICAL-009",
            "registry-hardening",
            evidence_ids,
        );
    }

    if alg.name == "Unencrypted-Private-Key" {
        let evidence_ids = find_evidence_ids(payload, &component.bom_ref);
        push_finding(
            payload,
            RiskSeverity::Critical,
            "Unencrypted private key found in process memory",
            &format!(
                "Unencrypted private key found in process memory: {}",
                component.bom_ref
            ),
            &component.bom_ref,
            &alg.name,
            "JANUS-CLASSICAL-008",
            "memory-key-leak",
            evidence_ids,
        );
    }
}

fn assess_network(payload: &mut CbomTelemetryPayload, obs: &NetworkObservation) {
    let evidence_ids = find_evidence_ids(payload, &obs.endpoint);
    if obs.cleartext {
        push_finding(
            payload,
            RiskSeverity::Critical,
            "Cleartext service observed",
            &format!(
                "{} exposes {} without cryptographic protection.",
                obs.endpoint, obs.protocol
            ),
            &obs.endpoint,
            "cleartext",
            "JANUS-NET-001",
            "enable-tls13-hybrid",
            evidence_ids,
        );
        return;
    }

    let version = obs.tls_version.to_ascii_uppercase();
    if version.starts_with("TLS1.0")
        || version.starts_with("TLS1.1")
        || version.starts_with("TLS1.2")
        || version.is_empty()
    {
        push_finding(
            payload,
            RiskSeverity::High,
            "TLS 1.3 is not enabled (blocks hybrid PQC key exchange)",
            &format!(
                "{} negotiated or reported {:?}. Hybrid post-quantum key agreement (ML-KEM) requires TLS 1.3. Enable TLS 1.3 first.",
                obs.endpoint, obs.tls_version
            ),
            &obs.endpoint,
            &obs.cipher_suite,
            "JANUS-NET-002",
            "enable-tls13-first",
            evidence_ids.clone(),
        );
    }

    let group = obs.named_group.to_ascii_uppercase();
    if !obs.pqc_hybrid && !group.contains("MLKEM") && !group.contains("ML-KEM") {
        push_finding(
            payload,
            RiskSeverity::Critical,
            "TLS key exchange is classical-only",
            &format!(
                "{} did not prove hybrid ML-KEM key agreement. Observed group={:?} cipher={:?}.",
                obs.endpoint, obs.named_group, obs.cipher_suite
            ),
            &obs.endpoint,
            &obs.named_group,
            "JANUS-PQC-005",
            "X25519MLKEM768",
            evidence_ids.clone(),
        );
    }

    let sig = obs.signature_algorithm.to_ascii_uppercase();
    if sig.contains("RSA") || sig.contains("ECDSA") {
        push_finding(
            payload,
            RiskSeverity::High,
            "Certificate signature remains classical",
            &format!(
                "{} certificate uses {}. Pilot ML-DSA or SLH-DSA in private trust domains and track public PKI readiness.",
                obs.endpoint, obs.signature_algorithm
            ),
            &obs.endpoint,
            &obs.signature_algorithm,
            "JANUS-PQC-006",
            "certificate-signature-modernization",
            evidence_ids,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_finding(
    payload: &mut CbomTelemetryPayload,
    severity: RiskSeverity,
    title: &str,
    description: &str,
    asset_ref: &str,
    algorithm: &str,
    rule: &str,
    profile: &str,
    evidence_ids: Vec<String>,
) {
    if payload
        .findings
        .iter()
        .any(|f| f.policy_rule_id == rule && f.asset_ref == asset_ref && f.algorithm == algorithm)
    {
        return;
    }
    payload.findings.push(CryptoFinding {
        finding_id: Uuid::new_v4().to_string(),
        severity: severity as i32,
        title: title.to_string(),
        description: description.to_string(),
        asset_ref: asset_ref.to_string(),
        algorithm: algorithm.to_string(),
        policy_rule_id: rule.to_string(),
        evidence_ids,
        migration_profile: profile.to_string(),
    });
}

fn role_name(role: i32) -> String {
    if role == CryptoRole::Kem as i32 {
        "KEM".to_string()
    } else if role == CryptoRole::KeyExchange as i32 {
        "key exchange".to_string()
    } else if role == CryptoRole::Signature as i32 {
        "signature".to_string()
    } else if role == CryptoRole::CertPublicKey as i32 {
        "certificate public key".to_string()
    } else if role == CryptoRole::CertSignature as i32 {
        "certificate signature".to_string()
    } else {
        "cryptographic operation".to_string()
    }
}

fn public_key_role(role: i32) -> bool {
    role == CryptoRole::Kem as i32
        || role == CryptoRole::KeyExchange as i32
        || role == CryptoRole::Signature as i32
        || role == CryptoRole::CertPublicKey as i32
        || role == CryptoRole::CertSignature as i32
}

fn contains_any(s: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| s.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        CbomComponent, CbomTelemetryPayload, CryptoAlgorithm, CryptoRole, RiskSeverity,
    };

    #[test]
    fn test_assess_unencrypted_private_key() {
        let mut payload = CbomTelemetryPayload::default();
        let comp = CbomComponent {
            bom_ref: "test-proc".to_string(),
            name: "test-process".to_string(),
            version: String::new(),
            component_type: "process-memory-key".to_string(),
            purl: String::new(),
            file_path: String::new(),
            language: "runtime".to_string(),
            algorithms: vec![CryptoAlgorithm {
                name: "Unencrypted-Private-Key".to_string(),
                family: "process-memory-key".to_string(),
                role: CryptoRole::Unspecified as i32,
                status: "scraped-from-memory".to_string(),
                key_bits: 0,
                curve: String::new(),
                implementation_library: "process-memory".to_string(),
                source_file: String::new(),
                source_line: 0,
                source_column: 0,
                symbol: "private-key-header".to_string(),
                confidence: 0.95,
                quantum_vulnerable: false,
                context_snippet: String::new(),
            }],
            dependencies: Vec::new(),
            reachable: true,
        };
        assess_algorithm(&mut payload, &comp, &comp.algorithms[0]);

        assert_eq!(payload.findings.len(), 1);
        assert_eq!(payload.findings[0].policy_rule_id, "JANUS-CLASSICAL-008");
        assert_eq!(payload.findings[0].severity, RiskSeverity::Critical as i32);
        assert_eq!(
            payload.findings[0].title,
            "Unencrypted private key found in process memory"
        );
    }

    #[test]
    fn test_assess_weak_registry_policies() {
        let mut payload = CbomTelemetryPayload::default();
        let comp = CbomComponent {
            bom_ref: "windows-gpo".to_string(),
            name: "Windows Cryptography Group Policy".to_string(),
            version: String::new(),
            component_type: "windows-gpo-cryptography".to_string(),
            purl: String::new(),
            file_path: String::new(),
            language: "windows-registry".to_string(),
            algorithms: vec![
                CryptoAlgorithm {
                    name: "TLS 1.0".to_string(),
                    family: "TLS".to_string(),
                    role: CryptoRole::KeyExchange as i32,
                    status: "windows-registry-observed".to_string(),
                    key_bits: 0,
                    curve: String::new(),
                    implementation_library: "Windows Cryptography".to_string(),
                    source_file: String::new(),
                    source_line: 0,
                    source_column: 0,
                    symbol: String::new(),
                    confidence: 0.80,
                    quantum_vulnerable: false,
                    context_snippet: String::new(),
                },
                CryptoAlgorithm {
                    name: "3DES".to_string(),
                    family: "legacy".to_string(),
                    role: CryptoRole::Symmetric as i32,
                    status: "windows-registry-observed".to_string(),
                    key_bits: 0,
                    curve: String::new(),
                    implementation_library: "Windows Cryptography".to_string(),
                    source_file: String::new(),
                    source_line: 0,
                    source_column: 0,
                    symbol: String::new(),
                    confidence: 0.80,
                    quantum_vulnerable: false,
                    context_snippet: String::new(),
                },
            ],
            dependencies: Vec::new(),
            reachable: true,
        };

        assess_algorithm(&mut payload, &comp, &comp.algorithms[0]);
        assess_algorithm(&mut payload, &comp, &comp.algorithms[1]);

        assert_eq!(payload.findings.len(), 2);
        assert_eq!(payload.findings[0].policy_rule_id, "JANUS-CLASSICAL-009");
        assert_eq!(payload.findings[0].severity, RiskSeverity::High as i32);
        assert_eq!(
            payload.findings[0].title,
            "Weak Schannel/TLS Policy enabled in Registry"
        );
        assert_eq!(payload.findings[1].policy_rule_id, "JANUS-CLASSICAL-009");
    }
}
