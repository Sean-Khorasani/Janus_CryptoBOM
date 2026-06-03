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
        let mut title = "Classical public-key cryptography is quantum-vulnerable".to_string();
        let mut desc = format!(
            "{} uses {} for role {}. Migrate to hybrid/PQC profile X25519MLKEM768 and ML-DSA where supported.",
            component.bom_ref, alg.name, alg.role
        );
        let mut rule = "JANUS-PQC-001";
        if name.contains("RSA") && alg.key_bits > 0 && alg.key_bits < 3072 {
            severity = RiskSeverity::Critical;
            title = "RSA key size below 2026 transition threshold".to_string();
            desc = format!(
                "{} uses RSA-{}; minimum transitional threshold is RSA-3072 and target state is PQC/hybrid.",
                component.bom_ref, alg.key_bits
            );
            rule = "JANUS-PQC-002";
        }
        push_finding(
            payload,
            severity,
            &title,
            &desc,
            &component.bom_ref,
            &alg.name,
            rule,
            "hybrid-tls13-mlkem-mldsa",
        );
        return;
    }

    if name.contains("MD5") || name.contains("SHA1") || name.contains("SHA-1") {
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
        );
    }

    if name.contains("AES-128") && alg.role == CryptoRole::Symmetric as i32 {
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
        );
    }
}

fn assess_network(payload: &mut CbomTelemetryPayload, obs: &NetworkObservation) {
    if obs.cleartext {
        push_finding(
            payload,
            RiskSeverity::Critical,
            "Cleartext service observed",
            &format!("{} exposes {} without cryptographic protection.", obs.endpoint, obs.protocol),
            &obs.endpoint,
            "cleartext",
            "JANUS-NET-001",
            "enable-tls13-hybrid",
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
            "TLS endpoint is not validated as TLS 1.3",
            &format!(
                "{} negotiated or reported {:?}. Target is TLS 1.3 with hybrid ECDHE-MLKEM support.",
                obs.endpoint, obs.tls_version
            ),
            &obs.endpoint,
            &obs.cipher_suite,
            "JANUS-NET-002",
            "tls13-hybrid-key-exchange",
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
        );
    }
}

fn push_finding(
    payload: &mut CbomTelemetryPayload,
    severity: RiskSeverity,
    title: &str,
    description: &str,
    asset_ref: &str,
    algorithm: &str,
    rule: &str,
    profile: &str,
) {
    if payload.findings.iter().any(|f| {
        f.policy_rule_id == rule && f.asset_ref == asset_ref && f.algorithm == algorithm
    }) {
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
        evidence_ids: Vec::new(),
        migration_profile: profile.to_string(),
    });
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
