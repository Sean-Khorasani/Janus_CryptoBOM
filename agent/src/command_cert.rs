//! CA-chained ML-DSA command-certificate verification (WP-029 P3, `janus-sig-v2`).
//!
//! In v2 the server embeds the leaf command-signing certificate (chained to a bundled ML-DSA
//! root CA) in the command instead of a bare public key. The agent trusts the bundled root and
//! verifies the chain — no fingerprint pinning. No X.509 crate verifies ML-DSA certificate
//! signatures, so this parses the structure with `x509-parser` and verifies the CA's signature
//! over the leaf's raw TBS with `fips204` (the same ML-DSA-65 primitive used elsewhere).

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use x509_parser::prelude::*;

/// Verifies that `leaf_der` is an ML-DSA leaf certificate validly issued by the ML-DSA root in
/// `root_der`, and returns the leaf's ML-DSA-65 public key bytes on success. Checks performed:
/// the leaf's issuer equals the root's subject, the root's public key verifies the CA signature
/// over the leaf's raw TBSCertificate, and the leaf is within its validity window. Returns
/// `None` on any failure (parse error, name mismatch, expired, bad signature).
pub fn verify_mldsa_leaf_against_root(leaf_der: &[u8], root_der: &[u8]) -> Option<Vec<u8>> {
    let (_, leaf) = X509Certificate::from_der(leaf_der).ok()?;
    let (_, root) = X509Certificate::from_der(root_der).ok()?;

    // The leaf must be issued by this root.
    if leaf.issuer() != root.subject() {
        return None;
    }
    // The leaf must currently be valid (not expired / not yet valid).
    if !leaf.validity().is_valid() {
        return None;
    }

    // Verify the CA's ML-DSA signature over the leaf's raw TBSCertificate bytes.
    let root_pk = mldsa_pk(root.public_key().subject_public_key.data.as_ref())?;
    let tbs = leaf.tbs_certificate.as_ref();
    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = leaf.signature_value.data.as_ref().try_into().ok()?;
    if sig_arr.iter().all(|&b| b == 0) {
        return None;
    }
    if !root_pk.verify(tbs, &sig_arr, &[]) {
        return None;
    }

    // The leaf's own public key is what subsequently verifies command signatures.
    let leaf_pk = leaf.public_key().subject_public_key.data.as_ref();
    // Sanity: it must be a well-formed ML-DSA-65 key.
    mldsa_pk(leaf_pk)?;
    Some(leaf_pk.to_vec())
}

/// Reads a certificate file (PEM or raw DER) and returns its DER bytes. Used to load the
/// bundled ML-DSA command root CA the agent trusts for janus-sig-v2 verification.
pub fn read_cert_der(path: &str) -> Option<Vec<u8>> {
    let raw = std::fs::read(path).ok()?;
    if let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&raw) {
        return Some(pem.contents);
    }
    // Fall back to treating the bytes as DER, but only if they parse as a certificate.
    if X509Certificate::from_der(&raw).is_ok() {
        return Some(raw);
    }
    None
}

fn mldsa_pk(bytes: &[u8]) -> Option<ml_dsa_65::PublicKey> {
    if bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let arr: [u8; ml_dsa_65::PK_LEN] = bytes.try_into().ok()?;
    ml_dsa_65::PublicKey::try_from_bytes(arr).ok()
}

/// Verifies an ML-DSA signature over `message` under the raw ML-DSA-65 public key `pk_bytes`
/// (empty context, matching the server signer). Used after `verify_mldsa_leaf_against_root`
/// has established trust in the leaf key.
pub fn verify_with_mldsa_pk(pk_bytes: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let pk = match mldsa_pk(pk_bytes) {
        Some(p) => p,
        None => return false,
    };
    if sig.iter().all(|&b| b == 0) {
        return false;
    }
    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    pk.verify(message, &sig_arr, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::Value;

    // Cross-language interop (WP-029 P3): the server (Go/circl) issues an ML-DSA Root CA + leaf
    // command cert and signs a canonical command with the leaf key; the agent (Rust/fips204 +
    // x509-parser) must verify the chain and the command signature. Fixture is produced by the
    // server's TestWriteMLDSACertChainFixture.
    #[test]
    fn verifies_server_produced_cert_chain() {
        let raw = include_str!("../tests/fixtures/mldsa_cert_chain_vector.json");
        let v: Value = serde_json::from_str(raw).expect("fixture json");
        let b64 = base64::engine::general_purpose::STANDARD;
        let root_der = b64
            .decode(v["root_cert_der_b64"].as_str().unwrap())
            .unwrap();
        let leaf_der = b64
            .decode(v["leaf_cert_der_b64"].as_str().unwrap())
            .unwrap();
        let message = b64.decode(v["message_b64"].as_str().unwrap()).unwrap();
        let sig = b64.decode(v["signature_b64"].as_str().unwrap()).unwrap();

        // The leaf chains to the root; recover the leaf public key.
        let leaf_pk = verify_mldsa_leaf_against_root(&leaf_der, &root_der)
            .expect("leaf must chain to the bundled root");

        // The command signature verifies under the cert-bound key.
        assert!(verify_with_mldsa_pk(&leaf_pk, &message, &sig));
        // Tampered message must fail.
        assert!(!verify_with_mldsa_pk(&leaf_pk, b"tampered", &sig));

        // A leaf checked against the wrong root (itself) must fail name/sig binding.
        assert!(verify_mldsa_leaf_against_root(&leaf_der, &leaf_der).is_none());
        // Garbage DER must fail, not panic.
        assert!(verify_mldsa_leaf_against_root(&[0u8; 8], &root_der).is_none());
    }

    // Revocation-by-expiry (WP-029 P4 short-lived-cert strategy): a leaf that chains to the
    // root and is correctly signed but whose validity window has passed must be rejected.
    #[test]
    fn rejects_expired_leaf_even_when_chain_is_valid() {
        let raw = include_str!("../tests/fixtures/mldsa_cert_chain_vector.json");
        let v: Value = serde_json::from_str(raw).expect("fixture json");
        let b64 = base64::engine::general_purpose::STANDARD;
        let root_der = b64
            .decode(v["root_cert_der_b64"].as_str().unwrap())
            .unwrap();
        let expired_der = b64
            .decode(v["expired_leaf_cert_der_b64"].as_str().unwrap())
            .unwrap();
        // Signed by the same root, issuer matches — but NotAfter is in the past.
        assert!(
            verify_mldsa_leaf_against_root(&expired_der, &root_der).is_none(),
            "an expired leaf must be rejected (revocation by short validity)"
        );
    }
}
