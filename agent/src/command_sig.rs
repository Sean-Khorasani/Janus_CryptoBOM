//! Migration-command signature verification.
//!
//! Baseline is HMAC-SHA256 over the canonical command (the shared `command_signing_key`),
//! which is mandatory and quantum-resistant. When the operator pins the server's ML-DSA
//! command-signing public-key fingerprint (`command_pqc_fingerprint`), the command MUST
//! ALSO carry a valid ML-DSA (FIPS 204) signature whose public key matches that pinned
//! SHA-256 fingerprint — an additional asymmetric layer that a compromised agent cannot
//! forge. Pinning also defeats downgrade: a fingerprint-pinned agent rejects any command
//! that lacks the ML-DSA envelope.
//!
//! The public key travels inside the (signed) command; trust comes from the pinned
//! fingerprint, so the key needs no secret channel — exactly the TLS-cert-pinning model.

use base64::Engine;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Prefix marking a dual-signed (HMAC + ML-DSA) `signed_directive`. The lines after it are
/// `<hmac-hex>`, `<base64 ML-DSA signature>`, `<base64 ML-DSA public key>`.
const ENVELOPE_V1: &str = "janus-sig-v1";

/// Verifies a command's signature(s) over `canonical`.
/// - HMAC is always required.
/// - If `pinned_fingerprint` is `Some`, a valid ML-DSA signature from the pinned key is
///   also required (and its absence is rejected as a downgrade).
pub fn verify_command(
    signed_directive: &[u8],
    canonical: &[u8],
    hmac_key: &[u8],
    pinned_fingerprint: Option<&str>,
) -> bool {
    let sd = match std::str::from_utf8(signed_directive) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Split into the HMAC part and optional ML-DSA (sig_b64, pub_b64).
    let (hmac_hex, mldsa) = match sd.strip_prefix(&format!("{ENVELOPE_V1}\n")) {
        Some(rest) => {
            let parts: Vec<&str> = rest.split('\n').collect();
            // Require exactly 3 parts (hmac, sig, pubkey) — reject malformed/padded
            // envelopes rather than silently ignoring extra fields (HARD-1).
            if parts.len() != 3 {
                return false;
            }
            (parts[0], Some((parts[1], parts[2])))
        }
        None => (sd, None),
    };

    if !verify_hmac(hmac_key, canonical, hmac_hex) {
        return false;
    }

    match pinned_fingerprint {
        None => true, // no ML-DSA trust anchor configured -> HMAC baseline only
        Some(fp) => match mldsa {
            Some((sig_b64, pub_b64)) => verify_mldsa(fp, sig_b64, pub_b64, canonical),
            None => false, // pinned but command has no ML-DSA signature -> reject (downgrade)
        },
    }
}

/// Prefix marking a CA-chained dual-signed `signed_directive` (WP-029 P3). The lines after it
/// are `<hmac-hex>`, `<base64 ML-DSA signature>`, `<base64 leaf command cert DER>`.
const ENVELOPE_V2: &str = "janus-sig-v2";

/// Verifies a `janus-sig-v2` command against a bundled ML-DSA command root CA. HMAC baseline is
/// required; the embedded leaf command certificate must chain to `root_ca_der` (verified with
/// `fips204`), and the command signature must verify under the leaf's public key. A command
/// WITHOUT a v2 envelope is rejected (downgrade guard) — callers use this only when a command
/// root CA is configured, which is itself the v2 trust anchor.
pub fn verify_command_v2(
    signed_directive: &[u8],
    canonical: &[u8],
    hmac_key: &[u8],
    root_ca_der: &[u8],
) -> bool {
    let sd = match std::str::from_utf8(signed_directive) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let rest = match sd.strip_prefix(&format!("{ENVELOPE_V2}\n")) {
        Some(r) => r,
        None => return false, // v2 trust anchor configured but command isn't v2 -> downgrade
    };
    let parts: Vec<&str> = rest.split('\n').collect();
    if parts.len() != 3 {
        return false;
    }
    let (hmac_hex, sig_b64, cert_b64) = (parts[0], parts[1], parts[2]);
    if !verify_hmac(hmac_key, canonical, hmac_hex) {
        return false;
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let cert_der = match b64.decode(cert_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = match b64.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Trust anchor: the leaf must chain to the bundled root; recover its public key.
    let leaf_pk = match crate::command_cert::verify_mldsa_leaf_against_root(&cert_der, root_ca_der)
    {
        Some(pk) => pk,
        None => return false,
    };
    crate::command_cert::verify_with_mldsa_pk(&leaf_pk, canonical, &sig)
}

/// Constant-time check that `hmac_hex` equals HMAC-SHA256(key, canonical) in hex.
fn verify_hmac(key: &[u8], canonical: &[u8], hmac_hex: &str) -> bool {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(canonical);
    let expected = hex::encode(mac.finalize().into_bytes());
    expected.as_bytes().ct_eq(hmac_hex.as_bytes()).into()
}

/// Verifies a detached HMAC-SHA256 signature (hex) over `blob` with `key`, in constant
/// time. Used for optional plugin-manifest signature pinning (FEAT-PLUGIN-SIG): the agent
/// refuses to load a plugin whose `plugin.toml.sig` does not match.
pub fn verify_blob_hmac(key: &[u8], blob: &[u8], sig_hex: &str) -> bool {
    verify_hmac(key, blob, sig_hex.trim())
}

/// Validates the embedded ML-DSA public key against the pinned fingerprint, then verifies
/// the signature over `canonical` with empty context (matching the server signer).
fn verify_mldsa(pinned_fp_hex: &str, sig_b64: &str, pub_b64: &str, canonical: &[u8]) -> bool {
    let b64 = base64::engine::general_purpose::STANDARD;
    let pub_bytes = match b64.decode(pub_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Defense-in-depth: reject an all-zero public key outright (HARD-2). A zero key
    // would fail the fingerprint check anyway, but be explicit.
    if pub_bytes.iter().all(|&b| b == 0) {
        return false;
    }
    // Trust anchor: the embedded key must match the operator-pinned fingerprint.
    let fp = Sha256::digest(&pub_bytes);
    if !hex::encode(fp).eq_ignore_ascii_case(pinned_fp_hex.trim()) {
        return false;
    }
    let pk_arr: [u8; ml_dsa_65::PK_LEN] = match pub_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk = match ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig_bytes = match b64.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Defense-in-depth: reject an all-zero signature outright (HARD-2).
    if sig_bytes.iter().all(|&b| b == 0) {
        return false;
    }
    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    pk.verify(canonical, &sig_arr, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // Cross-language interop: the server (Go/circl) signs; the agent (Rust/fips204) must
    // verify. The fixture is produced by the server's TestWriteMLDSAFixture.
    #[test]
    fn verifies_server_produced_mldsa_signature() {
        let raw = include_str!("../tests/fixtures/mldsa_command_vector.json");
        let v: Value = serde_json::from_str(raw).expect("fixture json");
        let b64 = base64::engine::general_purpose::STANDARD;
        let pub_b64 = v["public_key_b64"].as_str().unwrap();
        let sig_b64 = v["signature_b64"].as_str().unwrap();
        let msg = b64.decode(v["message_b64"].as_str().unwrap()).unwrap();

        let fp = hex::encode(Sha256::digest(b64.decode(pub_b64).unwrap()));
        assert!(
            verify_mldsa(&fp, sig_b64, pub_b64, &msg),
            "agent must verify the server's ML-DSA signature"
        );
        // Wrong message must fail.
        assert!(!verify_mldsa(&fp, sig_b64, pub_b64, b"tampered"));
        // Wrong fingerprint must fail (key not trusted).
        assert!(!verify_mldsa(&"00".repeat(32), sig_b64, pub_b64, &msg));
    }

    #[test]
    fn hmac_baseline_and_downgrade_protection() {
        let key = b"0123456789abcdef0123456789abcdef";
        let canonical = b"canonical-command-bytes";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(canonical);
        let hmac_hex = hex::encode(mac.finalize().into_bytes());

        // Legacy HMAC-only directive verifies when no fingerprint is pinned.
        assert!(verify_command(hmac_hex.as_bytes(), canonical, key, None));
        // Wrong key fails.
        assert!(!verify_command(
            hmac_hex.as_bytes(),
            canonical,
            b"wrong-key-wrong-key-wrong-key-32",
            None
        ));
        // Downgrade: fingerprint pinned but no ML-DSA envelope -> reject.
        assert!(!verify_command(
            hmac_hex.as_bytes(),
            canonical,
            key,
            Some(&"ab".repeat(32))
        ));
    }

    // janus-sig-v2 (CA-chained): a v2 envelope whose leaf cert chains to the bundled root and
    // whose command signature verifies must pass; a non-v2 directive must be rejected when the
    // v2 path is used (downgrade guard); a wrong HMAC key must fail.
    #[test]
    fn verify_command_v2_cert_chain_and_downgrade() {
        let raw = include_str!("../tests/fixtures/mldsa_cert_chain_vector.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let root_der = b64
            .decode(v["root_cert_der_b64"].as_str().unwrap())
            .unwrap();
        let leaf_cert_b64 = v["leaf_cert_der_b64"].as_str().unwrap();
        let sig_b64 = v["signature_b64"].as_str().unwrap();
        let message = b64.decode(v["message_b64"].as_str().unwrap()).unwrap();

        let key = b"0123456789abcdef0123456789abcdef";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(&message);
        let hmac_hex = hex::encode(mac.finalize().into_bytes());

        let directive = format!("{ENVELOPE_V2}\n{hmac_hex}\n{sig_b64}\n{leaf_cert_b64}");
        assert!(verify_command_v2(
            directive.as_bytes(),
            &message,
            key,
            &root_der
        ));

        // Wrong HMAC key fails even though the cert chain is valid.
        assert!(!verify_command_v2(
            directive.as_bytes(),
            &message,
            b"wrong-key-wrong-key-wrong-key-32",
            &root_der
        ));
        // Downgrade: a legacy HMAC-only directive is rejected when v2 trust is in force.
        assert!(!verify_command_v2(
            hmac_hex.as_bytes(),
            &message,
            key,
            &root_der
        ));
        // Tampered message → HMAC mismatch → reject.
        assert!(!verify_command_v2(
            directive.as_bytes(),
            b"tampered",
            key,
            &root_der
        ));
    }

    #[test]
    fn verify_blob_hmac_matches_and_rejects() {
        let key = b"plugin-signing-key-long-enough!!";
        let blob = b"name = 'x'\ncommand = 'certutil'\n";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(blob);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert!(verify_blob_hmac(key, blob, &sig));
        assert!(
            verify_blob_hmac(key, blob, &format!("  {sig}\n")),
            "trims whitespace"
        );
        assert!(!verify_blob_hmac(key, blob, &"00".repeat(32)), "wrong sig");
        assert!(!verify_blob_hmac(b"wrong-key", blob, &sig), "wrong key");
        assert!(!verify_blob_hmac(key, b"tampered", &sig), "tampered blob");
    }
}
