//! Online OCSP revocation checking for discovered TLS endpoints (FEAT-OCSP / WP-016).
//!
//! During active TLS probing the agent holds the endpoint's presented chain (leaf + issuer).
//! This module extracts the OCSP responder URL from the leaf's AIA extension and builds the
//! OCSP request. The response fetch + responder-signature verification (which `x509-ocsp` does
//! NOT do for us) + status extraction are added on top — a "good"/"revoked" status is only
//! ever reported after the responder signature is verified.
//!
//! Scope: this is descriptive posture telemetry for *scanned* endpoints (the `ocsp_status`
//! field), not a TLS trust gate. It is opt-in (active TLS probing) and time-boxed.

use anyhow::Result;
use der::{Decode, Encode};
use sha1::Sha1;
use x509_cert::ext::pkix::{name::GeneralName, AuthorityInfoAccessSyntax};
use x509_cert::Certificate;

// NOTE: these request-side helpers are the first increment of FEAT-OCSP. They are consumed by
// the live-check path (async fetch + responder-signature verification via `ring` + status
// mapping) wired into discovery/network.rs in the follow-up increment; allow(dead_code) until
// then so the gate's `clippy -D warnings` stays green without shipping a half-wired status.

/// Extract the first OCSP responder URL from a certificate's Authority Information Access
/// extension (id-ad-ocsp). Returns None if the cert has no AIA OCSP entry.
#[allow(dead_code)]
pub fn ocsp_responder_url(cert_der: &[u8]) -> Option<String> {
    let cert = Certificate::from_der(cert_der).ok()?;
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id == const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS {
            let aia = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()).ok()?;
            for ad in aia.0.iter() {
                if ad.access_method == const_oid::db::rfc5280::ID_AD_OCSP {
                    if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Build a DER-encoded OCSP request for (subject, issuer) using a SHA-1 CertId — the hash most
/// responders still require. Returns the request bytes to POST to the responder. The CertId is
/// built by x509-ocsp's `Request::from_cert` (hashes the issuer subject + key, pulls the
/// subject serial).
#[allow(dead_code)]
pub fn build_ocsp_request_der(subject_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>> {
    let subject = Certificate::from_der(subject_der)?;
    let issuer = Certificate::from_der(issuer_der)?;
    let request = x509_ocsp::Request::from_cert::<Sha1>(&issuer, &subject)
        .map_err(|e| anyhow::anyhow!("build OCSP CertId: {e:?}"))?;
    let req = x509_ocsp::builder::OcspRequestBuilder::default()
        .with_request(request)
        .build();
    Ok(req.to_der()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::Value;

    fn fixture() -> Value {
        let raw = include_str!("../tests/fixtures/ocsp_cert_vector.json");
        serde_json::from_str(raw).expect("fixture json")
    }

    #[test]
    fn extracts_ocsp_responder_url_from_aia() {
        let v = fixture();
        let b64 = base64::engine::general_purpose::STANDARD;
        let leaf = b64.decode(v["leaf_der_b64"].as_str().unwrap()).unwrap();
        let url = ocsp_responder_url(&leaf).expect("leaf has an AIA OCSP URL");
        assert_eq!(url, v["ocsp_url"].as_str().unwrap());
    }

    #[test]
    fn no_aia_yields_none() {
        // The issuer cert in the fixture has no AIA OCSP entry.
        let v = fixture();
        let b64 = base64::engine::general_purpose::STANDARD;
        let issuer = b64.decode(v["issuer_der_b64"].as_str().unwrap()).unwrap();
        assert!(ocsp_responder_url(&issuer).is_none());
        // Garbage input must not panic.
        assert!(ocsp_responder_url(&[0u8; 4]).is_none());
    }

    #[test]
    fn builds_a_wellformed_ocsp_request() {
        let v = fixture();
        let b64 = base64::engine::general_purpose::STANDARD;
        let leaf = b64.decode(v["leaf_der_b64"].as_str().unwrap()).unwrap();
        let issuer = b64.decode(v["issuer_der_b64"].as_str().unwrap()).unwrap();
        let der = build_ocsp_request_der(&leaf, &issuer).expect("build request");
        // Re-parse to confirm it is a well-formed OcspRequest carrying our CertId.
        let parsed = x509_ocsp::OcspRequest::from_der(&der).expect("request re-parses");
        let reqs = &parsed.tbs_request.request_list;
        assert_eq!(reqs.len(), 1, "exactly one request entry");
        // The CertId serial must equal the fixture leaf's serial (4242).
        let leaf_cert = Certificate::from_der(&leaf).unwrap();
        assert_eq!(
            reqs[0].req_cert.serial_number, leaf_cert.tbs_certificate.serial_number,
            "request CertId serial must match the leaf"
        );
    }
}
