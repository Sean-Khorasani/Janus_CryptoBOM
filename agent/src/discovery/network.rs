use crate::{
    config::AgentConfig,
    proto::{Evidence, NetworkObservation, CbomComponent, CryptoAlgorithm, CryptoRole},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{net::TcpStream, time::timeout};
use uuid::Uuid;
use std::sync::Arc;
use rustls::{ClientConfig, ClientConnection};
use rustls::pki_types::ServerName;

#[derive(Default)]
pub struct NetworkScanResult {
    pub observations: Vec<NetworkObservation>,
    pub components: Vec<CbomComponent>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

pub async fn scan(cfg: &AgentConfig) -> Result<NetworkScanResult> {
    let mut out = NetworkScanResult::default();
    
    // Ensure the default crypto provider is installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    // Enable TLS 1.3 and 1.2
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let config_arc = Arc::new(config);

    for target in &cfg.network_targets {
        if target.ends_with(":80") {
            out.observations.push(NetworkObservation {
                endpoint: target.clone(),
                protocol: "http".to_string(),
                tls_version: String::new(),
                cipher_suite: String::new(),
                named_group: String::new(),
                signature_algorithm: String::new(),
                certificate_subject: String::new(),
                certificate_issuer: String::new(),
                certificate_not_after_unix: 0,
                pqc_hybrid: false,
                cleartext: true,
            });
            out.evidence.push(evidence(target, "cleartext-port-observed", target.as_bytes(), 0.8));
            continue;
        }

        match native_probe(target, config_arc.clone()).await {
            Ok((obs, raw, peer_certs)) => {
                out.observations.push(obs);
                out.evidence.push(evidence(target, "rustls-handshake", &raw, 0.90));

                // Intermediate CA Auditing
                // Check all certificates in the chain beyond the end-entity (i.e. index >= 1)
                for (idx, cert) in peer_certs.iter().enumerate() {
                    let cert_bytes = cert.as_ref();
                    let (subj, iss, _not_after, sig) = parse_x509_der(cert_bytes);
                    let (pubkey_alg, key_bits) = parse_x509_pubkey(cert_bytes).unwrap_or(("unknown".to_string(), 0));

                    let is_intermediate = idx > 0;
                    let mut is_weak_intermediate = false;
                    let mut weak_reason = String::new();

                    if is_intermediate {
                        // Check if signature algorithm is MD5 or SHA-1
                        let sig_upper = sig.to_uppercase();
                        if sig_upper.contains("SHA1") || sig_upper.contains("SHA-1") || sig_upper.contains("MD5") {
                            is_weak_intermediate = true;
                            weak_reason = format!("Weak Intermediate CA Signature: {}", sig);
                        }
                        // Check if RSA key size is below 2048 bits
                        if pubkey_alg == "RSA" && key_bits > 0 && key_bits < 2048 {
                            is_weak_intermediate = true;
                            weak_reason = format!("Weak Intermediate CA RSA key length: {} bits", key_bits);
                        }
                    }

                    // Add intermediate CAs to components so they can be audited by policy engine
                    if is_intermediate {
                        let mut algorithms = vec![
                            CryptoAlgorithm {
                                name: sig.clone(),
                                family: if sig.to_uppercase().contains("ECDSA") { "ECC".to_string() } else if sig.to_uppercase().contains("RSA") { "RSA".to_string() } else { "hash".to_string() },
                                role: CryptoRole::CertSignature as i32,
                                status: if is_weak_intermediate { "weak-intermediate-ca-observed".to_string() } else { "intermediate-ca-observed".to_string() },
                                key_bits: 0,
                                curve: String::new(),
                                implementation_library: "Network TLS Chain".to_string(),
                                source_file: target.clone(),
                                source_line: 0,
                                source_column: 0,
                                symbol: weak_reason.clone(),
                                confidence: 0.90,
                                quantum_vulnerable: sig.to_uppercase().contains("RSA") || sig.to_uppercase().contains("ECDSA"),
                            }
                        ];

                        if key_bits > 0 {
                            algorithms.push(CryptoAlgorithm {
                                name: format!("{}-{}", pubkey_alg, key_bits),
                                family: pubkey_alg.clone(),
                                role: CryptoRole::CertPublicKey as i32,
                                status: if is_weak_intermediate { "weak-intermediate-ca-observed".to_string() } else { "intermediate-ca-observed".to_string() },
                                key_bits,
                                curve: String::new(),
                                implementation_library: "Network TLS Chain".to_string(),
                                source_file: target.clone(),
                                source_line: 0,
                                source_column: 0,
                                symbol: pubkey_alg.clone(),
                                confidence: 0.90,
                                quantum_vulnerable: pubkey_alg == "RSA" || pubkey_alg.contains("ECDSA"),
                            });
                        }

                        out.components.push(CbomComponent {
                            bom_ref: format!("certificate:intermediate-ca:{}", sha256_hex(cert_bytes)),
                            name: subj.clone(),
                            version: String::new(),
                            component_type: "certificate".to_string(),
                            purl: String::new(),
                            file_path: "network-tls-chain".to_string(),
                            language: "tls".to_string(),
                            algorithms,
                            dependencies: if iss.is_empty() { Vec::new() } else { vec![iss] },
                            reachable: true,
                        });
                    }
                }
            }
            Err(err) => {
                let raw = format!("probe-error:{err}");
                out.evidence.push(evidence(target, "rustls-handshake-error", raw.as_bytes(), 0.3));
            }
        }
    }
    Ok(out)
}

async fn negotiate_starttls(stream: &mut TcpStream, port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 4096];
    match port {
        25 | 587 => {
            // Read SMTP Banner
            let _ = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
            // Send EHLO
            stream.write_all(b"EHLO janus-agent\r\n").await?;
            // Read EHLO response
            loop {
                let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
                if n == 0 {
                    break;
                }
                let s = String::from_utf8_lossy(&buf[..n]);
                if s.contains("250 ") || s.contains("250\r\n") {
                    break;
                }
            }
            // Send STARTTLS
            stream.write_all(b"STARTTLS\r\n").await?;
            let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
            let resp = String::from_utf8_lossy(&buf[..n]);
            if !resp.starts_with("220") {
                return Err(anyhow::anyhow!("SMTP STARTTLS negotiation failed: {}", resp));
            }
        }
        389 => {
            // LDAP STARTTLS
            let ldap_start_tls = &[
                0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16, 0x31, 0x2e, 0x33, 0x2e, 0x36,
                0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36, 0x36, 0x2e, 0x32, 0x30,
                0x30, 0x33, 0x37,
            ];
            stream.write_all(ldap_start_tls).await?;
            let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
            if n < 7 || buf[0] != 0x30 {
                return Err(anyhow::anyhow!("LDAP STARTTLS negotiation failed"));
            }
        }
        5432 => {
            // PostgreSQL SSLRequest
            let ssl_req = &[0, 0, 0, 8, 4, 210, 45, 47];
            stream.write_all(ssl_req).await?;
            let mut resp = [0u8; 1];
            timeout(Duration::from_secs(2), stream.read_exact(&mut resp)).await??;
            if resp[0] != b'S' {
                return Err(anyhow::anyhow!("PostgreSQL SSL not supported"));
            }
        }
        3306 => {
            // MySQL Handshake & SSLRequest
            // Read handshake packet
            let _ = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
            // Send SSLRequest
            let ssl_req = &[
                0x20, 0x00, 0x00, 0x01,
                0x00, 0x8a, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
                0x21,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            stream.write_all(ssl_req).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn native_probe(target: &str, config: Arc<ClientConfig>) -> Result<(NetworkObservation, Vec<u8>, Vec<rustls::pki_types::CertificateDer<'static>>)> {
    let host = target.split(':').next().unwrap_or(target);
    let port = target.split(':').nth(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);
    
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(target))
        .await
        .map_err(|e| anyhow::anyhow!("Connection timeout: {}", e))??;

    negotiate_starttls(&mut stream, port).await?;
        
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name: {}", host))?;
        
    let mut conn = ClientConnection::new(config, server_name)?;
    
    let mut raw_bytes = Vec::new();
    let mut buf = [0u8; 4096];
    
    // Perform TLS handshake
    while conn.is_handshaking() {
        if conn.wants_write() {
            let mut wr = Vec::new();
            conn.write_tls(&mut wr)?;
            use tokio::io::AsyncWriteExt;
            stream.write_all(&wr).await?;
        }
        if conn.wants_read() {
            use tokio::io::AsyncReadExt;
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(anyhow::anyhow!("EOF during handshake"));
            }
            raw_bytes.extend_from_slice(&buf[..n]);
            conn.read_tls(&mut std::io::Cursor::new(&buf[..n]))?;
            conn.process_new_packets()?;
        }
    }

    // Complete the transaction with the peer to extract parameters
    let protocol = conn.protocol_version()
        .map(|v| format!("{:?}", v))
        .unwrap_or_else(|| "unknown".to_string());
        
    let cipher_suite = conn.negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_default();

    let mut cert_subject = String::new();
    let mut cert_issuer = String::new();
    let mut cert_not_after = 0;
    let mut sig_alg = String::new();

    let mut peer_certs = Vec::new();
    if let Some(certs) = conn.peer_certificates() {
        for cert in certs {
            peer_certs.push(rustls::pki_types::CertificateDer::from(cert.as_ref().to_vec()));
        }
    }

    if let Some(first_cert) = peer_certs.first() {
        let (subj, iss, not_after, sig) = parse_x509_der(first_cert.as_ref());
        cert_subject = subj;
        cert_issuer = iss;
        cert_not_after = not_after;
        sig_alg = sig;
    }

    // Extract named group from raw ServerHello bytes
    let mut pqc_hybrid = false;
    let mut named_group = String::new();
    if let Some(group_id) = extract_named_group(&raw_bytes) {
        let (name, hybrid) = match group_id {
            4588 => ("X25519MLKEM768".to_string(), true),
            4605 => ("SecP256r1MLKEM768".to_string(), true),
            4590 => ("X448MLKEM1024".to_string(), true),
            29 => ("X25519".to_string(), false),
            23 => ("secp256r1".to_string(), false),
            24 => ("secp384r1".to_string(), false),
            g => (format!("Unknown group (0x{:04x})", g), false),
        };
        named_group = name;
        pqc_hybrid = hybrid;
    }

    let obs = NetworkObservation {
        endpoint: target.to_string(),
        protocol: "tls".to_string(),
        tls_version: protocol,
        cipher_suite,
        named_group,
        signature_algorithm: sig_alg,
        certificate_subject: cert_subject,
        certificate_issuer: cert_issuer,
        certificate_not_after_unix: cert_not_after,
        pqc_hybrid,
        cleartext: false,
    };

    Ok((obs, raw_bytes, peer_certs))
}

pub(crate) fn extract_named_group(bytes: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i + 5 < bytes.len() {
        if bytes[i] == 0x16 && bytes[i+1] == 0x03 {
            let record_len = ((bytes[i+3] as usize) << 8) | (bytes[i+4] as usize);
            let record_end = i + 5 + record_len;
            if record_end > bytes.len() {
                break;
            }
            
            let mut hs_idx = i + 5;
            while hs_idx + 4 < record_end {
                let hs_type = bytes[hs_idx];
                let hs_len = ((bytes[hs_idx+1] as usize) << 16) | ((bytes[hs_idx+2] as usize) << 8) | (bytes[hs_idx+3] as usize);
                if hs_type == 0x02 { // ServerHello
                    let sh_end = hs_idx + 4 + hs_len;
                    if sh_end > record_end {
                        break;
                    }
                    
                    let mut sh_idx = hs_idx + 4 + 2 + 32; // Skip version & random
                    if sh_idx < sh_end {
                        let sess_len = bytes[sh_idx] as usize;
                        sh_idx += 1 + sess_len;
                    }
                    sh_idx += 2; // Skip cipher suite
                    sh_idx += 1; // Skip compression
                    
                    if sh_idx + 2 <= sh_end {
                        let ext_len = ((bytes[sh_idx] as usize) << 8) | (bytes[sh_idx+1] as usize);
                        sh_idx += 2;
                        let ext_end = sh_idx + ext_len;
                        if ext_end <= sh_end {
                            while sh_idx + 4 <= ext_end {
                                let ext_type = ((bytes[sh_idx] as usize) << 8) | (bytes[sh_idx+1] as usize);
                                let ext_val_len = ((bytes[sh_idx+2] as usize) << 8) | (bytes[sh_idx+3] as usize);
                                sh_idx += 4;
                                if ext_type == 51 { // key_share
                                    if ext_val_len >= 2 && sh_idx + 2 <= ext_end {
                                        let group = ((bytes[sh_idx] as u16) << 8) | (bytes[sh_idx+1] as u16);
                                        return Some(group);
                                    }
                                }
                                sh_idx += ext_val_len;
                            }
                        }
                    }
                }
                hs_idx += 4 + hs_len;
            }
            i = record_end;
        } else {
            i += 1;
        }
    }
    None
}

struct Element<'a> {
    tag: u8,
    value: &'a [u8],
}

fn read_tlv(mut data: &[u8]) -> Vec<Element<'_>> {
    let mut elements = Vec::new();
    while !data.is_empty() {
        let tag = data[0];
        if data.len() < 2 {
            break;
        }
        let len_byte = data[1];
        let (len, header_len) = if len_byte & 0x80 == 0 {
            (len_byte as usize, 2)
        } else {
            let num_bytes = (len_byte & 0x7f) as usize;
            if data.len() < 2 + num_bytes {
                break;
            }
            let mut l = 0;
            for b in &data[2..2 + num_bytes] {
                l = (l << 8) | (*b as usize);
            }
            (l, 2 + num_bytes)
        };
        if data.len() < header_len + len {
            break;
        }
        let value = &data[header_len..header_len + len];
        elements.push(Element { tag, value });
        data = &data[header_len + len..];
    }
    elements
}

pub(crate) fn parse_x509_der(der: &[u8]) -> (String, String, i64, String) {
    let mut subject = String::new();
    let mut issuer = String::new();
    let mut not_after = 0;
    let mut sig_alg = String::new();

    let top = read_tlv(der);
    if let Some(cert_seq) = top.first().filter(|e| e.tag == 0x30) {
        let tbs_seq = read_tlv(cert_seq.value);
        if let Some(tbs) = tbs_seq.first().filter(|e| e.tag == 0x30) {
            let tbs_elements = read_tlv(tbs.value);
            let mut idx = 0;
            if idx < tbs_elements.len() && tbs_elements[idx].tag == 0xa0 {
                idx += 1;
            }
            if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x02 {
                idx += 1;
            }
            if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
                let sig_elements = read_tlv(tbs_elements[idx].value);
                if let Some(oid_el) = sig_elements.first().filter(|e| e.tag == 0x06) {
                    sig_alg = parse_sig_alg_oid(oid_el.value);
                }
                idx += 1;
            }
            if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
                issuer = parse_name_sequence(tbs_elements[idx].value);
                idx += 1;
            }
            if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
                let validity_elements = read_tlv(tbs_elements[idx].value);
                if validity_elements.len() >= 2 {
                    let not_after_el = &validity_elements[1];
                    not_after = parse_time(not_after_el.tag, not_after_el.value);
                }
                idx += 1;
            }
            if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
                subject = parse_name_sequence(tbs_elements[idx].value);
            }
        }
    }

    fn parse_name_sequence(data: &[u8]) -> String {
        let mut parts = Vec::new();
        let sets = read_tlv(data);
        for set in sets.iter().filter(|e| e.tag == 0x31) {
            let seqs = read_tlv(set.value);
            for seq in seqs.iter().filter(|e| e.tag == 0x30) {
                let oid_val = read_tlv(seq.value);
                if oid_val.len() >= 2 && oid_val[0].tag == 0x06 {
                    let oid = oid_val[0].value;
                    let val = oid_val[1].value;
                    let val_str = String::from_utf8_lossy(val).to_string();
                    let prefix = if oid == [0x55, 0x04, 0x03] {
                        "CN"
                    } else if oid == [0x55, 0x04, 0x0a] {
                        "O"
                    } else if oid == [0x55, 0x04, 0x06] {
                        "C"
                    } else if oid == [0x55, 0x04, 0x0b] {
                        "OU"
                    } else {
                        continue;
                    };
                    parts.push(format!("{}={}", prefix, val_str));
                }
            }
        }
        parts.join(", ")
    }

    fn parse_time(tag: u8, val: &[u8]) -> i64 {
        let s = String::from_utf8_lossy(val);
        let format = if tag == 0x17 {
            let year_prefix = if s.len() >= 2 {
                let yy: i32 = s[0..2].parse().unwrap_or(0);
                if yy < 50 { "20" } else { "19" }
            } else { "" };
            format!("{}{}", year_prefix, s)
        } else {
            s.to_string()
        };
        if format.len() >= 14 {
            let year: i32 = format[0..4].parse().unwrap_or(0);
            let month: i32 = format[4..6].parse().unwrap_or(1);
            let day: i32 = format[6..8].parse().unwrap_or(1);
            let hour: i32 = format[8..10].parse().unwrap_or(0);
            let min: i32 = format[10..12].parse().unwrap_or(0);
            let sec: i32 = format[12..14].parse().unwrap_or(0);
            
            let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut days = 0;
            for y in 1970..year {
                days += if is_leap_year(y) { 366 } else { 365 };
            }
            for m in 1..month as usize {
                days += days_in_month[m];
                if m == 2 && is_leap_year(year) {
                    days += 1;
                }
            }
            days += day - 1;
            return (days as i64 * 86400) + (hour as i64 * 3600) + (min as i64 * 60) + sec as i64;
        }
        0
    }

    fn is_leap_year(year: i32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }
    fn parse_sig_alg_oid(oid: &[u8]) -> String {
        if oid == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] {
            "SHA256-RSA".to_string()
        } else if oid == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] {
            "SHA384-RSA".to_string()
        } else if oid == [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] {
            "ECDSA-SHA256".to_string()
        } else if oid == [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] {
            "ECDSA-SHA384".to_string()
        } else if oid == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05] {
            "SHA1-RSA".to_string()
        } else if oid == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04] {
            "MD5-RSA".to_string()
        } else {
            "unknown".to_string()
        }
    }

    (subject, issuer, not_after, sig_alg)
}

fn parse_x509_pubkey(der: &[u8]) -> Option<(String, u32)> {
    let top = read_tlv(der);
    let cert_seq = top.first().filter(|e| e.tag == 0x30)?;
    let tbs_seq = read_tlv(cert_seq.value);
    let tbs = tbs_seq.first().filter(|e| e.tag == 0x30)?;
    let tbs_elements = read_tlv(tbs.value);
    
    let mut idx = 0;
    if idx < tbs_elements.len() && tbs_elements[idx].tag == 0xa0 {
        idx += 1;
    }
    if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x02 {
        idx += 1;
    }
    if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
        idx += 1; // signature algorithm
    }
    if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
        idx += 1; // issuer
    }
    if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
        idx += 1; // validity
    }
    if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
        idx += 1; // subject
    }
    if idx < tbs_elements.len() && tbs_elements[idx].tag == 0x30 {
        // subjectPublicKeyInfo
        let spki_elements = read_tlv(tbs_elements[idx].value);
        if spki_elements.len() >= 2 {
            let alg_seq = &spki_elements[0];
            let pubkey_bitstring = &spki_elements[1];
            
            // Extract OID from alg_seq
            let alg_elements = read_tlv(alg_seq.value);
            let oid = alg_elements.first().filter(|e| e.tag == 0x06)?.value;
            
            if oid == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] {
                // RSA Public Key
                if pubkey_bitstring.value.len() > 1 {
                    let rsa_der = &pubkey_bitstring.value[1..];
                    let rsa_seq = read_tlv(rsa_der);
                    if let Some(seq) = rsa_seq.first().filter(|e| e.tag == 0x30) {
                        let rsa_elements = read_tlv(seq.value);
                        if let Some(modulus) = rsa_elements.first().filter(|e| e.tag == 0x02) {
                            let mut val = modulus.value;
                            if !val.is_empty() && val[0] == 0 {
                                val = &val[1..];
                            }
                            let bits = val.len() as u32 * 8;
                            return Some(("RSA".to_string(), bits));
                        }
                    }
                }
            } else if oid == [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] {
                // EC Public Key
                let mut curve = "unknown-curve".to_string();
                if alg_elements.len() >= 2 && alg_elements[1].tag == 0x06 {
                    let curve_oid = alg_elements[1].value;
                    if curve_oid == [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] {
                        curve = "secp256r1".to_string();
                    } else if curve_oid == [0x2b, 0x81, 0x04, 0x00, 0x0a] {
                        curve = "secp256k1".to_string();
                    } else if curve_oid == [0x2b, 0x81, 0x04, 0x00, 0x22] {
                        curve = "secp384r1".to_string();
                    } else if curve_oid == [0x2b, 0x81, 0x04, 0x00, 0x23] {
                        curve = "secp521r1".to_string();
                    }
                }
                return Some((format!("ECDSA ({curve})"), 256));
            }
        }
    }
    None
}

fn evidence(target: &str, tool: &str, raw: &[u8], confidence: f64) -> Evidence {
    let mut h = Sha256::new();
    h.update(raw);
    Evidence {
        evidence_id: Uuid::new_v4().to_string(),
        source_type: "network".to_string(),
        source_tool: tool.to_string(),
        target: target.to_string(),
        collection_time_unix: now(),
        raw_artifact_sha256: hex::encode(h.finalize()),
        confidence,
        sensitivity_class: "handshake-metadata".to_string(),
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
