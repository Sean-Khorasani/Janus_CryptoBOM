// Test data: Sample Rust source with cryptographic API usage
// Used by: tests/scripts/test-agent.ps1, tests/scripts/test-policy.ps1

use openssl::rsa::Rsa;
use openssl::sha;
use ring::rand;
use std::fs;

fn generate_rsa_key() -> Rsa<openssl::pkey::Private> {
    // JANUS-PQC-001: Classical public-key cryptography — RSA
    let rsa = Rsa::generate(2048).unwrap();
    rsa
}

fn hash_password(password: &str) -> Vec<u8> {
    // JANUS-CLASSICAL-003: Deprecated hash — SHA-1
    let mut hasher = sha::Sha1::new();
    hasher.update(password.as_bytes());
    hasher.finish().to_vec()
}

fn encrypt_data(key: &[u8], data: &[u8]) -> Vec<u8> {
    // JANUS-PQC-004: AES-128 for long-term data
    use openssl::symm::{Cipher, Crypter, Mode};
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    let mut out = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut out).unwrap();
    out.truncate(count);
    out
}

fn verify_signature(pubkey: &[u8], sig: &[u8], data: &[u8]) -> bool {
    // Usage intent: VERIFY (lower severity)
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_crypto() {
        // test-only code — should be flagged as test-only, lower confidence
        let _ = super::generate_rsa_key();
    }
}
