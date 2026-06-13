# Test data: Sample Python source with cryptographic API usage
# Used by: tests/scripts/test-agent.ps1

import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ecdsa_key():
    """JANUS-PQC-001: Classical ECDSA key generation"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

def weak_hash(data: bytes) -> str:
    """JANUS-CLASSICAL-003: MD5 usage"""
    return hashlib.md5(data).hexdigest()

def negotiate_ciphers():
    """Usage intent: NEGOTIATE (lower severity)"""
    supported = ["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"]
    return supported

def verify_certificate(cert_pem: str) -> bool:
    """Usage intent: VERIFY (lower severity)"""
    try:
        from cryptography.x509 import load_pem_x509_certificate
        cert = load_pem_x509_certificate(cert_pem.encode())
        return cert.not_valid_after_utc is not None
    except Exception:
        return False
