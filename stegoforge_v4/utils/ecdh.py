"""
ecdh.py — Elliptic Curve Diffie-Hellman (NIST P-256)
Same curve used by Signal, WhatsApp, TLS 1.3

Flow:
  1. Alice  → generate_keypair() → share public_pem openly
  2. Bob    → generate_keypair() → share public_pem openly
  3. Alice  → derive_shared_secret(alice_private, bob_public)   → 32-byte secret
  4. Bob    → derive_shared_secret(bob_private,   alice_public) → same 32-byte secret
  5. Both use that secret as AES-256 password — nothing secret was ever sent
"""

import hashlib, base64
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, generate_private_key, ECDH
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat,
    NoEncryption, load_pem_private_key, load_pem_public_key
)
from cryptography.hazmat.backends import default_backend


def generate_keypair() -> dict:
    private_key = generate_private_key(SECP256R1(), default_backend())
    public_key  = private_key.public_key()

    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()

    pub_raw     = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(pub_raw).hexdigest()[:16].upper()

    return {
        'private_pem' : private_pem,
        'public_pem'  : public_pem,
        'fingerprint' : fingerprint,
    }


def derive_shared_secret(my_private_pem: str, their_public_pem: str) -> bytes:
    private_key      = load_pem_private_key(my_private_pem.encode(), password=None, backend=default_backend())
    their_public_key = load_pem_public_key(their_public_pem.encode(), backend=default_backend())
    raw_secret       = private_key.exchange(ECDH(), their_public_key)
    return hashlib.sha256(raw_secret).digest()   # 32 uniform bytes


def secret_to_password(secret_bytes: bytes) -> str:
    return secret_bytes.hex()   # 64-char hex string → used as AES password


def get_fingerprint(public_pem: str) -> str:
    pub = load_pem_public_key(public_pem.encode(), backend=default_backend())
    raw = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(raw).hexdigest()[:16].upper()
