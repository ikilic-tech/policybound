"""Cryptographic primitives for PolicyBound.

Provides Ed25519 signing, verification, and hash chaining.

Threat model — what the cryptography guarantees:

1. INTEGRITY: Any modification to a decision record is detectable
   via SHA-256 content hashing.

2. CHAIN INTEGRITY: Inserting, deleting, or reordering records in
   the ledger is detectable via hash chaining. Each record includes
   the hash of the previous record.

3. AUTHENTICITY: Decision records are signed with Ed25519. A valid
   signature proves the record was produced by the holder of the
   private key. This prevents third parties from forging records.

4. INDEPENDENT VERIFICATION: Receipts contain all information needed
   to verify them offline — no access to the original application or
   ledger is required. Anyone with the public key can verify.

What the cryptography does NOT guarantee:

- CORRECTNESS: A signed record proves who signed it and that it hasn't
  been modified. It does NOT prove the recorded action was correct,
  appropriate, or legal.

- NON-REPUDIATION (legal): Ed25519 signatures provide cryptographic
  non-repudiation. Legal non-repudiation depends on key management
  practices, which are outside the scope of this library.

- KEY SECURITY: If the private signing key is compromised, an attacker
  can produce valid signatures. Key management is the operator's
  responsibility.

- COMPLETENESS: The system cannot prove that ALL actions were recorded.
  If the governance middleware is bypassed entirely, no record is created.

Canonical serialization uses sorted-key JSON (a simplified form of
RFC 8785 / JCS). This ensures the same logical content always produces
the same byte representation for hashing and signing.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey as Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey as Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Sentinel value for the first record in a chain
GENESIS_HASH = "0" * 64


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 signing keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(key: Ed25519PrivateKey) -> bytes:
    """Serialize a private key to PEM format."""
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def serialize_public_key(key: Ed25519PublicKey) -> bytes:
    """Serialize a public key to PEM format."""
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def load_private_key(data: bytes) -> Ed25519PrivateKey:
    """Load a private key from PEM bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        msg = "Expected Ed25519 private key"
        raise TypeError(msg)
    return key


def load_public_key(data: bytes) -> Ed25519PublicKey:
    """Load a public key from PEM bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        msg = "Expected Ed25519 public key"
        raise TypeError(msg)
    return key


def canonical_json(data: dict[str, Any]) -> bytes:
    """Produce canonical JSON bytes for hashing and signing.

    Uses sorted keys and no unnecessary whitespace, providing
    deterministic serialization. This is a simplified form of
    RFC 8785 (JSON Canonicalization Scheme).
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def compute_hash(data: bytes) -> str:
    """Compute SHA-256 hash of data, returned as hex string."""
    return hashlib.sha256(data).hexdigest()


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign data with Ed25519, returning raw signature bytes."""
    return private_key.sign(data)


def verify(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 signature.

    Returns True if valid, False if invalid.
    Does not raise on invalid signatures.
    """
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
