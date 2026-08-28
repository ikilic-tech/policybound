"""Tests for cryptographic primitives."""

from __future__ import annotations

import pytest

from policybound.crypto import (
    GENESIS_HASH,
    canonical_json,
    compute_hash,
    generate_keypair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    sign,
    verify,
)


class TestKeypair:
    def test_generate(self):
        priv, pub = generate_keypair()
        assert priv is not None
        assert pub is not None

    def test_roundtrip_private(self):
        priv, _ = generate_keypair()
        pem = serialize_private_key(priv)
        loaded = load_private_key(pem)
        assert serialize_private_key(loaded) == pem

    def test_roundtrip_public(self):
        _, pub = generate_keypair()
        pem = serialize_public_key(pub)
        loaded = load_public_key(pem)
        assert serialize_public_key(loaded) == pem

    def test_wrong_key_type(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        key = X25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with pytest.raises(TypeError):
            load_private_key(pem)


class TestCanonicalJson:
    def test_sorted_keys(self):
        result = canonical_json({"b": 1, "a": 2})
        assert result == b'{"a":2,"b":1}'

    def test_deterministic(self):
        data = {"z": 1, "a": 2, "m": 3}
        assert canonical_json(data) == canonical_json(data)

    def test_no_whitespace(self):
        result = canonical_json({"key": "value"})
        assert b" " not in result
        assert b"\n" not in result


class TestHashing:
    def test_compute_hash(self):
        h = compute_hash(b"hello")
        assert len(h) == 64  # SHA-256 hex digest
        assert h == compute_hash(b"hello")  # deterministic

    def test_different_input(self):
        assert compute_hash(b"hello") != compute_hash(b"world")


class TestSigning:
    def test_sign_verify(self):
        priv, pub = generate_keypair()
        data = b"test data"
        sig = sign(priv, data)
        assert verify(pub, sig, data) is True

    def test_verify_wrong_data(self):
        priv, pub = generate_keypair()
        sig = sign(priv, b"correct")
        assert verify(pub, sig, b"wrong") is False

    def test_verify_wrong_key(self):
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()
        sig = sign(priv1, b"data")
        assert verify(pub2, sig, b"data") is False


class TestGenesisHash:
    def test_format(self):
        assert GENESIS_HASH == "0" * 64
        assert len(GENESIS_HASH) == 64
