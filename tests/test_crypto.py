"""Tests for ed25519 cryptographic operations."""

from pokeupine.crypto import generate_keypair, sign, verify_signature


def test_generate_keypair():
    priv, pub = generate_keypair()
    assert len(priv) == 64  # 32 bytes hex
    assert len(pub) == 64


def test_sign_verify_round_trip():
    priv, pub = generate_keypair()
    data = "test merkle root hash"
    signature = sign(priv, data)
    assert verify_signature(signature, data, pub)


def test_verify_wrong_data():
    priv, pub = generate_keypair()
    data = "correct data"
    signature = sign(priv, data)
    assert not verify_signature(signature, "wrong data", pub)


def test_verify_wrong_key():
    priv1, pub1 = generate_keypair()
    _priv2, pub2 = generate_keypair()
    data = "test data"
    signature = sign(priv1, data)
    assert not verify_signature(signature, data, pub2)


def test_verify_empty_key():
    assert not verify_signature("aa" * 32, "data", "")


def test_sign_merkle_root():
    """Simulate the actual use case: signing a merkle root."""
    priv, pub = generate_keypair()
    merkle_root = "ab" * 32  # 64 hex chars
    signature = sign(priv, merkle_root)
    assert verify_signature(signature, merkle_root, pub)
    assert len(signature) == 128  # 64 bytes hex
