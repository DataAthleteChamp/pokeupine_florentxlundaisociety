"""Ed25519 signing and verification for pack integrity."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from pokeupine.config import REGISTRY_PUBLIC_KEY_HEX


def generate_keypair() -> tuple[str, str]:
    """Generate an ed25519 keypair.

    Returns:
        (private_key_hex, public_key_hex)
    """
    private_key = Ed25519PrivateKey.generate()

    priv_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    return priv_bytes.hex(), pub_bytes.hex()


def sign(private_key_hex: str, data: str) -> str:
    """Sign data with an ed25519 private key.

    Args:
        private_key_hex: Hex-encoded 32-byte private key
        data: The string data to sign (will be UTF-8 encoded)

    Returns:
        Hex-encoded signature
    """
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    signature = private_key.sign(data.encode("utf-8"))
    return signature.hex()


def verify_signature(
    signature_hex: str,
    data: str,
    public_key_hex: str | None = None,
) -> bool:
    """Verify an ed25519 signature.

    Args:
        signature_hex: Hex-encoded signature
        data: The string data that was signed
        public_key_hex: Hex-encoded public key (defaults to hard-coded registry key)

    Returns:
        True if signature is valid
    """
    pubkey_hex = public_key_hex or REGISTRY_PUBLIC_KEY_HEX
    if not pubkey_hex:
        return False

    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        public_key.verify(bytes.fromhex(signature_hex), data.encode("utf-8"))
        return True
    except Exception:
        return False
