"""Paths and constants for Pokeupine."""

from __future__ import annotations

from pathlib import Path

# User-level storage
POKEUPINE_HOME = Path.home() / ".pokeupine"
PACKS_DIR = POKEUPINE_HOME / "packs"
CACHE_DIR = POKEUPINE_HOME / "cache"
LLM_CACHE_DIR = CACHE_DIR / "llm"

# Registry
REGISTRY_BASE_URL = (
    "https://raw.githubusercontent.com/DataAthleteChamp/pokeupine-registry/main"
)

# Hard-coded registry public key (ed25519, hex-encoded)
# Generated once; the private key is used only during ingestion/signing
REGISTRY_PUBLIC_KEY_HEX = "16ff47bb16c8a7d8e6532fa5e81192fff72fd55d4604c50072cbde8ee0c35894"


def ensure_dirs() -> None:
    """Create storage directories if they don't exist."""
    PACKS_DIR.mkdir(parents=True, exist_ok=True)
    LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
