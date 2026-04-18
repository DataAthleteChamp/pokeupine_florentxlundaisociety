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
REGISTRY_PUBLIC_KEY_HEX = "fb1b999d78d89f1f959467862db62c68dcfd9df22f98d8521f4192e197f480c7"


def ensure_dirs() -> None:
    """Create storage directories if they don't exist."""
    PACKS_DIR.mkdir(parents=True, exist_ok=True)
    LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
