"""Registry client — pull and verify regulation packs."""

from __future__ import annotations

import json
from pathlib import Path

import requests
from rich.console import Console

from pokeupine.config import PACKS_DIR, REGISTRY_BASE_URL, ensure_dirs
from pokeupine.crypto import verify_signature
from pokeupine.schemas import Pack

console = Console()


def pull_pack(pack_id: str, version: str | None = None) -> Pack:
    """Fetch a regulation pack from the registry and verify its signature.

    Args:
        pack_id: Pack identifier (e.g. "pci-dss")
        version: Specific version (default: latest)

    Returns:
        The verified Pack object
    """
    ensure_dirs()

    # Fetch index
    console.print(f"  Fetching registry index from [dim]{REGISTRY_BASE_URL}[/dim]...")
    index_url = f"{REGISTRY_BASE_URL}/index.json"
    resp = requests.get(index_url, timeout=30)
    resp.raise_for_status()
    index = resp.json()

    # Find the requested pack
    pack_entry = None
    for p in index["packs"]:
        if p["id"] == pack_id:
            pack_entry = p
            break

    if pack_entry is None:
        console.print(f"[red]Error:[/red] Pack '{pack_id}' not found in registry")
        raise SystemExit(1)

    target_version = version or pack_entry["latest"]
    console.print(f"  Pulling [bold]{pack_id}@{target_version}[/bold]...")

    # Fetch pack.json
    pack_url = f"{REGISTRY_BASE_URL}/{pack_entry['url']}"
    resp = requests.get(pack_url, timeout=60)
    resp.raise_for_status()
    pack_data = resp.json()

    pack = Pack(**pack_data)

    # Verify signature
    console.print("  Verifying ed25519 signature...", end=" ")
    sig_valid = verify_signature(
        pack.manifest.merkle_root_signature,
        pack.manifest.merkle_root,
    )

    if sig_valid:
        console.print("[green]✓ verified[/green]")
    else:
        console.print("[red]✗ FAILED[/red]")
        console.print(
            "[red]Error:[/red] Pack signature verification failed. "
            "The pack may have been tampered with."
        )
        raise SystemExit(1)

    # Cache locally
    cache_dir = PACKS_DIR / pack_id / target_version
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / "pack.json"
    cache_path.write_text(json.dumps(pack_data, indent=2))

    console.print(
        f"  [green]✓[/green] Pack cached to {cache_path}\n"
        f"  {pack.manifest.controls_count} controls, "
        f"{pack.manifest.tests_count} tests\n"
    )

    return pack
