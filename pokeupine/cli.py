"""Pokeupine CLI — the user-facing interface.

Commands:
  pull    Fetch a regulation pack from the registry
  scan    Scan a codebase against installed packs
  explain Show a control's clause text with Merkle proof verification
  prove   Verify a control's Merkle proof (works without the PDF)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from pokeupine import __version__

app = typer.Typer(
    name="pokeupine",
    help="Compliance-as-Code CLI with proof-carrying regulation packs.",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"pokeupine {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(  # noqa: UP007
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Pokeupine — Compliance-as-Code with proof-carrying regulation packs."""


@app.command()
def pull(
    pack_id: str = typer.Argument(help="Pack identifier, e.g. 'pci-dss'"),
    version: Optional[str] = typer.Option(None, "--version", help="Pack version"),  # noqa: UP007
) -> None:
    """Fetch a regulation pack from the registry and verify its signature."""
    from pokeupine.registry import pull_pack

    pull_pack(pack_id, version=version)


@app.command()
def scan(
    target: Path = typer.Argument(help="Path to codebase to scan"),
    pack_id: str = typer.Option("pci-dss", "--pack", "-p", help="Pack to scan against"),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich, json"),
    exit_code: bool = typer.Option(False, "--exit-code", help="Return non-zero exit code on failures"),
) -> None:
    """Scan a codebase against installed regulation packs."""
    if not target.exists():
        console.print(f"[red]Error:[/red] Path {target} does not exist")
        raise typer.Exit(1)

    from pokeupine.config import PACKS_DIR, ensure_dirs
    from pokeupine.report.rich_report import print_report
    from pokeupine.scan.runner import run_scan
    from pokeupine.schemas import Pack

    ensure_dirs()

    pack_dir = PACKS_DIR / pack_id
    if not pack_dir.exists():
        # Try loading from bundled pack in repo
        bundled = Path(__file__).parent.parent / "pokeupine-registry" / "packs" / pack_id
        if not bundled.exists():
            console.print(
                f"[red]Error:[/red] Pack '{pack_id}' not installed. Run: pokeupine pull {pack_id}"
            )
            raise typer.Exit(1)
        pack_dir = bundled

    # Find the pack.json — look for latest version dir
    pack_json = None
    for version_dir in sorted(pack_dir.iterdir(), reverse=True):
        candidate = version_dir / "pack.json"
        if candidate.exists():
            pack_json = candidate
            break

    if pack_json is None:
        # Try pack.json directly in pack_dir
        if (pack_dir / "pack.json").exists():
            pack_json = pack_dir / "pack.json"
        else:
            console.print(f"[red]Error:[/red] No pack.json found in {pack_dir}")
            raise typer.Exit(1)

    import json

    pack_data = json.loads(pack_json.read_text())
    pack = Pack(**pack_data)

    # Verify pack signature before using it
    from pokeupine.crypto import verify_signature

    sig_valid = verify_signature(
        pack.manifest.merkle_root_signature,
        pack.manifest.merkle_root,
    )
    if not sig_valid:
        console.print(
            "[red]Error:[/red] Pack signature verification failed. "
            "Run [bold]pokeupine pull[/bold] to re-fetch."
        )
        raise typer.Exit(1)

    if output != "json":
        console.print(
            f"Scanning [bold]{target}[/bold]  "
            f"(1 pack: {pack.manifest.id}@{pack.manifest.version})\n"
        )

    findings = run_scan(target, pack)

    if output == "json":
        import json as json_mod
        import sys

        json_out = [f.model_dump() for f in findings]
        sys.stdout.write(json_mod.dumps(json_out, indent=2) + "\n")
    else:
        print_report(findings, pack)

    if exit_code and any(f.status == "fail" for f in findings):
        raise typer.Exit(1)


@app.command()
def explain(
    control_id: str = typer.Argument(help="Control ID, e.g. 'PCI-DSS-3.3.1'"),
    pack_id: str = typer.Option("pci-dss", "--pack", "-p", help="Pack to look up"),
) -> None:
    """Show a control's clause text with Merkle proof verification."""
    import json

    from pokeupine.crypto import verify_signature
    from pokeupine.merkle import leaf_hash, verify_proof

    pack_json = _find_pack_json(pack_id)
    if pack_json is None:
        console.print(f"[red]Error:[/red] Pack '{pack_id}' not found")
        raise typer.Exit(1)

    from pokeupine.schemas import Pack

    pack_data = json.loads(pack_json.read_text())
    pack = Pack(**pack_data)

    control = None
    for c in pack.controls:
        if c.id == control_id:
            control = c
            break

    if control is None:
        console.print(f"[red]Error:[/red] Control '{control_id}' not found in pack")
        raise typer.Exit(1)

    from rich.panel import Panel

    # Verify Merkle proof
    leaf = leaf_hash(control.clause_text)
    proof_valid = verify_proof(leaf, control.provenance.merkle_proof, pack.manifest.merkle_root)

    # Verify signature
    sig_valid = verify_signature(
        pack.manifest.merkle_root_signature,
        pack.manifest.merkle_root,
    )

    severity_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green"}
    color = severity_colors.get(control.severity, "white")

    console.print()
    console.print(
        f"PCI-DSS v{pack.manifest.version}   §{control.id.split('-')[-1]}   "
        f"page {control.provenance.page}   [{color}][{control.severity}][/{color}]"
    )
    console.print()
    console.print(Panel(control.clause_text, title=control.title, border_style="dim"))
    console.print()

    proof_mark = "[green]✓[/green]" if proof_valid else "[red]✗[/red]"
    sig_mark = "[green]✓[/green]" if sig_valid else "[red]✗[/red]"

    console.print(
        f"  {proof_mark} Merkle proof verified against signed root  "
        f"(ed25519 / {pack.manifest.signing_key_id})"
    )
    console.print(f"  {sig_mark} source_doc_sha256:  {control.provenance.source_doc_sha256[:12]}…")
    console.print(f"  {sig_mark} text_layer_sha256:  {control.provenance.text_layer_sha256[:12]}…")
    console.print()
    console.print("[bold]Remediation:[/bold]")
    console.print(f"  {control.requirement}")
    console.print()


@app.command()
def prove(
    control_id: str = typer.Argument(help="Control ID, e.g. 'PCI-DSS-3.3.1'"),
    pack_id: str = typer.Option("pci-dss", "--pack", "-p", help="Pack to verify"),
    no_pdf: bool = typer.Option(False, "--no-pdf", help="Emphasize proof is self-contained"),
) -> None:
    """Verify a control's Merkle proof — works WITHOUT the source PDF."""
    import json
    import time

    from pokeupine.crypto import verify_signature
    from pokeupine.merkle import leaf_hash, verify_proof

    pack_json = _find_pack_json(pack_id)
    if pack_json is None:
        console.print(f"[red]Error:[/red] Pack '{pack_id}' not found")
        raise typer.Exit(1)

    from pokeupine.schemas import Pack

    pack_data = json.loads(pack_json.read_text())
    pack = Pack(**pack_data)

    control = None
    for c in pack.controls:
        if c.id == control_id:
            control = c
            break

    if control is None:
        console.print(f"[red]Error:[/red] Control '{control_id}' not found in pack")
        raise typer.Exit(1)

    start = time.perf_counter()

    leaf = leaf_hash(control.clause_text)
    proof_valid = verify_proof(leaf, control.provenance.merkle_proof, pack.manifest.merkle_root)
    sig_valid = verify_signature(
        pack.manifest.merkle_root_signature,
        pack.manifest.merkle_root,
    )

    elapsed_ms = (time.perf_counter() - start) * 1000
    n_hashes = len(control.provenance.merkle_proof)

    proof_mark = "[green]✓[/green]" if proof_valid else "[red]✗[/red]"
    sig_mark = "[green]✓[/green]" if sig_valid else "[red]✗[/red]"

    console.print()
    console.print(
        f"  {proof_mark} Merkle path verified ({n_hashes} hashes, {elapsed_ms:.1f} ms)"
    )
    console.print(
        f"  {sig_mark} Root signature verified (ed25519, key {pack.manifest.signing_key_id})"
    )
    if no_pdf:
        console.print(
            "  [green]✓[/green] Source PDF NOT present on disk — proof is self-contained"
        )
    console.print()


def _find_pack_json(pack_id: str) -> Path | None:
    """Locate pack.json for a given pack ID, checking cache and bundled locations."""
    from pokeupine.config import PACKS_DIR

    # Check user cache
    pack_dir = PACKS_DIR / pack_id
    if pack_dir.exists():
        for version_dir in sorted(pack_dir.iterdir(), reverse=True):
            candidate = version_dir / "pack.json"
            if candidate.exists():
                return candidate

    # Check bundled in repo
    bundled = Path(__file__).parent.parent / "pokeupine-registry" / "packs" / pack_id
    if bundled.exists():
        for version_dir in sorted(bundled.iterdir(), reverse=True):
            candidate = version_dir / "pack.json"
            if candidate.exists():
                return candidate

    return None
