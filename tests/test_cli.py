"""End-to-end CLI smoke tests via typer's CliRunner."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pokeupine.cli import app


REPO_ROOT = Path(__file__).parent.parent
DEMO_APP = REPO_ROOT / "vulnerable-checkout"


def test_version_flag():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "pokeupine" in result.stdout


def test_help_lists_all_commands():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("pull", "scan", "explain", "prove"):
        assert cmd in result.stdout


def test_scan_demo_app_emits_findings():
    """Scanning vulnerable-checkout must surface ≥5 findings."""
    result = CliRunner().invoke(app, ["scan", str(DEMO_APP)])
    assert result.exit_code == 0, result.stdout
    assert "PCI-DSS-3.3.1" in result.stdout
    assert "PCI-DSS-3.5.1" in result.stdout
    assert "PCI-DSS-4.2.1" in result.stdout
    assert "findings" in result.stdout


def test_scan_nonexistent_path_errors():
    result = CliRunner().invoke(app, ["scan", "/definitely/does/not/exist"])
    assert result.exit_code != 0
    assert "does not exist" in result.stdout


def test_explain_known_control():
    result = CliRunner().invoke(app, ["explain", "PCI-DSS-3.3.1"])
    assert result.exit_code == 0
    assert "Merkle proof verified" in result.stdout
    assert "source_doc_sha256" in result.stdout


def test_explain_unknown_control_errors():
    result = CliRunner().invoke(app, ["explain", "PCI-DSS-99.9.9"])
    assert result.exit_code != 0
    assert "not found" in result.stdout


def test_prove_no_pdf():
    result = CliRunner().invoke(app, ["prove", "PCI-DSS-3.3.1", "--no-pdf"])
    assert result.exit_code == 0
    assert "Merkle path verified" in result.stdout
    assert "Root signature verified" in result.stdout
    assert "self-contained" in result.stdout
