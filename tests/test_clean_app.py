"""Negative-case scan: a clean app should produce zero PCI failures."""

from __future__ import annotations

import json
from pathlib import Path

from pokeupine.scan.runner import run_scan
from pokeupine.schemas import Pack


PACK_JSON = (
    Path(__file__).parent.parent / "pokeupine-registry" / "packs" / "pci-dss" / "4.0.0" / "pack.json"
)

CLEAN_APP_FILES = {
    "app.py": (
        "from fastapi import FastAPI\n"
        "from pydantic import BaseModel\n"
        "import requests\n"
        "\n"
        "app = FastAPI()\n"
        "\n"
        "def audit_log(func):\n"
        "    def wrapper(*a, **kw): return func(*a, **kw)\n"
        "    return wrapper\n"
        "\n"
        "def tokenize(value: str) -> str:\n"
        "    return 'tok_' + value[-4:]\n"
        "\n"
        "class Order(BaseModel):\n"
        "    customer_email: str\n"
        "    amount_cents: int\n"
        "\n"
        "class PasswordPolicy(BaseModel):\n"
        "    min_length: int = 14\n"
        "\n"
        "@app.post('/checkout')\n"
        "@audit_log\n"
        "def checkout(order: Order):\n"
        "    requests.post('https://fraud/score', json=order.dict())\n"
        "    return {'ok': True}\n"
    ),
    "SECURITY.md": (
        "# Security\n"
        "We run Semgrep SAST on every PR via GitHub Actions, blocking merge "
        "on any high-severity finding. Coverage spans the entire Python codebase.\n"
    ),
}


def _load_pack() -> Pack:
    return Pack(**json.loads(PACK_JSON.read_text()))


def test_clean_app_has_no_failures(tmp_path: Path):
    """A compliant app should produce zero `fail` findings."""
    for name, content in CLEAN_APP_FILES.items():
        (tmp_path / name).write_text(content)

    findings = run_scan(tmp_path, _load_pack())
    failures = [f for f in findings if f.status == "fail"]
    assert not failures, f"clean app produced failures: {[(f.test_id, f.evidence) for f in failures]}"
