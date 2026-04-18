"""Luhn-valid PAN literal detection in the dataflow engine."""

from __future__ import annotations

import json
from pathlib import Path

from pokeupine.scan.runner import run_scan
from pokeupine.schemas import Pack


PACK_JSON = (
    Path(__file__).parent.parent / "pokeupine-registry" / "packs" / "pci-dss" / "4.0.0" / "pack.json"
)


def _load_pack() -> Pack:
    return Pack(**json.loads(PACK_JSON.read_text()))


def test_luhn_flag_set_in_shipped_pack():
    """The 3.5.1 dataflow test must opt into Luhn literal detection."""
    pack = _load_pack()
    pan_test = next(t for t in pack.tests if t.id == "PCI-DSS-3.5.1::pan-unreadable")
    assert pan_test.spec.get("detect_pan_literals") is True


def test_luhn_pan_literal_in_db_execute_emits_finding(tmp_path: Path):
    """A Luhn-valid PAN literal piped into a storage sink must be flagged."""
    src = tmp_path / "store.py"
    src.write_text(
        "import sqlite3\n"
        'db = sqlite3.connect("x.db")\n'
        "def store():\n"
        "    db.execute(\"INSERT INTO orders VALUES ('4111111111111111')\")\n"
    )
    findings = run_scan(tmp_path, _load_pack())
    luhn = [f for f in findings if "Luhn-valid PAN" in f.evidence]
    assert luhn, f"expected a Luhn-PAN finding, got: {[f.evidence for f in findings]}"
    assert luhn[0].control_id == "PCI-DSS-3.5.1"
    assert luhn[0].file == "store.py"


def test_non_luhn_digit_string_not_flagged(tmp_path: Path):
    """Random 16-digit non-Luhn strings must NOT trigger a PAN finding."""
    src = tmp_path / "store.py"
    src.write_text(
        "import sqlite3\n"
        'db = sqlite3.connect("x.db")\n'
        "def store():\n"
        "    db.execute(\"INSERT INTO orders VALUES ('1234567890123456')\")\n"
    )
    findings = run_scan(tmp_path, _load_pack())
    assert not [f for f in findings if "Luhn-valid PAN" in f.evidence]
