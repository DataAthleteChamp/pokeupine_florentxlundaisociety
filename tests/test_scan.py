"""Integration test — full scan of vulnerable-checkout."""

import json
from pathlib import Path

import pytest

from pokeupine.scan.runner import run_scan
from pokeupine.schemas import Pack


DEMO_APP = Path(__file__).parent.parent / "vulnerable-checkout"
PACK_JSON = Path(__file__).parent.parent / "pokeupine-registry" / "packs" / "pci-dss" / "4.0.0" / "pack.json"


@pytest.fixture
def pci_pack() -> Pack:
    """Load the real PCI-DSS pack."""
    data = json.loads(PACK_JSON.read_text())
    return Pack(**data)


def test_full_scan_finding_count(pci_pack):
    """Full scan should produce exactly 6 findings."""
    findings = run_scan(DEMO_APP, pci_pack)
    assert len(findings) == 6


def test_full_scan_has_dataflow(pci_pack):
    """At least one finding should be from the dataflow engine."""
    findings = run_scan(DEMO_APP, pci_pack)
    dataflow_findings = [f for f in findings if "→" in f.evidence]
    assert len(dataflow_findings) >= 1


def test_full_scan_has_ast(pci_pack):
    """At least one finding should detect cleartext HTTP."""
    findings = run_scan(DEMO_APP, pci_pack)
    http_findings = [f for f in findings if "http://" in f.evidence.lower()]
    assert len(http_findings) >= 1


def test_full_scan_has_decorator(pci_pack):
    """At least one finding should detect missing @audit_log."""
    findings = run_scan(DEMO_APP, pci_pack)
    dec_findings = [f for f in findings if "audit_log" in f.evidence]
    assert len(dec_findings) >= 1


def test_full_scan_has_llm_judge(pci_pack):
    """At least one finding should be uncertain (LLM judge)."""
    findings = run_scan(DEMO_APP, pci_pack)
    uncertain = [f for f in findings if f.status == "uncertain"]
    assert len(uncertain) >= 1
    assert all(f.confidence < 1.0 for f in uncertain)


def test_full_scan_has_password_check(pci_pack):
    """At least one finding should detect weak password policy."""
    findings = run_scan(DEMO_APP, pci_pack)
    pwd_findings = [f for f in findings if "min_length" in f.evidence]
    assert len(pwd_findings) >= 1


def test_merkle_proof_verification(pci_pack):
    """All controls should have valid Merkle proofs."""
    from pokeupine.merkle import leaf_hash, verify_proof

    for control in pci_pack.controls:
        leaf = leaf_hash(control.clause_text)
        assert verify_proof(
            leaf, control.provenance.merkle_proof, pci_pack.manifest.merkle_root
        ), f"Merkle proof failed for {control.id}"


def test_signature_verification(pci_pack):
    """Pack signature should verify against hard-coded public key."""
    from pokeupine.crypto import verify_signature

    assert verify_signature(
        pci_pack.manifest.merkle_root_signature,
        pci_pack.manifest.merkle_root,
    )
