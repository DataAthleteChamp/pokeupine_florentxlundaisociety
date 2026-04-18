"""Tests for Pydantic schemas."""

from pokeupine.schemas import (
    Control,
    Finding,
    Pack,
    PackManifest,
    Provenance,
    TestCase,
)


def test_provenance_round_trip():
    p = Provenance(
        source_doc_sha256="a" * 64,
        text_layer_sha256="b" * 64,
        extractor="pymupdf-1.24.10",
        page=47,
        byte_range=(12340, 12567),
        merkle_proof=[("L", "c" * 64), ("R", "d" * 64)],
    )
    assert p.page == 47
    assert len(p.merkle_proof) == 2
    data = p.model_dump()
    p2 = Provenance(**data)
    assert p2 == p


def test_control_serialization(sample_control):
    data = sample_control.model_dump()
    c2 = Control(**data)
    assert c2.id == "PCI-DSS-3.3.1"
    assert c2.severity == "critical"
    assert c2.provenance.page == 1


def test_finding():
    f = Finding(
        test_id="PCI-DSS-3.3.1::no-cvv-storage",
        control_id="PCI-DSS-3.3.1",
        status="fail",
        file="app.py",
        line=24,
        evidence="Order.cvv → cursor.execute(arg 3)",
        remediation="Never persist CVV.",
    )
    assert f.status == "fail"
    assert f.confidence == 1.0


def test_test_case():
    t = TestCase(
        id="PCI-DSS-3.3.1::no-cvv-storage",
        control_id="PCI-DSS-3.3.1",
        kind="dataflow",
        spec={"sources": {}, "sinks": {}, "sanitizers": []},
    )
    assert t.kind == "dataflow"
    assert t.target_globs == ["**/*.py"]


def test_pack_manifest():
    m = PackManifest(
        title="PCI-DSS",
        source_url="https://example.com/pci-dss.pdf",
        source_doc_sha256="a" * 64,
        text_layer_sha256="b" * 64,
        merkle_root="c" * 64,
        merkle_root_signature="d" * 128,
        signing_key_id="registry-2026",
        controls_count=42,
        tests_count=6,
    )
    assert m.id == "pci-dss"
    assert m.version == "4.0.0"


def test_pack():
    p = Pack(
        manifest=PackManifest(
            title="PCI-DSS",
            source_url="https://example.com",
            source_doc_sha256="a" * 64,
            text_layer_sha256="b" * 64,
            merkle_root="c" * 64,
            merkle_root_signature="d" * 128,
            signing_key_id="registry-2026",
            controls_count=0,
            tests_count=0,
        ),
        controls=[],
        tests=[],
    )
    assert p.manifest.id == "pci-dss"
    assert len(p.controls) == 0
