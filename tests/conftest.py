"""Test fixtures and shared helpers."""

from __future__ import annotations

import pytest

from pokeupine.schemas import (
    Control,
    Provenance,
    TestCase,
)


@pytest.fixture
def sample_provenance() -> Provenance:
    """A minimal valid Provenance for testing."""
    return Provenance(
        source_doc_sha256="a" * 64,
        text_layer_sha256="b" * 64,
        extractor="pymupdf-1.24.10",
        page=1,
        byte_range=(0, 100),
        merkle_proof=[("L", "c" * 64)],
    )


@pytest.fixture
def sample_control(sample_provenance: Provenance) -> Control:
    """A minimal valid Control for testing."""
    return Control(
        id="PCI-DSS-3.3.1",
        title="SAD not stored after authorization",
        clause_text="Sensitive authentication data is not retained after authorization.",
        requirement="Never persist CVV/CVC.",
        severity="critical",
        provenance=sample_provenance,
    )


@pytest.fixture
def sample_test_case() -> TestCase:
    """A minimal valid TestCase for testing."""
    return TestCase(
        id="PCI-DSS-3.3.1::no-cvv-storage",
        control_id="PCI-DSS-3.3.1",
        kind="dataflow",
        spec={
            "sources": {"cvv_field": [{"kind": "pydantic_field", "field_name_regex": "^cvv$"}]},
            "sinks": {"storage": [{"kind": "call", "qualified_name_regex": "^cursor\\.execute$"}]},
            "sanitizers": [],
        },
    )
