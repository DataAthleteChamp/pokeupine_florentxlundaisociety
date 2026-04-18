"""Pydantic models for Pokeupine's data layer.

Every type used across CLI, ingestion, scan engines, and registry lives here.
Frozen after Phase 1 — both devs depend on these interfaces.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


TestKind = Literal[
    "ast_check",
    "dataflow",
    "decorator_required",
    "regex",
    "llm_judge",
]


class Provenance(BaseModel):
    """Cryptographic provenance linking a control to the source PDF."""

    source_doc_sha256: str
    text_layer_sha256: str
    extractor: str  # e.g. "pymupdf-1.24.10"
    page: int
    byte_range: tuple[int, int]  # span in text_layer
    merkle_proof: list[tuple[Literal["L", "R"], str]]  # sibling hashes leaf → root


class Control(BaseModel):
    """A single compliance control extracted from a regulation."""

    id: str  # "PCI-DSS-3.3.1"
    title: str
    clause_text: str  # verbatim substring of text_layer
    requirement: str  # plain-English summary
    severity: Literal["critical", "high", "medium", "low"]
    provenance: Provenance


class TestCase(BaseModel):
    """A test that checks code against a specific control."""

    __test__ = False  # prevent pytest collection

    id: str  # "PCI-DSS-3.3.1::no-cvv-storage"
    control_id: str
    kind: TestKind
    spec: dict  # kind-specific payload (sources/sinks/patterns)
    target_globs: list[str] = ["**/*.py"]


class Finding(BaseModel):
    """A single finding produced by a scan engine."""

    test_id: str
    control_id: str
    status: Literal["fail", "uncertain", "pass"]
    file: str | None = None
    line: int | None = None
    evidence: str  # rendered snippet or dataflow path
    remediation: str
    confidence: float = 1.0


class PackManifest(BaseModel):
    """Metadata for a signed regulation pack."""

    id: str = "pci-dss"
    version: str = "4.0.0"
    title: str
    source_url: str
    source_doc_sha256: str
    text_layer_sha256: str
    merkle_root: str
    merkle_root_signature: str  # ed25519 over merkle_root
    signing_key_id: str  # matches /keys/<id>.pub in registry
    controls_count: int
    tests_count: int


class Pack(BaseModel):
    """A complete regulation pack: manifest + controls + tests."""

    manifest: PackManifest
    controls: list[Control]
    tests: list[TestCase]
