"""RegulationProfile: declarative spec describing how to ingest one regulation.

A profile is a JSON file under `ingestion/profiles/`. It tells the otherwise
regulation-agnostic pipeline:
  - which PDF to fetch,
  - how to recognize a clause heading in the text layer,
  - how to derive a control ID from a heading,
  - how to validate that ID,
  - which sections of the document to send to the LLM,
  - how to phrase the LLM prompt (regulation name + ID example),
  - what test specs (if any) to embed in the produced pack,
  - which fallback controls (if any) to fall back to when the LLM extraction
    misses a required ID,
  - where in the registry to write the resulting pack.

This is the moat: new regulation = new profile JSON + same pipeline binary.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILES_DIR = Path(__file__).parent / "profiles"
PROJECT_ROOT = Path(__file__).parent.parent


@dataclass
class RegulationProfile:
    """Declarative ingestion profile for a single regulation."""

    # Identity
    pack_id: str
    pack_version: str
    pack_title: str
    source_url: str

    # Source
    pdf_path: Path  # absolute, resolved against project root if relative

    # Clause structure
    heading_regex: str  # e.g. r"^(\d+\.\d+(?:\.\d+)?)\s+" — group 1 = heading token
    id_template: str    # e.g. "PCI-DSS-{heading}" or "GDPR-ART-{heading}"
    id_regex: str       # validates produced control IDs

    # LLM extraction
    prompt_regulation_name: str  # e.g. "the PCI-DSS v4.0 standard"
    prompt_id_example: str       # e.g. "PCI-DSS-3.3.1"
    target_headings: list[str] = field(default_factory=list)  # heading prefixes to send to LLM

    # Output
    registry_path: str = ""  # e.g. "packs/pci-dss/4.0.0" — relative to registry root

    # Embedded test specs and fallback controls (optional)
    tests: list[dict[str, Any]] = field(default_factory=list)
    fallback_controls: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> RegulationProfile:
        """Load a profile from a JSON file.

        Accepts either an absolute path, a path relative to the profiles
        directory, or a bare profile name (e.g. "pci-dss" → profiles/pci-dss.json).
        """
        p = Path(path)
        if not p.exists():
            # Try as a name under PROFILES_DIR
            candidate = PROFILES_DIR / f"{p.name}.json" if p.suffix == "" else PROFILES_DIR / p.name
            if candidate.exists():
                p = candidate
            else:
                raise FileNotFoundError(f"Profile not found: {path}")

        data = json.loads(p.read_text())

        # Resolve PDF path against project root if relative
        pdf_path = Path(data["pdf_path"])
        if not pdf_path.is_absolute():
            pdf_path = (PROJECT_ROOT / pdf_path).resolve()

        return cls(
            pack_id=data["pack_id"],
            pack_version=data["pack_version"],
            pack_title=data["pack_title"],
            source_url=data["source_url"],
            pdf_path=pdf_path,
            heading_regex=data["heading_regex"],
            id_template=data["id_template"],
            id_regex=data["id_regex"],
            prompt_regulation_name=data["prompt_regulation_name"],
            prompt_id_example=data["prompt_id_example"],
            target_headings=data.get("target_headings", []),
            registry_path=data.get("registry_path") or f"packs/{data['pack_id']}/{data['pack_version']}",
            tests=data.get("tests", []),
            fallback_controls=data.get("fallback_controls", []),
        )

    def compile_heading_re(self) -> re.Pattern[str]:
        return re.compile(self.heading_regex, re.MULTILINE)

    def compile_id_re(self) -> re.Pattern[str]:
        return re.compile(self.id_regex)

    def make_id(self, heading: str) -> str:
        return self.id_template.format(heading=heading)

    def required_control_ids(self) -> set[str]:
        """Control IDs referenced by embedded test specs or supplied as fallback controls.

        When `tests` is empty (e.g. policy-only regulations like GDPR), the
        fallback_controls list defines the canonical set the pack must contain.
        """
        from_tests = {t["control_id"] for t in self.tests if "control_id" in t}
        from_fallback = {c["id"] for c in self.fallback_controls if "id" in c}
        return from_tests | from_fallback
