"""Regression tests for ingestion pipeline helpers.

Covers the fixes shipped after the first end-to-end GDPR run:
- Markdown code-fence stripping in LLM responses (Anthropic via litellm).
- target_headings filter is exact match (not prefix) so '5' does not match '50'.
- required_control_ids() includes fallback_controls so policy-only profiles
  (no test specs) still drive a non-empty pack.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ingestion.chunk import Chunk
from ingestion.llm_extract import extract_all, extract_controls_from_chunk
from ingestion.profile import RegulationProfile


@pytest.fixture
def gdpr_profile(tmp_path: Path) -> RegulationProfile:
    """Minimal GDPR-shaped profile for filter / fallback tests."""
    profile_data = {
        "pack_id": "test-reg",
        "pack_version": "1.0",
        "pack_title": "Test Regulation",
        "source_url": "https://example.invalid/reg",
        "pdf_path": "nonexistent.pdf",
        "heading_regex": r"^Article\s+(\d+)\s*\n",
        "id_template": "TEST-ART-{heading}",
        "id_regex": r"^TEST-ART-\d+$",
        "prompt_regulation_name": "the test regulation",
        "prompt_id_example": "TEST-ART-5",
        "target_headings": ["5", "32"],
        "registry_path": "packs/test/1.0",
        "tests": [],
        "fallback_controls": [
            {"id": "TEST-ART-5", "title": "T", "clause_text": "x",
             "requirement": "r", "severity": "high"},
            {"id": "TEST-ART-32", "title": "T", "clause_text": "x",
             "requirement": "r", "severity": "high"},
        ],
    }
    p = tmp_path / "profile.json"
    p.write_text(json.dumps(profile_data))
    return RegulationProfile.load(p)


def _make_chunk(heading: str) -> Chunk:
    return Chunk(heading=heading, text=f"Article {heading}\nbody", page=0,
                 byte_start=0, byte_end=10)


def test_target_headings_uses_exact_match_not_prefix(gdpr_profile):
    """target_headings='5' must not pick up Articles 50, 51, 58, etc."""
    chunks = [_make_chunk(h) for h in ["5", "32", "50", "51", "58", "501"]]

    with patch("ingestion.llm_extract.extract_controls_from_chunk",
               return_value=[]) as mock_extract:
        extract_all(chunks, profile=gdpr_profile)

    selected = [call.args[0].heading for call in mock_extract.call_args_list]
    assert sorted(selected) == ["32", "5"], (
        f"Expected exact-match filter to select only ['5', '32'], got {selected}"
    )


def test_required_control_ids_includes_fallback_controls(gdpr_profile):
    """Profiles with no test specs should still treat fallback IDs as required."""
    assert gdpr_profile.tests == []
    required = gdpr_profile.required_control_ids()
    assert required == {"TEST-ART-5", "TEST-ART-32"}


def test_extract_strips_markdown_json_fences(gdpr_profile):
    """Anthropic via litellm wraps JSON in ```json ... ```; we must unwrap it."""
    fenced_response = (
        "```json\n"
        '[{"id": "TEST-ART-5", "title": "Test", '
        '"clause_text": "verbatim text", '
        '"requirement": "do x", "severity": "high"}]\n'
        "```"
    )
    fake = MagicMock()
    fake.choices = [MagicMock()]
    fake.choices[0].message.content = fenced_response

    with patch("litellm.completion", return_value=fake), \
         patch("ingestion.llm_extract._get_cache") as mock_cache:
        mock_cache.return_value.get.return_value = None
        result = extract_controls_from_chunk(
            _make_chunk("5"), profile=gdpr_profile,
        )

    assert len(result) == 1
    assert result[0]["id"] == "TEST-ART-5"
    assert result[0]["clause_text"] == "verbatim text"


def test_extract_handles_unfenced_json(gdpr_profile):
    """Plain JSON arrays must continue to parse without modification."""
    plain = '[{"id": "TEST-ART-5", "title": "T", "clause_text": "x", '\
            '"requirement": "r", "severity": "high"}]'
    fake = MagicMock()
    fake.choices = [MagicMock()]
    fake.choices[0].message.content = plain

    with patch("litellm.completion", return_value=fake), \
         patch("ingestion.llm_extract._get_cache") as mock_cache:
        mock_cache.return_value.get.return_value = None
        result = extract_controls_from_chunk(
            _make_chunk("5"), profile=gdpr_profile,
        )

    assert len(result) == 1
    assert result[0]["id"] == "TEST-ART-5"
