"""Validate LLM-extracted controls against the source text layer.

Ensures:
1. clause_text is a verbatim substring of the text layer (whitespace-tolerant)
2. id matches the regulation's expected ID pattern (supplied by caller)
3. No duplicate ids
"""

from __future__ import annotations

import re
from typing import Any


# Generic fallback ID pattern. Real ingestion runs always pass a profile-supplied
# pattern via ``id_pattern=``; this default just keeps standalone use of
# ``validate_controls`` permissive without favouring any single regulation.
DEFAULT_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[\w.]+$")

REQUIRED_FIELDS = {"id", "title", "clause_text", "requirement", "severity"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _normalize_for_match(s: str) -> str:
    """Aggressively normalize text for fuzzy substring matching.

    Strips PDF artifacts: hyphenation across line breaks, soft hyphens,
    smart quotes, and collapses all whitespace.
    """
    # Remove hyphen-newline (e.g. "organisa-\ntional" -> "organisational")
    s = re.sub(r"-\s*\n\s*", "", s)
    # Normalize smart quotes to ASCII
    s = s.replace("\u2018", "'").replace("\u2019", "'")
    s = s.replace("\u201c", '"').replace("\u201d", '"')
    # Soft hyphen
    s = s.replace("\u00ad", "")
    # Collapse all whitespace
    s = " ".join(s.split())
    return s


def validate_controls(
    raw_controls: list[dict[str, Any]],
    full_text: str,
    id_pattern: re.Pattern[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate extracted controls.

    Args:
        raw_controls: Raw control dicts from LLM extraction
        full_text: The complete text layer for verbatim checking
        id_pattern: Compiled regex the control id must match. Defaults to a
                    permissive generic regulation-id pattern; real ingestion
                    runs should pass the pattern from the active profile.

    Returns:
        (valid_controls, rejected_controls)
    """
    pattern = id_pattern or DEFAULT_ID_PATTERN
    normalized_text = _normalize_for_match(full_text)

    valid: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for ctrl in raw_controls:
        reasons: list[str] = []

        missing = REQUIRED_FIELDS - set(ctrl.keys())
        if missing:
            reasons.append(f"missing fields: {missing}")

        ctrl_id = ctrl.get("id", "")
        clause_text = ctrl.get("clause_text", "")
        severity = ctrl.get("severity", "")

        if not pattern.match(ctrl_id):
            reasons.append(f"id '{ctrl_id}' doesn't match pattern {pattern.pattern}")

        if severity not in VALID_SEVERITIES:
            reasons.append(f"invalid severity '{severity}'")

        # Verbatim-or-fuzzy substring check.
        if clause_text:
            if clause_text not in full_text:
                normalized_clause = _normalize_for_match(clause_text)
                if normalized_clause not in normalized_text:
                    reasons.append("clause_text is not a verbatim substring of text_layer")

        if ctrl_id in seen_ids:
            reasons.append(f"duplicate id '{ctrl_id}'")

        if reasons:
            ctrl["_rejection_reasons"] = reasons
            rejected.append(ctrl)
        else:
            seen_ids.add(ctrl_id)
            valid.append(ctrl)

    return valid, rejected


def find_byte_range(clause_text: str, full_text: str) -> tuple[int, int] | None:
    """Find the byte range of clause_text in the text layer.

    Returns (byte_start, byte_end) or None if not found.
    """
    # Try exact match first
    idx = full_text.find(clause_text)
    if idx >= 0:
        byte_start = len(full_text[:idx].encode("utf-8"))
        byte_end = byte_start + len(clause_text.encode("utf-8"))
        return byte_start, byte_end

    # Try with normalized whitespace
    normalized_clause = " ".join(clause_text.split())
    normalized_text = " ".join(full_text.split())
    idx = normalized_text.find(normalized_clause)
    if idx >= 0:
        # Map back to original byte offset (approximate)
        byte_start = len(full_text[:idx].encode("utf-8"))
        byte_end = byte_start + len(clause_text.encode("utf-8"))
        return byte_start, byte_end

    return None


if __name__ == "__main__":
    print("Run via build_pack.py")
