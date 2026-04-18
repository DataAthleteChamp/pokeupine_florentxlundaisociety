"""Validate LLM-extracted controls against the source text layer.

Ensures:
1. clause_text is a verbatim substring of the text layer
2. id matches the expected PCI-DSS pattern
3. No duplicate ids
"""

from __future__ import annotations

import re
from typing import Any


ID_PATTERN = re.compile(r"^PCI-DSS-\d+\.\d+(\.\d+){0,2}$")

REQUIRED_FIELDS = {"id", "title", "clause_text", "requirement", "severity"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def validate_controls(
    raw_controls: list[dict[str, Any]],
    full_text: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate extracted controls.

    Args:
        raw_controls: Raw control dicts from LLM extraction
        full_text: The complete text layer for verbatim checking

    Returns:
        (valid_controls, rejected_controls)
    """
    valid: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for ctrl in raw_controls:
        reasons: list[str] = []

        # Check required fields
        missing = REQUIRED_FIELDS - set(ctrl.keys())
        if missing:
            reasons.append(f"missing fields: {missing}")

        ctrl_id = ctrl.get("id", "")
        clause_text = ctrl.get("clause_text", "")
        severity = ctrl.get("severity", "")

        # Check id format
        if not ID_PATTERN.match(ctrl_id):
            reasons.append(f"id '{ctrl_id}' doesn't match PCI-DSS-X.Y.Z pattern")

        # Check severity
        if severity not in VALID_SEVERITIES:
            reasons.append(f"invalid severity '{severity}'")

        # Check verbatim substring
        if clause_text and clause_text not in full_text:
            # Try with normalized whitespace
            normalized_clause = " ".join(clause_text.split())
            normalized_text = " ".join(full_text.split())
            if normalized_clause not in normalized_text:
                reasons.append("clause_text is not a verbatim substring of text_layer")

        # Check duplicate
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
