"""LLM extraction of Control objects from regulation text chunks.

Uses litellm for model access and diskcache for memoization.
Each chunk is sent to the LLM with a strict prompt requiring
verbatim clause_text extraction.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import diskcache
from dotenv import load_dotenv

from ingestion.chunk import Chunk

load_dotenv()

CACHE_DIR = Path(__file__).parent / "data" / "llm_cache"

EXTRACT_PROMPT = """\
You will be given a chunk of the PCI-DSS v4.0 standard between <CHUNK> tags.
Emit a JSON list of control objects, one per numbered requirement found in the chunk.

Each object must have these fields:
- "id": string in the form "PCI-DSS-X.Y.Z" matching the section number (e.g. "PCI-DSS-3.3.1")
- "title": short descriptive title (your wording)
- "clause_text": a CONTIGUOUS VERBATIM substring of the chunk — do NOT paraphrase
- "requirement": plain-English summary of what the requirement demands (your wording)
- "severity": one of "critical", "high", "medium", "low"

Hard constraints:
- clause_text MUST be a contiguous verbatim substring of the chunk text. Copy exactly.
- id MUST match the section number from the heading.
- If a chunk contains no normative requirement, return [].
- Return ONLY the JSON array. No markdown, no explanation.

<CHUNK>
{chunk_text}
</CHUNK>
"""


def _get_cache() -> diskcache.Cache:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return diskcache.Cache(str(CACHE_DIR))


def extract_controls_from_chunk(
    chunk: Chunk,
    model: str = "anthropic/claude-sonnet-4-20250514",
) -> list[dict[str, Any]]:
    """Extract Control-like dicts from a single chunk via LLM.

    Results are cached by (model, chunk_text_hash).
    """
    import litellm

    cache = _get_cache()
    cache_key = hashlib.sha256(
        f"{model}:{chunk.heading}:{chunk.text[:200]}".encode()
    ).hexdigest()

    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    prompt = EXTRACT_PROMPT.format(chunk_text=chunk.text)

    response = litellm.completion(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content.strip()

    # Parse response — handle both raw array and wrapped object
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            # Some models wrap in {"controls": [...]}
            for key in ("controls", "requirements", "items", "results"):
                if key in parsed and isinstance(parsed[key], list):
                    parsed = parsed[key]
                    break
            else:
                parsed = []
        if not isinstance(parsed, list):
            parsed = []
    except json.JSONDecodeError:
        parsed = []

    cache.set(cache_key, parsed, expire=86400 * 30)
    return parsed


def extract_all(
    chunks: list[Chunk],
    model: str = "anthropic/claude-sonnet-4-20250514",
    target_sections: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Extract controls from all chunks (or filtered sections).

    Args:
        chunks: List of text chunks
        model: LLM model to use
        target_sections: If set, only process chunks whose heading starts with one of these

    Returns:
        List of raw control dicts (not yet validated)
    """
    all_controls: list[dict[str, Any]] = []

    # Filter to target sections if specified
    filtered = chunks
    if target_sections:
        filtered = [
            c for c in chunks
            if any(c.heading.startswith(s) for s in target_sections)
        ]

    print(f"Extracting controls from {len(filtered)} chunks (model: {model})...")

    for i, chunk in enumerate(filtered):
        controls = extract_controls_from_chunk(chunk, model=model)
        if controls:
            # Attach chunk metadata
            for ctrl in controls:
                ctrl["_chunk_heading"] = chunk.heading
                ctrl["_chunk_page"] = chunk.page
                ctrl["_chunk_byte_start"] = chunk.byte_start
                ctrl["_chunk_byte_end"] = chunk.byte_end
            all_controls.extend(controls)

        if (i + 1) % 10 == 0:
            print(f"  Processed {i + 1}/{len(filtered)} chunks, {len(all_controls)} controls so far")

    print(f"Extracted {len(all_controls)} raw controls")
    return all_controls


if __name__ == "__main__":
    from ingestion.fetch import fetch
    from ingestion.extract_text import extract_text
    from ingestion.chunk import chunk_text

    pdf_path, _ = fetch()
    full_text, pages = extract_text(pdf_path)
    chunks = chunk_text(full_text, pages)

    # Only extract from sections relevant to our 6 demo tests
    target = ["3.3", "3.4", "3.5", "4.2", "6.2", "8.3", "10.2"]
    controls = extract_all(chunks, target_sections=target)

    for c in controls:
        print(f"  {c.get('id', '???'):20s}  {c.get('title', '')[:60]}")
