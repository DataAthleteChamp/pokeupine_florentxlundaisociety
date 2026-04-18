"""LLM extraction of Control objects from regulation text chunks.

Uses litellm for model access and diskcache for memoization.
The extraction prompt is templated and parameterised by a RegulationProfile,
so the same code path serves PCI-DSS, GDPR, and any future regulation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import diskcache
from dotenv import load_dotenv

from ingestion.chunk import Chunk
from ingestion.profile import RegulationProfile

load_dotenv()

CACHE_DIR = Path(__file__).parent / "data" / "llm_cache"

EXTRACT_PROMPT_TEMPLATE = """\
You will be given a chunk of {regulation_name} between <CHUNK> tags.
Emit a JSON list of control objects, one per numbered/named requirement found in the chunk.

Each object must have these fields:
- "id": string matching the pattern `{id_regex}` (e.g. "{id_example}")
- "title": short descriptive title (your wording)
- "clause_text": a CONTIGUOUS VERBATIM substring of the chunk — do NOT paraphrase
- "requirement": plain-English summary of what the requirement demands (your wording)
- "severity": one of "critical", "high", "medium", "low"

Hard constraints:
- clause_text MUST be a contiguous verbatim substring of the chunk text. Copy exactly.
- id MUST match the section/article number from the chunk's heading.
- If a chunk contains no normative requirement, return [].
- Return ONLY the JSON array. No markdown, no explanation.

<CHUNK>
{chunk_text}
</CHUNK>
"""


def _get_cache() -> diskcache.Cache:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return diskcache.Cache(str(CACHE_DIR))


def _build_prompt(profile: RegulationProfile, chunk_text: str) -> str:
    return EXTRACT_PROMPT_TEMPLATE.format(
        regulation_name=profile.prompt_regulation_name,
        id_regex=profile.id_regex,
        id_example=profile.prompt_id_example,
        chunk_text=chunk_text,
    )


def extract_controls_from_chunk(
    chunk: Chunk,
    profile: RegulationProfile,
    model: str = "anthropic/claude-sonnet-4-20250514",
) -> list[dict[str, Any]]:
    """Extract Control-like dicts from a single chunk via LLM.

    Results are cached by (model, profile.pack_id, chunk_text_hash).
    """
    import litellm

    cache = _get_cache()
    cache_key = hashlib.sha256(
        f"{model}:{profile.pack_id}:{chunk.heading}:{chunk.text[:200]}".encode()
    ).hexdigest()

    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    prompt = _build_prompt(profile, chunk.text)

    response = litellm.completion(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        response_format={"type": "json_object"},
    )

    raw = response.choices[0].message.content.strip()

    # Strip Markdown code fences some models emit despite response_format
    # (e.g. Anthropic via litellm sometimes wraps JSON in ```json ... ```).
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        if raw.endswith("```"):
            raw = raw[:-3]
        raw = raw.strip()

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
    profile: RegulationProfile,
    model: str = "anthropic/claude-sonnet-4-20250514",
    target_headings: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Extract controls from all chunks, optionally filtered by heading prefix.

    Args:
        chunks: List of text chunks
        profile: RegulationProfile driving prompt + ID conventions
        model: LLM model to use
        target_headings: Heading-prefix allowlist; defaults to profile.target_headings.
                         Empty list means "process every chunk".

    Returns:
        List of raw control dicts (not yet validated)
    """
    all_controls: list[dict[str, Any]] = []

    targets = target_headings if target_headings is not None else profile.target_headings
    filtered = chunks
    if targets:
        target_set = set(targets)
        filtered = [c for c in chunks if c.heading in target_set]

    print(f"Extracting controls from {len(filtered)} chunks "
          f"(profile: {profile.pack_id}, model: {model})...")

    for i, chunk in enumerate(filtered):
        controls = extract_controls_from_chunk(chunk, profile=profile, model=model)
        if controls:
            # Attach chunk metadata
            for ctrl in controls:
                ctrl["_chunk_heading"] = chunk.heading
                ctrl["_chunk_page"] = chunk.page
                ctrl["_chunk_byte_start"] = chunk.byte_start
                ctrl["_chunk_byte_end"] = chunk.byte_end
            all_controls.extend(controls)

        if (i + 1) % 10 == 0:
            print(f"  Processed {i + 1}/{len(filtered)} chunks, "
                  f"{len(all_controls)} controls so far")

    print(f"Extracted {len(all_controls)} raw controls")
    return all_controls


if __name__ == "__main__":
    import sys

    from ingestion.chunk import chunk_text
    from ingestion.extract_text import extract_text
    from ingestion.fetch import fetch

    if len(sys.argv) != 2:
        print("Usage: python -m ingestion.llm_extract <profile-name-or-path>")
        sys.exit(1)

    profile = RegulationProfile.load(sys.argv[1])
    pdf_path, _ = fetch(profile.pdf_path)
    full_text, pages = extract_text(pdf_path)
    chunks = chunk_text(full_text, pages, profile.compile_heading_re())
    controls = extract_all(chunks, profile=profile)

    for c in controls:
        print(f"  {c.get('id', '???'):20s}  {c.get('title', '')[:60]}")
