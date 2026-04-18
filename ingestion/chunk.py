"""Chunk a regulation text layer into clause-level segments.

Heading recognition is regulation-specific and supplied by the caller via a
compiled regex (group 1 = heading token used to derive the control ID).
Each chunk carries its page number and byte range in text_layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ingestion.extract_text import PageInfo


@dataclass
class Chunk:
    """A clause-level chunk of regulation text."""
    heading: str       # token captured by group 1 of the heading regex
    text: str          # full text of the clause
    page: int          # page number (0-indexed)
    byte_start: int    # start offset in text_layer
    byte_end: int      # end offset in text_layer


# Default for backwards compatibility / standalone use only. Real callers
# pass a profile-supplied compiled regex into chunk_text().
DEFAULT_HEADING_RE = re.compile(r"^(\d+\.\d+(?:\.\d+)?)\s+", re.MULTILINE)


def chunk_text(
    full_text: str,
    pages: list[PageInfo],
    heading_re: re.Pattern[str] | None = None,
) -> list[Chunk]:
    """Split the text layer into clause-level chunks.

    Args:
        full_text: The complete text layer
        pages: Page info list from extraction
        heading_re: Compiled regex with group 1 capturing the heading token
                    (e.g. "3.3.1" for PCI-DSS, "32" for GDPR Article).
                    Falls back to the PCI-DSS-style numbered-section pattern
                    when not supplied.

    Returns:
        List of Chunk objects with byte ranges
    """
    pattern = heading_re or DEFAULT_HEADING_RE
    matches = list(pattern.finditer(full_text))

    if not matches:
        return []

    chunks: list[Chunk] = []

    for i, match in enumerate(matches):
        heading = match.group(1)
        start_char = match.start()

        # End is the start of the next heading, or end of text
        if i + 1 < len(matches):
            end_char = matches[i + 1].start()
        else:
            end_char = len(full_text)

        chunk_text_str = full_text[start_char:end_char].strip()

        # Compute byte offsets
        byte_start = len(full_text[:start_char].encode("utf-8"))
        byte_end = len(full_text[:end_char].encode("utf-8"))

        # Find which page this chunk starts on
        page_num = _find_page(byte_start, pages)

        chunks.append(Chunk(
            heading=heading,
            text=chunk_text_str,
            page=page_num,
            byte_start=byte_start,
            byte_end=byte_end,
        ))

    return chunks


def _find_page(byte_offset: int, pages: list[PageInfo]) -> int:
    """Find which page a byte offset falls on."""
    for page in pages:
        if page.byte_start <= byte_offset < page.byte_end:
            return page.number
    # If past all pages, return last page
    return pages[-1].number if pages else 0


if __name__ == "__main__":
    import sys

    from ingestion.extract_text import extract_text
    from ingestion.fetch import fetch
    from ingestion.profile import RegulationProfile

    if len(sys.argv) != 2:
        print("Usage: python -m ingestion.chunk <profile-name-or-path>")
        sys.exit(1)

    profile = RegulationProfile.load(sys.argv[1])
    pdf_path, _ = fetch(profile.pdf_path)
    full_text, pages = extract_text(pdf_path)
    chunks = chunk_text(full_text, pages, profile.compile_heading_re())

    print(f"Found {len(chunks)} chunks for {profile.pack_id}")
    for c in chunks[:10]:
        print(f"  {c.heading:10s}  page {c.page:3d}  bytes {c.byte_start}-{c.byte_end}  ({len(c.text)} chars)")
    if len(chunks) > 10:
        print(f"  ... and {len(chunks) - 10} more")
