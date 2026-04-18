"""Chunk PCI-DSS text layer into clause-level segments.

Splits on numbered headings like "3.3.1", "4.2.1", etc.
Each chunk carries its page number and byte range in text_layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ingestion.extract_text import PageInfo


@dataclass
class Chunk:
    """A clause-level chunk of regulation text."""
    heading: str       # e.g. "3.3.1"
    text: str          # full text of the clause
    page: int          # page number (0-indexed)
    byte_start: int    # start offset in text_layer
    byte_end: int      # end offset in text_layer


# Pattern: standalone numbered heading at start of line, e.g. "3.3.1 " or "10.2.1 "
HEADING_RE = re.compile(r"^(\d+\.\d+(?:\.\d+)?)\s+", re.MULTILINE)


def chunk_text(full_text: str, pages: list[PageInfo]) -> list[Chunk]:
    """Split the text layer into clause-level chunks.

    Args:
        full_text: The complete text layer
        pages: Page info list from extraction

    Returns:
        List of Chunk objects with byte ranges
    """
    matches = list(HEADING_RE.finditer(full_text))

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
    from ingestion.fetch import fetch
    from ingestion.extract_text import extract_text

    pdf_path, _ = fetch()
    full_text, pages = extract_text(pdf_path)
    chunks = chunk_text(full_text, pages)

    print(f"Found {len(chunks)} chunks")
    for c in chunks[:10]:
        print(f"  {c.heading:10s}  page {c.page:3d}  bytes {c.byte_start}-{c.byte_end}  ({len(c.text)} chars)")
    if len(chunks) > 10:
        print(f"  ... and {len(chunks) - 10} more")
