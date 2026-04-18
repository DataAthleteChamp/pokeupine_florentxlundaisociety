"""Extract a deterministic text layer from a regulation PDF using PyMuPDF.

Produces a frozen text_layer.txt file with deterministic page separators.
All byte offsets in Provenance objects reference this file, not the PDF.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pymupdf


PAGE_SEPARATOR = "\f"

DATA_DIR = Path(__file__).parent / "data"


@dataclass
class PageInfo:
    """Metadata about an extracted page."""
    number: int  # 0-indexed
    text: str
    byte_start: int  # offset in text_layer
    byte_end: int


def extract_text(pdf_path: Path) -> tuple[str, list[PageInfo]]:
    """Extract all text from the PDF, page by page.

    Returns:
        (full_text, [PageInfo, ...])
    """
    doc = pymupdf.open(str(pdf_path))
    pages: list[PageInfo] = []
    parts: list[str] = []
    current_offset = 0

    for page_num in range(len(doc)):
        page = doc[page_num]
        text = page.get_text("text")
        encoded = text.encode("utf-8")
        byte_start = current_offset
        byte_end = current_offset + len(encoded)

        pages.append(PageInfo(
            number=page_num,
            text=text,
            byte_start=byte_start,
            byte_end=byte_end,
        ))

        parts.append(text)
        current_offset = byte_end + len(PAGE_SEPARATOR.encode("utf-8"))

    doc.close()

    full_text = PAGE_SEPARATOR.join(parts)
    return full_text, pages


def save_text_layer(full_text: str, output_dir: Path | None = None) -> tuple[Path, str]:
    """Write the extracted text to disk and compute its hash.

    Returns:
        (text_layer_path, text_layer_sha256)
    """
    out = output_dir or DATA_DIR
    out.mkdir(parents=True, exist_ok=True)

    text_path = out / "text_layer.txt"
    text_bytes = full_text.encode("utf-8")
    text_path.write_bytes(text_bytes)

    sha256 = hashlib.sha256(text_bytes).hexdigest()
    return text_path, sha256


if __name__ == "__main__":
    import sys

    from ingestion.fetch import fetch

    if len(sys.argv) != 2:
        print("Usage: python -m ingestion.extract_text <path/to/regulation.pdf>")
        sys.exit(1)

    pdf_path, doc_sha = fetch(Path(sys.argv[1]))
    print(f"Extracting text from {pdf_path}...")

    full_text, pages = extract_text(pdf_path)
    text_path, text_sha = save_text_layer(full_text)

    print(f"Pages: {len(pages)}")
    print(f"Text layer: {text_path} ({len(full_text):,} chars)")
    print(f"Text layer SHA-256: {text_sha}")
