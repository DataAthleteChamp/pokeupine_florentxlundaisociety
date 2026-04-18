"""Fetch and hash a regulation source PDF.

Pipeline-agnostic: the caller (build_pack via a RegulationProfile) supplies
the PDF path. No regulation-specific defaults live here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def hash_file(path: Path) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(pdf_path: Path) -> tuple[Path, str]:
    """Locate a regulation PDF and compute its SHA-256.

    Args:
        pdf_path: Absolute path to the PDF.

    Returns:
        (pdf_path, source_doc_sha256)
    """
    if pdf_path is None:
        raise ValueError("fetch() requires an explicit pdf_path (no defaults)")
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found at {pdf_path}")

    sha256 = hash_file(pdf_path)
    return pdf_path, sha256


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m ingestion.fetch <path/to/regulation.pdf>")
        sys.exit(1)

    path, sha = fetch(Path(sys.argv[1]))
    print(f"PDF: {path}")
    print(f"SHA-256: {sha}")
    print(f"Size: {path.stat().st_size:,} bytes")
