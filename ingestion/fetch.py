"""Fetch and hash the PCI-DSS PDF source document."""

from __future__ import annotations

import hashlib
from pathlib import Path

# Default location of the PDF in the project root
DEFAULT_PDF_PATH = Path(__file__).parent.parent / "PCI-DSS-v4_0_1.pdf"


def hash_file(path: Path) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(pdf_path: Path | None = None) -> tuple[Path, str]:
    """Locate the PCI-DSS PDF and compute its hash.

    Args:
        pdf_path: Path to the PDF file (default: project root)

    Returns:
        (pdf_path, source_doc_sha256)
    """
    path = pdf_path or DEFAULT_PDF_PATH
    if not path.exists():
        raise FileNotFoundError(f"PCI-DSS PDF not found at {path}")

    sha256 = hash_file(path)
    return path, sha256


if __name__ == "__main__":
    path, sha = fetch()
    print(f"PDF: {path}")
    print(f"SHA-256: {sha}")
    print(f"Size: {path.stat().st_size:,} bytes")
