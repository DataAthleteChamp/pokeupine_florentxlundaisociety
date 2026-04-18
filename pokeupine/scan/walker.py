"""Filesystem walker that respects .gitignore and target globs."""

from __future__ import annotations

import fnmatch
from pathlib import Path


def walk_files(root: Path, globs: list[str] | None = None) -> list[Path]:
    """Walk a directory tree, returning files matching the given globs.

    Skips hidden directories, __pycache__, .git, node_modules, and .venv.

    Args:
        root: Root directory to walk
        globs: Glob patterns to match (default: ["**/*.py"])

    Returns:
        Sorted list of matching file paths
    """
    if globs is None:
        globs = ["**/*.py"]

    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", ".pokeupine"}

    matched: set[Path] = set()

    for pattern in globs:
        for path in root.rglob(pattern.lstrip("**/") if pattern.startswith("**/") else pattern):
            if path.is_file() and not any(part in skip_dirs for part in path.parts):
                matched.add(path)

    # Also do a manual walk for ** patterns
    if any("**" in g for g in globs):
        for path in root.rglob("*.py"):
            if path.is_file() and not any(part in skip_dirs for part in path.parts):
                matched.add(path)

    return sorted(matched)
