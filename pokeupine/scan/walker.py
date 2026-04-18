"""Filesystem walker that respects .gitignore and target globs."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path


HARD_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pokeupine",
}


class _GitignoreRule:
    """A single .gitignore pattern attached to its base directory."""

    __slots__ = ("base", "pattern", "negate", "dir_only", "anchored")

    def __init__(self, base: Path, raw: str) -> None:
        self.base = base
        negate = raw.startswith("!")
        if negate:
            raw = raw[1:]
        dir_only = raw.endswith("/")
        if dir_only:
            raw = raw[:-1]
        anchored = raw.startswith("/") or ("/" in raw)
        if raw.startswith("/"):
            raw = raw[1:]
        self.pattern = raw
        self.negate = negate
        self.dir_only = dir_only
        self.anchored = anchored

    def matches(self, rel_posix: str, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False
        pat = self.pattern
        if self.anchored:
            if _fnmatch_path(rel_posix, pat):
                return True
            parts = rel_posix.split("/")
            for i in range(1, len(parts)):
                if _fnmatch_path("/".join(parts[:i]), pat):
                    return True
            return False
        for segment in rel_posix.split("/"):
            if fnmatch.fnmatchcase(segment, pat):
                return True
        return False


def _fnmatch_path(path: str, pattern: str) -> bool:
    """fnmatch with `**` support (matches across path separators)."""
    if "**" not in pattern:
        return fnmatch.fnmatchcase(path, pattern)
    parts = pattern.split("**")
    translated = []
    for p in parts:
        t = fnmatch.translate(p)
        if t.startswith("(?s:") and t.endswith(")\\Z"):
            t = t[4:-3]
        translated.append(t)
    regex = "(?s:" + ".*".join(translated) + ")\\Z"
    return re.match(regex, path) is not None


def _load_gitignore(directory: Path) -> list[_GitignoreRule]:
    gi = directory / ".gitignore"
    if not gi.is_file():
        return []
    try:
        text = gi.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rules: list[_GitignoreRule] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rules.append(_GitignoreRule(directory, stripped))
    return rules


def _ignored(abs_path: Path, rules: list[_GitignoreRule], is_dir: bool) -> bool:
    """Apply gitignore rules in order; later rules override earlier ones."""
    ignored = False
    for rule in rules:
        try:
            rel = abs_path.relative_to(rule.base).as_posix()
        except ValueError:
            continue
        if rule.matches(rel, is_dir):
            ignored = not rule.negate
    return ignored


def walk_files(root: Path, globs: list[str] | None = None) -> list[Path]:
    """Walk a directory tree, returning files matching the given globs.

    Skips HARD_SKIP_DIRS and any path matched by a `.gitignore` in `root`
    or any ancestor walked through. Nested .gitignore files compose.
    """
    if globs is None:
        globs = ["**/*.py"]

    matched: set[Path] = set()
    base_rules = _load_gitignore(root)

    for dirpath, dirnames, filenames in os.walk(root):
        dpath = Path(dirpath)
        rules = list(base_rules)
        if dpath != root:
            cursor = root
            for part in dpath.relative_to(root).parts:
                cursor = cursor / part
                rules.extend(_load_gitignore(cursor))

        kept_dirs = []
        for d in dirnames:
            if d in HARD_SKIP_DIRS:
                continue
            if _ignored(dpath / d, rules, is_dir=True):
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for fname in filenames:
            fpath = dpath / fname
            if any(part in HARD_SKIP_DIRS for part in fpath.parts):
                continue
            if _ignored(fpath, rules, is_dir=False):
                continue
            rel = fpath.relative_to(root).as_posix()
            for pattern in globs:
                if _fnmatch_path(rel, pattern):
                    matched.add(fpath)
                    break
                if pattern.startswith("**/") and _fnmatch_path(rel, pattern[3:]):
                    matched.add(fpath)
                    break

    return sorted(matched)
