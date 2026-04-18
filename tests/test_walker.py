"""Tests for the .gitignore-aware filesystem walker."""

from __future__ import annotations

from pathlib import Path

from pokeupine.scan.walker import walk_files


def _make_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


def test_walks_python_files(tmp_path: Path) -> None:
    _make_tree(tmp_path, {"a.py": "x=1", "src/b.py": "y=2", "notes.txt": "hi"})
    found = walk_files(tmp_path)
    rels = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert rels == ["a.py", "src/b.py"]


def test_respects_root_gitignore(tmp_path: Path) -> None:
    _make_tree(
        tmp_path,
        {
            "keep.py": "x=1",
            "build/out.py": "x=2",
            "src/app.py": "x=3",
            ".gitignore": "build/\n",
        },
    )
    found = walk_files(tmp_path)
    rels = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert "build/out.py" not in rels
    assert "keep.py" in rels
    assert "src/app.py" in rels


def test_respects_unanchored_pattern(tmp_path: Path) -> None:
    _make_tree(
        tmp_path,
        {
            "src/app.py": "x=1",
            "src/secret.py": "x=2",
            ".gitignore": "secret.py\n",
        },
    )
    found = walk_files(tmp_path)
    rels = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert "src/secret.py" not in rels
    assert "src/app.py" in rels


def test_negation(tmp_path: Path) -> None:
    _make_tree(
        tmp_path,
        {
            "build/keep.py": "x=1",
            "build/skip.py": "x=2",
            ".gitignore": "build/\n!build/keep.py\n",
        },
    )
    # Note: gitignore semantics — re-include below an excluded directory only
    # works if the directory itself is not excluded. We accept that
    # `build/keep.py` may stay excluded; just assert `build/skip.py` is gone.
    found = walk_files(tmp_path)
    rels = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert "build/skip.py" not in rels


def test_nested_gitignore(tmp_path: Path) -> None:
    _make_tree(
        tmp_path,
        {
            "src/app.py": "x=1",
            "src/cache/data.py": "x=2",
            "src/.gitignore": "cache/\n",
        },
    )
    found = walk_files(tmp_path)
    rels = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert "src/cache/data.py" not in rels
    assert "src/app.py" in rels


def test_hard_skip_dirs(tmp_path: Path) -> None:
    _make_tree(
        tmp_path,
        {
            ".git/hooks/pre-commit.py": "x=1",
            "__pycache__/foo.py": "x=2",
            ".venv/lib/x.py": "x=3",
            "real.py": "x=4",
        },
    )
    found = walk_files(tmp_path)
    rels = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert rels == ["real.py"]


def test_glob_filter(tmp_path: Path) -> None:
    _make_tree(tmp_path, {"a.py": "x", "b.txt": "x"})
    found = walk_files(tmp_path, ["**/*.txt"])
    rels = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert rels == ["b.txt"]
