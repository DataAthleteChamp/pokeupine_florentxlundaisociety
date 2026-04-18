"""Scan runner — dispatches TestCases to the appropriate engine."""

from __future__ import annotations

from pathlib import Path

from pokeupine.scan.walker import walk_files
from pokeupine.schemas import Finding, Pack


# Engine registry: maps TestKind → engine module
def _get_engine(kind: str):
    """Lazy-import the engine for a given TestKind."""
    if kind == "dataflow":
        from pokeupine.scan.engines.dataflow import DataflowEngine
        return DataflowEngine()
    elif kind == "ast_check":
        from pokeupine.scan.engines.ast_check import AstCheckEngine
        return AstCheckEngine()
    elif kind == "decorator_required":
        from pokeupine.scan.engines.decorator import DecoratorEngine
        return DecoratorEngine()
    elif kind == "regex":
        from pokeupine.scan.engines.regex import RegexEngine
        return RegexEngine()
    elif kind == "llm_judge":
        from pokeupine.scan.engines.llm_judge import LlmJudgeEngine
        return LlmJudgeEngine()
    else:
        raise ValueError(f"Unknown test kind: {kind}")


def run_scan(target: Path, pack: Pack) -> list[Finding]:
    """Run all tests in a pack against a target codebase.

    Deterministic engines run first; LLM-judge runs last.

    Args:
        target: Path to the codebase to scan
        pack: The regulation pack with controls and tests

    Returns:
        List of findings
    """
    findings: list[Finding] = []

    # Sort tests: deterministic first, llm_judge last
    deterministic = [t for t in pack.tests if t.kind != "llm_judge"]
    llm_tests = [t for t in pack.tests if t.kind == "llm_judge"]

    for test in deterministic + llm_tests:
        files = walk_files(target, test.target_globs)
        engine = _get_engine(test.kind)
        try:
            results = engine.run(test, files, target)
            findings.extend(results)
        except Exception as e:
            # Don't crash the whole scan if one engine fails
            findings.append(
                Finding(
                    test_id=test.id,
                    control_id=test.control_id,
                    status="uncertain",
                    evidence=f"Engine error: {e}",
                    remediation="Check engine configuration",
                    confidence=0.0,
                )
            )

    # Deduplicate: same (test_id, file, line) → keep first
    seen: set[tuple] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f.test_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped
