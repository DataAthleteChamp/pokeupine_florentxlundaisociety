"""LLM judge engine — checks for docs/policy presence with optional LLM call.

By default this engine is fully heuristic (deterministic file checks) so
demos run offline with zero flakiness. When `POKEUPINE_LLM=1` is set in
the environment, present-but-questionable files are passed to the LLM
gateway in `pokeupine.llm` for a pass/uncertain judgment. Failures from
the LLM call fall back to the heuristic verdict — never crash a scan.
"""

from __future__ import annotations

import os
from pathlib import Path

from pokeupine.schemas import Finding, TestCase


_MAX_LLM_FILE_BYTES = 16_000  # don't blow the context on huge READMEs


class LlmJudgeEngine:
    """Policy/docs presence checker, optionally LLM-assisted."""

    def run(self, test: TestCase, files: list[Path], target: Path) -> list[Finding]:
        spec = test.spec
        check_type = spec.get("check_type", "file_exists")

        if check_type == "file_exists":
            return self._check_file_exists(test, target, spec)
        if check_type == "file_contains":
            return self._check_file_contains(test, target, spec)
        if check_type == "llm_assess":
            return self._check_llm_assess(test, target, spec)
        return []

    # ---- file_exists --------------------------------------------------

    def _check_file_exists(
        self, test: TestCase, target: Path, spec: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        required_files = spec.get("required_files", [])
        description = spec.get("description", "Required documentation not found")
        question = spec.get(
            "llm_question",
            f"Does this document credibly describe {description}? "
            "Answer PASS or UNCERTAIN with a one-sentence reason.",
        )

        for filename in required_files:
            filepath = target / filename
            if not filepath.exists():
                findings.append(
                    Finding(
                        test_id=test.id,
                        control_id=test.control_id,
                        status="uncertain",
                        file=None,
                        line=None,
                        evidence=f"no {filename} found describing {description}",
                        remediation=spec.get(
                            "remediation",
                            f"Create a {filename} documenting your security review process.",
                        ),
                        confidence=0.6,
                    )
                )
                continue

            # File exists — optionally ask the LLM whether it actually covers
            # the required topic. Without LLM, we charitably assume PASS.
            verdict = _maybe_llm_verdict(filepath, question)
            if verdict == "uncertain":
                findings.append(
                    Finding(
                        test_id=test.id,
                        control_id=test.control_id,
                        status="uncertain",
                        file=filename,
                        line=None,
                        evidence=f"{filename} exists but LLM judge could not "
                                 f"confirm it covers {description}",
                        remediation=spec.get(
                            "remediation",
                            f"Expand {filename} to clearly describe {description}.",
                        ),
                        confidence=0.5,
                    )
                )

        return findings

    # ---- file_contains ------------------------------------------------

    def _check_file_contains(
        self, test: TestCase, target: Path, spec: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        filename = spec.get("filename", "")
        required_terms = spec.get("required_terms", [])

        filepath = target / filename
        if not filepath.exists():
            findings.append(
                Finding(
                    test_id=test.id,
                    control_id=test.control_id,
                    status="uncertain",
                    file=None,
                    line=None,
                    evidence=f"{filename} not found",
                    remediation=spec.get("remediation", f"Create {filename}"),
                    confidence=0.6,
                )
            )
            return findings

        content = filepath.read_text(encoding="utf-8", errors="replace").lower()
        missing = [term for term in required_terms if term.lower() not in content]

        if missing:
            findings.append(
                Finding(
                    test_id=test.id,
                    control_id=test.control_id,
                    status="uncertain",
                    file=filename,
                    line=None,
                    evidence=f"{filename} missing coverage of: {', '.join(missing)}",
                    remediation=spec.get("remediation", "Update documentation"),
                    confidence=0.5,
                )
            )

        return findings

    # ---- llm_assess ---------------------------------------------------

    def _check_llm_assess(
        self, test: TestCase, target: Path, spec: dict,
    ) -> list[Finding]:
        """Pure-LLM judgment over a single file's contents."""
        findings: list[Finding] = []
        filename = spec.get("filename", "")
        question = spec.get(
            "question", "Does this document satisfy the requirement? Answer PASS or UNCERTAIN."
        )
        filepath = target / filename

        if not filepath.exists():
            findings.append(
                Finding(
                    test_id=test.id,
                    control_id=test.control_id,
                    status="uncertain",
                    file=None,
                    line=None,
                    evidence=f"{filename} not found",
                    remediation=spec.get("remediation", f"Create {filename}"),
                    confidence=0.6,
                )
            )
            return findings

        verdict = _maybe_llm_verdict(filepath, question, force=True)
        if verdict == "uncertain":
            findings.append(
                Finding(
                    test_id=test.id,
                    control_id=test.control_id,
                    status="uncertain",
                    file=filename,
                    line=None,
                    evidence=f"LLM judge could not confirm {filename} satisfies the control",
                    remediation=spec.get("remediation", "Review and update the document"),
                    confidence=0.5,
                )
            )
        return findings


def _maybe_llm_verdict(filepath: Path, question: str, force: bool = False) -> str:
    """Return 'pass' or 'uncertain'.

    When `force` is True (llm_assess), we always try the LLM and fall back
    to 'uncertain' on any error. Otherwise we only call the LLM when
    POKEUPINE_LLM=1; without it we charitably return 'pass' for present files.
    """
    if not force and os.environ.get("POKEUPINE_LLM") != "1":
        return "pass"

    try:
        from pokeupine.llm import llm_complete

        content = filepath.read_bytes()[:_MAX_LLM_FILE_BYTES].decode(
            "utf-8", errors="replace"
        )
        prompt = (
            f"{question}\n\n"
            f"--- BEGIN {filepath.name} ---\n{content}\n--- END {filepath.name} ---\n"
            "Reply with exactly one word: PASS or UNCERTAIN."
        )
        reply = llm_complete(prompt).strip().upper()
        if reply.startswith("PASS"):
            return "pass"
        return "uncertain"
    except Exception:
        # LLM gateway unavailable / network error — degrade gracefully.
        return "pass" if not force else "uncertain"
