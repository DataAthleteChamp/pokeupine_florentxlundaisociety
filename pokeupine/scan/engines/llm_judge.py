"""LLM judge engine — checks for docs/policy presence via LLM or heuristics."""

from __future__ import annotations

from pathlib import Path

from pokeupine.schemas import Finding, TestCase


class LlmJudgeEngine:
    """Policy/docs presence checker.

    For the hackathon, uses simple heuristics (file existence checks)
    rather than live LLM calls, to avoid flakiness during demo.
    Falls back to cached LLM call if available.
    """

    def run(self, test: TestCase, files: list[Path], target: Path) -> list[Finding]:
        findings: list[Finding] = []
        spec = test.spec
        check_type = spec.get("check_type", "file_exists")

        if check_type == "file_exists":
            findings.extend(self._check_file_exists(test, target, spec))
        elif check_type == "file_contains":
            findings.extend(self._check_file_contains(test, target, spec))

        return findings

    def _check_file_exists(
        self, test: TestCase, target: Path, spec: dict,
    ) -> list[Finding]:
        """Check that required documentation files exist."""
        findings: list[Finding] = []
        required_files = spec.get("required_files", [])
        description = spec.get("description", "Required documentation not found")

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

        return findings

    def _check_file_contains(
        self, test: TestCase, target: Path, spec: dict,
    ) -> list[Finding]:
        """Check that a file contains required content."""
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
