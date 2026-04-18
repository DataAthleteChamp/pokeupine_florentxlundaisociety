"""Regex engine — simple line-level pattern matching."""

from __future__ import annotations

import re
from pathlib import Path

from pokeupine.schemas import Finding, TestCase


class RegexEngine:
    """Line-level regex matching engine."""

    def run(self, test: TestCase, files: list[Path], target: Path) -> list[Finding]:
        findings: list[Finding] = []
        spec = test.spec
        pattern = spec.get("pattern", "")
        if not pattern:
            return findings

        for filepath in files:
            try:
                source_text = filepath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            rel_path = str(filepath.relative_to(target))

            for i, line in enumerate(source_text.split("\n"), 1):
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            test_id=test.id,
                            control_id=test.control_id,
                            status="fail",
                            file=rel_path,
                            line=i,
                            evidence=f"Pattern match: {line.strip()[:80]}",
                            remediation=spec.get(
                                "remediation", "Review this finding and apply appropriate controls."
                            ),
                            confidence=1.0,
                        )
                    )

        return findings
