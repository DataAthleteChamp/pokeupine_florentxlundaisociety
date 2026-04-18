"""AST check engine — tree-sitter pattern matching for code violations."""

from __future__ import annotations

import re
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from pokeupine.schemas import Finding, TestCase

PY_LANGUAGE = Language(tspython.language())


def _get_parser() -> Parser:
    parser = Parser(PY_LANGUAGE)
    return parser


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk_all(node):
    yield node
    for child in node.children:
        yield from _walk_all(child)


class AstCheckEngine:
    """Pattern-matching engine using tree-sitter AST."""

    def run(self, test: TestCase, files: list[Path], target: Path) -> list[Finding]:
        findings: list[Finding] = []
        spec = test.spec
        check_type = spec.get("check_type", "")

        parser = _get_parser()

        for filepath in files:
            try:
                source_bytes = filepath.read_bytes()
                tree = parser.parse(source_bytes)
            except Exception:
                continue

            rel_path = str(filepath.relative_to(target))

            if check_type == "cleartext_http":
                findings.extend(
                    self._check_cleartext_http(tree, source_bytes, rel_path, test)
                )
            elif check_type == "weak_password_policy":
                findings.extend(
                    self._check_weak_password(tree, source_bytes, rel_path, test)
                )
            elif check_type == "pattern_match":
                findings.extend(
                    self._check_pattern(tree, source_bytes, rel_path, test, spec)
                )

        return findings

    def _check_cleartext_http(
        self, tree, source_bytes: bytes, rel_path: str, test: TestCase,
    ) -> list[Finding]:
        """Find requests.post/get with http:// URLs (not https)."""
        findings: list[Finding] = []

        for node in _walk_all(tree.root_node):
            if node.type == "call":
                call_text = _node_text(node, source_bytes)
                # Match requests.post("http://...") or requests.get("http://...")
                if re.search(r'requests\.\w+\s*\(\s*["\']http://', call_text):
                    line = node.start_point[0] + 1
                    # Extract the URL
                    url_match = re.search(r'["\']http://[^"\']*["\']', call_text)
                    url = url_match.group(0) if url_match else "http://..."
                    findings.append(
                        Finding(
                            test_id=test.id,
                            control_id=test.control_id,
                            status="fail",
                            file=rel_path,
                            line=line,
                            evidence=f'requests call using cleartext HTTP: {url}',
                            remediation=test.spec.get(
                                "remediation",
                                "Use HTTPS (TLS 1.2+) for all regulated data in transit.",
                            ),
                            confidence=1.0,
                        )
                    )

        return findings

    def _check_weak_password(
        self, tree, source_bytes: bytes, rel_path: str, test: TestCase,
    ) -> list[Finding]:
        """Find password ``min_length`` below the threshold supplied by the test spec.

        Spec keys (all optional):
            ``min_length``  – integer threshold; default 12.
            ``remediation`` – pack-supplied remediation string.

        Handles keyword arguments, plain assignments, and typed class fields.
        """
        findings: list[Finding] = []
        threshold = int(test.spec.get("min_length", 12))
        remediation = test.spec.get("remediation") or (
            f"Set minimum password length to {threshold} or greater per {test.control_id}."
        )

        for node in _walk_all(tree.root_node):
            if node.type in ("assignment", "keyword_argument"):
                text = _node_text(node, source_bytes)
                # Typed assignment: "min_length: int = 8"
                # Plain assignment:  "min_length = 8"
                # Keyword arg:       "min_length=8"
                match = re.search(r'min_length\s*(?::\s*\w+\s*)?=\s*(\d+)', text)
                if match:
                    value = int(match.group(1))
                    if value < threshold:
                        line = node.start_point[0] + 1
                        findings.append(
                            Finding(
                                test_id=test.id,
                                control_id=test.control_id,
                                status="fail",
                                file=rel_path,
                                line=line,
                                evidence=(
                                    f"min_length={value} in password validator "
                                    f"({test.control_id} requires ≥{threshold})"
                                ),
                                remediation=remediation,
                                confidence=1.0,
                            )
                        )

        return findings

    def _check_pattern(
        self, tree, source_bytes: bytes, rel_path: str, test: TestCase, spec: dict,
    ) -> list[Finding]:
        """Generic pattern matching against source text."""
        findings: list[Finding]= []
        pattern = spec.get("pattern", "")
        if not pattern:
            return findings

        source_text = source_bytes.decode("utf-8", errors="replace")
        for i, line_text in enumerate(source_text.split("\n"), 1):
            if re.search(pattern, line_text):
                findings.append(
                    Finding(
                        test_id=test.id,
                        control_id=test.control_id,
                        status="fail",
                        file=rel_path,
                        line=i,
                        evidence=f"Pattern match: {line_text.strip()[:80]}",
                        remediation=spec.get("remediation", "Review this finding."),
                        confidence=1.0,
                    )
                )

        return findings
