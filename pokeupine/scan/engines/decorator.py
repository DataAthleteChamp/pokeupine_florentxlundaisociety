"""Decorator engine — checks that functions carry required decorators."""

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


class DecoratorEngine:
    """Checks that functions matching a pattern carry a required decorator."""

    def run(self, test: TestCase, files: list[Path], target: Path) -> list[Finding]:
        findings: list[Finding] = []
        spec = test.spec

        required_decorator = spec.get("required_decorator", "")
        # Which functions to check — match by decorator pattern (e.g., functions with @app.post)
        target_decorator_regex = spec.get("target_decorator_regex", "")
        # Or match by parameter type
        target_param_type = spec.get("target_param_type", "")

        parser = _get_parser()

        for filepath in files:
            try:
                source_bytes = filepath.read_bytes()
                tree = parser.parse(source_bytes)
            except Exception:
                continue

            rel_path = str(filepath.relative_to(target))

            # Only check top-level decorated_definition and standalone function_definition
            for node in tree.root_node.children:
                if node.type == "decorated_definition":
                    func_findings = self._check_function(
                        node, source_bytes, rel_path, test,
                        required_decorator, target_decorator_regex, target_param_type,
                    )
                    findings.extend(func_findings)
                elif node.type == "function_definition":
                    # Standalone function (no decorators at all)
                    func_findings = self._check_function(
                        node, source_bytes, rel_path, test,
                        required_decorator, target_decorator_regex, target_param_type,
                    )
                    findings.extend(func_findings)

        return findings

    def _check_function(
        self,
        node,
        source_bytes: bytes,
        rel_path: str,
        test: TestCase,
        required_decorator: str,
        target_decorator_regex: str,
        target_param_type: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Get all decorators and the function def
        decorators: list[str] = []
        func_def = node
        func_name = ""

        if node.type == "decorated_definition":
            for child in node.children:
                if child.type == "decorator":
                    dec_text = _node_text(child, source_bytes)
                    # Strip trailing comments from decorator text
                    if "#" in dec_text:
                        dec_text = dec_text[:dec_text.index("#")].strip()
                    decorators.append(dec_text)
                elif child.type == "function_definition":
                    func_def = child
        elif node.type == "function_definition":
            pass  # standalone function, no decorators

        # Get function name
        for child in func_def.children:
            if child.type == "identifier":
                func_name = _node_text(child, source_bytes)
                break

        # Check if this function matches the target pattern
        is_target = False

        if target_decorator_regex:
            for dec in decorators:
                if re.search(target_decorator_regex, dec):
                    is_target = True
                    break

        if target_param_type and not is_target:
            # Check if any parameter has the target type
            for child in func_def.children:
                if child.type == "parameters":
                    param_text = _node_text(child, source_bytes)
                    if target_param_type in param_text:
                        is_target = True
                        break

        if not is_target:
            return findings

        # Check if the required decorator is present
        has_required = any(
            re.search(required_decorator, dec) for dec in decorators
        )

        if not has_required:
            line = func_def.start_point[0] + 1
            route_info = ""
            for dec in decorators:
                route_match = re.search(r'@app\.\w+\(["\']([^"\']+)', dec)
                if route_match:
                    route_info = f" route {route_match.group(1)}"
                    break

            findings.append(
                Finding(
                    test_id=test.id,
                    control_id=test.control_id,
                    status="fail",
                    file=rel_path,
                    line=line,
                    evidence=f"{func_name}{route_info} missing @{required_decorator} decorator",
                    remediation=f"Add @{required_decorator} decorator to all functions handling cardholder data.",
                    confidence=1.0,
                )
            )

        return findings
