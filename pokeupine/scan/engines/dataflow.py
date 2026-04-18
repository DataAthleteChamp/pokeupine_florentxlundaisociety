"""Dataflow engine — THE MOAT.

Intra-procedural taint analysis using tree-sitter-python.
Detects when regulated data (PAN, CVV, PHI) flows to storage/network
sinks without passing through a sanitizer.
"""

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
    """Extract the text of a tree-sitter node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _find_class_fields(tree, source_bytes: bytes) -> dict[str, list[str]]:
    """Find Pydantic BaseModel classes and their field names.

    Returns: {class_name: [field_name, ...]}
    """
    classes: dict[str, list[str]] = {}

    for node in _walk_all(tree.root_node):
        if node.type == "class_definition":
            class_name = None
            for child in node.children:
                if child.type == "identifier":
                    class_name = _node_text(child, source_bytes)
                    break

            if class_name is None:
                continue

            # Check if inherits from BaseModel (or similar)
            bases = []
            for child in node.children:
                if child.type == "argument_list":
                    for arg in child.children:
                        if arg.type == "identifier":
                            bases.append(_node_text(arg, source_bytes))

            fields = []
            body = None
            for child in node.children:
                if child.type == "block":
                    body = child
                    break

            if body:
                for stmt in body.children:
                    if stmt.type == "expression_statement":
                        expr = stmt.children[0] if stmt.children else None
                        if expr and expr.type == "assignment":
                            target = expr.children[0] if expr.children else None
                            if target and target.type == "identifier":
                                fields.append(_node_text(target, source_bytes))
                    elif stmt.type == "typed_assignment" or (
                        stmt.type == "expression_statement"
                        and stmt.child_count > 0
                        and stmt.children[0].type == "type"
                    ):
                        # type-annotated fields
                        for c in stmt.children:
                            if c.type == "identifier":
                                fields.append(_node_text(c, source_bytes))
                                break

            # Also find annotated assignments (field: type = ...)
            if body:
                for stmt in _walk_all(body):
                    if stmt.type == "typed_assignment" or stmt.type == "assignment":
                        # get the leftmost identifier
                        if stmt.children and stmt.children[0].type == "identifier":
                            fname = _node_text(stmt.children[0], source_bytes)
                            if fname not in fields:
                                fields.append(fname)

            classes[class_name] = fields

    return classes


def _walk_all(node):
    """Walk all nodes in a tree-sitter tree (DFS)."""
    yield node
    for child in node.children:
        yield from _walk_all(child)


def _find_functions(tree, source_bytes: bytes):
    """Find all function definitions in the tree."""
    for node in _walk_all(tree.root_node):
        if node.type == "function_definition":
            name = None
            for child in node.children:
                if child.type == "identifier":
                    name = _node_text(child, source_bytes)
                    break
            yield node, name


class DataflowEngine:
    """Intra-procedural taint analysis engine."""

    def run(self, test: TestCase, files: list[Path], target: Path) -> list[Finding]:
        findings: list[Finding] = []
        spec = test.spec

        source_specs = spec.get("sources", {})
        sink_specs = spec.get("sinks", {})
        sanitizer_specs = spec.get("sanitizers", [])

        parser = _get_parser()

        for filepath in files:
            try:
                source_bytes = filepath.read_bytes()
                tree = parser.parse(source_bytes)
            except Exception:
                continue

            file_findings = self._analyze_file(
                tree, source_bytes, filepath, target,
                source_specs, sink_specs, sanitizer_specs, test,
            )
            findings.extend(file_findings)

        return findings

    def _analyze_file(
        self,
        tree,
        source_bytes: bytes,
        filepath: Path,
        target: Path,
        source_specs: dict,
        sink_specs: dict,
        sanitizer_specs: list,
        test: TestCase,
    ) -> list[Finding]:
        findings: list[Finding] = []
        source_text = source_bytes.decode("utf-8", errors="replace")
        lines = source_text.split("\n")

        # Find classes and their fields (potential sources)
        classes = _find_class_fields(tree, source_bytes)

        # Build source field patterns from spec
        source_patterns: list[dict] = []
        for _category, patterns in source_specs.items():
            for pat in patterns:
                source_patterns.append(pat)

        # Identify which class.field combos are tainted sources
        tainted_fields: dict[str, str] = {}  # "Class.field" → source description
        for class_name, fields in classes.items():
            for field in fields:
                for pat in source_patterns:
                    if pat.get("kind") == "pydantic_field":
                        class_regex = pat.get("class_in", [])
                        field_regex = pat.get("field_name_regex", "")
                        if (not class_regex or class_name in class_regex) and re.match(
                            field_regex, field
                        ):
                            tainted_fields[f"{class_name}.{field}"] = f"{class_name}.{field}"

        if not tainted_fields:
            return findings

        # Build sink patterns
        sink_regexes: list[str] = []
        for _category, patterns in sink_specs.items():
            for pat in patterns:
                if pat.get("kind") == "call":
                    sink_regexes.append(pat["qualified_name_regex"])

        # Build sanitizer patterns
        sanitizer_regexes: list[str] = []
        for pat in sanitizer_specs:
            if pat.get("kind") == "call":
                sanitizer_regexes.append(pat["qualified_name_regex"])

        # For each function, do intra-procedural taint analysis
        for func_node, func_name in _find_functions(tree, source_bytes):
            func_findings = self._analyze_function(
                func_node, source_bytes, lines, filepath, target,
                tainted_fields, sink_regexes, sanitizer_regexes, test,
            )
            findings.extend(func_findings)

        return findings

    def _analyze_function(
        self,
        func_node,
        source_bytes: bytes,
        lines: list[str],
        filepath: Path,
        target: Path,
        tainted_fields: dict[str, str],
        sink_regexes: list[str],
        sanitizer_regexes: list[str],
        test: TestCase,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Track tainted variables: var_name → (source_description, source_line)
        tainted_vars: dict[str, tuple[str, int]] = {}

        # Walk the function body looking for parameter names that match tainted types
        params = self._get_function_params(func_node, source_bytes)

        # If a parameter is type-annotated with a tainted class, mark it tainted
        for param_name, param_type in params:
            for field_key, desc in tainted_fields.items():
                class_name = field_key.split(".")[0]
                if param_type == class_name:
                    # All fields of this parameter are tainted
                    tainted_vars[param_name] = (desc, func_node.start_point[0] + 1)

        # Walk statements looking for taint flow
        body = None
        for child in func_node.children:
            if child.type == "block":
                body = child
                break

        if not body:
            return findings

        for stmt in _walk_all(body):
            stmt_text = _node_text(stmt, source_bytes)
            stmt_line = stmt.start_point[0] + 1

            # Check for sanitizer calls
            if stmt.type in ("expression_statement", "assignment"):
                for san_re in sanitizer_regexes:
                    if re.search(san_re, stmt_text):
                        # Clear taint (simplified)
                        tainted_vars.clear()

            # Check for sinks
            if stmt.type == "expression_statement" or stmt.type == "call":
                for sink_re in sink_regexes:
                    if re.search(sink_re, stmt_text):
                        # Check if any tainted variable flows into this sink
                        for var_name, (source_desc, source_line) in tainted_vars.items():
                            if var_name in stmt_text:
                                rel_path = str(filepath.relative_to(target))
                                evidence = (
                                    f"{source_desc}  →  {var_name}  →  "
                                    f"{self._extract_sink_name(stmt_text)}"
                                )
                                findings.append(
                                    Finding(
                                        test_id=test.id,
                                        control_id=test.control_id,
                                        status="fail",
                                        file=rel_path,
                                        line=stmt_line,
                                        evidence=evidence,
                                        remediation=self._get_remediation(test.control_id),
                                        confidence=1.0,
                                    )
                                )

        return findings

    def _get_function_params(self, func_node, source_bytes: bytes) -> list[tuple[str, str | None]]:
        """Extract (name, type_annotation) pairs from function parameters."""
        params: list[tuple[str, str | None]] = []
        for child in func_node.children:
            if child.type == "parameters":
                for param in child.children:
                    if param.type == "typed_parameter":
                        name = None
                        annotation = None
                        for c in param.children:
                            if c.type == "identifier" and name is None:
                                name = _node_text(c, source_bytes)
                            elif c.type == "type":
                                annotation = _node_text(c, source_bytes)
                        if name:
                            params.append((name, annotation))
                    elif param.type == "identifier":
                        params.append((_node_text(param, source_bytes), None))
        return params

    def _extract_sink_name(self, stmt_text: str) -> str:
        """Extract a short sink name from a statement."""
        # Find the first call-like pattern
        match = re.search(r'(\w+(?:\.\w+)*)\s*\(', stmt_text)
        if match:
            return match.group(1) + "(...)"
        return stmt_text[:40].strip()

    def _get_remediation(self, control_id: str) -> str:
        remediations = {
            "PCI-DSS-3.3.1": "Never persist CVV/CVC. Delete SAD immediately after authorization.",
            "PCI-DSS-3.5.1": "Tokenize PAN with a PCI-validated provider; store the token only.",
        }
        return remediations.get(control_id, "Review the finding and apply appropriate controls.")
