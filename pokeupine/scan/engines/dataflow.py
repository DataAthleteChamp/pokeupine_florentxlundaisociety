"""Dataflow engine — THE MOAT.

Intra-procedural taint analysis using tree-sitter-python with real
def-use tracking:

  1. Parse the Python file with tree-sitter.
  2. Identify "tainted" Pydantic fields from the spec (sources).
  3. For each function, walk its top-level statements in execution order:
       - parameters typed with a tainted class become tainted vars
       - assignments propagate taint from RHS to LHS, with sanitizer
         calls clearing taint on their result
       - calls matching a sink pattern emit a finding when ANY argument
         (recursively) references a tainted var or a tainted attribute
  4. Optionally, also flag any Luhn-valid PAN literal that appears in
     a sink-matching call (opt-in via spec["detect_pan_literals"] = True).

Evidence string format is preserved as "Source -> var -> sink(...)" so
existing tests remain green.
"""

from __future__ import annotations

import re
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from pokeupine.schemas import Finding, TestCase

PY_LANGUAGE = Language(tspython.language())


def _get_parser() -> Parser:
    return Parser(PY_LANGUAGE)


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk_all(node):
    yield node
    for child in node.children:
        yield from _walk_all(child)


def _find_class_fields(tree, source_bytes: bytes) -> dict[str, list[str]]:
    classes: dict[str, list[str]] = {}
    for node in _walk_all(tree.root_node):
        if node.type != "class_definition":
            continue
        class_name = None
        for child in node.children:
            if child.type == "identifier":
                class_name = _node_text(child, source_bytes)
                break
        if class_name is None:
            continue
        body = next((c for c in node.children if c.type == "block"), None)
        fields: list[str] = []
        if body is not None:
            for stmt in body.children:
                if stmt.type != "expression_statement":
                    continue
                inner = stmt.children[0] if stmt.children else None
                if inner is None:
                    continue
                if inner.type == "assignment":
                    target = inner.children[0] if inner.children else None
                    if target is not None and target.type == "identifier":
                        name = _node_text(target, source_bytes)
                        if name not in fields:
                            fields.append(name)
        classes[class_name] = fields
    return classes


def _find_functions(tree, source_bytes: bytes):
    for node in _walk_all(tree.root_node):
        if node.type == "function_definition":
            name = None
            for child in node.children:
                if child.type == "identifier":
                    name = _node_text(child, source_bytes)
                    break
            yield node, name


_DIGITS_RE = re.compile(r"\d{13,19}")


def _luhn_ok(digits: str) -> bool:
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _string_contains_pan(text: str) -> str | None:
    for m in _DIGITS_RE.finditer(text):
        if _luhn_ok(m.group(0)):
            return m.group(0)
    return None


def _identifiers_in(node, source_bytes: bytes) -> set[str]:
    out: set[str] = set()
    for n in _walk_all(node):
        if n.type == "identifier":
            out.add(_node_text(n, source_bytes))
    return out


def _attribute_chains_in(node, source_bytes: bytes) -> set[str]:
    out: set[str] = set()
    for n in _walk_all(node):
        if n.type == "attribute":
            out.add(_node_text(n, source_bytes))
    return out


def _string_literals_in(node, source_bytes: bytes) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for n in _walk_all(node):
        if n.type == "string":
            text = _node_text(n, source_bytes)
            stripped = text
            for q in ("'''", '"""', '"', "'"):
                if stripped.startswith(q) and stripped.endswith(q):
                    stripped = stripped[len(q):-len(q)]
                    break
            out.append((stripped, n.start_point[0] + 1))
    return out


def _call_qualified_name(call_node, source_bytes: bytes) -> str | None:
    if call_node.type != "call":
        return None
    func = call_node.child_by_field_name("function")
    if func is None and call_node.children:
        func = call_node.children[0]
    if func is None:
        return None
    return _node_text(func, source_bytes)


class DataflowEngine:
    def run(self, test: TestCase, files: list[Path], target: Path) -> list[Finding]:
        findings: list[Finding] = []
        spec = test.spec
        source_specs = spec.get("sources", {})
        sink_specs = spec.get("sinks", {})
        sanitizer_specs = spec.get("sanitizers", [])
        detect_pan_literals = bool(spec.get("detect_pan_literals", False))

        parser = _get_parser()
        for filepath in files:
            try:
                source_bytes = filepath.read_bytes()
                tree = parser.parse(source_bytes)
            except Exception:
                continue
            findings.extend(self._analyze_file(
                tree, source_bytes, filepath, target,
                source_specs, sink_specs, sanitizer_specs,
                detect_pan_literals, test,
            ))
        return findings

    def _analyze_file(self, tree, source_bytes, filepath, target,
                      source_specs, sink_specs, sanitizer_specs,
                      detect_pan_literals, test):
        findings: list[Finding] = []
        classes = _find_class_fields(tree, source_bytes)

        source_patterns: list[dict] = []
        for _cat, pats in source_specs.items():
            for p in pats:
                source_patterns.append(p)

        tainted_fields: dict[str, str] = {}
        tainted_classes: set[str] = set()
        for class_name, fields in classes.items():
            for field in fields:
                for pat in source_patterns:
                    if pat.get("kind") != "pydantic_field":
                        continue
                    class_in = pat.get("class_in", [])
                    field_re = pat.get("field_name_regex", "")
                    if class_in and class_name not in class_in:
                        continue
                    if re.match(field_re, field):
                        key = f"{class_name}.{field}"
                        tainted_fields[key] = key
                        tainted_classes.add(class_name)

        sink_regexes: list[str] = [
            p["qualified_name_regex"]
            for _cat, pats in sink_specs.items()
            for p in pats
            if p.get("kind") == "call"
        ]
        sanitizer_regexes: list[str] = [
            p["qualified_name_regex"]
            for p in sanitizer_specs
            if p.get("kind") == "call"
        ]

        if not tainted_fields and not detect_pan_literals:
            return findings

        for func_node, _name in _find_functions(tree, source_bytes):
            findings.extend(self._analyze_function(
                func_node, source_bytes, filepath, target,
                tainted_fields, tainted_classes,
                sink_regexes, sanitizer_regexes,
                detect_pan_literals, test,
            ))

        if detect_pan_literals:
            findings.extend(self._scan_pan_literals(
                tree.root_node, source_bytes, filepath, target,
                sink_regexes, test,
            ))

        return findings

    def _analyze_function(self, func_node, source_bytes, filepath, target,
                          tainted_fields, tainted_classes,
                          sink_regexes, sanitizer_regexes,
                          detect_pan_literals, test):
        findings: list[Finding] = []
        rel_path = str(filepath.relative_to(target))

        tainted_vars: dict[str, str] = {}
        for pname, ptype in self._params(func_node, source_bytes):
            if ptype and ptype in tainted_classes:
                tainted_vars[pname] = pname

        body = next((c for c in func_node.children if c.type == "block"), None)
        if body is None:
            return findings

        for stmt in self._iter_statements(body):
            self._process_statement(
                stmt, source_bytes, filepath, target, rel_path,
                tainted_vars, tainted_fields, tainted_classes,
                sink_regexes, sanitizer_regexes,
                detect_pan_literals, test, findings,
            )
        return findings

    def _iter_statements(self, block):
        for child in block.children:
            t = child.type
            if t in ("if_statement", "for_statement", "while_statement",
                     "try_statement", "with_statement"):
                yield child
                for sub in _walk_all(child):
                    if sub.type == "block" and sub is not block:
                        yield from self._iter_statements(sub)
            else:
                yield child

    def _process_statement(self, stmt, source_bytes, filepath, target, rel_path,
                           tainted_vars, tainted_fields, tainted_classes,
                           sink_regexes, sanitizer_regexes,
                           detect_pan_literals, test, findings):
        for asn in _walk_all(stmt):
            if asn.type != "assignment":
                continue
            lhs = asn.children[0] if asn.children else None
            rhs = asn.children[-1] if asn.children else None
            if lhs is None or rhs is None or lhs is rhs:
                continue
            if lhs.type != "identifier":
                continue
            lhs_name = _node_text(lhs, source_bytes)

            sanitized = False
            for call in _walk_all(rhs):
                if call.type != "call":
                    continue
                qname = _call_qualified_name(call, source_bytes) or ""
                if any(re.search(r, qname) for r in sanitizer_regexes):
                    sanitized = True
                    break
            if sanitized:
                tainted_vars.pop(lhs_name, None)
                continue

            tainted_desc = self._rhs_taint(rhs, source_bytes, tainted_vars,
                                           tainted_fields, tainted_classes)
            if tainted_desc is not None:
                tainted_vars[lhs_name] = tainted_desc
            else:
                tainted_vars.pop(lhs_name, None)

        for call in _walk_all(stmt):
            if call.type != "call":
                continue
            qname = _call_qualified_name(call, source_bytes) or ""
            if not any(re.search(r, qname) for r in sink_regexes):
                continue
            args = call.child_by_field_name("arguments")
            if args is None:
                continue
            line = call.start_point[0] + 1

            arg_idents = _identifiers_in(args, source_bytes)
            arg_attrs = _attribute_chains_in(args, source_bytes)
            tainted_field_names = {
                k.split(".", 1)[1] for k in tainted_fields if "." in k
            }
            for var_name, source_desc in tainted_vars.items():
                attr_hit = next(
                    (a for a in sorted(arg_attrs)
                     if a.split(".", 1)[0] == var_name
                     and ("." not in a or a.split(".", 1)[1] in tainted_field_names)),
                    None,
                )
                if var_name in arg_idents or attr_hit:
                    field_desc = attr_hit or self._first_tainted_field_desc(
                        tainted_fields, tainted_classes,
                    ) or source_desc
                    evidence = f"{field_desc}  →  {var_name}  →  {qname}(...)"
                    findings.append(Finding(
                        test_id=test.id, control_id=test.control_id,
                        status="fail", file=rel_path, line=line,
                        evidence=evidence,
                        remediation=self._remediation(test),
                        confidence=1.0,
                    ))

            if detect_pan_literals:
                for lit, lit_line in _string_literals_in(args, source_bytes):
                    pan = _string_contains_pan(lit)
                    if pan:
                        evidence = (
                            f"Luhn-valid PAN literal '{pan[:6]}...{pan[-4:]}' "
                            f"→ {qname}(...)"
                        )
                        findings.append(Finding(
                            test_id=test.id, control_id=test.control_id,
                            status="fail", file=rel_path, line=lit_line,
                            evidence=evidence,
                            remediation=self._remediation(test),
                            confidence=1.0,
                        ))

    def _rhs_taint(self, rhs, source_bytes, tainted_vars,
                   tainted_fields, tainted_classes):
        idents = _identifiers_in(rhs, source_bytes)
        for v in idents:
            if v in tainted_vars:
                return tainted_vars[v]
        for chain in _attribute_chains_in(rhs, source_bytes):
            head = chain.split(".", 1)[0]
            if head in tainted_vars:
                return chain
        return None

    def _first_tainted_field_desc(self, tainted_fields, tainted_classes):
        for key in tainted_fields:
            cls = key.split(".", 1)[0]
            if cls in tainted_classes:
                return key
        return None

    def _params(self, func_node, source_bytes):
        params: list[tuple[str, str | None]] = []
        for child in func_node.children:
            if child.type != "parameters":
                continue
            for param in child.children:
                if param.type == "typed_parameter":
                    name = annotation = None
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

    def _scan_pan_literals(self, root_node, source_bytes, filepath, target,
                           sink_regexes, test):
        rel_path = str(filepath.relative_to(target))
        findings: list[Finding] = []
        for n in _walk_all(root_node):
            if n.type != "call":
                continue
            parent = n.parent
            inside_func = False
            while parent is not None:
                if parent.type == "function_definition":
                    inside_func = True
                    break
                parent = parent.parent
            if inside_func:
                continue
            qname = _call_qualified_name(n, source_bytes) or ""
            if not any(re.search(r, qname) for r in sink_regexes):
                continue
            args = n.child_by_field_name("arguments")
            if args is None:
                continue
            for lit, lit_line in _string_literals_in(args, source_bytes):
                pan = _string_contains_pan(lit)
                if pan:
                    findings.append(Finding(
                        test_id=test.id, control_id=test.control_id,
                        status="fail", file=rel_path, line=lit_line,
                        evidence=f"Luhn-valid PAN literal '{pan[:6]}...{pan[-4:]}' "
                                 f"→ {qname}(...)",
                        remediation=self._remediation(test),
                        confidence=1.0,
                    ))
        return findings

    def _remediation(self, test: TestCase) -> str:
        """Pack-supplied remediation wins; otherwise fall back to a generic note."""
        spec_remediation = test.spec.get("remediation")
        if isinstance(spec_remediation, str) and spec_remediation.strip():
            return spec_remediation
        return "Review the finding and apply the relevant control's remediation guidance."
