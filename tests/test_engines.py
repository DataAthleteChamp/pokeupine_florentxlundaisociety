"""Tests for scan engines against the vulnerable-checkout demo app."""

from pathlib import Path

import pytest

from pokeupine.schemas import TestCase


DEMO_APP = Path(__file__).parent.parent / "vulnerable-checkout"


class TestDataflowEngine:
    def test_cvv_to_db(self):
        """Dataflow engine should detect CVV flowing to cursor.execute."""
        from pokeupine.scan.engines.dataflow import DataflowEngine

        test = TestCase(
            id="PCI-DSS-3.3.1::no-cvv-storage",
            control_id="PCI-DSS-3.3.1",
            kind="dataflow",
            spec={
                "sources": {
                    "sad_field": [
                        {
                            "kind": "pydantic_field",
                            "class_in": ["Order"],
                            "field_name_regex": "^cvv$",
                        }
                    ]
                },
                "sinks": {
                    "storage": [
                        {
                            "kind": "call",
                            "qualified_name_regex": r"db\.execute",
                        }
                    ]
                },
                "sanitizers": [],
            },
        )

        engine = DataflowEngine()
        files = list(DEMO_APP.glob("*.py"))
        findings = engine.run(test, files, DEMO_APP)

        assert len(findings) >= 1
        assert any(f.status == "fail" for f in findings)
        assert any("order" in f.evidence.lower() or "Order" in f.evidence for f in findings)

    def test_pan_to_db(self):
        """Dataflow engine should detect card_number flowing to DB."""
        from pokeupine.scan.engines.dataflow import DataflowEngine

        test = TestCase(
            id="PCI-DSS-3.5.1::pan-unreadable",
            control_id="PCI-DSS-3.5.1",
            kind="dataflow",
            spec={
                "sources": {
                    "pan_typed": [
                        {
                            "kind": "pydantic_field",
                            "class_in": ["Order", "Payment", "Card", "Transaction"],
                            "field_name_regex": r"^(card_number|pan|cc(_num)?)$",
                        }
                    ]
                },
                "sinks": {
                    "storage": [
                        {
                            "kind": "call",
                            "qualified_name_regex": r"db\.execute",
                        }
                    ]
                },
                "sanitizers": [
                    {
                        "kind": "call",
                        "qualified_name_regex": r"^(tokenize|vault\.store|mask_pan)$",
                    }
                ],
            },
        )

        engine = DataflowEngine()
        files = list(DEMO_APP.glob("*.py"))
        findings = engine.run(test, files, DEMO_APP)

        assert len(findings) >= 1
        assert any(f.status == "fail" for f in findings)


class TestAstCheckEngine:
    def test_cleartext_http(self):
        """AST engine should detect requests.post with http:// URL."""
        from pokeupine.scan.engines.ast_check import AstCheckEngine

        test = TestCase(
            id="PCI-DSS-4.2.1::strong-crypto-transit",
            control_id="PCI-DSS-4.2.1",
            kind="ast_check",
            spec={"check_type": "cleartext_http"},
        )

        engine = AstCheckEngine()
        files = list(DEMO_APP.glob("*.py"))
        findings = engine.run(test, files, DEMO_APP)

        assert len(findings) >= 1
        assert any("http://" in f.evidence for f in findings)

    def test_weak_password(self):
        """AST engine should detect min_length < 12."""
        from pokeupine.scan.engines.ast_check import AstCheckEngine

        test = TestCase(
            id="PCI-DSS-8.3.6::password-length",
            control_id="PCI-DSS-8.3.6",
            kind="ast_check",
            spec={"check_type": "weak_password_policy"},
        )

        engine = AstCheckEngine()
        files = list(DEMO_APP.glob("*.py"))
        findings = engine.run(test, files, DEMO_APP)

        assert len(findings) >= 1
        assert any("min_length=8" in f.evidence for f in findings)


class TestDecoratorEngine:
    def test_missing_audit_log(self):
        """Decorator engine should detect missing @audit_log on checkout."""
        from pokeupine.scan.engines.decorator import DecoratorEngine

        test = TestCase(
            id="PCI-DSS-10.2.1::audit-log-required",
            control_id="PCI-DSS-10.2.1",
            kind="decorator_required",
            spec={
                "required_decorator": "audit_log",
                "target_decorator_regex": r"@app\.(post|put|patch|delete)",
                "target_param_type": "",
            },
        )

        engine = DecoratorEngine()
        files = list(DEMO_APP.glob("*.py"))
        findings = engine.run(test, files, DEMO_APP)

        assert len(findings) >= 1
        assert any("audit_log" in f.evidence for f in findings)


class TestLlmJudgeEngine:
    def test_missing_security_md(self):
        """LLM judge should detect missing SECURITY.md."""
        from pokeupine.scan.engines.llm_judge import LlmJudgeEngine

        test = TestCase(
            id="PCI-DSS-6.2.4::sast-in-ci",
            control_id="PCI-DSS-6.2.4",
            kind="llm_judge",
            spec={
                "check_type": "file_exists",
                "required_files": ["SECURITY.md"],
                "description": "code review process",
                "remediation": "Create a SECURITY.md describing your SAST/code review process.",
            },
        )

        engine = LlmJudgeEngine()
        findings = engine.run(test, [], DEMO_APP)

        assert len(findings) >= 1
        assert findings[0].status == "uncertain"
        assert findings[0].confidence < 1.0
