"""Tests for scan engines against the vulnerable-checkout demo app."""

from pathlib import Path


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

    def test_luhn_pan_literal(self, tmp_path):
        """Detects a Luhn-valid PAN string baked into a sink call."""
        from pokeupine.scan.engines.dataflow import DataflowEngine

        src = tmp_path / "loader.py"
        src.write_text(
            "def seed(db):\n"
            "    db.execute('INSERT INTO orders VALUES (\"4111111111111111\")')\n"
        )

        test = TestCase(
            id="PCI-DSS-3.5.1::pan-literal",
            control_id="PCI-DSS-3.5.1",
            kind="dataflow",
            spec={
                "sources": {},  # no class-based sources needed
                "sinks": {
                    "storage": [
                        {"kind": "call", "qualified_name_regex": r"db\.execute"},
                    ],
                },
                "sanitizers": [],
                "detect_pan_literals": True,
            },
        )
        findings = DataflowEngine().run(test, [src], tmp_path)
        assert len(findings) == 1
        assert "Luhn-valid PAN literal" in findings[0].evidence
        assert "411111" in findings[0].evidence

    def test_sanitizer_clears_taint(self, tmp_path):
        """A tokenize() sanitizer breaks the def-use chain to the sink."""
        from pokeupine.scan.engines.dataflow import DataflowEngine

        src = tmp_path / "svc.py"
        src.write_text(
            "from pydantic import BaseModel\n"
            "class Order(BaseModel):\n"
            "    card_number: str = ''\n"
            "def store(order: Order, db):\n"
            "    token = tokenize(order.card_number)\n"
            "    db.execute('INSERT INTO o VALUES (?)', (token,))\n"
        )
        test = TestCase(
            id="PCI-DSS-3.5.1::sanitized",
            control_id="PCI-DSS-3.5.1",
            kind="dataflow",
            spec={
                "sources": {
                    "pan": [{
                        "kind": "pydantic_field",
                        "class_in": ["Order"],
                        "field_name_regex": r"^card_number$",
                    }],
                },
                "sinks": {
                    "storage": [{"kind": "call", "qualified_name_regex": r"db\.execute"}],
                },
                "sanitizers": [{"kind": "call", "qualified_name_regex": r"^tokenize$"}],
            },
        )
        findings = DataflowEngine().run(test, [src], tmp_path)
        # token is no longer tainted, but `order.card_number` itself never
        # reaches the sink → no finding expected.
        assert findings == []

    def test_aliased_pan_still_caught(self, tmp_path):
        """`pan = order.card_number; db.execute(... pan ...)` still flags."""
        from pokeupine.scan.engines.dataflow import DataflowEngine

        src = tmp_path / "svc.py"
        src.write_text(
            "from pydantic import BaseModel\n"
            "class Order(BaseModel):\n"
            "    card_number: str = ''\n"
            "def store(order: Order, db):\n"
            "    pan = order.card_number\n"
            "    db.execute('INSERT INTO o VALUES (?)', (pan,))\n"
        )
        test = TestCase(
            id="PCI-DSS-3.5.1::alias",
            control_id="PCI-DSS-3.5.1",
            kind="dataflow",
            spec={
                "sources": {
                    "pan": [{
                        "kind": "pydantic_field",
                        "class_in": ["Order"],
                        "field_name_regex": r"^card_number$",
                    }],
                },
                "sinks": {
                    "storage": [{"kind": "call", "qualified_name_regex": r"db\.execute"}],
                },
                "sanitizers": [],
            },
        )
        findings = DataflowEngine().run(test, [src], tmp_path)
        assert len(findings) >= 1
        assert any("pan" in f.evidence for f in findings)


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
    def test_missing_security_md(self, tmp_path):
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
        findings = engine.run(test, [], tmp_path)

        assert len(findings) >= 1
        assert findings[0].status == "uncertain"
        assert findings[0].confidence < 1.0

    def test_llm_assess_calls_gateway(self, monkeypatch, tmp_path):
        """llm_assess check_type must invoke pokeupine.llm.llm_complete."""
        from pokeupine.scan.engines.llm_judge import LlmJudgeEngine

        doc = tmp_path / "SECURITY.md"
        doc.write_text("# Security\nWe run SAST in CI on every PR.\n")

        calls = []

        def fake_llm_complete(prompt, **kwargs):
            calls.append(prompt)
            return "PASS"

        # Patch the symbol where llm_judge imports it lazily.
        import pokeupine.llm
        monkeypatch.setattr(pokeupine.llm, "llm_complete", fake_llm_complete)

        test = TestCase(
            id="PCI-DSS-6.2.4::sast-llm",
            control_id="PCI-DSS-6.2.4",
            kind="llm_judge",
            spec={
                "check_type": "llm_assess",
                "filename": "SECURITY.md",
                "question": "Does this describe SAST in CI?",
            },
        )
        engine = LlmJudgeEngine()
        findings = engine.run(test, [], tmp_path)

        assert len(calls) == 1, "llm_complete should have been called exactly once"
        assert "SECURITY.md" in calls[0]
        # PASS verdict → no finding emitted.
        assert findings == []

    def test_llm_assess_uncertain_emits_finding(self, monkeypatch, tmp_path):
        """When the LLM is unsure, an uncertain finding is produced."""
        from pokeupine.scan.engines.llm_judge import LlmJudgeEngine

        doc = tmp_path / "SECURITY.md"
        doc.write_text("we love security")

        import pokeupine.llm
        monkeypatch.setattr(
            pokeupine.llm, "llm_complete", lambda prompt, **kw: "UNCERTAIN: vague"
        )

        test = TestCase(
            id="PCI-DSS-6.2.4::sast-llm",
            control_id="PCI-DSS-6.2.4",
            kind="llm_judge",
            spec={"check_type": "llm_assess", "filename": "SECURITY.md"},
        )
        findings = LlmJudgeEngine().run(test, [], tmp_path)
        assert len(findings) == 1
        assert findings[0].status == "uncertain"

    def test_llm_assess_falls_back_when_gateway_errors(self, monkeypatch, tmp_path):
        """LLM gateway errors must NOT crash a scan."""
        from pokeupine.scan.engines.llm_judge import LlmJudgeEngine

        doc = tmp_path / "SECURITY.md"
        doc.write_text("anything")

        def boom(*a, **kw):
            raise RuntimeError("network down")

        import pokeupine.llm
        monkeypatch.setattr(pokeupine.llm, "llm_complete", boom)

        test = TestCase(
            id="PCI-DSS-6.2.4::sast-llm",
            control_id="PCI-DSS-6.2.4",
            kind="llm_judge",
            spec={"check_type": "llm_assess", "filename": "SECURITY.md"},
        )
        # Should produce uncertain finding (force=True path), not raise.
        findings = LlmJudgeEngine().run(test, [], tmp_path)
        assert len(findings) == 1
        assert findings[0].status == "uncertain"
