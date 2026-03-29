"""
Tests for the SARIF parser (src.sast.sarif.parser).

Uses an inline SARIF document to verify parsing of findings, CWE
extraction from CodeQL tags, severity mapping, taint flow extraction,
confidence extraction, and language detection.
"""

from __future__ import annotations

import json

import pytest

from src.sast.sarif.parser import SARIFParser
from src.sast.sarif.schema import Language, Severity


# ── Inline SARIF fixture ──────────────────────────────────────────────────────

MOCK_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "version": "2.18.0",
                    "rules": [
                        {
                            "id": "py/sql-injection",
                            "shortDescription": {"text": "SQL Injection"},
                            "fullDescription": {
                                "text": "User input flows into SQL query"
                            },
                            "defaultConfiguration": {"level": "error"},
                            "properties": {
                                "tags": [
                                    "security",
                                    "external/cwe/cwe-89",
                                ],
                                "precision": "high",
                            },
                        },
                        {
                            "id": "py/xss",
                            "shortDescription": {"text": "Cross-site Scripting"},
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {
                                "tags": [
                                    "security",
                                    "external/cwe/cwe-79",
                                ],
                                "precision": "medium",
                            },
                        },
                        {
                            "id": "py/log-info",
                            "shortDescription": {"text": "Verbose Logging"},
                            "defaultConfiguration": {"level": "note"},
                            "properties": {
                                "tags": ["maintainability"],
                            },
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "py/sql-injection",
                    "level": "error",
                    "message": {"text": "SQL injection via f-string"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/db.py"},
                                "region": {
                                    "startLine": 42,
                                    "endLine": 42,
                                    "startColumn": 5,
                                    "endColumn": 60,
                                    "snippet": {
                                        "text": 'cursor.execute(f"SELECT ...")'
                                    },
                                },
                            }
                        }
                    ],
                    "codeFlows": [
                        {
                            "threadFlows": [
                                {
                                    "locations": [
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "src/views.py"
                                                    },
                                                    "region": {"startLine": 10},
                                                },
                                                "message": {"text": "user input"},
                                            },
                                        },
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "src/helpers.py"
                                                    },
                                                    "region": {"startLine": 22},
                                                },
                                                "message": {"text": "passes through helper"},
                                            },
                                        },
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "src/db.py"
                                                    },
                                                    "region": {"startLine": 42},
                                                },
                                                "message": {"text": "SQL sink"},
                                            },
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                },
                {
                    "ruleId": "py/xss",
                    "level": "warning",
                    "message": {"text": "Reflected XSS in template"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "src/templates/page.html"
                                },
                                "region": {"startLine": 15},
                            }
                        }
                    ],
                    "properties": {"confidence": 0.72},
                },
                {
                    "ruleId": "py/log-info",
                    "level": "note",
                    "message": {"text": "Excessive logging statement"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "src/logger.go"
                                },
                                "region": {"startLine": 5},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}


@pytest.fixture
def parser() -> SARIFParser:
    return SARIFParser()


@pytest.fixture
def sarif_string() -> str:
    return json.dumps(MOCK_SARIF)


# ── parse_string produces correct Findings ────────────────────────────────────

class TestParseString:
    def test_returns_correct_count(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        assert len(findings) == 3

    def test_finding_has_rule_id(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        rule_ids = {f.rule_id for f in findings}
        assert "py/sql-injection" in rule_ids
        assert "py/xss" in rule_ids

    def test_finding_has_message(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        assert sqli.sast_message == "SQL injection via f-string"

    def test_tool_name_extracted(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        assert all(f.sast_tool == "CodeQL" for f in findings)

    def test_finding_has_deterministic_id(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        ids = [f.id for f in findings]
        assert all(len(fid) == 16 for fid in ids)
        # IDs should be deterministic — parse again and compare
        findings2 = parser.parse_string(sarif_string)
        assert [f.id for f in findings] == [f.id for f in findings2]

    def test_invalid_json_raises(self, parser):
        with pytest.raises(Exception):
            parser.parse_string("not json")

    def test_non_dict_raises(self, parser):
        with pytest.raises(ValueError, match="top-level JSON object"):
            parser.parse_string("[1,2,3]")


# ── CWE extraction from CodeQL tags ──────────────────────────────────────────

class TestCWEExtraction:
    def test_codeql_tag_format(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        assert sqli.cwe_id == "CWE-89"
        assert sqli.cwe_name == "SQL Injection"

    def test_cwe_79_extracted(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        xss = [f for f in findings if f.rule_id == "py/xss"][0]
        assert xss.cwe_id == "CWE-79"

    def test_no_cwe_tag(self, parser, sarif_string):
        """Rule with no CWE tag -> empty cwe_id."""
        findings = parser.parse_string(sarif_string)
        log = [f for f in findings if f.rule_id == "py/log-info"][0]
        assert log.cwe_id == ""

    def test_explicit_cwe_property(self, parser):
        """Rule with explicit 'cwe' property."""
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Tool",
                            "rules": [
                                {
                                    "id": "r1",
                                    "shortDescription": {"text": "Deser"},
                                    "properties": {"cwe": "CWE-502"},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "r1",
                            "message": {"text": "deser"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        findings = parser.parse_string(json.dumps(sarif))
        assert findings[0].cwe_id == "CWE-502"


# ── Severity mapping ─────────────────────────────────────────────────────────

class TestSeverityMapping:
    @pytest.mark.parametrize(
        "sarif_level, expected_severity",
        [
            ("error", Severity.HIGH),
            ("warning", Severity.MEDIUM),
            ("note", Severity.LOW),
            ("none", Severity.INFO),
        ],
    )
    def test_level_to_severity(self, sarif_level, expected_severity):
        assert SARIFParser._map_severity(sarif_level) == expected_severity

    def test_unknown_level_defaults_to_medium(self):
        assert SARIFParser._map_severity("unknown") == Severity.MEDIUM

    def test_from_parsed_findings(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        assert sqli.severity == Severity.HIGH  # "error" -> HIGH

        xss = [f for f in findings if f.rule_id == "py/xss"][0]
        assert xss.severity == Severity.MEDIUM  # "warning" -> MEDIUM

        log = [f for f in findings if f.rule_id == "py/log-info"][0]
        assert log.severity == Severity.LOW  # "note" -> LOW


# ── Taint flow extraction from codeFlows ──────────────────────────────────────

class TestTaintFlowExtraction:
    def test_taint_flow_present(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        assert sqli.taint_flow is not None

    def test_taint_flow_length(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        assert sqli.taint_flow.length == 3

    def test_taint_flow_source_and_sink(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        tf = sqli.taint_flow
        assert tf.source.kind == "source"
        assert tf.source.location.file_path == "src/views.py"
        assert tf.sink.kind == "sink"
        assert tf.sink.location.file_path == "src/db.py"

    def test_taint_flow_is_interprocedural(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        assert sqli.taint_flow.is_interprocedural is True

    def test_no_code_flow_returns_none(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        xss = [f for f in findings if f.rule_id == "py/xss"][0]
        assert xss.taint_flow is None

    def test_taint_flow_labels(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        labels = [s.label for s in sqli.taint_flow.steps]
        assert "user input" in labels
        assert "SQL sink" in labels


# ── Confidence extraction ─────────────────────────────────────────────────────

class TestConfidenceExtraction:
    def test_explicit_confidence_property(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        xss = [f for f in findings if f.rule_id == "py/xss"][0]
        assert xss.sast_confidence == pytest.approx(0.72)

    def test_precision_based_confidence(self, parser, sarif_string):
        """SQL injection rule has precision=high -> 0.85."""
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        assert sqli.sast_confidence == pytest.approx(0.85)

    @pytest.mark.parametrize(
        "precision, expected",
        [
            ("very-high", 0.95),
            ("high", 0.85),
            ("medium", 0.65),
            ("low", 0.40),
        ],
    )
    def test_precision_mapping(self, precision, expected):
        from src.sast.sarif.parser import _PRECISION_TO_CONFIDENCE
        assert _PRECISION_TO_CONFIDENCE[precision] == expected


# ── Language detection from file paths ────────────────────────────────────────

class TestLanguageDetection:
    @pytest.mark.parametrize(
        "file_path, expected",
        [
            ("src/app.py", Language.PYTHON),
            ("src/app.js", Language.JAVASCRIPT),
            ("src/app.ts", Language.TYPESCRIPT),
            ("src/App.java", Language.JAVA),
            ("src/main.cpp", Language.CPP),
            ("src/main.c", Language.C),
            ("src/main.go", Language.GO),
        ],
    )
    def test_language_from_extension(self, file_path, expected):
        assert SARIFParser._detect_language(file_path) == expected

    def test_empty_path_defaults_to_python(self):
        assert SARIFParser._detect_language("") == Language.PYTHON

    def test_unknown_extension_defaults_to_python(self):
        assert SARIFParser._detect_language("file.xyz") == Language.PYTHON

    def test_language_in_parsed_finding(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        assert sqli.language == Language.PYTHON

        log = [f for f in findings if f.rule_id == "py/log-info"][0]
        assert log.language == Language.GO  # file is logger.go


# ── Location extraction ──────────────────────────────────────────────────────

class TestLocationExtraction:
    def test_full_location(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
        loc = sqli.location
        assert loc.file_path == "src/db.py"
        assert loc.start_line == 42
        assert loc.end_line == 42
        assert loc.start_column == 5
        assert loc.end_column == 60
        assert loc.snippet == 'cursor.execute(f"SELECT ...")'

    def test_minimal_location(self, parser, sarif_string):
        findings = parser.parse_string(sarif_string)
        xss = [f for f in findings if f.rule_id == "py/xss"][0]
        loc = xss.location
        assert loc.file_path == "src/templates/page.html"
        assert loc.start_line == 15
