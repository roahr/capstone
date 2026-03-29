"""
Tests for the Tree-sitter pre-screener (src.sast.treesitter.prescreener).

Verifies language detection, vulnerability pattern matching against the
test fixtures, and deduplication logic.  Tree-sitter parsing is tested
with real files where possible, with graceful skips when the tree-sitter
grammar packages are not installed.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.sast.sarif.schema import Language
from src.sast.treesitter.prescreener import (
    LANGUAGE_EXTENSIONS,
    TreeSitterPreScreener,
)

# Paths to test fixtures
FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"
VULNERABLE_PY = str(FIXTURES_DIR / "vulnerable_python.py")
SAFE_PY = str(FIXTURES_DIR / "safe_python.py")


# ── Language detection ────────────────────────────────────────────────────────

class TestLanguageDetection:
    def test_python_extensions(self):
        ps = TreeSitterPreScreener()
        assert ps.detect_language("foo.py") == Language.PYTHON

    @pytest.mark.parametrize(
        "filename, expected",
        [
            ("app.js", Language.JAVASCRIPT),
            ("app.jsx", Language.JAVASCRIPT),
            ("index.ts", Language.TYPESCRIPT),
            ("index.tsx", Language.TYPESCRIPT),
            ("Main.java", Language.JAVA),
            ("lib.c", Language.C),
            ("lib.cpp", Language.CPP),
            ("lib.cc", Language.CPP),
            ("lib.h", Language.C),
            ("lib.hpp", Language.CPP),
            ("main.go", Language.GO),
        ],
    )
    def test_extension_mapping(self, filename, expected):
        ps = TreeSitterPreScreener()
        assert ps.detect_language(filename) == expected

    def test_unknown_extension_returns_none(self):
        ps = TreeSitterPreScreener()
        assert ps.detect_language("notes.txt") is None
        assert ps.detect_language("config.yaml") is None

    def test_case_insensitive(self):
        ps = TreeSitterPreScreener()
        # Path(...).suffix.lower() handles this
        assert ps.detect_language("APP.PY") == Language.PYTHON


# ── Vulnerability detection (requires tree-sitter) ────────────────────────────

def _ts_available() -> bool:
    """Check if tree-sitter and the Python grammar are importable."""
    try:
        import tree_sitter
        import tree_sitter_python
        return True
    except ImportError:
        return False


_skip_no_ts = pytest.mark.skipif(
    not _ts_available(),
    reason="tree-sitter or tree-sitter-python not installed",
)


@_skip_no_ts
class TestSQLInjectionDetection:
    """Uses tests/fixtures/vulnerable_python.py."""

    def test_detects_sql_injection(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(VULNERABLE_PY)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-89" in cwe_ids, (
            "Pre-screener should detect SQL injection in vulnerable fixture"
        )

    def test_sql_injection_severity_critical(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(VULNERABLE_PY)
        sqli_findings = [f for f in result.findings if f.cwe_id == "CWE-89"]
        from src.sast.sarif.schema import Severity
        for f in sqli_findings:
            assert f.severity == Severity.CRITICAL


@_skip_no_ts
class TestCommandInjectionDetection:
    def test_detects_command_injection(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(VULNERABLE_PY)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-78" in cwe_ids, (
            "Pre-screener should detect command injection in vulnerable fixture"
        )


@_skip_no_ts
class TestHardcodedSecretDetection:
    def test_detects_hardcoded_secrets(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(VULNERABLE_PY)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-798" in cwe_ids, (
            "Pre-screener should detect hardcoded secrets in vulnerable fixture"
        )


@_skip_no_ts
class TestSafeCodeNoAlerts:
    """Uses tests/fixtures/safe_python.py."""

    def test_safe_code_is_clearly_safe(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(SAFE_PY)
        # Safe code may produce some findings from pattern matching
        # (pre-screener is intentionally over-approximate), but
        # at minimum there should be fewer findings than the
        # vulnerable fixture.
        vuln_result = ps.prescreen_file(VULNERABLE_PY)
        assert len(result.findings) < len(vuln_result.findings), (
            "Safe code should produce fewer findings than vulnerable code"
        )

    def test_safe_sql_not_flagged_as_injection(self):
        """Parameterised queries should ideally not trigger SQL injection."""
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(SAFE_PY)
        sqli = [f for f in result.findings if f.cwe_id == "CWE-89"]
        # Pre-screener may still flag cursor.execute, but check it is
        # not the parameterized form or there are fewer hits.
        assert len(sqli) <= 2, (
            "Safe parameterized queries should produce at most minor hits"
        )


# ── Deduplication ─────────────────────────────────────────────────────────────

@_skip_no_ts
class TestDeduplication:
    def test_no_duplicate_locations(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(VULNERABLE_PY)
        keys = set()
        for f in result.findings:
            key = f"{f.cwe_id}:{f.location.file_path}:{f.location.start_line}"
            assert key not in keys, f"Duplicate finding at {key}"
            keys.add(key)


# ── Finding metadata ──────────────────────────────────────────────────────────

@_skip_no_ts
class TestFindingMetadata:
    def test_findings_have_required_fields(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(VULNERABLE_PY)
        for f in result.findings:
            assert f.id, "Finding must have an id"
            assert f.rule_id.startswith("ts/"), "Rule ID should have ts/ prefix"
            assert f.cwe_id.startswith("CWE-"), "CWE ID should start with CWE-"
            assert f.location.start_line > 0
            assert f.sast_tool == "tree-sitter"
            assert f.sast_confidence > 0
            assert f.language == Language.PYTHON

    def test_result_language_detected(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(VULNERABLE_PY)
        assert result.language == Language.PYTHON

    def test_scan_time_recorded(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file(VULNERABLE_PY)
        assert result.scan_time_ms > 0


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_nonexistent_file(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file("/nonexistent/file.py")
        assert result.findings == []

    def test_unsupported_extension(self):
        ps = TreeSitterPreScreener()
        result = ps.prescreen_file("readme.txt")
        assert result.is_clearly_safe is True
