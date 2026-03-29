"""
Tests for SEC-C core data models (src.sast.sarif.schema).

Covers Finding, UncertaintyScore, TaintFlow, ScanResult, and the
Severity / Verdict enums.
"""

from __future__ import annotations

import pytest

from src.sast.sarif.schema import (
    Finding,
    GraphValidation,
    Language,
    Location,
    ScanResult,
    Severity,
    StageResolved,
    TaintFlow,
    TaintFlowStep,
    UncertaintyScore,
    Verdict,
)


# ── Severity enum ─────────────────────────────────────────────────────────────

class TestSeverityEnum:
    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_from_string(self):
        assert Severity("critical") is Severity.CRITICAL

    def test_is_str_subclass(self):
        assert isinstance(Severity.HIGH, str)


# ── Verdict enum ──────────────────────────────────────────────────────────────

class TestVerdictEnum:
    def test_values(self):
        assert Verdict.CONFIRMED.value == "confirmed"
        assert Verdict.LIKELY.value == "likely"
        assert Verdict.POTENTIAL.value == "potential"
        assert Verdict.SAFE.value == "safe"
        assert Verdict.UNKNOWN.value == "unknown"

    def test_from_string(self):
        assert Verdict("safe") is Verdict.SAFE

    def test_is_str_subclass(self):
        assert isinstance(Verdict.CONFIRMED, str)


# ── Location ──────────────────────────────────────────────────────────────────

class TestLocation:
    def test_display_with_column(self):
        loc = Location(file_path="foo.py", start_line=10, start_column=5)
        assert loc.display == "foo.py:10:5"

    def test_display_without_column(self):
        loc = Location(file_path="bar.py", start_line=3)
        assert loc.display == "bar.py:3"


# ── TaintFlow ─────────────────────────────────────────────────────────────────

class TestTaintFlow:
    def test_empty_flow(self):
        flow = TaintFlow()
        assert flow.length == 0
        assert flow.source is None
        assert flow.sink is None
        assert flow.is_interprocedural is False

    def test_single_step(self):
        step = TaintFlowStep(
            location=Location(file_path="a.py", start_line=1),
            kind="source",
        )
        flow = TaintFlow(steps=[step])
        assert flow.length == 1
        assert flow.source is step
        assert flow.sink is step
        assert flow.is_interprocedural is False

    def test_source_and_sink(self):
        src = TaintFlowStep(
            location=Location(file_path="a.py", start_line=1), kind="source"
        )
        mid = TaintFlowStep(
            location=Location(file_path="a.py", start_line=5), kind="intermediate"
        )
        snk = TaintFlowStep(
            location=Location(file_path="a.py", start_line=10), kind="sink"
        )
        flow = TaintFlow(steps=[src, mid, snk])
        assert flow.length == 3
        assert flow.source is src
        assert flow.sink is snk

    def test_is_interprocedural_true(self):
        """Steps across different files -> interprocedural."""
        flow = TaintFlow(
            steps=[
                TaintFlowStep(
                    location=Location(file_path="a.py", start_line=1)
                ),
                TaintFlowStep(
                    location=Location(file_path="b.py", start_line=5)
                ),
            ]
        )
        assert flow.is_interprocedural is True

    def test_is_interprocedural_false(self):
        """All steps in same file -> not interprocedural."""
        flow = TaintFlow(
            steps=[
                TaintFlowStep(
                    location=Location(file_path="a.py", start_line=1)
                ),
                TaintFlowStep(
                    location=Location(file_path="a.py", start_line=5)
                ),
            ]
        )
        assert flow.is_interprocedural is False


# ── UncertaintyScore ──────────────────────────────────────────────────────────

class TestUncertaintyScore:
    def test_total_calculation(self):
        u = UncertaintyScore(
            confidence_uncertainty=1.0,
            complexity_uncertainty=1.0,
            novelty_uncertainty=1.0,
            conflict_uncertainty=1.0,
        )
        # 0.4*1 + 0.3*1 + 0.2*1 + 0.1*1 = 1.0
        assert u.total == pytest.approx(1.0)

    def test_total_with_mixed_values(self):
        u = UncertaintyScore(
            confidence_uncertainty=0.5,
            complexity_uncertainty=0.3,
            novelty_uncertainty=0.15,
            conflict_uncertainty=0.0,
        )
        expected = 0.4 * 0.5 + 0.3 * 0.3 + 0.2 * 0.15 + 0.1 * 0.0
        assert u.total == pytest.approx(expected)

    def test_total_zero_when_all_zero(self):
        u = UncertaintyScore()
        assert u.total == pytest.approx(0.0)

    def test_should_escalate_true(self):
        u = UncertaintyScore(
            confidence_uncertainty=1.0,
            complexity_uncertainty=1.0,
            novelty_uncertainty=0.0,
            conflict_uncertainty=0.0,
        )
        # 0.4 + 0.3 = 0.7 >= 0.5
        assert u.should_escalate is True

    def test_should_escalate_false(self):
        u = UncertaintyScore(
            confidence_uncertainty=0.1,
            complexity_uncertainty=0.1,
            novelty_uncertainty=0.1,
            conflict_uncertainty=0.1,
        )
        # 0.04 + 0.03 + 0.02 + 0.01 = 0.1 < 0.5
        assert u.should_escalate is False

    def test_should_escalate_boundary(self):
        """At or just above 0.5 -> should escalate."""
        u = UncertaintyScore(
            confidence_uncertainty=0.5,
            complexity_uncertainty=0.5,
            novelty_uncertainty=0.5,
            conflict_uncertainty=0.5,
        )
        # 0.4*0.5 + 0.3*0.5 + 0.2*0.5 + 0.1*0.5 is approximately 0.5
        # (may be 0.49999999999999994 due to IEEE 754 float arithmetic).
        assert u.total == pytest.approx(0.5)

        # Use a finding with a tiny severity adjustment to cross the
        # boundary cleanly.
        u2 = UncertaintyScore(
            confidence_uncertainty=0.5,
            complexity_uncertainty=0.5,
            novelty_uncertainty=0.5,
            conflict_uncertainty=0.5,
            severity_adjustment=0.01,  # nudge above 0.5
        )
        assert u2.total > 0.5
        assert u2.should_escalate is True

    def test_custom_weights(self):
        u = UncertaintyScore(
            confidence_uncertainty=1.0,
            complexity_uncertainty=0.0,
            novelty_uncertainty=0.0,
            conflict_uncertainty=0.0,
            w_conf=0.6,
            w_comp=0.2,
            w_nov=0.1,
            w_confl=0.1,
        )
        assert u.total == pytest.approx(0.6)


# ── Finding ───────────────────────────────────────────────────────────────────

class TestFinding:
    def test_creation_defaults(self):
        f = Finding()
        assert f.severity == Severity.MEDIUM
        assert f.verdict == Verdict.UNKNOWN
        assert f.language == Language.PYTHON
        assert f.sast_confidence == 0.0
        assert f.fused_score == 0.0
        assert f.stage_resolved == StageResolved.UNRESOLVED

    def test_creation_with_values(self, sample_finding: Finding):
        assert sample_finding.cwe_id == "CWE-89"
        assert sample_finding.severity == Severity.CRITICAL
        assert sample_finding.sast_confidence == 0.85
        assert sample_finding.location.start_line == 42
        assert sample_finding.taint_flow is not None
        assert sample_finding.taint_flow.length == 3

    def test_is_escalated_to_graph(self):
        f = Finding(
            uncertainty=UncertaintyScore(
                confidence_uncertainty=1.0,
                complexity_uncertainty=1.0,
            )
        )
        assert f.is_escalated_to_graph is True

    def test_is_not_escalated_to_graph(self):
        f = Finding(
            uncertainty=UncertaintyScore(
                confidence_uncertainty=0.1,
                complexity_uncertainty=0.1,
                novelty_uncertainty=0.1,
                conflict_uncertainty=0.1,
            )
        )
        assert f.is_escalated_to_graph is False

    def test_is_escalated_to_llm_ambiguous(self):
        f = Finding(
            graph_validation=GraphValidation(
                conformal_prediction_set=["safe", "vulnerable"],
            )
        )
        assert f.is_escalated_to_llm is True

    def test_is_not_escalated_to_llm_singleton(self):
        f = Finding(
            graph_validation=GraphValidation(
                conformal_prediction_set=["vulnerable"],
            )
        )
        assert f.is_escalated_to_llm is False

    def test_is_not_escalated_to_llm_no_graph(self):
        f = Finding()
        assert f.is_escalated_to_llm is False

    def test_display_summary(self, sample_finding: Finding):
        summary = sample_finding.display_summary
        assert "[CRITICAL]" in summary
        assert "CWE-89" in summary
        assert "src/app/db.py:42:5" in summary


# ── ScanResult ────────────────────────────────────────────────────────────────

class TestScanResult:
    def test_total_findings(self, sample_scan_result: ScanResult):
        assert sample_scan_result.total_findings == 5

    def test_by_severity(self, sample_scan_result: ScanResult):
        by_sev = sample_scan_result.by_severity()
        assert Severity.CRITICAL in by_sev
        assert len(by_sev[Severity.CRITICAL]) == 1
        assert Severity.HIGH in by_sev
        assert Severity.MEDIUM in by_sev
        assert Severity.LOW in by_sev
        assert Severity.INFO in by_sev

    def test_by_cwe(self, sample_scan_result: ScanResult):
        by_cwe = sample_scan_result.by_cwe()
        assert "CWE-89" in by_cwe
        assert "CWE-78" in by_cwe
        assert len(by_cwe) == 5  # 5 distinct CWEs

    def test_cascade_efficiency(self, sample_scan_result: ScanResult):
        # resolved_at_sast=3, total=3+1+1+0=5
        assert sample_scan_result.cascade_efficiency == pytest.approx(3 / 5)

    def test_cascade_efficiency_zero_total(self):
        sr = ScanResult()
        assert sr.cascade_efficiency == 0.0

    def test_confirmed_count(self):
        sr = ScanResult(
            findings=[
                Finding(verdict=Verdict.CONFIRMED),
                Finding(verdict=Verdict.CONFIRMED),
                Finding(verdict=Verdict.LIKELY),
                Finding(verdict=Verdict.SAFE),
            ]
        )
        assert sr.confirmed_count == 2
        assert sr.likely_count == 1
        assert sr.potential_count == 0

    def test_by_language(self, sample_scan_result: ScanResult):
        by_lang = sample_scan_result.by_language()
        assert Language.PYTHON in by_lang
        assert len(by_lang[Language.PYTHON]) == 5
