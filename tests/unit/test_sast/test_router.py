"""
Tests for the escalation router (src.sast.router).

Verifies that findings are routed correctly between pipeline stages
based on severity-adjusted uncertainty, taint complexity, and conformal
prediction ambiguity.
"""

from __future__ import annotations

import pytest

from src.sast.router import EscalationRouter, RoutingStats
from src.sast.sarif.schema import (
    Finding,
    GraphValidation,
    Language,
    Location,
    Severity,
    StageResolved,
    TaintFlow,
    TaintFlowStep,
    Verdict,
)


# -- Helper factories --------------------------------------------------------

def _make_finding(
    *,
    severity: Severity = Severity.MEDIUM,
    sast_confidence: float = 0.9,
    cwe_id: str = "CWE-89",
    taint_steps: list[TaintFlowStep] | None = None,
) -> Finding:
    """Build a minimal Finding for routing tests."""
    return Finding(
        rule_id="test-rule",
        cwe_id=cwe_id,
        severity=severity,
        language=Language.PYTHON,
        location=Location(file_path="test.py", start_line=1),
        sast_confidence=sast_confidence,
        taint_flow=TaintFlow(steps=taint_steps) if taint_steps else None,
    )


def _make_interprocedural_flow() -> TaintFlow:
    return TaintFlow(
        steps=[
            TaintFlowStep(
                location=Location(file_path="a.py", start_line=1), kind="source"
            ),
            TaintFlowStep(
                location=Location(file_path="b.py", start_line=5), kind="sink"
            ),
        ]
    )


# -- Low-uncertainty findings resolved at SAST --------------------------------

class TestLowUncertaintyResolved:
    def test_high_confidence_common_cwe_resolved(self):
        """High-confidence finding for common CWE with medium severity -> SAST."""
        router = EscalationRouter()
        finding = _make_finding(
            severity=Severity.MEDIUM,
            sast_confidence=0.95,
            cwe_id="CWE-89",
        )
        resolved, escalated = router.route([finding])
        assert len(resolved) == 1
        assert len(escalated) == 0
        assert finding.stage_resolved == StageResolved.SAST
        assert finding.verdict == Verdict.SAFE

    def test_resolved_stats_tracked(self):
        router = EscalationRouter()
        finding = _make_finding(
            severity=Severity.LOW, sast_confidence=0.95
        )
        router.route([finding])
        assert router.stats.total_processed == 1
        assert router.stats.resolved_count == 1
        assert router.stats.escalated_count == 0


# -- High-uncertainty findings escalated ---------------------------------------

class TestHighUncertaintyEscalated:
    def test_low_confidence_rare_cwe_escalated(self):
        """Low confidence + rare CWE -> high uncertainty -> escalated."""
        router = EscalationRouter()
        finding = _make_finding(
            severity=Severity.MEDIUM,
            sast_confidence=0.1,
            cwe_id="CWE-9999",
        )
        resolved, escalated = router.route([finding])
        assert len(escalated) == 1
        assert len(resolved) == 0
        assert router.stats.escalated_by_uncertainty >= 1


# -- Severity adjustment affects escalation ------------------------------------

class TestSeverityAdjustment:
    def test_critical_severity_boosts_uncertainty(self):
        """CRITICAL severity adds +0.15 to uncertainty score, may cause escalation."""
        router = EscalationRouter()
        finding = _make_finding(
            severity=Severity.CRITICAL, sast_confidence=0.99
        )
        router.route([finding])
        # The severity adjustment (+0.15) is applied to the uncertainty score
        assert finding.uncertainty.severity_adjustment == pytest.approx(0.15)

    def test_high_severity_boosts_uncertainty(self):
        """HIGH severity adds +0.10 to uncertainty score."""
        router = EscalationRouter()
        finding = _make_finding(
            severity=Severity.HIGH, sast_confidence=0.99
        )
        router.route([finding])
        assert finding.uncertainty.severity_adjustment == pytest.approx(0.10)

    def test_low_severity_reduces_uncertainty(self):
        """LOW severity subtracts 0.05 from uncertainty score."""
        router = EscalationRouter()
        finding = _make_finding(
            severity=Severity.LOW, sast_confidence=0.95
        )
        router.route([finding])
        assert finding.uncertainty.severity_adjustment == pytest.approx(-0.05)

    def test_medium_severity_no_adjustment(self):
        """MEDIUM severity has 0.0 adjustment."""
        router = EscalationRouter()
        finding = _make_finding(
            severity=Severity.MEDIUM, sast_confidence=0.95
        )
        router.route([finding])
        assert finding.uncertainty.severity_adjustment == pytest.approx(0.0)

    def test_critical_with_low_confidence_escalates_due_to_boost(self):
        """CRITICAL with low confidence and rare CWE escalates; the +0.15
        boost pushes it over the threshold that MEDIUM would not cross."""
        router = EscalationRouter()
        # Low confidence (0.3) for a rare CWE -> base uncertainty is high,
        # +0.15 CRITICAL boost further ensures escalation.
        finding_crit = _make_finding(
            severity=Severity.CRITICAL,
            sast_confidence=0.3,
            cwe_id="CWE-9999",
        )
        # Same parameters but MEDIUM severity for comparison
        finding_med = _make_finding(
            severity=Severity.MEDIUM,
            sast_confidence=0.3,
            cwe_id="CWE-9999",
        )
        _, escalated = router.route([finding_crit])
        assert len(escalated) == 1
        # Verify the CRITICAL score is higher than it would be for MEDIUM
        router2 = EscalationRouter()
        router2.route([finding_med])
        assert finding_crit.uncertainty.total > finding_med.uncertainty.total

    def test_interprocedural_critical_always_escalates(self):
        """Interprocedural + CRITICAL is always escalated regardless of U_score."""
        router = EscalationRouter()
        finding = Finding(
            rule_id="test",
            cwe_id="CWE-89",
            severity=Severity.CRITICAL,
            language=Language.PYTHON,
            location=Location(file_path="a.py", start_line=1),
            sast_confidence=0.99,
            taint_flow=_make_interprocedural_flow(),
        )
        _, escalated = router.route([finding])
        assert len(escalated) == 1


# -- Long taint paths escalate ------------------------------------------------

class TestLongTaintPathEscalates:
    def test_path_longer_than_threshold_escalates(self):
        router = EscalationRouter(
            config={
                "taint_length_threshold": 3,
            }
        )
        steps = [
            TaintFlowStep(
                location=Location(file_path="a.py", start_line=i)
            )
            for i in range(5)  # 5 steps > threshold 3
        ]
        finding = _make_finding(sast_confidence=0.95, taint_steps=steps)
        _, escalated = router.route([finding])
        assert len(escalated) == 1
        assert router.stats.escalated_by_taint_length >= 1

    def test_short_path_not_escalated_by_length(self):
        router = EscalationRouter(
            config={
                "taint_length_threshold": 3,
            }
        )
        steps = [
            TaintFlowStep(
                location=Location(file_path="a.py", start_line=i)
            )
            for i in range(2)  # 2 steps <= threshold 3
        ]
        finding = _make_finding(sast_confidence=0.95, taint_steps=steps)
        resolved, _ = router.route([finding])
        assert len(resolved) == 1


# -- Interprocedural findings escalate ----------------------------------------

class TestInterproceduralEscalates:
    def test_cross_file_taint_escalates(self):
        router = EscalationRouter()
        finding = Finding(
            rule_id="test",
            cwe_id="CWE-89",
            severity=Severity.MEDIUM,
            language=Language.PYTHON,
            location=Location(file_path="a.py", start_line=1),
            sast_confidence=0.95,
            taint_flow=_make_interprocedural_flow(),
        )
        _, escalated = router.route([finding])
        assert len(escalated) == 1
        assert router.stats.escalated_by_interprocedural >= 1


# -- route_from_graph: conformal prediction routing ----------------------------

class TestRouteFromGraph:
    def test_singleton_vulnerable_resolved(self):
        router = EscalationRouter()
        finding = Finding(
            graph_validation=GraphValidation(
                conformal_prediction_set=["vulnerable"],
            )
        )
        resolved, escalated = router.route_from_graph([finding])
        assert len(resolved) == 1
        assert len(escalated) == 0
        assert finding.stage_resolved == StageResolved.GRAPH
        assert finding.verdict == Verdict.LIKELY

    def test_singleton_safe_resolved(self):
        router = EscalationRouter()
        finding = Finding(
            graph_validation=GraphValidation(
                conformal_prediction_set=["safe"],
            )
        )
        resolved, _ = router.route_from_graph([finding])
        assert len(resolved) == 1
        assert finding.verdict == Verdict.SAFE

    def test_ambiguous_set_escalated(self):
        router = EscalationRouter()
        finding = Finding(
            graph_validation=GraphValidation(
                conformal_prediction_set=["safe", "vulnerable"],
            )
        )
        _, escalated = router.route_from_graph([finding])
        assert len(escalated) == 1
        assert router.stats.escalated_by_ambiguous_prediction >= 1

    def test_no_graph_validation_escalated(self):
        """Finding without graph_validation should escalate."""
        router = EscalationRouter()
        finding = Finding()
        _, escalated = router.route_from_graph([finding])
        assert len(escalated) == 1

    def test_empty_prediction_set_unknown(self):
        router = EscalationRouter()
        finding = Finding(
            graph_validation=GraphValidation(conformal_prediction_set=[])
        )
        resolved, _ = router.route_from_graph([finding])
        assert len(resolved) == 1
        assert finding.verdict == Verdict.UNKNOWN


# -- Routing statistics --------------------------------------------------------

class TestRoutingStats:
    def test_initial_stats_zero(self):
        stats = RoutingStats()
        assert stats.total_processed == 0
        assert stats.escalation_rate == 0.0

    def test_escalation_rate(self):
        router = EscalationRouter()
        findings = [
            # Low confidence + rare CWE + CRITICAL boost -> will escalate
            _make_finding(severity=Severity.CRITICAL, sast_confidence=0.1, cwe_id="CWE-9999"),
            _make_finding(
                severity=Severity.MEDIUM,
                sast_confidence=0.95,
                cwe_id="CWE-89",
            ),
        ]
        router.route(findings)
        assert router.stats.total_processed == 2
        assert router.stats.escalated_count >= 1

    def test_reset_stats(self):
        router = EscalationRouter()
        router.route([_make_finding(severity=Severity.CRITICAL)])
        assert router.stats.total_processed > 0
        router.reset_stats()
        assert router.stats.total_processed == 0
        assert router.stats.escalated_count == 0

    def test_mixed_batch_stats(self):
        router = EscalationRouter()
        findings = [
            # Low confidence + rare CWE + CRITICAL -> escalates
            _make_finding(severity=Severity.CRITICAL, sast_confidence=0.1, cwe_id="CWE-9999"),
            _make_finding(severity=Severity.LOW, sast_confidence=0.99),
            _make_finding(severity=Severity.LOW, sast_confidence=0.99),
        ]
        resolved, escalated = router.route(findings)
        assert router.stats.total_processed == 3
        assert len(escalated) >= 1
        assert len(resolved) + len(escalated) == 3
