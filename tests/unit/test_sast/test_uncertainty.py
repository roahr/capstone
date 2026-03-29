"""
Tests for the 4-factor uncertainty scorer (src.sast.uncertainty.scorer).

Verifies each uncertainty factor individually and the composite total,
as well as the escalation threshold behaviour.
"""

from __future__ import annotations

import pytest

from src.sast.sarif.schema import (
    Finding,
    GraphValidation,
    Location,
    Severity,
    TaintFlow,
    TaintFlowStep,
)
from src.sast.uncertainty.scorer import UncertaintyScorer


# ── Confidence uncertainty ────────────────────────────────────────────────────

class TestConfidenceUncertainty:
    """High SAST confidence -> low uncertainty; low confidence -> high."""

    @pytest.mark.parametrize(
        "sast_confidence, expected_uncertainty",
        [
            (0.9, 0.1),
            (1.0, 0.0),
            (0.0, 1.0),
            (0.5, 0.5),
            (0.75, 0.25),
        ],
    )
    def test_inverse_of_confidence(self, sast_confidence, expected_uncertainty):
        scorer = UncertaintyScorer()
        finding = Finding(sast_confidence=sast_confidence)
        result = scorer.score(finding)
        assert result.confidence_uncertainty == pytest.approx(
            expected_uncertainty, abs=1e-9
        )

    def test_high_confidence_low_uncertainty(self):
        scorer = UncertaintyScorer()
        finding = Finding(sast_confidence=0.95)
        result = scorer.score(finding)
        assert result.confidence_uncertainty < 0.1

    def test_low_confidence_high_uncertainty(self):
        scorer = UncertaintyScorer()
        finding = Finding(sast_confidence=0.1)
        result = scorer.score(finding)
        assert result.confidence_uncertainty > 0.8


# ── Complexity uncertainty ────────────────────────────────────────────────────

class TestComplexityUncertainty:
    """Simple paths -> low uncertainty; complex paths -> high."""

    def test_no_taint_flow(self):
        scorer = UncertaintyScorer()
        finding = Finding()
        result = scorer.score(finding)
        assert result.complexity_uncertainty == pytest.approx(0.0)

    def test_single_step_flow(self):
        scorer = UncertaintyScorer()
        finding = Finding(
            taint_flow=TaintFlow(
                steps=[
                    TaintFlowStep(
                        location=Location(file_path="a.py", start_line=1)
                    )
                ]
            )
        )
        result = scorer.score(finding)
        # hop_score = (1-1)/4 = 0, depth_score = 0 => avg = 0
        assert result.complexity_uncertainty == pytest.approx(0.0)

    def test_long_taint_path(self):
        scorer = UncertaintyScorer()
        steps = [
            TaintFlowStep(
                location=Location(file_path="a.py", start_line=i)
            )
            for i in range(6)  # 6 steps = 5 hops
        ]
        finding = Finding(taint_flow=TaintFlow(steps=steps))
        result = scorer.score(finding)
        # hop_score = (6-1)/4 = 1.0 (clamped), depth_score = 0 => avg = 0.5
        assert result.complexity_uncertainty == pytest.approx(0.5)

    def test_complex_interprocedural(self):
        """Interprocedural flow without graph validation -> depth heuristic of 2."""
        scorer = UncertaintyScorer()
        steps = [
            TaintFlowStep(
                location=Location(file_path="a.py", start_line=1)
            ),
            TaintFlowStep(
                location=Location(file_path="b.py", start_line=5)
            ),
            TaintFlowStep(
                location=Location(file_path="c.py", start_line=10)
            ),
        ]
        finding = Finding(taint_flow=TaintFlow(steps=steps))
        result = scorer.score(finding)
        # hop_score = (3-1)/4 = 0.5, depth_score = 2/5 = 0.4 => avg = 0.45
        assert result.complexity_uncertainty == pytest.approx(0.45)

    def test_with_graph_interprocedural_depth(self):
        """Graph validation provides explicit interprocedural depth."""
        scorer = UncertaintyScorer()
        steps = [
            TaintFlowStep(
                location=Location(file_path="a.py", start_line=1)
            ),
            TaintFlowStep(
                location=Location(file_path="a.py", start_line=5)
            ),
        ]
        finding = Finding(
            taint_flow=TaintFlow(steps=steps),
            graph_validation=GraphValidation(interprocedural_depth=4),
        )
        result = scorer.score(finding)
        # hop_score = (2-1)/4 = 0.25, depth_score = 4/5 = 0.8 => avg = 0.525
        assert result.complexity_uncertainty == pytest.approx(0.525)


# ── Novelty uncertainty ───────────────────────────────────────────────────────

class TestNoveltyUncertainty:
    """Common CWEs -> low novelty; rare CWEs -> high."""

    @pytest.mark.parametrize(
        "cwe_id",
        ["CWE-89", "CWE-78", "CWE-79", "CWE-502", "CWE-327", "CWE-798"],
    )
    def test_common_cwe_low_novelty(self, cwe_id):
        scorer = UncertaintyScorer()
        finding = Finding(cwe_id=cwe_id)
        result = scorer.score(finding)
        assert result.novelty_uncertainty == pytest.approx(0.15)

    @pytest.mark.parametrize(
        "cwe_id",
        ["CWE-1234", "CWE-9999", "CWE-42"],
    )
    def test_rare_cwe_high_novelty(self, cwe_id):
        scorer = UncertaintyScorer()
        finding = Finding(cwe_id=cwe_id)
        result = scorer.score(finding)
        assert result.novelty_uncertainty == pytest.approx(0.85)

    def test_missing_cwe_maximum_novelty(self):
        scorer = UncertaintyScorer()
        finding = Finding(cwe_id="")
        result = scorer.score(finding)
        assert result.novelty_uncertainty == pytest.approx(1.0)

    def test_bare_number_normalized(self):
        """CWE ID without 'CWE-' prefix is normalised."""
        scorer = UncertaintyScorer()
        finding = Finding(cwe_id="89")
        result = scorer.score(finding)
        assert result.novelty_uncertainty == pytest.approx(0.15)


# ── Conflict uncertainty ──────────────────────────────────────────────────────

class TestConflictUncertainty:
    def test_single_tool_no_conflict(self):
        scorer = UncertaintyScorer()
        finding = Finding()
        result = scorer.score(finding)
        assert result.conflict_uncertainty == pytest.approx(0.0)

    def test_corroborating_no_verdicts(self):
        scorer = UncertaintyScorer()
        finding = Finding(
            properties={"corroborating_tools": ["semgrep"]},
        )
        result = scorer.score(finding)
        assert result.conflict_uncertainty == pytest.approx(0.5)

    def test_all_tools_agree(self):
        scorer = UncertaintyScorer()
        finding = Finding(
            properties={
                "corroborating_tools": ["semgrep", "snyk"],
                "tool_verdicts": {
                    "codeql": "vulnerable",
                    "semgrep": "vulnerable",
                    "snyk": "vulnerable",
                },
            },
        )
        result = scorer.score(finding)
        assert result.conflict_uncertainty == pytest.approx(0.1)

    def test_hard_disagreement(self):
        scorer = UncertaintyScorer()
        finding = Finding(
            properties={
                "corroborating_tools": ["semgrep"],
                "tool_verdicts": {
                    "codeql": "vulnerable",
                    "semgrep": "safe",
                },
            },
        )
        result = scorer.score(finding)
        assert result.conflict_uncertainty == pytest.approx(1.0)

    def test_soft_disagreement(self):
        scorer = UncertaintyScorer()
        finding = Finding(
            properties={
                "corroborating_tools": ["semgrep"],
                "tool_verdicts": {
                    "codeql": "likely",
                    "semgrep": "potential",
                },
            },
        )
        result = scorer.score(finding)
        assert result.conflict_uncertainty == pytest.approx(0.5)


# ── Total score & escalation ──────────────────────────────────────────────────

class TestTotalScoreAndEscalation:
    def test_total_respects_weights(self):
        scorer = UncertaintyScorer()
        finding = Finding(
            sast_confidence=0.5,  # conf_u = 0.5
            cwe_id="CWE-89",     # novelty = 0.15
        )
        result = scorer.score(finding)
        expected = 0.4 * 0.5 + 0.3 * 0.0 + 0.2 * 0.15 + 0.1 * 0.0
        assert result.total == pytest.approx(expected)

    def test_custom_weights(self):
        scorer = UncertaintyScorer(
            config={"weights": {"confidence": 1.0, "complexity": 0.0, "novelty": 0.0, "conflict": 0.0}}
        )
        finding = Finding(sast_confidence=0.3)
        result = scorer.score(finding)
        assert result.total == pytest.approx(0.7)

    def test_score_written_back_to_finding(self):
        scorer = UncertaintyScorer()
        finding = Finding(sast_confidence=0.5)
        result = scorer.score(finding)
        assert finding.uncertainty is result

    def test_escalation_threshold_met(self):
        scorer = UncertaintyScorer()
        finding = Finding(sast_confidence=0.0, cwe_id="CWE-9999")
        result = scorer.score(finding)
        # conf_u=1.0, novelty=0.85 -> total = 0.4*1 + 0.2*0.85 = 0.57 >= 0.5
        assert result.should_escalate is True

    def test_escalation_threshold_not_met(self):
        scorer = UncertaintyScorer()
        finding = Finding(sast_confidence=0.95, cwe_id="CWE-89")
        result = scorer.score(finding)
        # conf_u=0.05, novelty=0.15 -> total = 0.02 + 0.03 = 0.05 < 0.5
        assert result.should_escalate is False
