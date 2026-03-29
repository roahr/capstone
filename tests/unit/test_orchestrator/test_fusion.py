"""
Tests for the score fusion engine (src.orchestrator.fusion).

Verifies default weights, CWE-specific weight loading, partial-stage
fusion, three-tier classification, and LLM override rules.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any

import pytest
import yaml

from src.orchestrator.fusion import ScoreFusionEngine
from src.sast.sarif.schema import (
    AttackerVerdict,
    DefenderVerdict,
    Finding,
    GraphValidation,
    LLMValidation,
    Severity,
    Verdict,
)


# ── Default weights ───────────────────────────────────────────────────────────

class TestDefaultWeights:
    def test_default_sast_weight(self):
        engine = ScoreFusionEngine()
        assert engine.default_sast_weight == pytest.approx(0.3)

    def test_default_gat_weight(self):
        engine = ScoreFusionEngine()
        assert engine.default_gat_weight == pytest.approx(0.3)

    def test_default_llm_weight(self):
        engine = ScoreFusionEngine()
        assert engine.default_llm_weight == pytest.approx(0.4)

    def test_get_weights_no_cwe_config(self):
        engine = ScoreFusionEngine()
        a, b, g = engine.get_weights("CWE-89")
        assert (a, b, g) == (0.3, 0.3, 0.4)


# ── CWE-specific weight loading ──────────────────────────────────────────────

class TestCWEWeightLoading:
    def test_load_from_yaml(self, tmp_path):
        yaml_data = {
            "CWE-89": {
                "sast_weight": 0.2,
                "gat_weight": 0.3,
                "llm_weight": 0.5,
            },
            "default": {
                "sast_weight": 0.35,
                "gat_weight": 0.35,
                "llm_weight": 0.30,
            },
        }
        yaml_path = tmp_path / "weights.yaml"
        yaml_path.write_text(yaml.dump(yaml_data))

        engine = ScoreFusionEngine(cwe_weights_path=str(yaml_path))
        a, b, g = engine.get_weights("CWE-89")
        assert (a, b, g) == (0.2, 0.3, 0.5)

    def test_default_key_fallback(self, tmp_path):
        yaml_data = {
            "default": {
                "sast_weight": 0.35,
                "gat_weight": 0.35,
                "llm_weight": 0.30,
            },
        }
        yaml_path = tmp_path / "weights.yaml"
        yaml_path.write_text(yaml.dump(yaml_data))

        engine = ScoreFusionEngine(cwe_weights_path=str(yaml_path))
        a, b, g = engine.get_weights("CWE-9999")
        assert (a, b, g) == (0.35, 0.35, 0.30)

    def test_missing_file_graceful(self):
        engine = ScoreFusionEngine(cwe_weights_path="/nonexistent/weights.yaml")
        # Should not raise; falls back to defaults
        a, b, g = engine.get_weights("CWE-89")
        assert (a, b, g) == (0.3, 0.3, 0.4)


# ── Fusion with varying stage availability ────────────────────────────────────

class TestPartialStageFusion:
    def test_sast_only(self):
        """Only SAST stage ran; weight renormalises to 1.0."""
        engine = ScoreFusionEngine()
        finding = Finding(sast_confidence=0.8, cwe_id="CWE-89")
        result = engine.fuse(finding)
        # renormalized: alpha=0.3 is the only weight -> score = 0.8 * (0.3/0.3)
        assert result.fused_score == pytest.approx(0.8)

    def test_sast_plus_graph(self):
        """SAST + Graph stages; LLM weight excluded from normalization."""
        engine = ScoreFusionEngine()
        finding = Finding(
            sast_confidence=0.8,
            cwe_id="CWE-89",
            graph_validation=GraphValidation(structural_risk_score=0.6),
        )
        result = engine.fuse(finding)
        # weights: 0.3 + 0.3 = 0.6 total
        # fused = 0.8*(0.3/0.6) + 0.6*(0.3/0.6) = 0.4 + 0.3 = 0.7
        assert result.fused_score == pytest.approx(0.7)

    def test_all_three_stages(self):
        """SAST + Graph + LLM."""
        engine = ScoreFusionEngine()
        finding = Finding(
            sast_confidence=0.9,
            cwe_id="CWE-89",
            graph_validation=GraphValidation(structural_risk_score=0.8),
            llm_validation=LLMValidation(consensus_confidence=0.95),
        )
        result = engine.fuse(finding)
        # 0.3*0.9 + 0.3*0.8 + 0.4*0.95 = 0.27 + 0.24 + 0.38 = 0.89
        assert result.fused_score == pytest.approx(0.89)

    def test_fused_score_clamped_to_01(self):
        engine = ScoreFusionEngine()
        finding = Finding(sast_confidence=1.0, cwe_id="CWE-89")
        result = engine.fuse(finding)
        assert 0.0 <= result.fused_score <= 1.0


# ── Three-tier classification ─────────────────────────────────────────────────

class TestThreeTierClassification:
    @pytest.mark.parametrize(
        "sast_conf, expected_verdict",
        [
            (0.95, Verdict.CONFIRMED),   # 0.95 >= 0.85
            (0.70, Verdict.LIKELY),      # 0.50 <= 0.70 < 0.85
            (0.30, Verdict.POTENTIAL),   # 0 < 0.30 < 0.50
        ],
    )
    def test_threshold_classification(self, sast_conf, expected_verdict):
        engine = ScoreFusionEngine()
        finding = Finding(sast_confidence=sast_conf, cwe_id="CWE-89")
        result = engine.fuse(finding)
        assert result.verdict == expected_verdict

    def test_zero_score_is_unknown(self):
        engine = ScoreFusionEngine()
        finding = Finding(sast_confidence=0.0, cwe_id="CWE-89")
        result = engine.fuse(finding)
        assert result.verdict == Verdict.UNKNOWN

    def test_custom_thresholds(self):
        engine = ScoreFusionEngine(
            config={
                "classification": {
                    "confirmed_threshold": 0.9,
                    "likely_threshold": 0.6,
                }
            }
        )
        finding = Finding(sast_confidence=0.85, cwe_id="CWE-89")
        result = engine.fuse(finding)
        # 0.85 >= 0.6 but < 0.9 -> LIKELY
        assert result.verdict == Verdict.LIKELY


# ── LLM override rules ───────────────────────────────────────────────────────

class TestLLMOverrideRules:
    def test_attacker_confirmed_low_defense(self):
        """Attacker exploitable + defense < 0.3 -> Confirmed regardless of score."""
        engine = ScoreFusionEngine()
        finding = Finding(
            sast_confidence=0.3,
            cwe_id="CWE-89",
            llm_validation=LLMValidation(
                attacker=AttackerVerdict(exploitable=True, confidence=0.9),
                defender=DefenderVerdict(defense_coverage_score=0.1),
                consensus_confidence=0.5,
            ),
        )
        result = engine.fuse(finding)
        assert result.verdict == Verdict.CONFIRMED

    def test_attacker_not_exploitable_high_defense(self):
        """Attacker not exploitable + defense > 0.8 -> Safe."""
        engine = ScoreFusionEngine()
        finding = Finding(
            sast_confidence=0.9,
            cwe_id="CWE-89",
            llm_validation=LLMValidation(
                attacker=AttackerVerdict(exploitable=False, confidence=0.1),
                defender=DefenderVerdict(defense_coverage_score=0.95),
                consensus_confidence=0.5,
            ),
        )
        result = engine.fuse(finding)
        assert result.verdict == Verdict.SAFE

    def test_no_llm_validation_no_override(self):
        """Without LLM data, standard thresholds apply."""
        engine = ScoreFusionEngine()
        finding = Finding(sast_confidence=0.3, cwe_id="CWE-89")
        result = engine.fuse(finding)
        assert result.verdict != Verdict.CONFIRMED


# ── Explanation generation ────────────────────────────────────────────────────

class TestExplanation:
    def test_explanation_populated(self):
        engine = ScoreFusionEngine()
        finding = Finding(
            sast_confidence=0.8,
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            sast_message="SQL injection via f-string",
        )
        result = engine.fuse(finding)
        assert result.nl_explanation
        assert "CWE-89" in result.nl_explanation
        assert "SAST confidence" in result.nl_explanation
        assert "Fused score" in result.nl_explanation

    def test_explanation_includes_graph_info(self):
        engine = ScoreFusionEngine()
        finding = Finding(
            sast_confidence=0.8,
            cwe_id="CWE-89",
            graph_validation=GraphValidation(
                structural_risk_score=0.7,
                conformal_prediction_set=["vulnerable"],
            ),
        )
        result = engine.fuse(finding)
        assert "Graph structural risk" in result.nl_explanation


# ── Batch fusion ──────────────────────────────────────────────────────────────

class TestBatchFusion:
    def test_batch_fuse_returns_same_length(self, sample_findings_batch):
        engine = ScoreFusionEngine()
        results = engine.batch_fuse(sample_findings_batch)
        assert len(results) == len(sample_findings_batch)

    def test_batch_fuse_all_have_verdict(self, sample_findings_batch):
        engine = ScoreFusionEngine()
        results = engine.batch_fuse(sample_findings_batch)
        for f in results:
            assert f.verdict in (
                Verdict.CONFIRMED, Verdict.LIKELY,
                Verdict.POTENTIAL, Verdict.SAFE, Verdict.UNKNOWN,
            )
