"""
Score Fusion Engine: Combines scores from all pipeline stages.

Implements the novel fusion formula:
    final_score = α × sast_confidence + β × gat_risk_score + γ × llm_consensus_score

With CWE-specific weight adaptation for optimal per-category performance.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from src.sast.sarif.schema import Finding, Verdict

logger = logging.getLogger(__name__)


class ScoreFusionEngine:
    """
    Fuses confidence scores from SAST, Graph, and LLM stages into a
    unified vulnerability score with three-tier classification.

    The fusion weights are adapted per CWE category. Initial weights are
    based on domain expertise. Run scripts/calibrate_weights.py to
    calibrate on labeled data.
    - Injection flaws (CWE-78, 79, 89): LLM-heavy (better context understanding)
    - Crypto weaknesses (CWE-327, 328): SAST-heavy (LLM struggles with crypto)
    - Memory safety (CWE-416, 476): Graph-heavy (structural analysis)
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        cwe_weights_path: str | None = None,
    ):
        self.config = config or {}

        # Default fusion weights
        fusion_config = self.config.get("fusion", {})
        self.default_sast_weight = fusion_config.get("sast_weight", 0.3)
        self.default_gat_weight = fusion_config.get("gat_weight", 0.3)
        self.default_llm_weight = fusion_config.get("llm_weight", 0.4)

        # Classification thresholds
        class_config = self.config.get("classification", {})
        self.confirmed_threshold = class_config.get("confirmed_threshold", 0.85)
        self.likely_threshold = class_config.get("likely_threshold", 0.50)

        # Load CWE-specific weights
        self.cwe_weights: dict[str, dict[str, float]] = {}
        if cwe_weights_path:
            self._load_cwe_weights(cwe_weights_path)

    def _load_cwe_weights(self, path: str) -> None:
        """Load CWE-specific fusion weights from YAML config."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            for key, value in data.items():
                if isinstance(value, dict) and "sast_weight" in value:
                    self.cwe_weights[key] = value
            logger.info(f"Loaded CWE-specific weights for {len(self.cwe_weights)} categories")
        except Exception as e:
            logger.warning(f"Could not load CWE weights from {path}: {e}")

    def get_weights(self, cwe_id: str) -> tuple[float, float, float]:
        """
        Get fusion weights (α, β, γ) for a specific CWE.

        Returns CWE-specific weights if available, otherwise defaults.
        """
        if cwe_id in self.cwe_weights:
            w = self.cwe_weights[cwe_id]
            return w["sast_weight"], w["gat_weight"], w["llm_weight"]

        if "default" in self.cwe_weights:
            w = self.cwe_weights["default"]
            return w["sast_weight"], w["gat_weight"], w["llm_weight"]

        return self.default_sast_weight, self.default_gat_weight, self.default_llm_weight

    def fuse(self, finding: Finding) -> Finding:
        """
        Compute fused score and classify a finding.

        Formula: final = α·SAST + β·GAT + γ·LLM
        Where weights are CWE-adapted.
        """
        alpha, beta, gamma = self.get_weights(finding.cwe_id)

        # Get component scores
        sast_score = finding.sast_confidence

        gat_score = 0.0
        if finding.graph_validation:
            gat_score = finding.graph_validation.structural_risk_score

        llm_score = 0.0
        if finding.llm_validation:
            llm_score = finding.llm_validation.consensus_confidence

        # Normalize weights based on which stages were executed
        stages_run = []
        weights = []

        stages_run.append(("sast", sast_score, alpha))
        weights.append(alpha)

        if finding.graph_validation is not None:
            stages_run.append(("graph", gat_score, beta))
            weights.append(beta)

        if finding.llm_validation is not None:
            stages_run.append(("llm", llm_score, gamma))
            weights.append(gamma)

        # Renormalize weights to sum to 1.0
        total_weight = sum(weights)
        if total_weight == 0:
            finding.fused_score = sast_score
        else:
            fused = sum(score * (weight / total_weight) for _, score, weight in stages_run)
            finding.fused_score = min(max(fused, 0.0), 1.0)

        # Classify into three tiers
        finding.verdict = self._classify(finding.fused_score, finding)

        # Generate explanation
        finding.nl_explanation = self._generate_explanation(finding, stages_run)

        return finding

    def _classify(self, score: float, finding: Finding) -> Verdict:
        """
        Classify finding into three tiers based on fused score.

        Special rules:
        - If LLM attacker confirmed exploit -> Confirmed regardless of score
        - If LLM defender confirmed safe -> Safe regardless of score
        """
        # LLM override rules
        if finding.llm_validation:
            llm = finding.llm_validation
            if llm.attacker.exploitable and llm.defender.defense_coverage_score < 0.3:
                return Verdict.CONFIRMED
            if not llm.attacker.exploitable and llm.defender.defense_coverage_score > 0.8:
                return Verdict.SAFE

        # Standard threshold classification
        if score >= self.confirmed_threshold:
            return Verdict.CONFIRMED
        elif score >= self.likely_threshold:
            return Verdict.LIKELY
        elif score > 0.0:
            return Verdict.POTENTIAL
        else:
            return Verdict.UNKNOWN

    def _generate_explanation(
        self, finding: Finding, stages: list[tuple[str, float, float]]
    ) -> str:
        """Generate a natural language explanation of the fusion result."""
        parts = []

        parts.append(f"{finding.cwe_id} ({finding.cwe_name}): {finding.sast_message}")

        # Stage-by-stage reasoning
        for stage_name, score, weight in stages:
            if stage_name == "sast":
                parts.append(f"SAST confidence: {score:.0%} (weight: {weight:.0%})")
            elif stage_name == "graph":
                parts.append(f"Graph structural risk: {score:.0%} (weight: {weight:.0%})")
                if finding.graph_validation:
                    gv = finding.graph_validation
                    cp_set = ", ".join(gv.conformal_prediction_set)
                    parts.append(f"  Conformal prediction set: {{{cp_set}}}")
            elif stage_name == "llm":
                parts.append(f"LLM consensus confidence: {score:.0%} (weight: {weight:.0%})")
                if finding.llm_validation:
                    lv = finding.llm_validation
                    parts.append(f"  Attacker: {'exploitable' if lv.attacker.exploitable else 'not exploitable'}")
                    parts.append(f"  Defender: coverage {lv.defender.defense_coverage_score:.0%}")

        parts.append(f"Fused score: {finding.fused_score:.2f} -> Verdict: {finding.verdict.value}")

        return "\n".join(parts)

    def batch_fuse(self, findings: list[Finding]) -> list[Finding]:
        """Fuse scores for a batch of findings."""
        return [self.fuse(f) for f in findings]
