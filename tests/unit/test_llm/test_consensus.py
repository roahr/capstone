"""
Tests for the consensus engine (src.llm.consensus.engine).

Verifies the dual-agent consensus rules, confidence calculation,
and explanation generation. All Gemini API calls are mocked.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.llm.consensus.engine import ConsensusEngine
from src.sast.sarif.schema import (
    AttackerVerdict,
    DefenderVerdict,
    Finding,
    Location,
    Severity,
    Verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_attacker(
    exploitable: bool = False,
    confidence: float = 0.8,
    payload: str | None = None,
    blocking_factors: list[str] | None = None,
    reasoning: str = "attacker reasoning",
) -> AttackerVerdict:
    return AttackerVerdict(
        exploitable=exploitable,
        confidence=confidence,
        payload=payload,
        blocking_factors=blocking_factors or [],
        reasoning=reasoning,
    )


def _make_defender(
    defense_coverage_score: float = 0.5,
    path_feasible: bool = True,
    sanitizers_found: list[dict] | None = None,
    access_controls: list[str] | None = None,
    framework_protections: list[str] | None = None,
    reasoning: str = "defender reasoning",
) -> DefenderVerdict:
    return DefenderVerdict(
        defense_coverage_score=defense_coverage_score,
        path_feasible=path_feasible,
        sanitizers_found=sanitizers_found or [],
        access_controls=access_controls or [],
        framework_protections=framework_protections or [],
        reasoning=reasoning,
    )


@pytest.fixture
def mock_gemini_client() -> MagicMock:
    """A fully mocked GeminiClient that never touches the network."""
    client = MagicMock()
    client.model_pro = "gemini-2.5-pro"
    client.model_flash = "gemini-2.5-flash"
    client.generate = AsyncMock(return_value={})
    return client


@pytest.fixture
def consensus_engine(mock_gemini_client: MagicMock) -> ConsensusEngine:
    """ConsensusEngine wired to a mock Gemini client."""
    with patch("src.llm.consensus.engine.AttackerAgent"), \
         patch("src.llm.consensus.engine.DefenderAgent"):
        engine = ConsensusEngine(client=mock_gemini_client)
    return engine


# ── Rule 1: Confirmed ────────────────────────────────────────────────────────

class TestRule1Confirmed:
    """attacker.exploitable=True AND defender.defense_coverage < 0.5 -> CONFIRMED"""

    def test_basic_confirmed(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=True, confidence=0.9)
        defender = _make_defender(defense_coverage_score=0.2)

        verdict, confidence = consensus_engine._apply_consensus(attacker, defender)

        assert verdict == Verdict.CONFIRMED
        assert 0.0 < confidence <= 1.0

    @pytest.mark.parametrize("defense_score", [0.0, 0.1, 0.3, 0.49])
    def test_confirmed_various_low_defense(
        self, consensus_engine: ConsensusEngine, defense_score: float
    ):
        attacker = _make_attacker(exploitable=True, confidence=0.85)
        defender = _make_defender(defense_coverage_score=defense_score)

        verdict, _ = consensus_engine._apply_consensus(attacker, defender)
        assert verdict == Verdict.CONFIRMED

    def test_confirmed_confidence_calculation(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=True, confidence=0.9)
        defender = _make_defender(defense_coverage_score=0.2)

        _, confidence = consensus_engine._apply_consensus(attacker, defender)

        # confidence = max(atk_confidence, 1.0 - def_coverage) = max(0.9, 0.8) = 0.9
        assert confidence == pytest.approx(0.9)


# ── Rule 2: Safe ─────────────────────────────────────────────────────────────

class TestRule2Safe:
    """attacker.exploitable=False AND defender.defense_coverage > 0.7 -> SAFE"""

    def test_basic_safe(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=False, confidence=0.1)
        defender = _make_defender(defense_coverage_score=0.9)

        verdict, confidence = consensus_engine._apply_consensus(attacker, defender)

        assert verdict == Verdict.SAFE
        assert 0.0 < confidence <= 1.0

    @pytest.mark.parametrize("defense_score", [0.71, 0.8, 0.95, 1.0])
    def test_safe_various_high_defense(
        self, consensus_engine: ConsensusEngine, defense_score: float
    ):
        attacker = _make_attacker(exploitable=False, confidence=0.2)
        defender = _make_defender(defense_coverage_score=defense_score)

        verdict, _ = consensus_engine._apply_consensus(attacker, defender)
        assert verdict == Verdict.SAFE

    def test_safe_confidence_calculation(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=False, confidence=0.1)
        defender = _make_defender(defense_coverage_score=0.9)

        _, confidence = consensus_engine._apply_consensus(attacker, defender)

        # confidence = max(def_coverage, 1.0 - atk_confidence) = max(0.9, 0.9) = 0.9
        assert confidence == pytest.approx(0.9)


# ── Rule 3: Likely ───────────────────────────────────────────────────────────

class TestRule3Likely:
    """attacker.exploitable=True AND defender.defense_coverage >= 0.5 -> LIKELY"""

    def test_basic_likely(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=True, confidence=0.7)
        defender = _make_defender(defense_coverage_score=0.6)

        verdict, confidence = consensus_engine._apply_consensus(attacker, defender)

        assert verdict == Verdict.LIKELY
        assert 0.3 <= confidence <= 0.85

    @pytest.mark.parametrize("defense_score", [0.5, 0.6, 0.7, 0.8, 1.0])
    def test_likely_various_defense_coverage(
        self, consensus_engine: ConsensusEngine, defense_score: float
    ):
        attacker = _make_attacker(exploitable=True, confidence=0.7)
        defender = _make_defender(defense_coverage_score=defense_score)

        verdict, _ = consensus_engine._apply_consensus(attacker, defender)
        assert verdict == Verdict.LIKELY

    def test_likely_confidence_bounded(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=True, confidence=0.99)
        defender = _make_defender(defense_coverage_score=0.5)

        _, confidence = consensus_engine._apply_consensus(attacker, defender)

        # Clamped between 0.3 and 0.85
        assert 0.3 <= confidence <= 0.85


# ── Rule 4: Potential ────────────────────────────────────────────────────────

class TestRule4Potential:
    """attacker.exploitable=False AND defender.defense_coverage <= 0.7 -> POTENTIAL"""

    def test_basic_potential(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=False, confidence=0.3)
        defender = _make_defender(defense_coverage_score=0.4)

        verdict, confidence = consensus_engine._apply_consensus(attacker, defender)

        assert verdict == Verdict.POTENTIAL
        assert 0.2 <= confidence <= 0.6

    @pytest.mark.parametrize("defense_score", [0.0, 0.2, 0.5, 0.7])
    def test_potential_various_defense_coverage(
        self, consensus_engine: ConsensusEngine, defense_score: float
    ):
        attacker = _make_attacker(exploitable=False, confidence=0.3)
        defender = _make_defender(defense_coverage_score=defense_score)

        verdict, _ = consensus_engine._apply_consensus(attacker, defender)
        assert verdict == Verdict.POTENTIAL

    def test_potential_confidence_bounded(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=False, confidence=0.0)
        defender = _make_defender(defense_coverage_score=0.0)

        _, confidence = consensus_engine._apply_consensus(attacker, defender)

        assert 0.2 <= confidence <= 0.6


# ── Rule 2b: Path not feasible -> Safe ───────────────────────────────────────

class TestRule2bPathNotFeasible:
    """path_feasible=False AND not exploitable -> SAFE with 0.8 confidence"""

    def test_path_not_feasible_safe(self, consensus_engine: ConsensusEngine):
        attacker = _make_attacker(exploitable=False, confidence=0.3)
        defender = _make_defender(defense_coverage_score=0.4, path_feasible=False)

        verdict, confidence = consensus_engine._apply_consensus(attacker, defender)

        assert verdict == Verdict.SAFE
        assert confidence == pytest.approx(0.8)

    def test_path_not_feasible_but_exploitable_not_safe(
        self, consensus_engine: ConsensusEngine
    ):
        """If the attacker succeeded, path_feasible=False doesn't override to SAFE."""
        attacker = _make_attacker(exploitable=True, confidence=0.9)
        defender = _make_defender(defense_coverage_score=0.2, path_feasible=False)

        verdict, _ = consensus_engine._apply_consensus(attacker, defender)

        # Rule 1 triggers first (exploitable + low defense)
        assert verdict == Verdict.CONFIRMED


# ── Explanation generation ───────────────────────────────────────────────────

class TestExplanationGeneration:
    """Verify that _build_explanation includes attacker and defender details."""

    def test_explanation_includes_attacker_info(self, consensus_engine: ConsensusEngine):
        finding = Finding(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            location=Location(file_path="app.py", start_line=10),
        )
        attacker = _make_attacker(
            exploitable=True,
            confidence=0.9,
            payload="' OR 1=1 --",
            blocking_factors=["none"],
            reasoning="SQL injection via f-string concatenation",
        )
        defender = _make_defender(
            defense_coverage_score=0.2,
            sanitizers_found=[{"function": "escape_string"}],
            access_controls=["auth_required"],
            framework_protections=["CSRF token"],
            reasoning="Insufficient sanitization",
        )

        explanation = consensus_engine._build_explanation(
            finding, attacker, defender, Verdict.CONFIRMED, 0.9
        )

        assert "Attacker Analysis" in explanation
        assert "Exploitable: YES" in explanation
        assert "' OR 1=1 --" in explanation
        assert "Blocking factors:" in explanation

    def test_explanation_includes_defender_info(self, consensus_engine: ConsensusEngine):
        finding = Finding(
            cwe_id="CWE-79",
            cwe_name="XSS",
            location=Location(file_path="view.py", start_line=5),
        )
        attacker = _make_attacker(exploitable=False, confidence=0.1)
        defender = _make_defender(
            defense_coverage_score=0.9,
            sanitizers_found=[{"function": "html.escape"}],
            access_controls=["role_check"],
            framework_protections=["CSP header"],
            reasoning="Strong defensive posture",
        )

        explanation = consensus_engine._build_explanation(
            finding, attacker, defender, Verdict.SAFE, 0.9
        )

        assert "Defender Analysis" in explanation
        assert "Defense Coverage: 90%" in explanation
        assert "Sanitizers: html.escape" in explanation
        assert "Access Controls: role_check" in explanation
        assert "Framework Protections: CSP header" in explanation
        assert "Path Feasible: YES" in explanation

    def test_explanation_includes_consensus_verdict(
        self, consensus_engine: ConsensusEngine
    ):
        finding = Finding(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            location=Location(file_path="db.py", start_line=42),
        )
        attacker = _make_attacker(exploitable=True, confidence=0.9)
        defender = _make_defender(defense_coverage_score=0.2)

        explanation = consensus_engine._build_explanation(
            finding, attacker, defender, Verdict.CONFIRMED, 0.9
        )

        assert "Consensus" in explanation
        assert "CONFIRMED" in explanation
        assert "CWE-89" in explanation

    def test_explanation_handles_missing_optional_fields(
        self, consensus_engine: ConsensusEngine
    ):
        finding = Finding(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            location=Location(file_path="db.py", start_line=42),
        )
        attacker = _make_attacker(
            exploitable=False, payload=None, reasoning=""
        )
        defender = _make_defender(defense_coverage_score=0.5, reasoning="")

        explanation = consensus_engine._build_explanation(
            finding, attacker, defender, Verdict.POTENTIAL, 0.5
        )

        # Should not crash; should contain placeholder reasoning
        assert "no attacker reasoning" in explanation or "Attacker Analysis" in explanation


# ── Full validate flow (agents mocked) ───────────────────────────────────────

class TestValidateFlow:
    """Test the full validate() method with mocked agents."""

    async def test_validate_attaches_llm_validation(
        self, consensus_engine: ConsensusEngine
    ):
        finding = Finding(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            location=Location(file_path="app.py", start_line=10),
        )

        # Mock agent responses
        consensus_engine.attacker.analyze = AsyncMock(
            return_value=_make_attacker(exploitable=True, confidence=0.9)
        )
        consensus_engine.defender.analyze = AsyncMock(
            return_value=_make_defender(defense_coverage_score=0.2)
        )

        result = await consensus_engine.validate(finding)

        assert result.llm_validation is not None
        assert result.llm_validation.consensus_verdict == Verdict.CONFIRMED
        assert result.llm_validation.attacker.exploitable is True
        assert result.llm_validation.defender.defense_coverage_score == pytest.approx(0.2)
        assert result.verdict == Verdict.CONFIRMED

    async def test_validate_sets_model_used(
        self, consensus_engine: ConsensusEngine
    ):
        finding = Finding(
            cwe_id="CWE-79",
            cwe_name="XSS",
            location=Location(file_path="view.py", start_line=5),
        )

        consensus_engine.attacker.analyze = AsyncMock(
            return_value=_make_attacker(exploitable=False)
        )
        consensus_engine.defender.analyze = AsyncMock(
            return_value=_make_defender(defense_coverage_score=0.9)
        )

        result = await consensus_engine.validate(finding)

        assert result.llm_validation.model_used == "gemini-2.5-pro"

    async def test_validate_populates_explanation(
        self, consensus_engine: ConsensusEngine
    ):
        finding = Finding(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            location=Location(file_path="db.py", start_line=42),
        )

        consensus_engine.attacker.analyze = AsyncMock(
            return_value=_make_attacker(exploitable=True, confidence=0.8)
        )
        consensus_engine.defender.analyze = AsyncMock(
            return_value=_make_defender(defense_coverage_score=0.3)
        )

        result = await consensus_engine.validate(finding)

        assert result.llm_validation.nl_explanation
        assert "CWE-89" in result.llm_validation.nl_explanation
