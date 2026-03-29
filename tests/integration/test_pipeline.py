"""
Integration tests for the full SEC-C cascade pipeline
(src.orchestrator.pipeline).

Verifies the PipelineOrchestrator with mock modules for SAST, Graph,
and LLM stages. All external tools, APIs, and GPU dependencies are
mocked.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.orchestrator.fusion import ScoreFusionEngine
from src.orchestrator.pipeline import CascadeStats, PipelineOrchestrator
from src.reporting.html_reporter import HTMLReporter
from src.reporting.sarif_reporter import SARIFReporter
from src.sast.sarif.schema import (
    AttackerVerdict,
    DefenderVerdict,
    Finding,
    GraphValidation,
    Language,
    LLMValidation,
    Location,
    ScanResult,
    Severity,
    StageResolved,
    TaintFlow,
    TaintFlowStep,
    UncertaintyScore,
    Verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    *,
    id: str = "f-001",
    cwe_id: str = "CWE-89",
    cwe_name: str = "SQL Injection",
    severity: Severity = Severity.CRITICAL,
    sast_confidence: float = 0.85,
    uncertainty_total_high: bool = True,
    language: Language = Language.PYTHON,
) -> Finding:
    """Create a synthetic finding with controllable uncertainty."""
    if uncertainty_total_high:
        # Total >= 0.5 so it escalates to graph
        uncertainty = UncertaintyScore(
            confidence_uncertainty=0.7,
            complexity_uncertainty=0.8,
            novelty_uncertainty=0.3,
            conflict_uncertainty=0.2,
        )
    else:
        # Total < 0.5 so it resolves at SAST
        uncertainty = UncertaintyScore(
            confidence_uncertainty=0.1,
            complexity_uncertainty=0.1,
            novelty_uncertainty=0.1,
            conflict_uncertainty=0.0,
        )

    return Finding(
        id=id,
        rule_id="py/sql-injection",
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        severity=severity,
        language=language,
        location=Location(file_path="app.py", start_line=42),
        sast_confidence=sast_confidence,
        sast_message="SQL injection via f-string",
        uncertainty=uncertainty,
    )


def _make_graph_validated_finding(
    finding: Finding,
    *,
    ambiguous: bool = True,
    risk_score: float = 0.7,
) -> Finding:
    """Attach graph validation to a finding."""
    if ambiguous:
        pred_set = ["safe", "vulnerable"]
    else:
        pred_set = ["vulnerable"]

    finding.graph_validation = GraphValidation(
        structural_risk_score=risk_score,
        conformal_prediction_set=pred_set,
        conformal_coverage=0.9,
        taint_path_length=3,
    )
    return finding


def _make_llm_validated_finding(
    finding: Finding,
    *,
    exploitable: bool = True,
    defense_coverage: float = 0.2,
    consensus_verdict: Verdict = Verdict.CONFIRMED,
) -> Finding:
    """Attach LLM validation to a finding."""
    finding.llm_validation = LLMValidation(
        attacker=AttackerVerdict(
            exploitable=exploitable,
            confidence=0.9,
            reasoning="test attacker reasoning",
        ),
        defender=DefenderVerdict(
            defense_coverage_score=defense_coverage,
            reasoning="test defender reasoning",
        ),
        consensus_verdict=consensus_verdict,
        consensus_confidence=0.85,
        model_used="gemini-2.5-pro",
    )
    finding.verdict = consensus_verdict
    return finding


# ---------------------------------------------------------------------------
# Mock modules
# ---------------------------------------------------------------------------

class MockSASTEngine:
    """Mock SAST engine that returns pre-configured findings."""

    def __init__(self, findings: list[Finding]):
        self._findings = findings

    async def analyze(
        self, target: str, languages: list | None, github_repo: str | None
    ) -> list[Finding]:
        return self._findings


class MockGraphValidator:
    """Mock graph validator that attaches synthetic graph validation."""

    def __init__(self, ambiguous: bool = True, risk_score: float = 0.7):
        self._ambiguous = ambiguous
        self._risk_score = risk_score

    async def validate(self, finding: Finding) -> Finding:
        return _make_graph_validated_finding(
            finding, ambiguous=self._ambiguous, risk_score=self._risk_score
        )


class MockLLMValidator:
    """Mock LLM validator that attaches synthetic LLM validation."""

    def __init__(
        self,
        exploitable: bool = True,
        defense_coverage: float = 0.2,
        verdict: Verdict = Verdict.CONFIRMED,
    ):
        self._exploitable = exploitable
        self._defense = defense_coverage
        self._verdict = verdict

    async def validate(self, finding: Finding) -> Finding:
        return _make_llm_validated_finding(
            finding,
            exploitable=self._exploitable,
            defense_coverage=self._defense,
            consensus_verdict=self._verdict,
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def orchestrator() -> PipelineOrchestrator:
    return PipelineOrchestrator()


# ── CascadeStats ─────────────────────────────────────────────────────────────

class TestCascadeStats:
    def test_default_zeros(self):
        stats = CascadeStats()
        assert stats.total_findings == 0
        assert stats.resolved_sast == 0
        assert stats.resolved_graph == 0
        assert stats.resolved_llm == 0
        assert stats.unresolved == 0

    def test_cascade_efficiency(self):
        stats = CascadeStats(total_findings=10, resolved_sast=6)
        assert stats.cascade_efficiency == pytest.approx(0.6)

    def test_cascade_efficiency_zero(self):
        stats = CascadeStats()
        assert stats.cascade_efficiency == 0.0

    def test_graph_resolution_rate(self):
        stats = CascadeStats(escalated_to_graph=8, resolved_graph=4)
        assert stats.graph_resolution_rate == pytest.approx(0.5)

    def test_llm_resolution_rate(self):
        stats = CascadeStats(escalated_to_llm=5, resolved_llm=5)
        assert stats.llm_resolution_rate == pytest.approx(1.0)

    def test_summary_keys(self):
        stats = CascadeStats(total_findings=10, resolved_sast=3)
        summary = stats.summary()
        assert "total_findings" in summary
        assert "resolved_at_sast" in summary
        assert "cascade_efficiency" in summary


# ── Pipeline with mock modules ───────────────────────────────────────────────

class TestPipelineOrchestrator:
    """Test the orchestrator with fully mocked SAST/Graph/LLM modules."""

    async def test_scan_with_no_engines_returns_empty(self, orchestrator):
        result = await orchestrator.scan("/tmp/test")
        assert result.total_findings == 0
        assert result.findings == []

    @patch("src.sast.router.EscalationRouter")
    async def test_sast_only_scan(self, MockRouter, orchestrator):
        """Findings that resolve at SAST never reach Graph or LLM."""
        findings = [
            _make_finding(id="f-001", severity=Severity.LOW, uncertainty_total_high=False),
            _make_finding(id="f-002", severity=Severity.INFO, uncertainty_total_high=False),
        ]

        # Configure router: all findings resolve at SAST, none escalated
        mock_router_instance = MagicMock()
        mock_router_instance.route.return_value = (findings, [])
        MockRouter.return_value = mock_router_instance

        orchestrator.set_sast_engine(MockSASTEngine(findings))

        result = await orchestrator.scan("/tmp/test", max_stage="sast")

        assert result.total_findings == 2
        assert result.resolved_at_sast == 2
        assert result.resolved_at_graph == 0
        assert result.resolved_at_llm == 0

    @patch("src.sast.router.EscalationRouter")
    async def test_full_cascade_all_stages(self, MockRouter, orchestrator):
        """Finding escalates through all three stages."""
        findings = [
            _make_finding(id="f-001", uncertainty_total_high=True),
        ]

        # SAST router: nothing resolved, 1 escalated
        mock_router = MagicMock()
        mock_router.route.return_value = ([], findings)
        # Graph router: nothing resolved, 1 escalated to LLM
        mock_router.route_from_graph.return_value = ([], findings)
        MockRouter.return_value = mock_router

        orchestrator.set_sast_engine(MockSASTEngine(findings))
        orchestrator.set_graph_validator(MockGraphValidator(ambiguous=True))
        orchestrator.set_llm_validator(MockLLMValidator())

        result = await orchestrator.scan("/tmp/test")

        assert result.total_findings == 1
        assert result.resolved_at_llm == 1

    @patch("src.sast.router.EscalationRouter")
    async def test_cascade_statistics_tracked(self, MockRouter, orchestrator):
        """Statistics are properly counted across all stages."""
        resolved_sast = [_make_finding(id="f-res", uncertainty_total_high=False)]
        escalated = [
            _make_finding(id="f-esc-1", uncertainty_total_high=True),
            _make_finding(id="f-esc-2", uncertainty_total_high=True),
        ]
        all_findings = resolved_sast + escalated

        mock_router = MagicMock()
        mock_router.route.return_value = (resolved_sast, escalated)
        # Graph resolves 1, escalates 1
        mock_router.route_from_graph.return_value = ([escalated[0]], [escalated[1]])
        MockRouter.return_value = mock_router

        orchestrator.set_sast_engine(MockSASTEngine(all_findings))
        orchestrator.set_graph_validator(MockGraphValidator(ambiguous=True))
        orchestrator.set_llm_validator(MockLLMValidator())

        result = await orchestrator.scan("/tmp/test")

        assert result.total_findings == 3
        assert result.resolved_at_sast == 1
        assert result.resolved_at_graph == 1
        assert result.resolved_at_llm == 1

    @patch("src.sast.router.EscalationRouter")
    async def test_graph_resolves_without_llm(self, MockRouter, orchestrator):
        """Findings resolved at graph stage never reach LLM."""
        findings = [_make_finding(id="f-001")]

        mock_router = MagicMock()
        mock_router.route.return_value = ([], findings)
        # Graph resolves the finding (unambiguous prediction set)
        mock_router.route_from_graph.return_value = (findings, [])
        MockRouter.return_value = mock_router

        orchestrator.set_sast_engine(MockSASTEngine(findings))
        orchestrator.set_graph_validator(MockGraphValidator(ambiguous=False))
        # No LLM validator set

        result = await orchestrator.scan("/tmp/test")

        assert result.resolved_at_graph == 1
        assert result.resolved_at_llm == 0

    @patch("src.sast.router.EscalationRouter")
    async def test_max_stage_graph_stops_before_llm(self, MockRouter, orchestrator):
        """max_stage='graph' prevents LLM from running."""
        findings = [_make_finding(id="f-001")]

        mock_router = MagicMock()
        mock_router.route.return_value = ([], findings)
        mock_router.route_from_graph.return_value = ([], findings)
        MockRouter.return_value = mock_router

        orchestrator.set_sast_engine(MockSASTEngine(findings))
        orchestrator.set_graph_validator(MockGraphValidator(ambiguous=True))
        orchestrator.set_llm_validator(MockLLMValidator())

        result = await orchestrator.scan("/tmp/test", max_stage="graph")

        # LLM should not have run
        assert result.resolved_at_llm == 0


# ── Score fusion integration ─────────────────────────────────────────────────

class TestScoreFusionIntegration:
    """Test that score fusion produces valid outputs end-to-end."""

    def test_fused_score_in_valid_range(self):
        engine = ScoreFusionEngine()
        finding = _make_finding(id="f-fuse")
        _make_graph_validated_finding(finding, ambiguous=False, risk_score=0.7)
        _make_llm_validated_finding(finding, exploitable=True, defense_coverage=0.1)

        result = engine.fuse(finding)

        assert 0.0 <= result.fused_score <= 1.0

    @pytest.mark.parametrize(
        "sast_conf, expected_verdict",
        [
            (0.95, Verdict.CONFIRMED),
            (0.70, Verdict.LIKELY),
            (0.30, Verdict.POTENTIAL),
        ],
    )
    def test_three_tier_classification(self, sast_conf, expected_verdict):
        engine = ScoreFusionEngine()
        finding = Finding(sast_confidence=sast_conf, cwe_id="CWE-89")

        result = engine.fuse(finding)

        assert result.verdict == expected_verdict

    def test_all_three_stages_fuse(self):
        engine = ScoreFusionEngine()
        finding = _make_finding(id="f-all3", sast_confidence=0.9)
        _make_graph_validated_finding(finding, risk_score=0.8)
        _make_llm_validated_finding(finding, consensus_verdict=Verdict.CONFIRMED)
        finding.llm_validation.consensus_confidence = 0.95

        result = engine.fuse(finding)

        # 0.3*0.9 + 0.3*0.8 + 0.4*0.95 = 0.27 + 0.24 + 0.38 = 0.89
        assert result.fused_score == pytest.approx(0.89)
        assert 0.0 <= result.fused_score <= 1.0

    @patch("src.sast.router.EscalationRouter")
    async def test_pipeline_with_score_fuser(self, MockRouter):
        """Score fuser runs on all findings after cascade completes."""
        findings = [
            _make_finding(id="f-001"),
            _make_finding(id="f-002"),
        ]

        mock_router = MagicMock()
        mock_router.route.return_value = ([], findings)
        mock_router.route_from_graph.return_value = ([], findings)
        MockRouter.return_value = mock_router

        fuser = ScoreFusionEngine()
        orch = PipelineOrchestrator()
        orch.set_sast_engine(MockSASTEngine(findings))
        orch.set_graph_validator(MockGraphValidator())
        orch.set_llm_validator(MockLLMValidator())
        orch.set_score_fuser(fuser)

        result = await orch.scan("/tmp/test")

        for f in result.findings:
            assert 0.0 <= f.fused_score <= 1.0


# ── SARIF report generation ──────────────────────────────────────────────────

class TestSARIFReportGeneration:
    """Test SARIF 2.1.0 report generation from ScanResult."""

    @pytest.fixture
    def scan_result(self) -> ScanResult:
        findings = [
            Finding(
                id="sarif-001",
                rule_id="py/sql-injection",
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                severity=Severity.CRITICAL,
                verdict=Verdict.CONFIRMED,
                language=Language.PYTHON,
                location=Location(file_path="app.py", start_line=42, start_column=5),
                sast_confidence=0.9,
                sast_message="SQL injection via f-string",
                fused_score=0.88,
                stage_resolved=StageResolved.LLM,
            ),
            Finding(
                id="sarif-002",
                rule_id="py/xss",
                cwe_id="CWE-79",
                cwe_name="Cross-site Scripting",
                severity=Severity.MEDIUM,
                verdict=Verdict.SAFE,
                language=Language.PYTHON,
                location=Location(file_path="view.py", start_line=10),
                sast_confidence=0.5,
                sast_message="Reflected XSS",
                fused_score=0.3,
                stage_resolved=StageResolved.GRAPH,
            ),
        ]
        return ScanResult(
            findings=findings,
            scan_target="/tmp/test-project",
            languages_detected=[Language.PYTHON],
            total_files_scanned=10,
            total_lines_scanned=2000,
            scan_duration_ms=500.0,
            resolved_at_sast=0,
            resolved_at_graph=1,
            resolved_at_llm=1,
            unresolved=0,
        )

    def test_sarif_structure(self, scan_result):
        reporter = SARIFReporter()
        sarif = reporter.generate(scan_result)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_has_results(self, scan_result):
        reporter = SARIFReporter()
        sarif = reporter.generate(scan_result)

        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_result_fields(self, scan_result):
        reporter = SARIFReporter()
        sarif = reporter.generate(scan_result)

        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "py/sql-injection"
        assert result["level"] == "error"
        assert result["message"]["text"] == "SQL injection via f-string"
        assert "locations" in result

    def test_sarif_custom_properties(self, scan_result):
        reporter = SARIFReporter()
        sarif = reporter.generate(scan_result)

        props = sarif["runs"][0]["results"][0]["properties"]
        assert "sec-c/verdict" in props
        assert props["sec-c/verdict"] == "confirmed"
        assert "sec-c/fused_confidence" in props
        assert "sec-c/stage_resolved" in props

    def test_sarif_cascade_stats_in_invocation(self, scan_result):
        reporter = SARIFReporter()
        sarif = reporter.generate(scan_result)

        invocation = sarif["runs"][0]["invocations"][0]
        cascade = invocation["properties"]["sec-c/cascade_stats"]
        assert cascade["total_findings"] == 2
        assert cascade["resolved_at_graph"] == 1
        assert cascade["resolved_at_llm"] == 1

    def test_sarif_rules_collected(self, scan_result):
        reporter = SARIFReporter()
        sarif = reporter.generate(scan_result)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "py/sql-injection" in rule_ids
        assert "py/xss" in rule_ids

    def test_sarif_write_to_file(self, scan_result, tmp_path):
        reporter = SARIFReporter()
        output_path = str(tmp_path / "report.sarif")

        written_path = reporter.write(scan_result, output_path)

        assert Path(written_path).exists()
        with open(written_path) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 2


# ── HTML report generation ───────────────────────────────────────────────────

class TestHTMLReportGeneration:
    """Test HTML report generation from ScanResult."""

    @pytest.fixture
    def scan_result(self) -> ScanResult:
        findings = [
            Finding(
                id="html-001",
                rule_id="py/sql-injection",
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                severity=Severity.CRITICAL,
                verdict=Verdict.CONFIRMED,
                language=Language.PYTHON,
                location=Location(
                    file_path="app.py",
                    start_line=42,
                    snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
                ),
                sast_confidence=0.9,
                sast_message="SQL injection via f-string",
                fused_score=0.88,
            ),
            Finding(
                id="html-002",
                rule_id="py/xss",
                cwe_id="CWE-79",
                cwe_name="Cross-site Scripting",
                severity=Severity.MEDIUM,
                verdict=Verdict.SAFE,
                language=Language.PYTHON,
                location=Location(file_path="view.py", start_line=10),
                sast_confidence=0.5,
                sast_message="Reflected XSS",
                fused_score=0.3,
            ),
        ]
        return ScanResult(
            findings=findings,
            scan_target="/tmp/test-project",
            languages_detected=[Language.PYTHON],
            scan_duration_ms=500.0,
            resolved_at_sast=0,
            resolved_at_graph=1,
            resolved_at_llm=1,
        )

    def test_html_generation(self, scan_result, tmp_path):
        reporter = HTMLReporter(auto_open=False)
        output_path = str(tmp_path / "report.html")

        result_path = reporter.generate(scan_result, output_path)

        assert Path(result_path).exists()

    def test_html_contains_findings(self, scan_result, tmp_path):
        reporter = HTMLReporter(auto_open=False)
        output_path = str(tmp_path / "report.html")
        reporter.generate(scan_result, output_path)

        content = Path(output_path).read_text(encoding="utf-8")

        assert "CWE-89" in content
        assert "CWE-79" in content
        assert "SEC-C" in content or "Sec-C" in content

    def test_html_contains_metrics(self, scan_result, tmp_path):
        reporter = HTMLReporter(auto_open=False)
        output_path = str(tmp_path / "report.html")
        reporter.generate(scan_result, output_path)

        content = Path(output_path).read_text(encoding="utf-8")

        assert "Total Findings" in content
        assert "Confirmed" in content
        assert "Cascade" in content

    def test_html_contains_target(self, scan_result, tmp_path):
        reporter = HTMLReporter(auto_open=False)
        output_path = str(tmp_path / "report.html")
        reporter.generate(scan_result, output_path)

        content = Path(output_path).read_text(encoding="utf-8")

        assert "/tmp/test-project" in content

    def test_html_verdict_badges(self, scan_result, tmp_path):
        reporter = HTMLReporter(auto_open=False)
        output_path = str(tmp_path / "report.html")
        reporter.generate(scan_result, output_path)

        content = Path(output_path).read_text(encoding="utf-8")

        assert "badge-confirmed" in content
        assert "badge-safe" in content


# ── Build result ─────────────────────────────────────────────────────────────

class TestBuildResult:
    """Test the _build_result helper on the orchestrator."""

    def test_build_result_populates_languages(self, orchestrator):
        import time

        findings = [
            Finding(language=Language.PYTHON),
            Finding(language=Language.JAVASCRIPT),
            Finding(language=Language.PYTHON),
        ]

        result = orchestrator._build_result("/tmp/test", findings, time.perf_counter())

        lang_values = [l.value for l in result.languages_detected]
        assert "python" in lang_values
        assert "javascript" in lang_values

    def test_build_result_records_timing(self, orchestrator):
        import time

        start = time.perf_counter()
        result = orchestrator._build_result("/tmp/test", [], start)

        assert result.scan_duration_ms >= 0.0
