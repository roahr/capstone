"""
Pipeline Orchestrator: Multi-stage cascade coordinator.

Manages the SAST -> Graph -> LLM cascade with uncertainty-driven escalation.
This is the core innovation of the SEC-C framework -- the first published
uncertainty-driven cascading escalation system for vulnerability detection.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.sast.sarif.schema import (
    AttackerVerdict,
    DefenderVerdict,
    Finding,
    Language,
    LLMValidation,
    ScanResult,
    StageResolved,
    Verdict,
)

if TYPE_CHECKING:
    from src.reporting.scan_display import ScanDisplay

logger = logging.getLogger(__name__)


@dataclass
class CascadeStats:
    """Statistics about the cascade execution."""
    total_findings: int = 0
    resolved_sast: int = 0
    escalated_to_graph: int = 0
    resolved_graph: int = 0
    escalated_to_llm: int = 0
    resolved_llm: int = 0
    unresolved: int = 0

    # Timing
    sast_time_ms: float = 0.0
    graph_time_ms: float = 0.0
    llm_time_ms: float = 0.0
    total_time_ms: float = 0.0

    @property
    def cascade_efficiency(self) -> float:
        """Fraction of findings resolved at Stage 1 (SAST)."""
        if self.total_findings == 0:
            return 0.0
        return self.resolved_sast / self.total_findings

    @property
    def graph_resolution_rate(self) -> float:
        """Fraction of escalated findings resolved at Stage 2 (Graph)."""
        if self.escalated_to_graph == 0:
            return 0.0
        return self.resolved_graph / self.escalated_to_graph

    @property
    def llm_resolution_rate(self) -> float:
        """Fraction of escalated findings resolved at Stage 3 (LLM)."""
        if self.escalated_to_llm == 0:
            return 0.0
        return self.resolved_llm / self.escalated_to_llm

    def summary(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "resolved_at_sast": self.resolved_sast,
            "resolved_at_graph": self.resolved_graph,
            "resolved_at_llm": self.resolved_llm,
            "unresolved": self.unresolved,
            "cascade_efficiency": f"{self.cascade_efficiency:.1%}",
            "sast_time_ms": f"{self.sast_time_ms:.1f}",
            "graph_time_ms": f"{self.graph_time_ms:.1f}",
            "llm_time_ms": f"{self.llm_time_ms:.1f}",
            "total_time_ms": f"{self.total_time_ms:.1f}",
        }


class PipelineOrchestrator:
    """
    Orchestrates the multi-stage SEC-C cascade.

    Flow:
    1. SAST Engine scans code → produces findings with uncertainty scores
    2. Findings with U_score >= threshold escalate to Graph stage
    3. Graph stage validates with CPG + Mini-GAT + Conformal Prediction
    4. Ambiguous findings (CP set = {safe, vuln}) escalate to LLM
    5. LLM dual-agent validates with attacker/defender protocol
    6. All findings fused and reported
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        display: ScanDisplay | None = None,
    ):
        self.config = config or {}
        self.stats = CascadeStats()
        self._display = display

        # Module references (injected or lazily created)
        self._sast_engine = None
        self._graph_validator = None
        self._llm_validator = None
        self._score_fuser = None
        self._reporter = None

    def set_sast_engine(self, engine: Any) -> None:
        self._sast_engine = engine

    def set_graph_validator(self, validator: Any) -> None:
        self._graph_validator = validator

    def set_llm_validator(self, validator: Any) -> None:
        self._llm_validator = validator

    def set_score_fuser(self, fuser: Any) -> None:
        self._score_fuser = fuser

    def set_display(self, display: ScanDisplay) -> None:
        """Set the scan display for real-time output."""
        self._display = display

    async def scan(
        self,
        target: str,
        languages: list[Language] | None = None,
        max_stage: str = "llm",
        github_repo: str | None = None,
    ) -> ScanResult:
        """
        Execute the full SEC-C cascade on a target.

        Args:
            target: Path to local directory or file
            languages: Languages to scan (auto-detect if None)
            max_stage: Maximum stage to run ("sast", "graph", "llm")
            github_repo: GitHub repo (owner/repo) to scan instead of local

        Returns:
            ScanResult with all findings and cascade statistics
        """
        total_start = time.perf_counter()
        self.stats = CascadeStats()
        disp = self._display

        logger.info(f"Starting SEC-C cascade scan on: {target or github_repo}")

        # Display header
        if disp:
            lang_names = [l.value for l in languages] if languages else []
            disp.show_header(target or github_repo or "", lang_names, max_stage)

        # -- Stage 1: SAST Engine ------------------------------------------
        if disp:
            disp.show_sast_start()

        sast_start = time.perf_counter()
        all_findings = await self._run_sast_stage(target, languages, github_repo)
        sast_elapsed_s = time.perf_counter() - sast_start
        self.stats.sast_time_ms = sast_elapsed_s * 1000
        self.stats.total_findings = len(all_findings)

        logger.info(f"SAST produced {len(all_findings)} findings in {self.stats.sast_time_ms:.0f}ms")

        # Gather SAST sub-stage metrics from engine properties (if available)
        if disp:
            sast_meta = self._extract_sast_metadata()
            disp.show_treesitter_result(
                files_scanned=sast_meta.get("ts_files", 0),
                findings_count=sast_meta.get("ts_findings", 0),
                time_ms=sast_meta.get("ts_time_ms", 0.0),
            )
            if sast_meta.get("codeql_available", False):
                disp.show_codeql_result(
                    db_time=sast_meta.get("codeql_db_time_s", 0.0),
                    query_suite=sast_meta.get("codeql_suite", "security-extended"),
                    findings_count=sast_meta.get("codeql_findings", 0),
                    corroborated=sast_meta.get("codeql_corroborated", 0),
                )
            else:
                disp.show_codeql_skipped(sast_meta.get("codeql_skip_reason", "not available"))

        # If max_stage is sast, resolve ALL findings at SAST stage
        if max_stage == "sast":
            from src.llm.consensus.cvss import compute_cvss_from_cwe_default

            for f in all_findings:
                f.stage_resolved = StageResolved.SAST
                if f.sast_confidence >= 0.8:
                    f.verdict = Verdict.CONFIRMED if f.sast_confidence >= 0.9 else Verdict.LIKELY
                else:
                    f.verdict = Verdict.POTENTIAL
                # Assign CWE-default CVSS for SAST-only findings
                score, vector, severity = compute_cvss_from_cwe_default(f.cwe_id)
                f.cvss_base_score = score
                f.cvss_vector = vector
                f.cvss_severity = severity
            self.stats.resolved_sast = len(all_findings)
            logger.info(f"SAST-only mode: all {len(all_findings)} findings resolved at Stage 1")

            if disp:
                threshold = self._get_uncertainty_threshold()
                disp.show_uncertainty_result(
                    total=len(all_findings),
                    resolved=len(all_findings),
                    escalated=0,
                    threshold=threshold,
                )
                if all_findings:
                    disp.show_findings_table(all_findings, "SAST Findings (all resolved)")
                disp.show_stage_complete("Stage 1", len(all_findings), 0, sast_elapsed_s)

            # Run score fusion
            if self._score_fuser:
                for finding in all_findings:
                    self._score_fuser.fuse(finding)

            result = self._build_result(target, all_findings, total_start)
            if disp:
                disp.show_results_summary(result)
            return result

        # Route: resolved vs escalated
        resolved_sast, escalated_to_graph = self._route_sast_findings(all_findings)
        self.stats.resolved_sast = len(resolved_sast)
        self.stats.escalated_to_graph = len(escalated_to_graph)

        # Mark resolved findings
        from src.llm.consensus.cvss import compute_cvss_from_cwe_default

        for f in resolved_sast:
            f.stage_resolved = StageResolved.SAST
            if f.sast_confidence >= 0.8:
                f.verdict = Verdict.CONFIRMED if f.sast_confidence >= 0.9 else Verdict.LIKELY
            else:
                f.verdict = Verdict.POTENTIAL
            # Assign CWE-default CVSS for SAST-resolved findings
            score, vector, severity = compute_cvss_from_cwe_default(f.cwe_id)
            f.cvss_base_score = score
            f.cvss_vector = vector
            f.cvss_severity = severity

        logger.info(
            f"SAST resolved {len(resolved_sast)}, "
            f"escalating {len(escalated_to_graph)} to Graph stage"
        )

        if disp:
            threshold = self._get_uncertainty_threshold()
            disp.show_uncertainty_result(
                total=len(all_findings),
                resolved=len(resolved_sast),
                escalated=len(escalated_to_graph),
                threshold=threshold,
            )
            if escalated_to_graph:
                disp.show_findings_table(escalated_to_graph, "Escalated to Graph")
            disp.show_stage_complete(
                "Stage 1", len(resolved_sast), len(escalated_to_graph), sast_elapsed_s
            )

        if not escalated_to_graph:
            result = self._build_result(target, all_findings, total_start)
            if disp:
                disp.show_results_summary(result)
            return result

        # -- Stage 2: Graph-Augmented Validation ---------------------------
        if disp:
            disp.show_graph_start()

        graph_start = time.perf_counter()
        graph_validated = await self._run_graph_stage(escalated_to_graph)
        graph_elapsed_s = time.perf_counter() - graph_start
        self.stats.graph_time_ms = graph_elapsed_s * 1000

        # Route: resolved vs escalated to LLM
        resolved_graph, escalated_to_llm = self._route_graph_findings(graph_validated)
        self.stats.resolved_graph = len(resolved_graph)
        self.stats.escalated_to_llm = len(escalated_to_llm)

        for f in resolved_graph:
            f.stage_resolved = StageResolved.GRAPH

        logger.info(
            f"Graph resolved {len(resolved_graph)}, "
            f"escalating {len(escalated_to_llm)} to LLM stage"
        )

        if disp:
            graph_meta = self._extract_graph_metadata(graph_validated)
            disp.show_graph_result(
                cpg_count=graph_meta.get("cpg_count", len(escalated_to_graph)),
                slice_reduction=graph_meta.get("slice_reduction", 0.0),
                gat_status=graph_meta.get("gat_status", "skipped -- model not trained"),
                cp_status=graph_meta.get("cp_status", "skipped -- not calibrated"),
            )
            if escalated_to_llm:
                disp.show_findings_table(escalated_to_llm, "Escalated to LLM")
            disp.show_stage_complete(
                "Stage 2", len(resolved_graph), len(escalated_to_llm), graph_elapsed_s
            )

        if max_stage == "graph" or not escalated_to_llm:
            result = self._build_result(target, all_findings, total_start)
            if disp:
                disp.show_results_summary(result)
            return result

        # -- Stage 3: LLM Dual-Agent Validation ---------------------------
        if disp:
            disp.show_llm_start()

        llm_start = time.perf_counter()
        llm_validated = await self._run_llm_stage(escalated_to_llm, display=disp)
        llm_elapsed_s = time.perf_counter() - llm_start
        self.stats.llm_time_ms = llm_elapsed_s * 1000
        self.stats.resolved_llm = len(llm_validated)

        for f in llm_validated:
            f.stage_resolved = StageResolved.LLM

        logger.info(f"LLM resolved {len(llm_validated)} findings")

        # Count confirmed vs filtered for display
        llm_confirmed = sum(
            1 for f in llm_validated
            if f.verdict in (Verdict.CONFIRMED, Verdict.LIKELY)
        )
        llm_filtered = sum(
            1 for f in llm_validated if f.verdict == Verdict.SAFE
        )

        if disp:
            disp.show_stage_complete(
                "Stage 3", llm_confirmed + llm_filtered, 0, llm_elapsed_s
            )

        # Count unresolved
        self.stats.unresolved = sum(
            1 for f in all_findings if f.stage_resolved == StageResolved.UNRESOLVED
        )

        # -- Score Fusion --------------------------------------------------
        if self._score_fuser:
            for finding in all_findings:
                self._score_fuser.fuse(finding)

        result = self._build_result(target, all_findings, total_start)
        if disp:
            disp.show_results_summary(result)
        return result

    async def _run_sast_stage(
        self,
        target: str,
        languages: list[Language] | None,
        github_repo: str | None,
    ) -> list[Finding]:
        """Execute SAST analysis (Module 1)."""
        if self._sast_engine is None:
            logger.warning("SAST engine not configured, skipping Stage 1")
            return []

        return await self._sast_engine.analyze(target, languages, github_repo)

    async def _run_graph_stage(self, findings: list[Finding]) -> list[Finding]:
        """Execute Graph validation (Module 2)."""
        if self._graph_validator is None:
            logger.warning("Graph validator not configured, passing findings through")
            return findings

        validated = []
        for finding in findings:
            result = await self._graph_validator.validate(finding)
            validated.append(result)
        return validated

    async def _run_llm_stage(
        self,
        findings: list[Finding],
        display: ScanDisplay | None = None,
    ) -> list[Finding]:
        """Execute LLM dual-agent validation (Module 3).

        Attempts batch validation first (via ``validate_batch``) to
        conserve API quota.  Falls back to individual ``validate`` calls
        if the validator does not support batching or the batch call fails.
        """
        if self._llm_validator is None:
            logger.warning("LLM validator not configured, passing findings through")
            return findings

        total = len(findings)
        validated: list[Finding] = []

        # Try batch validation first
        if hasattr(self._llm_validator, "validate_batch") and total > 1:
            try:
                logger.info(
                    "Attempting batch LLM validation for %d findings", total
                )
                validated = await self._llm_validator.validate_batch(findings)
            except Exception as e:
                logger.warning(
                    "Batch LLM validation failed, falling back to "
                    "individual validation: %s", e,
                )
                validated = []

        # Fall back to individual validation if batch did not produce results
        if not validated:
            for idx, finding in enumerate(findings, start=1):
                result = await self._llm_validator.validate(finding)
                validated.append(result)

        # Emit per-finding display
        if display:
            for idx, result in enumerate(validated, start=1):
                if result.llm_validation is not None:
                    llm_val = result.llm_validation
                    display.show_llm_finding(
                        index=idx,
                        total=total,
                        finding=result,
                        attacker_verdict=llm_val.attacker,
                        defender_verdict=llm_val.defender,
                        consensus=llm_val,
                    )
                else:
                    # LLM ran but produced no structured validation
                    display.show_llm_finding(
                        index=idx,
                        total=total,
                        finding=result,
                        attacker_verdict=AttackerVerdict(),
                        defender_verdict=DefenderVerdict(),
                        consensus=None,
                    )

        return validated

    def _route_sast_findings(
        self, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """Route SAST findings: resolve confident ones, escalate uncertain ones."""
        from src.sast.router import EscalationRouter

        router = EscalationRouter(self.config.get("sast", {}).get("uncertainty", {}))
        return router.route(findings)

    def _route_graph_findings(
        self, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """Route Graph findings: resolve clear ones, escalate ambiguous ones."""
        from src.sast.router import EscalationRouter

        router = EscalationRouter(self.config.get("sast", {}).get("uncertainty", {}))
        return router.route_from_graph(findings)

    def _get_uncertainty_threshold(self) -> float:
        """Return the configured uncertainty threshold."""
        return float(
            self.config.get("sast", {})
            .get("uncertainty", {})
            .get("uncertainty_threshold", 0.5)
        )

    def _extract_sast_metadata(self) -> dict[str, Any]:
        """Extract display metadata from the SAST engine, if available.

        The SAST engine may expose ``last_scan_metadata`` with sub-stage
        timings and counts.  If the engine does not provide this, safe
        defaults are returned so the display never errors.
        """
        meta: dict[str, Any] = {
            "ts_files": 0,
            "ts_findings": 0,
            "ts_time_ms": 0.0,
            "codeql_available": False,
            "codeql_skip_reason": "not available",
            "codeql_db_time_s": 0.0,
            "codeql_suite": "security-extended",
            "codeql_findings": 0,
            "codeql_corroborated": 0,
        }

        engine = self._sast_engine
        if engine is None:
            return meta

        # Support engines that expose ``last_scan_metadata``.
        scan_meta = getattr(engine, "last_scan_metadata", None)
        if isinstance(scan_meta, dict):
            meta["ts_files"] = scan_meta.get("treesitter_files_scanned", meta["ts_files"])
            meta["ts_findings"] = scan_meta.get("treesitter_findings", meta["ts_findings"])
            meta["ts_time_ms"] = scan_meta.get("treesitter_time_ms", meta["ts_time_ms"])
            meta["codeql_available"] = scan_meta.get("codeql_available", meta["codeql_available"])
            meta["codeql_skip_reason"] = scan_meta.get("codeql_skip_reason", meta["codeql_skip_reason"])
            meta["codeql_db_time_s"] = scan_meta.get("codeql_db_time_s", meta["codeql_db_time_s"])
            meta["codeql_suite"] = scan_meta.get("codeql_query_suite", meta["codeql_suite"])
            meta["codeql_findings"] = scan_meta.get("codeql_findings", meta["codeql_findings"])
            meta["codeql_corroborated"] = scan_meta.get("codeql_corroborated", meta["codeql_corroborated"])
        else:
            # Fallback: infer from engine attributes
            meta["codeql_available"] = getattr(engine, "_codeql_available", False)
            if not meta["codeql_available"]:
                meta["codeql_skip_reason"] = "CLI not found on PATH"

        return meta

    def _extract_graph_metadata(
        self, validated: list[Finding]
    ) -> dict[str, Any]:
        """Extract display metadata from graph validation results.

        Derives CPG counts and average slice reduction from the
        ``GraphValidation`` attached to each finding.
        """
        meta: dict[str, Any] = {
            "cpg_count": 0,
            "slice_reduction": 0.0,
            "gat_status": "skipped -- model not trained",
            "cp_status": "skipped -- not calibrated",
        }

        cpg_count = 0
        total_sanitizer_cov = 0.0
        any_cp = False
        any_gat = False

        for f in validated:
            gv = f.graph_validation
            if gv is None:
                continue
            cpg_count += 1
            total_sanitizer_cov += gv.sanitizer_coverage

            if gv.conformal_prediction_set:
                any_cp = True
            if gv.attention_weights:
                any_gat = True

        meta["cpg_count"] = cpg_count

        if cpg_count > 0:
            avg_coverage = total_sanitizer_cov / cpg_count
            # Slice reduction is complementary to sanitizer coverage
            meta["slice_reduction"] = avg_coverage * 100

        if any_gat:
            meta["gat_status"] = f"completed ({cpg_count} graphs analyzed)"
        if any_cp:
            meta["cp_status"] = f"completed ({cpg_count} predictions)"

        # Check if graph validator exposes richer metadata
        gv_obj = self._graph_validator
        if gv_obj is not None:
            gv_meta = getattr(gv_obj, "last_validation_metadata", None)
            if isinstance(gv_meta, dict):
                meta["slice_reduction"] = gv_meta.get("avg_slice_reduction_pct", meta["slice_reduction"])
                meta["gat_status"] = gv_meta.get("gat_status", meta["gat_status"])
                meta["cp_status"] = gv_meta.get("cp_status", meta["cp_status"])

        return meta

    def _build_result(
        self, target: str, findings: list[Finding], start_time: float
    ) -> ScanResult:
        """Build the final ScanResult."""
        total_time = (time.perf_counter() - start_time) * 1000
        self.stats.total_time_ms = total_time

        # Detect languages from findings
        languages_detected = list({f.language for f in findings})

        result = ScanResult(
            findings=findings,
            scan_target=target,
            languages_detected=languages_detected,
            scan_duration_ms=total_time,
            resolved_at_sast=self.stats.resolved_sast,
            resolved_at_graph=self.stats.resolved_graph,
            resolved_at_llm=self.stats.resolved_llm,
            unresolved=self.stats.unresolved,
        )

        logger.info(
            f"Scan complete: {len(findings)} findings, "
            f"cascade efficiency {self.stats.cascade_efficiency:.1%}, "
            f"total time {total_time:.0f}ms"
        )
        logger.info(f"Cascade stats: {self.stats.summary()}")

        return result
