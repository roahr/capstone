"""
Escalation routing for the SEC-C multi-stage pipeline.

Determines which findings can be resolved at the current stage and which
must be escalated to the next (more expensive) analysis stage:

    SAST  -->  Graph  -->  LLM  -->  Unresolved

Two routers are provided:

* :meth:`EscalationRouter.route` — SAST-to-Graph routing based on
  uncertainty score, severity, taint complexity, and interprocedural
  analysis.
* :meth:`EscalationRouter.route_from_graph` — Graph-to-LLM routing based
  on conformal prediction set ambiguity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.sast.sarif.schema import (
    Finding,
    Severity,
    StageResolved,
    Verdict,
)
from src.sast.uncertainty.scorer import UncertaintyScorer


@dataclass
class RoutingStats:
    """Accumulated statistics for routing decisions."""

    total_processed: int = 0
    resolved_count: int = 0
    escalated_count: int = 0

    # Per-reason escalation counters (a single finding may trigger multiple
    # reasons, but is only counted once in *escalated_count*).
    escalated_by_uncertainty: int = 0
    escalated_by_severity_adjusted: int = 0
    escalated_by_taint_length: int = 0
    escalated_by_interprocedural: int = 0
    escalated_by_interprocedural_critical: int = 0
    escalated_by_ambiguous_prediction: int = 0

    @property
    def escalation_rate(self) -> float:
        """Fraction of processed findings that were escalated."""
        if self.total_processed == 0:
            return 0.0
        return self.escalated_count / self.total_processed


class EscalationRouter:
    """Route findings between pipeline stages based on configurable criteria.

    Parameters
    ----------
    config : dict[str, Any] | None
        Optional configuration overrides.  Recognised keys:

        * ``"uncertainty_threshold"`` — float, default ``0.5``.  Findings
          whose total uncertainty score (including severity adjustment)
          meets or exceeds this value are escalated.
        * ``"taint_length_threshold"`` — int, default ``3``.  Findings with
          a taint path longer than this value are escalated.
        * ``"scorer_config"`` — dict passed through to
          :class:`UncertaintyScorer`.
        * ``"severity_adjustments"`` — mapping of severity name to additive
          float adjustment applied to the uncertainty score.  Default:
          ``{"critical": 0.15, "high": 0.10, "medium": 0.00, "low": -0.05}``.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}

        self._uncertainty_threshold: float = float(
            config.get("uncertainty_threshold", 0.5)
        )
        self._taint_length_threshold: int = int(
            config.get("taint_length_threshold", 3)
        )

        # Severity adjustments are passed through to the scorer
        severity_adjustments = config.get("severity_adjustments")

        scorer_config = dict(config.get("scorer_config") or {})
        if severity_adjustments is not None:
            scorer_config["severity_adjustments"] = severity_adjustments
        self._scorer = UncertaintyScorer(scorer_config)

        # Mutable routing statistics — reset with :meth:`reset_stats`.
        self._stats = RoutingStats()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def stats(self) -> RoutingStats:
        """Read-only access to the accumulated routing statistics."""
        return self._stats

    def reset_stats(self) -> None:
        """Reset all routing counters to zero."""
        self._stats = RoutingStats()

    def route(
        self, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """Route findings from the SAST stage to the Graph stage.

        Each finding is evaluated against the following escalation criteria
        (evaluated in order, but *all* matching reasons are recorded):

        1. **Severity-adjusted uncertainty score** — the 4-factor uncertainty
           score with a severity-based additive adjustment (CRITICAL +0.15,
           HIGH +0.10, etc.).  If ``total >= uncertainty_threshold``, the
           finding is escalated.
        2. **Taint path length** — longer than ``taint_length_threshold``.
        3. **Interprocedural** — the taint path crosses file boundaries.
        4. **Interprocedural + CRITICAL** — if the finding has an
           interprocedural taint flow *and* severity is CRITICAL, it is
           always escalated regardless of the uncertainty score.

        A finding that does not match *any* criterion is considered resolved
        at the SAST stage and receives ``stage_resolved = SAST`` and
        ``verdict = SAFE``.

        Returns
        -------
        tuple[list[Finding], list[Finding]]
            ``(resolved, escalated)`` — two disjoint lists that together
            contain every input finding exactly once.
        """
        resolved: list[Finding] = []
        escalated: list[Finding] = []

        for finding in findings:
            # Ensure the uncertainty score is computed (includes severity
            # adjustment via the scorer).
            self._scorer.score(finding)

            should_escalate = False

            # 1. Severity-adjusted uncertainty score
            if finding.uncertainty.total >= self._uncertainty_threshold:
                self._stats.escalated_by_uncertainty += 1
                # Track that severity adjustment contributed to escalation
                if finding.uncertainty.severity_adjustment > 0:
                    self._stats.escalated_by_severity_adjusted += 1
                should_escalate = True

            # 2. Taint path length
            taint_length = (
                finding.taint_flow.length if finding.taint_flow else 0
            )
            if taint_length > self._taint_length_threshold:
                self._stats.escalated_by_taint_length += 1
                should_escalate = True

            # 3. Interprocedural
            is_interproc = (
                finding.taint_flow.is_interprocedural
                if finding.taint_flow
                else False
            )
            if is_interproc:
                self._stats.escalated_by_interprocedural += 1
                should_escalate = True

            # 4. Exception: interprocedural + CRITICAL always escalates
            if is_interproc and finding.severity == Severity.CRITICAL:
                if not should_escalate:
                    # Only count if this is the sole reason for escalation
                    self._stats.escalated_by_interprocedural_critical += 1
                should_escalate = True

            # Classify
            if should_escalate:
                escalated.append(finding)
                self._stats.escalated_count += 1
            else:
                finding.stage_resolved = StageResolved.SAST
                finding.verdict = Verdict.SAFE
                resolved.append(finding)
                self._stats.resolved_count += 1

            self._stats.total_processed += 1

        return resolved, escalated

    def route_from_graph(
        self, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """Route findings from the Graph stage to the LLM stage.

        A finding is escalated to LLM validation if its conformal prediction
        set is **ambiguous** — i.e., it contains both ``"safe"`` and
        ``"vulnerable"``, meaning the graph model cannot confidently classify
        the finding on its own.

        Findings that are *not* ambiguous are resolved at the graph stage:
        if the prediction set contains only ``"vulnerable"`` the verdict is
        set to ``LIKELY``; if it contains only ``"safe"`` the verdict is
        ``SAFE``.

        Returns
        -------
        tuple[list[Finding], list[Finding]]
            ``(resolved, escalated)``
        """
        resolved: list[Finding] = []
        escalated: list[Finding] = []

        for finding in findings:
            gv = finding.graph_validation

            # No graph validation data — cannot resolve, must escalate.
            if gv is None:
                escalated.append(finding)
                self._stats.escalated_count += 1
                self._stats.escalated_by_ambiguous_prediction += 1
                self._stats.total_processed += 1
                continue

            if gv.is_ambiguous:
                escalated.append(finding)
                self._stats.escalated_count += 1
                self._stats.escalated_by_ambiguous_prediction += 1
            else:
                finding.stage_resolved = StageResolved.GRAPH
                # Determine verdict from the unambiguous prediction set.
                preds = {p.lower() for p in gv.conformal_prediction_set}
                if "vulnerable" in preds:
                    finding.verdict = Verdict.LIKELY
                elif "safe" in preds:
                    finding.verdict = Verdict.SAFE
                else:
                    # Empty or unexpected prediction set — be conservative.
                    finding.verdict = Verdict.UNKNOWN
                resolved.append(finding)
                self._stats.resolved_count += 1

            self._stats.total_processed += 1

        return resolved, escalated
