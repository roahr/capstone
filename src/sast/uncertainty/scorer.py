"""
4-factor uncertainty quantification for SAST findings.

Computes a composite uncertainty score from four independent factors:
  1. Confidence uncertainty  — inverse of SAST tool confidence
  2. Complexity uncertainty  — taint path length and interprocedural depth
  3. Novelty uncertainty     — rarity of the CWE pattern
  4. Conflict uncertainty    — disagreement between multiple SAST tools

A post-hoc severity adjustment is applied after the 4-factor weighted sum
to nudge the score based on finding severity (CRITICAL +0.15, HIGH +0.10,
MEDIUM +0.00, LOW -0.05 by default).
"""

from __future__ import annotations

from typing import Any

from src.sast.sarif.schema import Finding, Severity, UncertaintyScore


# Well-known CWE IDs with established detection heuristics.
# These patterns are thoroughly studied and SAST tools handle them reliably,
# so findings for these CWEs carry *low* novelty uncertainty.
_COMMON_CWE_IDS: frozenset[str] = frozenset({
    # Injection
    "CWE-89",   # SQL Injection
    "CWE-78",   # OS Command Injection
    "CWE-77",   # Command Injection
    "CWE-94",   # Code Injection
    # XSS
    "CWE-79",   # Cross-site Scripting (XSS)
    # Path traversal
    "CWE-22",   # Path Traversal
    "CWE-23",   # Relative Path Traversal
    # Deserialization
    "CWE-502",  # Deserialization of Untrusted Data
    # XXE
    "CWE-611",  # Improper Restriction of XML External Entity Reference
    # SSRF
    "CWE-918",  # Server-Side Request Forgery
    # Authentication / Authorization
    "CWE-287",  # Improper Authentication
    "CWE-862",  # Missing Authorization
    "CWE-863",  # Incorrect Authorization
    # Cryptography
    "CWE-327",  # Use of a Broken or Risky Cryptographic Algorithm
    "CWE-328",  # Use of Weak Hash
    "CWE-330",  # Use of Insufficiently Random Values
    # Information exposure
    "CWE-200",  # Exposure of Sensitive Information
    "CWE-209",  # Error Message Information Leak
    # Buffer / memory
    "CWE-119",  # Buffer Overflow
    "CWE-120",  # Classic Buffer Overflow
    "CWE-125",  # Out-of-bounds Read
    "CWE-787",  # Out-of-bounds Write
    # Open redirect
    "CWE-601",  # URL Redirection to Untrusted Site
    # Hardcoded credentials
    "CWE-798",  # Use of Hard-coded Credentials
    # LDAP injection
    "CWE-90",   # LDAP Injection
})

# Novelty score assigned to well-known CWEs (low uncertainty).
_COMMON_CWE_NOVELTY: float = 0.15
# Novelty score assigned to rare / less-studied CWEs (high uncertainty).
_RARE_CWE_NOVELTY: float = 0.85

# Complexity scaling constants.
_MAX_TAINT_HOPS: int = 5
_MAX_INTERPROC_DEPTH: int = 5


class UncertaintyScorer:
    """Compute a 4-factor uncertainty score for a single SAST finding.

    Parameters
    ----------
    config : dict[str, Any] | None
        Optional configuration overrides.  Recognised keys:

        * ``"weights"`` — mapping with keys ``confidence``, ``complexity``,
          ``novelty``, ``conflict`` (all ``float``).  Defaults are
          ``0.4, 0.3, 0.2, 0.1``.
        * ``"common_cwe_ids"`` — an iterable of CWE ID strings that should
          be treated as well-known (low novelty).  Defaults to the built-in
          list.
    """

    # Default severity adjustments applied as a post-hoc additive term
    # to the 4-factor weighted uncertainty score.
    _DEFAULT_SEVERITY_ADJUSTMENTS: dict[str, float] = {
        "critical": 0.15,
        "high": 0.10,
        "medium": 0.00,
        "low": -0.05,
    }

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}

        weights = config.get("weights", {})
        self._w_conf: float = float(weights.get("confidence", 0.4))
        self._w_comp: float = float(weights.get("complexity", 0.3))
        self._w_nov: float = float(weights.get("novelty", 0.2))
        self._w_confl: float = float(weights.get("conflict", 0.1))

        custom_cwes = config.get("common_cwe_ids")
        self._common_cwes: frozenset[str] = (
            frozenset(custom_cwes) if custom_cwes is not None else _COMMON_CWE_IDS
        )

        # Severity adjustments (post-hoc additive term on the uncertainty score)
        sev_adj = config.get("severity_adjustments")
        if sev_adj is not None:
            self._severity_adjustments: dict[str, float] = {
                k: float(v) for k, v in sev_adj.items()
            }
        else:
            self._severity_adjustments = dict(self._DEFAULT_SEVERITY_ADJUSTMENTS)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, finding: Finding) -> UncertaintyScore:
        """Compute the composite 4-factor uncertainty score for *finding*.

        After computing the weighted 4-factor sum, a severity adjustment is
        applied as a post-hoc additive term.  The result is clamped to
        ``[0, 1]``.

        The returned :class:`UncertaintyScore` is also written back onto
        ``finding.uncertainty`` so downstream pipeline stages can inspect it
        without a separate lookup.

        Returns
        -------
        UncertaintyScore
            Populated model with all four factor scores and the configured
            weights.
        """
        sev_adj = self.severity_adjustment(finding)
        u = UncertaintyScore(
            confidence_uncertainty=self._confidence_uncertainty(finding),
            complexity_uncertainty=self._complexity_uncertainty(finding),
            novelty_uncertainty=self._novelty_uncertainty(finding),
            conflict_uncertainty=self._conflict_uncertainty(finding),
            w_conf=self._w_conf,
            w_comp=self._w_comp,
            w_nov=self._w_nov,
            w_confl=self._w_confl,
            severity_adjustment=sev_adj,
        )
        finding.uncertainty = u
        return u

    def severity_adjustment(self, finding: Finding) -> float:
        """Return the severity-based adjustment value for *finding*.

        The adjustment is looked up from the configured
        ``severity_adjustments`` mapping.  Severities not present in the
        mapping (e.g. ``INFO``) receive an adjustment of ``0.0``.

        Returns
        -------
        float
            Additive adjustment to apply to the 4-factor weighted score.
        """
        sev_name = finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity)
        return self._severity_adjustments.get(sev_name.lower(), 0.0)

    # ------------------------------------------------------------------
    # Factor computations
    # ------------------------------------------------------------------

    def _confidence_uncertainty(self, finding: Finding) -> float:
        """Inverse of the SAST tool's self-reported confidence.

        A tool that reports ``sast_confidence = 0.9`` produces an uncertainty
        of ``0.1``.  A tool reporting ``0.0`` (or no confidence at all) yields
        the maximum uncertainty of ``1.0``.
        """
        return _clamp(1.0 - finding.sast_confidence)

    def _complexity_uncertainty(self, finding: Finding) -> float:
        """Estimate uncertainty from taint-path complexity.

        Two sub-signals are combined equally:

        * **Hop count** — number of steps in the taint flow.  1 hop (or no
          taint flow) maps to ``0.0``; >= ``_MAX_TAINT_HOPS`` hops maps to
          ``1.0``.
        * **Interprocedural depth** — pulled from
          ``finding.graph_validation.interprocedural_depth`` when available,
          otherwise inferred from ``taint_flow.is_interprocedural``.

        The two sub-scores are averaged to produce the final factor.
        """
        # --- hop count ---
        taint_length: int = 0
        is_interproc: bool = False

        if finding.taint_flow is not None:
            taint_length = finding.taint_flow.length
            is_interproc = finding.taint_flow.is_interprocedural

        hop_score = _clamp((taint_length - 1) / max(_MAX_TAINT_HOPS - 1, 1))

        # --- interprocedural depth ---
        interproc_depth: int = 0
        if finding.graph_validation is not None:
            interproc_depth = finding.graph_validation.interprocedural_depth
        elif is_interproc:
            # Heuristic: if we know it crosses files but have no graph data,
            # assume a moderate depth of 2.
            interproc_depth = 2

        depth_score = _clamp(interproc_depth / _MAX_INTERPROC_DEPTH)

        return _clamp((hop_score + depth_score) / 2.0)

    def _novelty_uncertainty(self, finding: Finding) -> float:
        """Score based on how well-studied the CWE pattern is.

        Well-known vulnerability classes (SQL injection, XSS, buffer
        overflows, etc.) have mature detection rules and low false-positive
        rates, so they receive a *low* novelty uncertainty.  Rare or niche
        CWEs with fewer established patterns receive a *high* novelty score.

        If ``cwe_id`` is empty or missing, the finding is treated as highly
        novel (maximum uncertainty).
        """
        cwe_id = finding.cwe_id.strip()
        if not cwe_id:
            return 1.0

        # Normalise: accept both "CWE-89" and "89"
        normalised = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"

        if normalised in self._common_cwes:
            return _COMMON_CWE_NOVELTY
        return _RARE_CWE_NOVELTY

    def _conflict_uncertainty(self, finding: Finding) -> float:
        """Score based on inter-tool agreement on the same location.

        If only a single tool produced the finding, there is no conflict and
        the score is ``0.0``.  Conflict is detected via the ``tags`` and
        ``properties`` fields on the finding:

        * ``properties["corroborating_tools"]`` — list of tool names that
          independently flagged the same location.
        * ``properties["tool_verdicts"]`` — mapping ``{tool_name: verdict}``
          recording each tool's classification for this location.

        When multiple tools agree, uncertainty stays low.  When they disagree
        (e.g., one says "vulnerable", another says "safe"), uncertainty rises
        toward ``1.0``.
        """
        corroborating: list[str] = finding.properties.get("corroborating_tools", [])

        # Single-tool finding — no conflict possible.
        if not corroborating:
            return 0.0

        tool_verdicts: dict[str, str] = finding.properties.get("tool_verdicts", {})

        # If we have corroborating tools but no verdict map, we cannot tell
        # whether they agree. Treat as moderate uncertainty.
        if not tool_verdicts:
            return 0.5

        unique_verdicts = set(tool_verdicts.values())

        if len(unique_verdicts) <= 1:
            # All tools agree — low conflict uncertainty.
            return 0.1

        # Check for strong disagreement: one tool says safe, another
        # says the opposite.
        has_safe = any(v in ("safe", "false_positive") for v in unique_verdicts)
        has_vuln = any(
            v in ("vulnerable", "confirmed", "likely") for v in unique_verdicts
        )

        if has_safe and has_vuln:
            # Hard disagreement — high uncertainty.
            return 1.0

        # Soft disagreement (e.g., "likely" vs "potential").
        return 0.5


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp *value* to the ``[lo, hi]`` interval."""
    return max(lo, min(hi, value))
