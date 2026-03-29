"""CVSS v3.1 Base Score Calculator.

Implements the standard NIST CVSS v3.1 scoring formula using
sub-metric values estimated by the attacker and defender LLM agents.
"""

from __future__ import annotations
from typing import Any

# CVSS v3.1 metric value mappings (from NIST specification)
_AV = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20}
_AC = {"low": 0.77, "high": 0.44}
_PR_UNCHANGED = {"none": 0.85, "low": 0.62, "high": 0.27}
_PR_CHANGED = {"none": 0.85, "low": 0.68, "high": 0.50}
_UI = {"none": 0.85, "required": 0.62}
_IMPACT = {"none": 0.0, "low": 0.22, "high": 0.56}

_SEVERITY_RANGES = [
    (9.0, 10.0, "critical"),
    (7.0, 8.9, "high"),
    (4.0, 6.9, "medium"),
    (0.1, 3.9, "low"),
    (0.0, 0.0, "none"),
]

# Default CVSS vectors for common CWEs (used for SAST-only findings)
CWE_CVSS_DEFAULTS: dict[str, dict[str, str]] = {
    "CWE-89":  {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "none"},
    "CWE-78":  {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "CWE-79":  {"av": "network", "ac": "low", "pr": "none", "ui": "required", "s": "changed", "c": "low", "i": "low", "a": "none"},
    "CWE-22":  {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "none", "a": "none"},
    "CWE-502": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "CWE-798": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "CWE-327": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "none", "a": "none"},
    "CWE-94":  {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "CWE-120": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "CWE-134": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "CWE-416": {"av": "local", "ac": "high", "pr": "low", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "CWE-611": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "none", "a": "none"},
    "CWE-90":  {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "none"},
    "CWE-1321":{"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "low", "i": "low", "a": "low"},
}


def _roundup(x: float) -> float:
    """CVSS v3.1 roundup function: round up to 1 decimal place."""
    import math
    return math.ceil(x * 10) / 10


def compute_cvss_base_score(
    attack_vector: str = "network",
    attack_complexity: str = "low",
    privileges_required: str = "none",
    user_interaction: str = "none",
    scope: str = "unchanged",
    confidentiality: str = "none",
    integrity: str = "none",
    availability: str = "none",
) -> tuple[float, str, str]:
    """Compute CVSS v3.1 base score from sub-metrics.

    Returns (base_score, vector_string, severity_label).
    """
    av = _AV.get(attack_vector.lower(), 0.85)
    ac = _AC.get(attack_complexity.lower(), 0.77)
    scope_lower = scope.lower()
    pr_map = _PR_CHANGED if scope_lower == "changed" else _PR_UNCHANGED
    pr = pr_map.get(privileges_required.lower(), 0.85)
    ui = _UI.get(user_interaction.lower(), 0.85)

    c = _IMPACT.get(confidentiality.lower(), 0.0)
    i = _IMPACT.get(integrity.lower(), 0.0)
    a = _IMPACT.get(availability.lower(), 0.0)

    # Impact Sub Score
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    if iss <= 0:
        return 0.0, _build_vector(attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability), "none"

    # Impact
    if scope_lower == "changed":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Base Score
    if impact <= 0:
        base_score = 0.0
    elif scope_lower == "changed":
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base_score = _roundup(min(impact + exploitability, 10.0))

    vector = _build_vector(attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality, integrity, availability)
    severity = _score_to_severity(base_score)

    return base_score, vector, severity


def compute_cvss_from_cwe_default(cwe_id: str) -> tuple[float, str, str]:
    """Compute CVSS using default values for a given CWE.

    Used for SAST-only findings that don't go through LLM analysis.
    Returns (base_score, vector_string, severity_label).
    """
    defaults = CWE_CVSS_DEFAULTS.get(cwe_id)
    if not defaults:
        # Generic default: network, low complexity, high confidentiality impact
        defaults = {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "low", "i": "low", "a": "none"}

    return compute_cvss_base_score(
        attack_vector=defaults["av"],
        attack_complexity=defaults["ac"],
        privileges_required=defaults["pr"],
        user_interaction=defaults["ui"],
        scope=defaults["s"],
        confidentiality=defaults["c"],
        integrity=defaults["i"],
        availability=defaults["a"],
    )


def _build_vector(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> str:
    """Build CVSS v3.1 vector string."""
    parts = {
        "AV": av[0].upper(), "AC": ac[0].upper(),
        "PR": pr[0].upper(), "UI": ui[0].upper(),
        "S": s[0].upper(), "C": c[0].upper(),
        "I": i[0].upper(), "A": a[0].upper(),
    }
    return "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in parts.items())


def _score_to_severity(score: float) -> str:
    """Map CVSS base score to severity label."""
    for low, high, label in _SEVERITY_RANGES:
        if low <= score <= high:
            return label
    return "none"
