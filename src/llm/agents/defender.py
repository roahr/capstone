"""
Defender Agent (Blue Team): Identifies sanitization and access controls.

The Defender Agent performs defensive analysis of code to identify
all protections that prevent exploitation of a potential vulnerability.

Uses CWE-specific Jinja2 prompt templates for research-grade analysis
with category-specific defensive knowledge (parameterization checks,
encoding validation, class allowlists, etc.).
"""

from __future__ import annotations

import logging
from typing import Any

from src.llm.agents.base import BaseSecurityAgent
from src.llm.api.base_client import BaseLLMClient
from src.sast.sarif.schema import DefenderVerdict, Finding

logger = logging.getLogger(__name__)


class DefenderAgent(BaseSecurityAgent):
    """
    Blue Team LLM agent that identifies defensive measures in code.

    Analyzes sanitization, validation, access controls, and framework
    protections to determine if an identified vulnerability is actually
    exploitable despite the attacker's analysis.

    Prompt generation uses Jinja2 templates loaded from
    ``src/llm/prompts/templates/defender_{category}.jinja2`` where
    *category* is derived from the finding's CWE ID.
    """

    def __init__(
        self,
        client: BaseLLMClient,
        rag_knowledge_base: Any | None = None,
        use_pro: bool = False,
    ):
        super().__init__(client, rag_knowledge_base, use_pro)

    @property
    def role(self) -> str:
        return "defender"

    @property
    def system_instruction(self) -> str:
        return (
            "You are an expert defensive security engineer and secure code reviewer. "
            "Your role is to identify all security protections in code — input validation, "
            "sanitization, encoding, access controls, framework safeguards, and any other "
            "defensive measures. You are thorough and conservative: if protection exists, "
            "you find it. But you are also honest: if protection is incomplete or missing, "
            "you report that clearly. "
            "Always respond in valid JSON format."
        )

    def build_prompt(self, finding: Finding, context: dict[str, Any]) -> str:
        """Build the defender analysis prompt using CWE-specific Jinja2 templates.

        Template selection is based on the finding's CWE ID:
        - CWE-78/79/89/94/95 -> defender_injection.jinja2
        - CWE-502            -> defender_deserialization.jinja2
        - CWE-22             -> defender_path_traversal.jinja2
        - CWE-327/328        -> defender_crypto.jinja2
        - CWE-287/862        -> defender_auth.jinja2
        - Others             -> defender_default.jinja2
        """
        try:
            return self._render_template(finding, context)
        except Exception as e:
            logger.warning(
                "Template rendering failed for %s, falling back to inline prompt: %s",
                finding.cwe_id, e,
            )
            return self._build_fallback_prompt(finding, context)

    def _build_fallback_prompt(self, finding: Finding, context: dict[str, Any]) -> str:
        """Inline fallback prompt used when template rendering fails."""
        code_slice = self._format_code_slice(finding, context)
        taint_path = self._format_taint_path(finding)
        rag_context = self._format_rag_context(context)

        graph_context = ""
        if finding.graph_validation:
            gv = finding.graph_validation
            graph_context = (
                f"\nGraph Analysis Results:\n"
                f"  Structural Risk Score: {gv.structural_risk_score:.2f}\n"
                f"  Sanitizer Coverage: {gv.sanitizer_coverage:.2f}\n"
                f"  Data Flow Fan-out: {gv.data_flow_fan_out}\n"
            )

        prompt = f"""Analyze the following code for defensive protections against a potential {finding.cwe_id} ({finding.cwe_name}) vulnerability.

## Code Under Analysis
```
{code_slice}
```

## Identified Taint Path
{taint_path}

## SAST Finding
- Rule: {finding.rule_id}
- Message: {finding.sast_message}
- Location: {finding.location.display}
- SAST Confidence: {finding.sast_confidence:.0%}
{graph_context}
## Reference Knowledge
{rag_context}

## Your Task (Defender Perspective)
Perform a thorough defensive analysis:
1. Input validation present in the code path
2. Sanitization/encoding functions
3. Access controls and authorization checks
4. Framework-level safeguards
5. Path feasibility assessment

Respond with this exact JSON structure:
{{
    "sanitizers_found": [
        {{"function": "name", "effectiveness": 0.0 to 1.0, "description": "..."}}
    ],
    "access_controls": ["control 1", "control 2"],
    "framework_protections": ["protection 1"],
    "path_feasible": true/false,
    "defense_coverage_score": 0.0 to 1.0,
    "confidence_justification": "why this coverage score",
    "assumptions": ["assumption 1"],
    "counterexamples": ["condition 1"],
    "reasoning": "detailed explanation of defensive posture",
    "scope": "unchanged|changed",
    "confidentiality_impact": "none|low|high",
    "integrity_impact": "none|low|high",
    "availability_impact": "none|low|high",
    "defense_evidence": ["evidence 1", "evidence 2"]
}}"""

        return prompt

    def parse_response(self, response: dict[str, Any]) -> DefenderVerdict:
        if isinstance(response, str):
            return DefenderVerdict(reasoning=f"Raw response: {response[:500]}")

        return DefenderVerdict(
            sanitizers_found=response.get("sanitizers_found", []),
            access_controls=response.get("access_controls", []),
            framework_protections=response.get("framework_protections", []),
            path_feasible=response.get("path_feasible", True),
            defense_coverage_score=min(
                max(float(response.get("defense_coverage_score", 0.0)), 0.0), 1.0
            ),
            reasoning=response.get("reasoning", ""),
            scope=response.get("scope", "unchanged"),
            confidentiality_impact=response.get("confidentiality_impact", "none"),
            integrity_impact=response.get("integrity_impact", "none"),
            availability_impact=response.get("availability_impact", "none"),
            defense_evidence=response.get("defense_evidence", []),
        )

    def _default_verdict(self) -> DefenderVerdict:
        return DefenderVerdict(
            path_feasible=True,
            defense_coverage_score=0.0,
            reasoning="Analysis failed — assuming no defenses (conservative)",
        )
