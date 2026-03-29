"""
Attacker Agent (Red Team): Attempts to construct exploit payloads.

The Attacker Agent receives a vulnerability finding with code context
and attempts to construct a concrete exploit that traverses the taint
path from source to sink without sanitization.

Uses CWE-specific Jinja2 prompt templates for research-grade analysis
with category-specific exploit knowledge (injection payloads, gadget
chains, traversal techniques, etc.).
"""

from __future__ import annotations

import logging
from typing import Any

from src.llm.agents.base import BaseSecurityAgent
from src.llm.api.base_client import BaseLLMClient
from src.sast.sarif.schema import AttackerVerdict, Finding

logger = logging.getLogger(__name__)


class AttackerAgent(BaseSecurityAgent):
    """
    Red Team LLM agent that attempts to exploit identified vulnerabilities.

    Strategy inspired by Vulnhalla (CyberArk 2025) guided questioning
    and ZeroFalse (arXiv 2025) CWE-specific prompting.

    Prompt generation uses Jinja2 templates loaded from
    ``src/llm/prompts/templates/attacker_{category}.jinja2`` where
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
        return "attacker"

    @property
    def system_instruction(self) -> str:
        return (
            "You are an expert offensive security researcher and penetration tester. "
            "Your role is to analyze code for exploitable vulnerabilities. "
            "You approach code like a skilled attacker would — looking for ways to "
            "bypass input validation, exploit unsafe operations, and craft payloads "
            "that demonstrate real exploitability. "
            "Be thorough but honest: if the code is actually safe, say so. "
            "Always respond in valid JSON format."
        )

    def build_prompt(self, finding: Finding, context: dict[str, Any]) -> str:
        """Build the attacker analysis prompt using CWE-specific Jinja2 templates.

        Template selection is based on the finding's CWE ID:
        - CWE-78/79/89/94/95 -> attacker_injection.jinja2
        - CWE-502            -> attacker_deserialization.jinja2
        - CWE-22             -> attacker_path_traversal.jinja2
        - CWE-327/328        -> attacker_crypto.jinja2
        - CWE-287/862        -> attacker_auth.jinja2
        - Others             -> attacker_default.jinja2
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
                f"  Taint Path Length: {gv.taint_path_length}\n"
                f"  Control Flow Complexity: {gv.control_flow_complexity:.2f}\n"
                f"  Sanitizer Coverage: {gv.sanitizer_coverage:.2f}\n"
                f"  Interprocedural Depth: {gv.interprocedural_depth}\n"
            )

        prompt = f"""Analyze the following code for a potential {finding.cwe_id} ({finding.cwe_name}) vulnerability.

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

## Your Task (Attacker Perspective)
Attempt to construct a concrete exploit payload that:
1. Enters at the identified taint source
2. Traverses the taint path without being sanitized or blocked
3. Reaches the sink in a dangerous/exploitable state

Consider:
- What input values would trigger the vulnerability?
- Are there any sanitizers, validators, or access controls in the path?
- Is the taint path actually reachable at runtime?
- Could framework-level protections block the attack?

Respond with this exact JSON structure:
{{
    "exploitable": true/false,
    "payload": "concrete exploit payload string or null",
    "execution_trace": ["step 1: ...", "step 2: ..."],
    "blocking_factors": ["factor 1", "factor 2"],
    "confidence": 0.0 to 1.0,
    "confidence_justification": "why this confidence level",
    "assumptions": ["assumption 1", "assumption 2"],
    "counterexamples": ["condition 1", "condition 2"],
    "reasoning": "detailed explanation"
}}"""

        return prompt

    def parse_response(self, response: dict[str, Any]) -> AttackerVerdict:
        if isinstance(response, str):
            return AttackerVerdict(reasoning=f"Raw response: {response[:500]}")

        return AttackerVerdict(
            exploitable=response.get("exploitable", False),
            payload=response.get("payload"),
            execution_trace=response.get("execution_trace", []),
            blocking_factors=response.get("blocking_factors", []),
            confidence=min(max(float(response.get("confidence", 0.0)), 0.0), 1.0),
            reasoning=response.get("reasoning", ""),
        )

    def _default_verdict(self) -> AttackerVerdict:
        return AttackerVerdict(
            exploitable=False,
            confidence=0.0,
            reasoning="Analysis failed — unable to determine exploitability",
        )
