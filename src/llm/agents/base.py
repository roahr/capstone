"""
Base Agent: Foundation class for LLM security agents.

Both the Attacker and Defender agents extend this base class,
which handles prompt rendering, context assembly, Jinja2 template
loading, and response parsing.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import jinja2

from src.llm.api.base_client import BaseLLMClient
from src.sast.sarif.schema import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE -> template category mapping
# ---------------------------------------------------------------------------
# Maps individual CWE IDs to the template category name used for selecting
# the correct Jinja2 prompt template.  CWE IDs not listed here fall back
# to the "default" category.

_CWE_CATEGORY_MAP: dict[str, str] = {
    # Injection family
    "CWE-78": "injection",
    "CWE-79": "injection",
    "CWE-89": "injection",
    "CWE-94": "injection",
    "CWE-95": "injection",
    # Broader injection CWEs that share the same analysis pattern
    "CWE-77": "injection",
    "CWE-74": "injection",
    "CWE-90": "injection",
    "CWE-917": "injection",

    # Deserialization
    "CWE-502": "deserialization",

    # Path traversal
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-35": "path_traversal",
    "CWE-59": "path_traversal",

    # Cryptographic weaknesses
    "CWE-327": "crypto",
    "CWE-328": "crypto",
    "CWE-330": "crypto",
    "CWE-331": "crypto",

    # Authentication / Authorization
    "CWE-287": "auth",
    "CWE-862": "auth",
    "CWE-863": "auth",
    "CWE-284": "auth",
    "CWE-285": "auth",
}

# ---------------------------------------------------------------------------
# Template directory (relative to this source file)
# ---------------------------------------------------------------------------
_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "prompts" / "templates"


def _cwe_to_category(cwe_id: str) -> str:
    """Map a CWE identifier to its template category name.

    Returns ``"default"`` for CWE IDs not explicitly mapped.
    """
    normalised = cwe_id.upper().strip()
    return _CWE_CATEGORY_MAP.get(normalised, "default")


class BaseSecurityAgent(ABC):
    """
    Abstract base class for SEC-C LLM security agents.

    Subclasses implement the specific prompt strategy and
    response parsing for attacker vs defender roles.
    """

    def __init__(
        self,
        client: BaseLLMClient,
        rag_knowledge_base: Any | None = None,
        use_pro: bool = False,
    ):
        self.client = client
        self.rag = rag_knowledge_base
        self.use_pro = use_pro

        # Jinja2 template environment -- loaded lazily on first use
        self._jinja_env: jinja2.Environment | None = None

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def role(self) -> str:
        """Agent role name (e.g., 'attacker', 'defender')."""
        ...

    @property
    @abstractmethod
    def system_instruction(self) -> str:
        """System instruction for the agent."""
        ...

    @abstractmethod
    def build_prompt(self, finding: Finding, context: dict[str, Any]) -> str:
        """Build the analysis prompt for this agent."""
        ...

    @abstractmethod
    def parse_response(self, response: dict[str, Any]) -> Any:
        """Parse the LLM response into the agent's verdict model."""
        ...

    # ------------------------------------------------------------------
    # Prompt tier selection
    # ------------------------------------------------------------------

    @staticmethod
    def _get_prompt_tier(finding: Finding, config: dict[str, Any] | None = None) -> str:
        """Determine the prompt tier based on the finding's uncertainty score.

        Three tiers control how much context is included in the prompt:

        * ``"minimal"`` — just code snippet + CWE name (~500 tokens).
          Used when ``U_score < minimal_threshold`` (default 0.3).
        * ``"standard"`` — code + taint path + CWE description (~1500 tokens).
          Used when ``minimal_threshold <= U_score < standard_threshold``
          (default 0.6).
        * ``"full"`` — everything including RAG context (~3000 tokens).
          Used when ``U_score >= standard_threshold``.

        Parameters
        ----------
        finding : Finding
            The vulnerability finding whose uncertainty score drives selection.
        config : dict[str, Any] | None
            Optional configuration with ``prompt_tier_thresholds`` mapping
            containing ``minimal`` and ``standard`` float thresholds.

        Returns
        -------
        str
            One of ``"minimal"``, ``"standard"``, or ``"full"``.
        """
        thresholds = (config or {}).get("prompt_tier_thresholds", {})
        minimal_threshold = float(thresholds.get("minimal", 0.3))
        standard_threshold = float(thresholds.get("standard", 0.6))

        u_score = finding.uncertainty.total

        if u_score < minimal_threshold:
            return "minimal"
        elif u_score < standard_threshold:
            return "standard"
        else:
            return "full"

    # ------------------------------------------------------------------
    # Core analysis loop
    # ------------------------------------------------------------------

    async def analyze(self, finding: Finding, context: dict[str, Any] | None = None) -> Any:
        """
        Run the agent's analysis on a finding.

        Args:
            finding: The vulnerability finding to analyze
            context: Additional context (code slice, RAG results, etc.)

        Returns:
            Agent-specific verdict (AttackerVerdict or DefenderVerdict)
        """
        ctx = context or {}

        # Enrich context with RAG if available
        if self.rag:
            rag_results = await self._query_rag(finding)
            ctx["rag_context"] = rag_results

        # Build prompt
        prompt = self.build_prompt(finding, ctx)

        logger.debug(f"[{self.role}] Sending prompt ({len(prompt)} chars) to Gemini")

        try:
            response = await self.client.generate(
                prompt=prompt,
                use_pro=self.use_pro,
                json_mode=True,
                system_instruction=self.system_instruction,
            )

            verdict = self.parse_response(response)
            logger.info(f"[{self.role}] Analysis complete for {finding.cwe_id} at {finding.location.display}")
            return verdict

        except Exception as e:
            logger.error(f"[{self.role}] Analysis failed: {e}")
            return self._default_verdict()

    # ------------------------------------------------------------------
    # Jinja2 template loading
    # ------------------------------------------------------------------

    def _get_jinja_env(self) -> jinja2.Environment:
        """Return (and lazily create) the Jinja2 template environment."""
        if self._jinja_env is None:
            self._jinja_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
                autoescape=False,  # prompts are plain text, not HTML
                undefined=jinja2.StrictUndefined,
                keep_trailing_newline=True,
            )
        return self._jinja_env

    def _load_template(self, cwe_id: str, role: str) -> jinja2.Template:
        """Load the CWE-specific Jinja2 prompt template for *role*.

        Template selection follows this priority:

        1. ``{role}_{category}.jinja2`` where *category* is derived from
           the CWE ID via :data:`_CWE_CATEGORY_MAP`.
        2. ``{role}_default.jinja2`` if no category-specific template
           exists.

        Args:
            cwe_id: CWE identifier (e.g. ``"CWE-89"``).
            role: Agent role (``"attacker"`` or ``"defender"``).

        Returns:
            A compiled :class:`jinja2.Template` ready for rendering.
        """
        env = self._get_jinja_env()
        category = _cwe_to_category(cwe_id)
        template_name = f"{role}_{category}.jinja2"

        try:
            return env.get_template(template_name)
        except jinja2.TemplateNotFound:
            logger.warning(
                "Template %s not found, falling back to %s_default.jinja2",
                template_name, role,
            )
            return env.get_template(f"{role}_default.jinja2")

    def _render_template(
        self,
        finding: Finding,
        context: dict[str, Any],
    ) -> str:
        """Render the CWE-specific Jinja2 template for this agent.

        Collects all template variables from the *finding* and *context*,
        loads the appropriate template via :meth:`_load_template`, and
        returns the rendered prompt string.
        """
        template = self._load_template(finding.cwe_id, self.role)

        code_slice = self._format_code_slice(finding, context)
        taint_path = self._format_taint_path(finding)
        rag_context = self._format_rag_context(context)

        # Graph context string
        graph_context = ""
        if finding.graph_validation:
            gv = finding.graph_validation
            parts = [
                f"  Structural Risk Score: {gv.structural_risk_score:.2f}",
                f"  Taint Path Length: {gv.taint_path_length}",
                f"  Control Flow Complexity: {gv.control_flow_complexity:.2f}",
                f"  Sanitizer Coverage: {gv.sanitizer_coverage:.2f}",
                f"  Interprocedural Depth: {gv.interprocedural_depth}",
                f"  Data Flow Fan-out: {gv.data_flow_fan_out}",
            ]
            graph_context = "\n".join(parts)

        template_vars = {
            "code_slice": code_slice,
            "taint_path": taint_path,
            "cwe_id": finding.cwe_id,
            "cwe_name": finding.cwe_name,
            "sast_message": finding.sast_message,
            "sast_confidence": f"{finding.sast_confidence:.0%}",
            "location": finding.location.display,
            "graph_context": graph_context,
            "rag_context": rag_context,
            "language": finding.language.value if finding.language else "unknown",
        }

        return template.render(**template_vars)

    # ------------------------------------------------------------------
    # RAG integration
    # ------------------------------------------------------------------

    async def _query_rag(self, finding: Finding) -> dict[str, Any]:
        """Query the RAG knowledge base for relevant context."""
        if not self.rag:
            return {}

        try:
            results = self.rag.query(
                cwe_id=finding.cwe_id,
                code_snippet=finding.location.snippet or "",
                top_k=5,
            )
            return results
        except Exception as e:
            logger.warning(f"RAG query failed: {e}")
            return {}

    # ------------------------------------------------------------------
    # Verdict default
    # ------------------------------------------------------------------

    @abstractmethod
    def _default_verdict(self) -> Any:
        """Return a default verdict when analysis fails."""
        ...

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    def _format_code_slice(self, finding: Finding, context: dict[str, Any]) -> str:
        """Format the code slice for the prompt."""
        code = context.get("code_slice", "")
        if not code and finding.location.snippet:
            code = finding.location.snippet
        return code

    def _format_taint_path(self, finding: Finding) -> str:
        """Format the taint flow path for the prompt."""
        if not finding.taint_flow or not finding.taint_flow.steps:
            return "No taint path available"

        parts = []
        for i, step in enumerate(finding.taint_flow.steps):
            kind = step.kind or "intermediate"
            loc = f"{step.location.file_path}:{step.location.start_line}"
            label = step.label or step.location.snippet or ""
            parts.append(f"  Step {i + 1} [{kind}]: {label} ({loc})")

        return "\n".join(parts)

    def _format_rag_context(self, context: dict[str, Any]) -> str:
        """Format RAG results for the prompt."""
        rag = context.get("rag_context", {})
        if not rag:
            return ""

        parts = []
        if "cwe_description" in rag:
            parts.append(f"CWE Description: {rag['cwe_description']}")
        if "similar_cves" in rag:
            for cve in rag["similar_cves"][:3]:
                parts.append(f"Similar CVE: {cve.get('id', 'N/A')} - {cve.get('description', '')[:200]}")
        if "code_examples" in rag:
            for ex in rag["code_examples"][:2]:
                parts.append(f"Example ({ex.get('type', 'unknown')}):\n{ex.get('code', '')[:500]}")
        if "owasp_guidance" in rag:
            parts.append(f"OWASP Guidance: {rag['owasp_guidance']}")

        return "\n".join(parts)
