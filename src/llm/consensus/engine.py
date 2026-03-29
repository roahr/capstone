"""
Consensus Engine: Combines Attacker and Defender agent verdicts.

Implements the adversarial consensus protocol where the Attacker's
exploit attempts and the Defender's protection analysis are combined
to produce a final triage decision.

The engine optionally accepts a RAG :class:`KnowledgeBase` which is
queried *before* dispatching each finding to the agents, so that both
the Attacker and Defender receive the same CWE-enriched context in
their prompts.

Supports batch validation: multiple findings can be analysed in a
single LLM call to conserve API quota.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from src.llm.agents.attacker import AttackerAgent
from src.llm.agents.defender import DefenderAgent
from src.llm.api.base_client import BaseLLMClient
from src.sast.sarif.schema import (
    AttackerVerdict,
    DefenderVerdict,
    Finding,
    LLMValidation,
    Verdict,
)

logger = logging.getLogger(__name__)


class ConsensusEngine:
    """
    Dual-agent consensus engine for vulnerability triage.

    Runs Attacker and Defender agents on the same finding, then
    combines their verdicts using the consensus rules:

    - If attacker succeeds AND defender coverage < threshold -> Confirmed
    - If attacker fails AND defender coverage > threshold -> Safe
    - Otherwise -> Likely (uncertain, lean toward vulnerable)

    Thresholds are configurable via the ``consensus`` config section:

    - ``confirmed_defense_threshold`` (default 0.5)
    - ``safe_defense_threshold`` (default 0.7)
    - ``infeasible_confidence`` (default 0.8)

    This adversarial protocol achieves higher accuracy than single-model
    approaches (88% vs 50% per Columbia University research).

    Args:
        client: Gemini API client for LLM requests.
        rag_knowledge_base: Optional RAG knowledge base for CWE/CVE
            context enrichment.  Passed through to both agents **and**
            queried at the engine level to inject RAG context into the
            shared context dict before agent dispatch.
        config: Optional configuration overrides for agent behaviour.
    """

    def __init__(
        self,
        client: BaseLLMClient,
        rag_knowledge_base: Any | None = None,
        config: dict[str, Any] | None = None,
    ):
        self.config = config or {}
        self.client = client
        self.rag = rag_knowledge_base

        # ---- Consensus thresholds from config ----
        consensus_cfg = self.config.get("consensus", {})
        self._confirmed_defense_threshold: float = float(
            consensus_cfg.get("confirmed_defense_threshold", 0.5)
        )
        self._safe_defense_threshold: float = float(
            consensus_cfg.get("safe_defense_threshold", 0.7)
        )
        self._infeasible_confidence: float = float(
            consensus_cfg.get("infeasible_confidence", 0.8)
        )

        # ---- Batch settings ----
        gemini_cfg = self.config.get("gemini", {})
        self._max_batch_size: int = int(gemini_cfg.get("max_batch_size", 5))

        # Create agents -- both receive the same RAG knowledge base so
        # they can individually query it as well (e.g. for code examples).
        # Agents now default to Flash (use_pro=False) to conserve quota.
        self.attacker = AttackerAgent(
            client=client,
            rag_knowledge_base=rag_knowledge_base,
            use_pro=False,
        )
        self.defender = DefenderAgent(
            client=client,
            rag_knowledge_base=rag_knowledge_base,
            use_pro=False,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def validate(
        self,
        finding: Finding,
        context: dict[str, Any] | None = None,
    ) -> Finding:
        """
        Run dual-agent validation on a finding.

        Executes both Attacker and Defender agents, then applies
        consensus rules to determine the final verdict.

        If a RAG knowledge base is available, the engine queries it for
        the finding's CWE **before** dispatching to agents, ensuring
        both agents share identical enriched context.
        """
        ctx = dict(context) if context else {}

        logger.debug(
            "Dual-agent validation: %s at %s",
            finding.cwe_id, finding.location.display,
        )

        # ---- RAG enrichment (engine-level) ----
        if self.rag and "rag_context" not in ctx:
            rag_result = self._query_rag_for_finding(finding)
            if rag_result:
                ctx["rag_context"] = rag_result

        # Run both agents
        attacker_verdict = await self.attacker.analyze(finding, ctx)
        defender_verdict = await self.defender.analyze(finding, ctx)

        # Apply consensus rules
        consensus_verdict, consensus_confidence = self._apply_consensus(
            attacker_verdict, defender_verdict
        )

        # Build explanation
        explanation = self._build_explanation(
            finding, attacker_verdict, defender_verdict,
            consensus_verdict, consensus_confidence
        )

        # Compute CVSS from agent sub-scores
        from src.llm.consensus.cvss import compute_cvss_base_score

        cvss_score, cvss_vector, cvss_severity = compute_cvss_base_score(
            attack_vector=attacker_verdict.attack_vector,
            attack_complexity=attacker_verdict.attack_complexity,
            privileges_required=attacker_verdict.privileges_required,
            user_interaction=attacker_verdict.user_interaction,
            scope=defender_verdict.scope,
            confidentiality=defender_verdict.confidentiality_impact,
            integrity=defender_verdict.integrity_impact,
            availability=defender_verdict.availability_impact,
        )

        # Build evidence narrative
        evidence_narrative = self._build_evidence_narrative(
            finding, attacker_verdict, defender_verdict, cvss_score, cvss_severity
        )

        # Attach results to finding
        model_name = (
            self.client.model_pro if self.attacker.use_pro
            else self.client.model_flash
        )
        finding.llm_validation = LLMValidation(
            attacker=attacker_verdict,
            defender=defender_verdict,
            consensus_verdict=consensus_verdict,
            consensus_confidence=consensus_confidence,
            model_used=model_name,
            nl_explanation=explanation,
            cvss_base_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_severity=cvss_severity,
            evidence_narrative=evidence_narrative,
        )

        # Update finding verdict and CVSS
        finding.verdict = consensus_verdict
        finding.cvss_base_score = cvss_score
        finding.cvss_vector = cvss_vector
        finding.cvss_severity = cvss_severity

        logger.debug(
            "Consensus: %s (confidence: %.2f) for %s at %s",
            consensus_verdict.value, consensus_confidence,
            finding.cwe_id, finding.location.display,
        )

        return finding

    # ------------------------------------------------------------------
    # Batch validation
    # ------------------------------------------------------------------

    async def validate_batch(
        self,
        findings: list[Finding],
        context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """
        Validate multiple findings in a single LLM call to conserve quota.

        Constructs a single prompt asking the LLM to analyse all findings
        at once, returning a JSON array with one entry per finding.  If the
        batch call fails (e.g. malformed response, API error), falls back
        to individual :meth:`validate` calls.

        Findings are processed in chunks of ``max_batch_size`` (default 5).

        Parameters
        ----------
        findings : list[Finding]
            The findings to validate.
        context : dict[str, Any] | None
            Optional shared context (RAG, code slices, etc.).

        Returns
        -------
        list[Finding]
            The input findings with ``llm_validation`` and ``verdict`` set.
        """
        if not findings:
            return []

        # Process in chunks of max_batch_size
        results: list[Finding] = []
        for chunk_start in range(0, len(findings), self._max_batch_size):
            chunk = findings[chunk_start : chunk_start + self._max_batch_size]
            try:
                chunk_results = await self._validate_batch_chunk(chunk, context)
                results.extend(chunk_results)
            except Exception as e:
                logger.debug(
                    "Batch validation failed for %d findings, using individual: %s",
                    len(chunk), str(e)[:80],
                )
                for finding in chunk:
                    result = await self.validate(finding, context)
                    results.append(result)

        return results

    async def _validate_batch_chunk(
        self,
        findings: list[Finding],
        context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Validate a single batch chunk via one LLM call."""
        ctx = dict(context) if context else {}

        # Build the batch prompt
        prompt = self._build_batch_prompt(findings, ctx)

        logger.info(
            "Running batch validation for %d findings in a single LLM call",
            len(findings),
        )

        # Send as a single request (use Flash to conserve Pro quota)
        response = await self.client.generate(
            prompt=prompt,
            use_pro=False,
            json_mode=True,
            system_instruction=(
                "You are an expert security analyst performing dual-perspective "
                "(attacker + defender) vulnerability triage. Analyze each finding "
                "and respond with a JSON array. Always respond in valid JSON format."
            ),
        )

        # Parse the batch response
        parsed = self._parse_batch_response(response, len(findings))

        # Apply results to each finding
        for i, finding in enumerate(findings):
            entry = parsed[i]

            attacker_verdict = AttackerVerdict(
                exploitable=entry.get("attacker", {}).get("exploitable", False),
                payload=entry.get("attacker", {}).get("payload"),
                confidence=min(max(
                    float(entry.get("attacker", {}).get("confidence", 0.0)),
                    0.0), 1.0),
                reasoning=entry.get("attacker", {}).get("reasoning", ""),
            )

            defender_verdict = DefenderVerdict(
                sanitizers_found=entry.get("defender", {}).get("sanitizers_found", []),
                access_controls=entry.get("defender", {}).get("access_controls", []),
                framework_protections=entry.get("defender", {}).get("framework_protections", []),
                path_feasible=entry.get("defender", {}).get("path_feasible", True),
                defense_coverage_score=min(max(
                    float(entry.get("defender", {}).get("defense_coverage_score", 0.0)),
                    0.0), 1.0),
                reasoning=entry.get("defender", {}).get("reasoning", ""),
            )

            consensus_verdict, consensus_confidence = self._apply_consensus(
                attacker_verdict, defender_verdict
            )

            explanation = self._build_explanation(
                finding, attacker_verdict, defender_verdict,
                consensus_verdict, consensus_confidence,
            )

            finding.llm_validation = LLMValidation(
                attacker=attacker_verdict,
                defender=defender_verdict,
                consensus_verdict=consensus_verdict,
                consensus_confidence=consensus_confidence,
                model_used=self.client.model_flash,
                nl_explanation=explanation,
            )
            finding.verdict = consensus_verdict

            logger.info(
                "Batch consensus: %s (confidence: %.2f) for %s at %s",
                consensus_verdict.value, consensus_confidence,
                finding.cwe_id, finding.location.display,
            )

        return findings

    def _build_batch_prompt(
        self,
        findings: list[Finding],
        context: dict[str, Any],
    ) -> str:
        """Construct a single prompt for batch analysis of multiple findings."""
        parts = [
            f"Analyze these {len(findings)} vulnerability findings. "
            "For each finding, provide both attacker (red team) and defender "
            "(blue team) analysis.\n",
        ]

        for i, finding in enumerate(findings):
            code_snippet = ""
            if finding.location.snippet:
                code_snippet = finding.location.snippet

            taint_info = "No taint path available"
            if finding.taint_flow and finding.taint_flow.steps:
                steps = []
                for j, step in enumerate(finding.taint_flow.steps):
                    kind = step.kind or "intermediate"
                    loc = f"{step.location.file_path}:{step.location.start_line}"
                    label = step.label or step.location.snippet or ""
                    steps.append(f"    Step {j + 1} [{kind}]: {label} ({loc})")
                taint_info = "\n".join(steps)

            parts.append(
                f"## Finding {i + 1}: {finding.cwe_id} ({finding.cwe_name})\n"
                f"- Rule: {finding.rule_id}\n"
                f"- Location: {finding.location.display}\n"
                f"- Severity: {finding.severity.value}\n"
                f"- SAST Confidence: {finding.sast_confidence:.0%}\n"
                f"- Message: {finding.sast_message}\n"
                f"### Code\n```\n{code_snippet}\n```\n"
                f"### Taint Path\n{taint_info}\n"
            )

        parts.append(
            "Respond with a JSON array of objects, one per finding, in order. "
            "Each object must have this structure:\n"
            "```json\n"
            "[\n"
            "  {\n"
            '    "finding_index": 1,\n'
            '    "attacker": {\n'
            '      "exploitable": true/false,\n'
            '      "payload": "exploit string or null",\n'
            '      "confidence": 0.0 to 1.0,\n'
            '      "reasoning": "explanation"\n'
            "    },\n"
            '    "defender": {\n'
            '      "sanitizers_found": [],\n'
            '      "access_controls": [],\n'
            '      "framework_protections": [],\n'
            '      "path_feasible": true/false,\n'
            '      "defense_coverage_score": 0.0 to 1.0,\n'
            '      "reasoning": "explanation"\n'
            "    }\n"
            "  }\n"
            "]\n"
            "```"
        )

        return "\n".join(parts)

    def _parse_batch_response(
        self,
        response: Any,
        expected_count: int,
    ) -> list[dict[str, Any]]:
        """Parse the batch LLM response into a list of per-finding dicts.

        Raises ``ValueError`` if the response cannot be parsed into the
        expected number of entries.
        """
        if isinstance(response, str):
            try:
                response = json.loads(response)
            except json.JSONDecodeError as e:
                raise ValueError(f"Batch response is not valid JSON: {e}") from e

        if isinstance(response, list):
            entries = response
        elif isinstance(response, dict):
            # Some models wrap the array in an object
            for key in ("findings", "results", "analyses"):
                if key in response and isinstance(response[key], list):
                    entries = response[key]
                    break
            else:
                raise ValueError(
                    "Batch response is a dict but contains no recognisable array key"
                )
        else:
            raise ValueError(f"Unexpected batch response type: {type(response)}")

        if len(entries) != expected_count:
            logger.warning(
                "Batch response has %d entries but expected %d; "
                "padding/truncating to match",
                len(entries), expected_count,
            )
            # Pad with empty dicts if too few
            while len(entries) < expected_count:
                entries.append({})
            # Truncate if too many
            entries = entries[:expected_count]

        return entries

    # ------------------------------------------------------------------
    # RAG query (engine-level, shared by both agents)
    # ------------------------------------------------------------------

    def _query_rag_for_finding(self, finding: Finding) -> dict[str, Any]:
        """Query the RAG knowledge base for the finding's CWE.

        This is called once at the engine level so both agents receive
        identical RAG context.  Individual agents may perform additional
        RAG queries via their own ``_query_rag`` method.
        """
        try:
            result = self.rag.query(
                cwe_id=finding.cwe_id,
                code_snippet=finding.location.snippet or "",
                top_k=5,
            )
            if result:
                logger.debug(
                    "RAG context retrieved for %s: %d keys",
                    finding.cwe_id, len(result),
                )
            return result
        except Exception as e:
            logger.warning("Engine-level RAG query failed for %s: %s", finding.cwe_id, e)
            return {}

    # ------------------------------------------------------------------
    # Consensus logic
    # ------------------------------------------------------------------

    def _apply_consensus(
        self,
        attacker: AttackerVerdict,
        defender: DefenderVerdict,
    ) -> tuple[Verdict, float]:
        """
        Apply consensus rules to determine the final verdict.

        Thresholds are read from configuration:
        - ``confirmed_defense_threshold`` (default 0.5)
        - ``safe_defense_threshold`` (default 0.7)
        - ``infeasible_confidence`` (default 0.8)

        Rules:
        1. Attacker exploitable + low defense -> Confirmed (TP)
        2. Attacker not exploitable + high defense -> Safe (FP filtered)
        3. Otherwise -> Likely (uncertain)
        """
        atk_exploitable = attacker.exploitable
        atk_confidence = attacker.confidence
        def_coverage = defender.defense_coverage_score
        def_feasible = defender.path_feasible

        confirmed_thresh = self._confirmed_defense_threshold
        safe_thresh = self._safe_defense_threshold
        infeasible_conf = self._infeasible_confidence

        # Rule 1: Strong evidence of vulnerability
        if atk_exploitable and def_coverage < confirmed_thresh:
            confidence = max(atk_confidence, 1.0 - def_coverage)
            return Verdict.CONFIRMED, min(confidence, 1.0)

        # Rule 2: Strong evidence of safety
        if not atk_exploitable and def_coverage > safe_thresh:
            confidence = max(def_coverage, 1.0 - atk_confidence)
            return Verdict.SAFE, min(confidence, 1.0)

        # Rule 2b: Path not feasible -> Safe
        if not def_feasible and not atk_exploitable:
            confidence = infeasible_conf
            return Verdict.SAFE, confidence

        # Rule 3: Attacker succeeded but strong defenses exist
        if atk_exploitable and def_coverage >= confirmed_thresh:
            # Partial defense -- likely vulnerable but not certain
            confidence = 0.5 + 0.3 * (atk_confidence - def_coverage)
            return Verdict.LIKELY, min(max(confidence, 0.3), 0.85)

        # Rule 4: Attacker failed but weak defenses
        if not atk_exploitable and def_coverage <= safe_thresh:
            # Might be vulnerable, attacker just didn't find the path
            confidence = 0.4 + 0.2 * (1.0 - def_coverage)
            return Verdict.POTENTIAL, min(max(confidence, 0.2), 0.6)

        # Default: uncertain
        confidence = 0.5
        return Verdict.LIKELY, confidence

    def _build_explanation(
        self,
        finding: Finding,
        attacker: AttackerVerdict,
        defender: DefenderVerdict,
        verdict: Verdict,
        confidence: float,
    ) -> str:
        """Build a natural language explanation of the consensus."""
        parts = [
            f"## Dual-Agent Triage: {finding.cwe_id} ({finding.cwe_name})",
            f"Location: {finding.location.display}",
            "",
            "### Attacker Analysis (Red Team)",
            f"Exploitable: {'YES' if attacker.exploitable else 'NO'} "
            f"(confidence: {attacker.confidence:.0%})",
        ]

        if attacker.payload:
            parts.append(f"Payload: `{attacker.payload[:200]}`")

        if attacker.blocking_factors:
            parts.append(f"Blocking factors: {', '.join(attacker.blocking_factors)}")

        parts.extend([
            "",
            "### Defender Analysis (Blue Team)",
            f"Defense Coverage: {defender.defense_coverage_score:.0%}",
            f"Path Feasible: {'YES' if defender.path_feasible else 'NO'}",
        ])

        if defender.sanitizers_found:
            sanitizer_names = [s.get("function", "unknown") for s in defender.sanitizers_found]
            parts.append(f"Sanitizers: {', '.join(sanitizer_names)}")

        if defender.access_controls:
            parts.append(f"Access Controls: {', '.join(defender.access_controls)}")

        if defender.framework_protections:
            parts.append(f"Framework Protections: {', '.join(defender.framework_protections)}")

        parts.extend([
            "",
            "### Consensus",
            f"**Verdict: {verdict.value.upper()}** (confidence: {confidence:.0%})",
            "",
            "### Reasoning",
            attacker.reasoning[:300] if attacker.reasoning else "(no attacker reasoning)",
            "",
            defender.reasoning[:300] if defender.reasoning else "(no defender reasoning)",
        ])

        return "\n".join(parts)

    def _build_evidence_narrative(
        self,
        finding: Finding,
        attacker: AttackerVerdict,
        defender: DefenderVerdict,
        cvss_score: float,
        cvss_severity: str,
    ) -> str:
        """Build a plain-language narrative explaining the finding for stakeholders."""
        cwe = f"{finding.cwe_id} ({finding.cwe_name})" if finding.cwe_name else finding.cwe_id
        location = finding.location.display

        # Build from attacker/defender analysis
        parts = []

        if attacker.exploitable:
            av_desc = {"network": "from the network", "adjacent": "from an adjacent network", "local": "locally", "physical": "with physical access"}.get(attacker.attack_vector, "")
            pr_desc = {"none": "without authentication", "low": "with low privileges", "high": "with high privileges"}.get(attacker.privileges_required, "")
            parts.append(f"This {finding.cwe_name or cwe} vulnerability at {location} is exploitable {av_desc} {pr_desc}.")
        else:
            parts.append(f"This potential {finding.cwe_name or cwe} at {location} was not found to be exploitable.")

        # Evidence from attacker
        if attacker.evidence_steps:
            key_evidence = attacker.evidence_steps[0] if attacker.evidence_steps else ""
            if key_evidence:
                parts.append(key_evidence + ".")

        # Payload info
        if attacker.exploitable and attacker.payload:
            parts.append(f"A working exploit payload was constructed.")

        # Defender findings
        if defender.defense_evidence:
            parts.append(defender.defense_evidence[0] + ".")
        elif defender.defense_coverage_score < 0.2:
            parts.append("No effective defensive controls were identified in the code path.")

        # CVSS context
        parts.append(f"CVSS v3.1 base score: {cvss_score} ({cvss_severity.upper()}).")

        return " ".join(parts)
