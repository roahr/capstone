"""
Context Assembler: Packages finding context for LLM consumption.

Combines code slices, taint paths, SAST uncertainty factors, graph
structural risk scores, and RAG knowledge into a unified context
package that fits within Gemini's 1M token context window.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.sast.sarif.schema import Finding

logger = logging.getLogger(__name__)

MAX_CODE_SLICE_LINES = 200  # Max lines to include in LLM context
CONTEXT_LINES_BEFORE = 20  # Lines before the finding location
CONTEXT_LINES_AFTER = 20   # Lines after the finding location


class ContextAssembler:
    """
    Assembles rich context for LLM dual-agent validation.

    Packages:
    - Code slice around the vulnerability location
    - Full taint path with annotated steps
    - SAST uncertainty factors breakdown
    - Graph validation metrics (if available)
    - RAG-retrieved CWE/CVE knowledge
    """

    def __init__(self, rag_knowledge_base: Any | None = None):
        self.rag = rag_knowledge_base

    def assemble(self, finding: Finding) -> dict[str, Any]:
        """
        Assemble full context for a finding.

        Returns a dict with all context needed by the attacker/defender agents.
        """
        context: dict[str, Any] = {}

        # Code slice
        context["code_slice"] = self._extract_code_slice(finding)

        # Taint path summary
        context["taint_summary"] = self._summarize_taint_path(finding)

        # SAST uncertainty breakdown
        context["uncertainty_breakdown"] = {
            "total": finding.uncertainty.total,
            "confidence": finding.uncertainty.confidence_uncertainty,
            "complexity": finding.uncertainty.complexity_uncertainty,
            "novelty": finding.uncertainty.novelty_uncertainty,
            "conflict": finding.uncertainty.conflict_uncertainty,
        }

        # Graph validation metrics
        if finding.graph_validation:
            gv = finding.graph_validation
            context["graph_metrics"] = {
                "structural_risk": gv.structural_risk_score,
                "taint_path_length": gv.taint_path_length,
                "control_flow_complexity": gv.control_flow_complexity,
                "data_flow_fan_out": gv.data_flow_fan_out,
                "sanitizer_coverage": gv.sanitizer_coverage,
                "interprocedural_depth": gv.interprocedural_depth,
                "conformal_set": gv.conformal_prediction_set,
            }

        # RAG context
        if self.rag:
            try:
                rag_results = self.rag.query(
                    cwe_id=finding.cwe_id,
                    code_snippet=finding.location.snippet or "",
                    top_k=5,
                )
                context["rag_context"] = rag_results
            except Exception as e:
                logger.warning(f"RAG query failed: {e}")

        return context

    def _extract_code_slice(self, finding: Finding) -> str:
        """Extract relevant code around the finding location."""
        file_path = finding.location.file_path
        target_line = finding.location.start_line

        try:
            path = Path(file_path)
            if not path.exists():
                return finding.location.snippet or f"[File not found: {file_path}]"

            lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        except Exception as e:
            logger.warning(f"Could not read source file {file_path}: {e}")
            return finding.location.snippet or ""

        # Determine slice range
        start = max(0, target_line - CONTEXT_LINES_BEFORE - 1)
        end = min(len(lines), target_line + CONTEXT_LINES_AFTER)

        # If taint flow spans multiple lines, expand to cover all
        if finding.taint_flow and finding.taint_flow.steps:
            flow_lines = [
                s.location.start_line
                for s in finding.taint_flow.steps
                if s.location.file_path == file_path
            ]
            if flow_lines:
                start = max(0, min(flow_lines) - 5)
                end = min(len(lines), max(flow_lines) + 5)

        # Cap at max lines
        if end - start > MAX_CODE_SLICE_LINES:
            end = start + MAX_CODE_SLICE_LINES

        # Format with line numbers
        slice_lines = []
        for i in range(start, end):
            line_num = i + 1
            marker = " >> " if line_num == target_line else "    "
            slice_lines.append(f"{line_num:4d}{marker}{lines[i]}")

        return "\n".join(slice_lines)

    def _summarize_taint_path(self, finding: Finding) -> str:
        """Create a human-readable taint path summary."""
        if not finding.taint_flow or not finding.taint_flow.steps:
            return "No taint path available"

        parts = [f"Taint path ({finding.taint_flow.length} steps):"]
        for i, step in enumerate(finding.taint_flow.steps):
            kind = step.kind.upper() if step.kind else "STEP"
            loc = f"{step.location.file_path}:{step.location.start_line}"
            label = step.label or step.location.snippet or ""
            arrow = " -> " if i < len(finding.taint_flow.steps) - 1 else ""
            parts.append(f"  [{kind}] {label} ({loc}){arrow}")

        if finding.taint_flow.is_interprocedural:
            parts.append("  [INTERPROCEDURAL: crosses file/function boundaries]")

        return "\n".join(parts)
