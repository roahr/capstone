"""
SARIF Reporter: Generates SARIF 2.1.0 compliant output.

Produces standardized security reports compatible with GitHub Security tab,
VS Code SARIF Viewer, and other SARIF consumers. Includes custom SEC-C
properties for uncertainty scores, conformal prediction sets, and
dual-agent verdicts.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.sast.sarif.schema import Finding, ScanResult, Severity, Verdict

logger = logging.getLogger(__name__)

# SARIF severity mapping
SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Verdict to SARIF kind mapping
VERDICT_TO_SARIF_KIND: dict[Verdict, str] = {
    Verdict.CONFIRMED: "fail",
    Verdict.LIKELY: "fail",
    Verdict.POTENTIAL: "review",
    Verdict.SAFE: "pass",
    Verdict.UNKNOWN: "open",
}


class SARIFReporter:
    """
    Generates SARIF 2.1.0 compliant reports with SEC-C extensions.

    Custom properties added under the `sec-c/` namespace:
    - sec-c/uncertainty_score: Module 1 uncertainty quantification
    - sec-c/structural_risk: Module 2 graph-based risk score
    - sec-c/conformal_prediction_set: Module 2 calibrated prediction set
    - sec-c/attacker_verdict: Module 3 red team analysis
    - sec-c/defender_verdict: Module 3 blue team analysis
    - sec-c/fused_confidence: Final fused score
    - sec-c/stage_resolved: Which cascade stage resolved this finding
    - sec-c/nl_explanation: Natural language explanation
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.tool_name = self.config.get("tool_name", "sec-c")
        self.tool_version = self.config.get("tool_version", "2.0.0")
        self.include_custom = self.config.get("include_custom_properties", True)

    def generate(self, scan_result: ScanResult) -> dict[str, Any]:
        """Generate a complete SARIF document from a ScanResult."""
        # Collect unique rules
        rules = self._collect_rules(scan_result.findings)

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/sec-c/sec-c",
                            "semanticVersion": self.tool_version,
                            "rules": rules,
                            "properties": {
                                "sec-c/framework": "Multi-Stage Code Security Framework",
                                "sec-c/stages": ["sast", "graph", "llm"],
                            },
                        }
                    },
                    "results": [
                        self._finding_to_result(f) for f in scan_result.findings
                    ],
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                            "properties": {
                                "sec-c/cascade_stats": {
                                    "total_findings": scan_result.total_findings,
                                    "resolved_at_sast": scan_result.resolved_at_sast,
                                    "resolved_at_graph": scan_result.resolved_at_graph,
                                    "resolved_at_llm": scan_result.resolved_at_llm,
                                    "unresolved": scan_result.unresolved,
                                    "cascade_efficiency": f"{scan_result.cascade_efficiency:.1%}",
                                    "scan_duration_ms": scan_result.scan_duration_ms,
                                },
                            },
                        }
                    ],
                }
            ],
        }

        return sarif

    def write(self, scan_result: ScanResult, output_path: str) -> str:
        """Generate SARIF and write to file."""
        sarif = self.generate(scan_result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            json.dump(sarif, f, indent=2, default=str)

        logger.info(f"SARIF report written to {output_path}")
        return str(path)

    def _collect_rules(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Collect unique rules from findings."""
        seen: dict[str, dict[str, Any]] = {}

        for f in findings:
            if f.rule_id not in seen:
                rule: dict[str, Any] = {
                    "id": f.rule_id,
                    "shortDescription": {"text": f.cwe_name or f.rule_id},
                    "fullDescription": {"text": f.sast_message},
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
                    },
                    "properties": {
                        "tags": [f.cwe_id] if f.cwe_id else [],
                        "precision": "high" if f.sast_confidence >= 0.8 else "medium",
                    },
                }
                if f.cwe_id:
                    rule["properties"]["cwe"] = f.cwe_id

                seen[f.rule_id] = rule

        return list(seen.values())

    def _finding_to_result(self, finding: Finding) -> dict[str, Any]:
        """Convert a Finding to a SARIF result object."""
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
            "kind": VERDICT_TO_SARIF_KIND.get(finding.verdict, "open"),
            "message": {
                "text": finding.sast_message,
            },
            "locations": [self._location_to_sarif(finding)],
        }

        # Add taint flow as code flow
        if finding.taint_flow and finding.taint_flow.steps:
            result["codeFlows"] = [self._taint_flow_to_code_flow(finding)]

        # Add SEC-C custom properties
        if self.include_custom:
            result["properties"] = self._build_custom_properties(finding)

        return result

    def _location_to_sarif(self, finding: Finding) -> dict[str, Any]:
        """Convert a Finding's location to SARIF format."""
        loc = finding.location
        physical_location: dict[str, Any] = {
            "artifactLocation": {
                "uri": loc.file_path.replace("\\", "/"),
            },
            "region": {
                "startLine": loc.start_line,
            },
        }

        if loc.end_line:
            physical_location["region"]["endLine"] = loc.end_line
        if loc.start_column:
            physical_location["region"]["startColumn"] = loc.start_column
        if loc.end_column:
            physical_location["region"]["endColumn"] = loc.end_column
        if loc.snippet:
            physical_location["region"]["snippet"] = {"text": loc.snippet}

        return {"physicalLocation": physical_location}

    def _taint_flow_to_code_flow(self, finding: Finding) -> dict[str, Any]:
        """Convert a TaintFlow to SARIF codeFlow format."""
        thread_flow_locations = []

        for step in finding.taint_flow.steps:
            tfl: dict[str, Any] = {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": step.location.file_path.replace("\\", "/"),
                        },
                        "region": {
                            "startLine": step.location.start_line,
                        },
                    },
                    "message": {"text": step.label or step.kind},
                },
            }
            if step.kind:
                tfl["kinds"] = [step.kind]

            thread_flow_locations.append(tfl)

        return {
            "threadFlows": [
                {"locations": thread_flow_locations}
            ],
        }

    def _build_custom_properties(self, finding: Finding) -> dict[str, Any]:
        """Build SEC-C custom properties for a finding."""
        props: dict[str, Any] = {
            "sec-c/verdict": finding.verdict.value,
            "sec-c/fused_confidence": round(finding.fused_score, 4),
            "sec-c/stage_resolved": finding.stage_resolved.value,
            "sec-c/uncertainty_score": round(finding.uncertainty.total, 4),
        }

        if finding.graph_validation:
            gv = finding.graph_validation
            props["sec-c/structural_risk"] = round(gv.structural_risk_score, 4)
            props["sec-c/conformal_prediction_set"] = gv.conformal_prediction_set
            props["sec-c/conformal_coverage"] = round(gv.conformal_coverage, 4)

        if finding.llm_validation:
            lv = finding.llm_validation
            props["sec-c/attacker_verdict"] = {
                "exploitable": lv.attacker.exploitable,
                "confidence": round(lv.attacker.confidence, 4),
            }
            props["sec-c/defender_verdict"] = {
                "defense_coverage": round(lv.defender.defense_coverage_score, 4),
                "path_feasible": lv.defender.path_feasible,
            }
            props["sec-c/model_used"] = lv.model_used

        if finding.nl_explanation:
            props["sec-c/nl_explanation"] = finding.nl_explanation[:2000]

        if finding.remediation:
            props["sec-c/remediation"] = finding.remediation

        return props
