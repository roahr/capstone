"""
Core data models for the SEC-C framework.

Unified schema for vulnerability findings across all pipeline stages.
All modules produce and consume these models for interoperability.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POTENTIAL = "potential"
    SAFE = "safe"
    UNKNOWN = "unknown"


class StageResolved(str, Enum):
    SAST = "sast"
    GRAPH = "graph"
    LLM = "llm"
    UNRESOLVED = "unresolved"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CPP = "cpp"
    C = "c"
    GO = "go"


class Location(BaseModel):
    """Source code location of a finding."""
    file_path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    snippet: str | None = None

    @property
    def display(self) -> str:
        loc = f"{self.file_path}:{self.start_line}"
        if self.start_column:
            loc += f":{self.start_column}"
        return loc


class TaintFlowStep(BaseModel):
    """A single step in a taint propagation path."""
    location: Location
    label: str = ""
    kind: str = ""  # source, sink, intermediate, sanitizer


class TaintFlow(BaseModel):
    """Complete taint propagation path from source to sink."""
    steps: list[TaintFlowStep] = Field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def source(self) -> TaintFlowStep | None:
        return self.steps[0] if self.steps else None

    @property
    def sink(self) -> TaintFlowStep | None:
        return self.steps[-1] if self.steps else None

    @property
    def is_interprocedural(self) -> bool:
        if len(self.steps) < 2:
            return False
        files = {s.location.file_path for s in self.steps}
        return len(files) > 1


class UncertaintyScore(BaseModel):
    """4-factor uncertainty quantification for a finding.

    After the weighted 4-factor sum, an optional ``severity_adjustment``
    is added as a post-hoc term and the result is clamped to ``[0, 1]``.
    """
    confidence_uncertainty: float = Field(0.0, ge=0.0, le=1.0)
    complexity_uncertainty: float = Field(0.0, ge=0.0, le=1.0)
    novelty_uncertainty: float = Field(0.0, ge=0.0, le=1.0)
    conflict_uncertainty: float = Field(0.0, ge=0.0, le=1.0)

    # Weights
    w_conf: float = 0.4
    w_comp: float = 0.3
    w_nov: float = 0.2
    w_confl: float = 0.1

    # Post-hoc severity adjustment (additive)
    severity_adjustment: float = 0.0

    @property
    def total(self) -> float:
        raw = (
            self.w_conf * self.confidence_uncertainty
            + self.w_comp * self.complexity_uncertainty
            + self.w_nov * self.novelty_uncertainty
            + self.w_confl * self.conflict_uncertainty
            + self.severity_adjustment
        )
        return max(0.0, min(1.0, raw))

    @property
    def should_escalate(self) -> bool:
        return self.total >= 0.5


class GraphValidation(BaseModel):
    """Results from Module 2: Graph-Augmented Validation."""
    structural_risk_score: float = Field(0.0, ge=0.0, le=1.0)
    conformal_prediction_set: list[str] = Field(default_factory=list)  # ["safe"], ["vulnerable"], ["safe", "vulnerable"]
    conformal_coverage: float = Field(0.9, ge=0.0, le=1.0)
    taint_path_length: int = 0
    control_flow_complexity: float = 0.0
    data_flow_fan_out: int = 0
    sanitizer_coverage: float = 0.0
    interprocedural_depth: int = 0
    attention_weights: dict[str, float] = Field(default_factory=dict)

    @property
    def is_ambiguous(self) -> bool:
        return len(self.conformal_prediction_set) > 1


class AttackerVerdict(BaseModel):
    """Results from the Red Team (Attacker) LLM agent."""
    exploitable: bool = False
    payload: str | None = None
    execution_trace: list[str] = Field(default_factory=list)
    blocking_factors: list[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reasoning: str = ""


class DefenderVerdict(BaseModel):
    """Results from the Blue Team (Defender) LLM agent."""
    sanitizers_found: list[dict[str, Any]] = Field(default_factory=list)
    access_controls: list[str] = Field(default_factory=list)
    framework_protections: list[str] = Field(default_factory=list)
    path_feasible: bool = True
    defense_coverage_score: float = Field(0.0, ge=0.0, le=1.0)
    reasoning: str = ""


class LLMValidation(BaseModel):
    """Results from Module 3: LLM Dual-Agent Validation."""
    attacker: AttackerVerdict = Field(default_factory=AttackerVerdict)
    defender: DefenderVerdict = Field(default_factory=DefenderVerdict)
    consensus_verdict: Verdict = Verdict.UNKNOWN
    consensus_confidence: float = Field(0.0, ge=0.0, le=1.0)
    model_used: str = ""
    nl_explanation: str = ""


class Finding(BaseModel):
    """
    Unified vulnerability finding that flows through all pipeline stages.

    This is the core data model of the SEC-C framework. A Finding is created
    by Module 1 (SAST), enriched by Module 2 (Graph), validated by Module 3 (LLM),
    and reported by Module 4 (Reporting).
    """
    # Identity
    id: str = ""
    rule_id: str = ""
    cwe_id: str = ""
    cwe_name: str = ""

    # Classification
    severity: Severity = Severity.MEDIUM
    verdict: Verdict = Verdict.UNKNOWN
    language: Language = Language.PYTHON

    # Location
    location: Location = Field(default_factory=lambda: Location(file_path="", start_line=0))
    taint_flow: TaintFlow | None = None

    # SAST (Module 1) results
    sast_confidence: float = Field(0.0, ge=0.0, le=1.0)
    sast_message: str = ""
    sast_tool: str = "codeql"
    uncertainty: UncertaintyScore = Field(default_factory=UncertaintyScore)

    # Graph (Module 2) results
    graph_validation: GraphValidation | None = None

    # LLM (Module 3) results
    llm_validation: LLMValidation | None = None

    # Final (Module 4) results
    fused_score: float = Field(0.0, ge=0.0, le=1.0)
    stage_resolved: StageResolved = StageResolved.UNRESOLVED
    nl_explanation: str = ""
    remediation: str = ""

    # Metadata
    timestamp: datetime = Field(default_factory=datetime.now)
    processing_time_ms: float = 0.0
    tags: list[str] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_escalated_to_graph(self) -> bool:
        return self.uncertainty.should_escalate

    @property
    def is_escalated_to_llm(self) -> bool:
        return (
            self.graph_validation is not None
            and self.graph_validation.is_ambiguous
        )

    @property
    def display_summary(self) -> str:
        return (
            f"[{self.severity.value.upper()}] {self.cwe_id}: {self.sast_message} "
            f"at {self.location.display} "
            f"(verdict={self.verdict.value}, score={self.fused_score:.2f})"
        )


class ScanResult(BaseModel):
    """Complete result of a SEC-C scan."""
    findings: list[Finding] = Field(default_factory=list)
    scan_target: str = ""
    languages_detected: list[Language] = Field(default_factory=list)
    total_files_scanned: int = 0
    total_lines_scanned: int = 0
    scan_duration_ms: float = 0.0

    # Cascade statistics
    resolved_at_sast: int = 0
    resolved_at_graph: int = 0
    resolved_at_llm: int = 0
    unresolved: int = 0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def confirmed_count(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.CONFIRMED)

    @property
    def likely_count(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.LIKELY)

    @property
    def potential_count(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.POTENTIAL)

    @property
    def cascade_efficiency(self) -> float:
        total = self.resolved_at_sast + self.resolved_at_graph + self.resolved_at_llm + self.unresolved
        if total == 0:
            return 0.0
        return self.resolved_at_sast / total

    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    def by_cwe(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.cwe_id, []).append(f)
        return result

    def by_language(self) -> dict[Language, list[Finding]]:
        result: dict[Language, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.language, []).append(f)
        return result
