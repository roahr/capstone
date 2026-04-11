# Sec-C: System Data Model & Pipeline Flow

> Complete reference for all data structures, pipeline stages, routing logic, and consensus rules.
> Source: `src/sast/sarif/schema.py`, `src/orchestrator/pipeline.py`, `src/sast/router.py`, `src/llm/consensus/engine.py`

---

## 1. Core Enums

```
Severity:       CRITICAL | HIGH | MEDIUM | LOW | INFO
Verdict:        CONFIRMED | LIKELY | POTENTIAL | SAFE | UNKNOWN
StageResolved:  SAST | GRAPH | LLM | UNRESOLVED
Language:       PYTHON | JAVASCRIPT | TYPESCRIPT | JAVA | CPP | C | GO
```

---

## 2. Data Model Classes (Pydantic v2)

### Location
```
file_path: str                    # Source file path
start_line: int                   # Line number (1-indexed)
end_line: int | None              # Optional end line
start_column: int | None          # Optional column
end_column: int | None
snippet: str | None               # Code snippet at location
```

### TaintFlowStep
```
location: Location                # Where this step occurs
label: str                        # Description (e.g., "user input read")
kind: str                         # "source" | "sink" | "intermediate" | "sanitizer"
```

### TaintFlow
```
steps: list[TaintFlowStep]        # Complete propagation path
---
length → count of steps
source → first step (or None)
sink → last step (or None)
is_interprocedural → True if steps cross file boundaries
```

### UncertaintyScore
```
confidence_uncertainty: float     # [0,1] — how unsure the tool is
complexity_uncertainty: float     # [0,1] — analysis complexity
novelty_uncertainty: float        # [0,1] — pattern rarity
conflict_uncertainty: float       # [0,1] — multi-tool disagreement
severity_adjustment: float        # Additive post-hoc term
---
total → weighted sum clamped [0,1]
should_escalate → True if total >= 0.5
```

### GraphValidation (Module 2 output)
```
structural_risk_score: float      # [0,1] CPG structural analysis
conformal_prediction_set: list[str]  # ["safe"], ["vulnerable"], or both
conformal_coverage: float         # [0,1] prediction set confidence
taint_path_length: int
control_flow_complexity: float
data_flow_fan_out: int
sanitizer_coverage: float
interprocedural_depth: int        # Call stack depth
attention_weights: dict[str, float]  # GAT attention scores per edge
---
is_ambiguous → True if prediction set contains both "safe" and "vulnerable"
```

### AttackerVerdict (Red Team — Module 3)
```
exploitable: bool                 # Can this be exploited?
payload: str | None               # Proof-of-concept exploit
execution_trace: list[str]        # Step-by-step attack path
blocking_factors: list[str]       # What prevents exploitation
confidence: float                 # [0,1] attacker confidence
reasoning: str                    # Natural language analysis
attack_vector: str                # "network" | "adjacent" | "local" | "physical"
attack_complexity: str            # "low" | "high"
privileges_required: str          # "none" | "low" | "high"
user_interaction: str             # "none" | "required"
evidence_steps: list[str]         # Supporting evidence chain
```

### DefenderVerdict (Blue Team — Module 3)
```
sanitizers_found: list[dict]      # Input validation functions found
access_controls: list[str]        # Authorization checks
framework_protections: list[str]  # Framework-level defenses
path_feasible: bool               # Is the vulnerability path reachable?
defense_coverage_score: float     # [0,1] defense completeness
reasoning: str                    # Natural language analysis
scope: str                        # "unchanged" | "changed" (CVSS)
confidentiality_impact: str       # "none" | "low" | "high"
integrity_impact: str             # "none" | "low" | "high"
availability_impact: str          # "none" | "low" | "high"
defense_evidence: list[str]       # Supporting evidence
```

### LLMValidation (Module 3 combined output)
```
attacker: AttackerVerdict         # Red team analysis
defender: DefenderVerdict         # Blue team analysis
consensus_verdict: Verdict        # Final triage decision
consensus_confidence: float       # [0,1] confidence in verdict
model_used: str                   # LLM model identifier
nl_explanation: str               # Natural language explanation
cvss_base_score: float            # 0.0 – 10.0
cvss_vector: str                  # CVSS v3.1 vector string
cvss_severity: str                # "critical" | "high" | "medium" | "low" | "none"
evidence_narrative: str           # Stakeholder-facing narrative
```

### Finding (Central Object — Traverses All 4 Stages)
```
# Identity
id: str                           # Unique finding ID
rule_id: str                      # Detection rule that triggered
cwe_id: str                       # CWE identifier (e.g., "CWE-89")
cwe_name: str                     # CWE name (e.g., "SQL Injection")

# Classification
severity: Severity                # CRITICAL / HIGH / MEDIUM / LOW / INFO
verdict: Verdict                  # CONFIRMED / LIKELY / POTENTIAL / SAFE / UNKNOWN
language: Language                # Source code language

# Location
location: Location                # Where the finding is
taint_flow: TaintFlow | None      # Data flow path (if taint-tracked)

# Module 1 (SAST)
sast_confidence: float            # [0,1] SAST tool confidence
sast_message: str                 # SAST finding description
sast_tool: str                    # "treesitter" | "codeql" | "both"
uncertainty: UncertaintyScore     # 4-factor uncertainty

# Module 2 (Graph)
graph_validation: GraphValidation | None

# Module 3 (LLM)
llm_validation: LLMValidation | None

# Module 4 (Reporting)
fused_score: float                # [0,1] combined score
cvss_base_score: float | None     # CVSS v3.1 base score
cvss_vector: str | None           # CVSS vector string
cvss_severity: str | None         # Severity rating
stage_resolved: StageResolved     # Which stage resolved this
nl_explanation: str | None        # Natural language explanation
remediation: str | None           # Fix recommendation

# Metadata
timestamp: datetime
processing_time_ms: float | None
tags: list[str]
properties: dict[str, Any]       # Custom extensible properties
---
is_escalated_to_graph → uncertainty.should_escalate
is_escalated_to_llm → graph_validation exists AND is_ambiguous
display_summary → formatted output string
```

### ScanResult (Final Output)
```
findings: list[Finding]           # All findings
scan_target: str                  # Target path or repo
languages_detected: list[Language]
total_files_scanned: int
total_lines_scanned: int
scan_duration_ms: float

# Cascade statistics
resolved_at_sast: int
resolved_at_graph: int
resolved_at_llm: int
unresolved: int
---
total_findings → len(findings)
confirmed_count, likely_count, potential_count → verdict counts
cascade_efficiency → resolved_at_sast / total_findings
by_severity() → dict[Severity, list[Finding]]
by_cwe() → dict[str, list[Finding]]
by_language() → dict[Language, list[Finding]]
```

---

## 3. Pipeline Flow

```
scan(target, languages, max_stage, github_repo) → ScanResult
│
├── Stage 1: SAST Engine
│   ├── TreeSitter pre-screening (24 patterns, <100ms)
│   ├── CodeQL taint analysis (if available, ~300s timeout)
│   ├── Generate Finding objects with UncertaintyScore
│   └── Route: EscalationRouter.route(findings)
│       ├── Resolved (U < 0.5, short taint, single-file) → stage_resolved = SAST
│       └── Escalated (U >= 0.5, long taint, interprocedural, or CRITICAL) → to Graph
│
├── Stage 2: Graph Validator (if escalated findings exist)
│   ├── Build Code Property Graph (Joern CPG or tree-sitter approximate)
│   ├── Backward slice from sink
│   ├── Extract features: GraphCodeBERT (768) + 5 structural = 773 dims
│   ├── Mini-GAT inference → softmax probabilities
│   ├── Conformal prediction (APS) → prediction set
│   ├── Populate GraphValidation
│   └── Route: EscalationRouter.route_from_graph(findings)
│       ├── Singleton {"safe"} → verdict = SAFE, stage_resolved = GRAPH
│       ├── Singleton {"vulnerable"} → verdict = LIKELY, stage_resolved = GRAPH
│       └── Ambiguous {"safe", "vulnerable"} → escalated to LLM
│
├── Stage 3: LLM Dual-Agent (if ambiguous findings exist)
│   ├── Query RAG knowledge base (FAISS + BM25, top-5)
│   ├── AttackerAgent.analyze(finding, context) → AttackerVerdict
│   ├── DefenderAgent.analyze(finding, context) → DefenderVerdict
│   ├── Consensus Engine: 4 rules → (verdict, confidence)
│   ├── CVSS v3.1 base score computation
│   ├── Evidence narrative construction
│   └── Populate LLMValidation, update Finding
│
└── Stage 4: Score Fusion + Reporting
    ├── ScoreFusionEngine.fuse(finding) → fused_score
    │   └── fused = (α·SAST + β·GAT + γ·LLM) / (α+β+γ), CWE-adaptive
    ├── Classification: ≥0.85 CONFIRMED, ≥0.50 LIKELY, <0.50 POTENTIAL
    ├── Generate SARIF 2.1.0 output
    ├── Generate HTML dashboard (if --dashboard)
    └── Return ScanResult with cascade statistics
```

---

## 4. Escalation Routing Logic

### SAST → Graph Routing

A finding is escalated if **ANY** of these conditions are true:

| Condition | Check | Rationale |
|-----------|-------|-----------|
| High uncertainty | `U_total >= 0.5` (after severity adjustment) | Core cascade mechanism |
| Long taint path | `taint_path_length > 3` | Complex data flows need structural analysis |
| Interprocedural | `taint_flow.is_interprocedural == True` | Cross-file flows are hard for SAST |
| Interprocedural + CRITICAL | Always escalate regardless of U score | Safety-critical, never skip |

Otherwise: `stage_resolved = SAST`, `verdict = SAFE`

### Graph → LLM Routing

| Conformal Result | Action |
|-----------------|--------|
| Singleton {"safe"} | Resolved: verdict = SAFE, stage = GRAPH |
| Singleton {"vulnerable"} | Resolved: verdict = LIKELY, stage = GRAPH |
| Both {"safe", "vulnerable"} | Ambiguous: escalated to LLM |
| No graph validation | Escalated to LLM (graceful degradation) |

---

## 5. Consensus Protocol (4 Rules)

The consensus engine combines AttackerVerdict and DefenderVerdict:

### Rule 1: CONFIRMED
```
Condition: attacker.exploitable AND defender.defense_coverage < 0.5
Result:    Verdict.CONFIRMED
Confidence: max(attacker.confidence, 1 - defender.defense_coverage)
```
Both agents agree the vulnerability is real and undefended.

### Rule 2: SAFE
```
Condition: NOT attacker.exploitable AND defender.defense_coverage > 0.7
Result:    Verdict.SAFE
Confidence: max(defender.defense_coverage, 1 - attacker.confidence)
```
Both agents agree the code is protected.

### Rule 2b: SAFE (Infeasible Path)
```
Condition: NOT defender.path_feasible AND NOT attacker.exploitable
Result:    Verdict.SAFE
Confidence: 0.8 (fixed)
```
The vulnerability path is not reachable in practice.

### Rule 3: LIKELY (Disagreement, Leaning Vulnerable)
```
Condition: attacker.exploitable AND defender.defense_coverage >= 0.5
Result:    Verdict.LIKELY
Confidence: 0.5 + 0.3 × (attacker.confidence - defender.defense_coverage), clamped [0.3, 0.85]
```
Attacker found an exploit but defenses exist — weighted blend.

### Rule 4: POTENTIAL (Disagreement, Leaning Safe)
```
Condition: NOT attacker.exploitable AND defender.defense_coverage <= 0.7
Result:    Verdict.POTENTIAL
Confidence: 0.4 + 0.2 × (1 - defender.defense_coverage), clamped [0.2, 0.6]
```
Attacker couldn't exploit but defenses are incomplete.

### Default Fallback
```
Result:    Verdict.LIKELY
Confidence: 0.5
```

---

## 6. LLM Override Rules (in Score Fusion)

After consensus, the fusion engine applies override checks:

| Condition | Override |
|-----------|---------|
| attacker.exploitable AND defender.defense_coverage < 0.3 | Force CONFIRMED |
| NOT attacker.exploitable AND defender.defense_coverage > 0.8 | Force SAFE |

---

## 7. RAG Knowledge Retrieval

### Hybrid Search (per finding)

```
1. FAISS search: embed(cwe_id + code_snippet) → top-5 nearest vectors
2. BM25 search: tokenize(cwe_id + code_snippet) → top-5 keyword matches
3. Reciprocal Rank Fusion:
   RRF_score = (1 / (60 + rank_faiss)) + (1 / (60 + rank_bm25))
4. Re-rank by RRF score, return top-5
```

### What RAG Returns

| Field | Content |
|-------|---------|
| CWE description | Full CWE entry (name, description, mitigations) |
| Similar CVEs | Real-world CVE examples with CVSS scores |
| OWASP category | Mapped OWASP Top 10 2021 category |
| Mitigation guidance | Category-specific fix recommendations |

### CWE-to-OWASP Mapping (examples)

| CWE | OWASP Category |
|-----|---------------|
| CWE-79, CWE-89, CWE-78 | A03:2021 Injection |
| CWE-287, CWE-862 | A01:2021 Broken Access Control |
| CWE-327, CWE-328 | A02:2021 Cryptographic Failures |
| CWE-502 | A08:2021 Software and Data Integrity Failures |
| CWE-611 | A05:2021 Security Misconfiguration |

---

## 8. Prompt Tier System

The LLM agents use tiered prompts based on finding uncertainty:

| Tier | U_score Range | Included Content | ~Tokens |
|------|---------------|-----------------|---------|
| Minimal | < 0.3 | Code snippet + CWE name | 500 |
| Standard | 0.3 – 0.6 | + taint path + CWE description | 1,500 |
| Full | > 0.6 | + RAG context (CVE examples, mitigations) | 3,000 |

Templates are CWE-category-specific Jinja2 files:
- `injection/attacker_injection.jinja2`
- `crypto/defender_crypto.jinja2`
- `deserialization/attacker_deserialization.jinja2`
- `default/attacker_default.jinja2` (fallback)

---

## 9. CascadeStats (Metrics Tracking)

```
total_findings: int               # Total findings from SAST
resolved_sast: int                # Resolved at Stage 1
escalated_to_graph: int           # Sent to Stage 2
resolved_graph: int               # Resolved at Stage 2
escalated_to_llm: int             # Sent to Stage 3
resolved_llm: int                 # Resolved at Stage 3
unresolved: int                   # Not resolved at any stage
sast_time_ms: float               # Stage 1 duration
graph_time_ms: float              # Stage 2 duration
llm_time_ms: float                # Stage 3 duration
total_time_ms: float              # End-to-end duration
---
cascade_efficiency = resolved_sast / total_findings
graph_resolution_rate = resolved_graph / escalated_to_graph
llm_resolution_rate = resolved_llm / escalated_to_llm
```

---

## 10. Output Formats

### SARIF 2.1.0
- Schema version: 2.1.0
- Tool name: sec-c, version: 2.0.0
- Custom properties namespace: `sec-c/*`
- Properties include: uncertainty score, graph validation, LLM validation, fused score, CVSS

### HTML Dashboard
- Self-contained single HTML file (all CSS/JS/SVG inlined)
- Interactive: sorting, filtering by stage/verdict/severity
- Sections: summary stats, cascade breakdown, finding table, finding detail modals
- Auto-opens in browser

### Console Output
- Rich terminal tables with color-coded severity/verdict
- Cascade statistics summary
- Real-time stage progress during scan
