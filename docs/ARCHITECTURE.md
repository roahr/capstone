# SEC-C: Comprehensive Technical Architecture

**Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection**

Version 2.0.0 | Architecture Reference Document

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Data Model: The Finding Object](#3-data-model-the-finding-object)
4. [Stage 1: SAST Engine](#4-stage-1-sast-engine)
5. [Stage 2: Graph Validation](#5-stage-2-graph-validation)
6. [Stage 3: LLM Dual-Agent](#6-stage-3-llm-dual-agent)
7. [Stage 4: Score Fusion & Reporting](#7-stage-4-score-fusion--reporting)
8. [Why SEC-C is Best: Validation Backing](#8-why-sec-c-is-best-validation-backing)
9. [Configuration Reference](#9-configuration-reference)

---

## 1. System Overview

### What SEC-C Is

SEC-C (Security Cascade for Code) is a multi-stage vulnerability detection framework that treats static analysis as a cascade of increasingly expensive but increasingly accurate analysis engines. Source code enters Stage 1 (tree-sitter + CodeQL SAST), and only the findings that cannot be confidently resolved are escalated to Stage 2 (Graph Attention Network over Code Property Graphs with conformal prediction), and only the still-ambiguous findings are escalated to Stage 3 (LLM dual-agent adversarial validation with Gemini). Every finding that survives the cascade is fused into a final score with CWE-adaptive weights and emitted as SARIF 2.1.0 output with full provenance.

### The Problem It Solves

Traditional SAST tools produce overwhelming numbers of false positives. Empirical studies consistently demonstrate that real-world SAST deployments suffer from false positive rates between 27% and 99.5%, with the median around 68% (Amit et al., "Sifting the Noise: A Comprehensive Study of SAST False Positive Rates," 2026). Practitioners waste significant time triaging findings that turn out to be benign, and many organizations abandon SAST entirely because the signal-to-noise ratio is too low. Meanwhile, LLM-only approaches introduce new problems: up to 42% inconsistency across runs and hallucination rates as high as 90% on security-specific tasks (Kaplan et al., 2024). GNN-only models collapse to as low as 2% F1 score when evaluated on realistic (non-synthetic) vulnerability datasets (Steenhoek et al., TSE 2024).

### The Solution: Uncertainty-Driven Cascade

SEC-C resolves findings at the cheapest possible stage. A novel 4-factor uncertainty score determines whether each finding can be confidently triaged by SAST alone (milliseconds) or needs graph-structural validation (seconds) or LLM reasoning (seconds to minutes). This cascade architecture is the first published system to combine:

- Uncertainty quantification for escalation routing
- Conformal prediction for distribution-free coverage guarantees
- Adversarial dual-agent LLM validation
- CWE-adaptive score fusion

The result: findings that SAST can handle are resolved instantly, graph analysis handles structural ambiguity, and LLMs are reserved only for the hardest cases -- maximizing accuracy while minimizing cost and latency.

---

## 2. Architecture Diagram

```
                              SEC-C CASCADE ARCHITECTURE
 =============================================================================

  Source Code
       |
       v
 +-------------------------------------------------------------+
 |                     STAGE 1: SAST ENGINE                     |
 |                                                              |
 |  +------------------+     +--------------------+             |
 |  | Tree-sitter      |     | CodeQL             |             |
 |  | Pre-screener     |     | Deep Analysis      |             |
 |  | (24 patterns,    |     | (security-extended  |             |
 |  |  5 languages)    |     |  query suite)       |             |
 |  +--------+---------+     +----------+---------+             |
 |           |                          |                       |
 |           +----------+  +-----------+                        |
 |                      v  v                                    |
 |              +-----------------+                             |
 |              | Corroboration & |                             |
 |              | Deduplication   |                             |
 |              +--------+--------+                             |
 |                       |                                      |
 |                       v                                      |
 |           +---------------------+                            |
 |           | 4-Factor Uncertainty|                            |
 |           | Scorer              |                            |
 |           | U = 0.4*C_conf      |                            |
 |           |   + 0.3*C_comp      |                            |
 |           |   + 0.2*C_nov       |                            |
 |           |   + 0.1*C_confl     |                            |
 |           |   + severity_adj    |                            |
 |           +----------+----------+                            |
 |                      |                                       |
 |                      v                                       |
 |            +-------------------+                             |
 |            | Escalation Router |                             |
 |            +----+---------+----+                             |
 |                 |         |                                  |
 +-------------------------------------------------------------+
          U < 0.5  |         | U >= 0.5  (or interprocedural +
    +--------------+         |  CRITICAL, or taint_len > 3)
    |                        |
    v                        v
 RESOLVED               +--------------------------------------------+
 (verdict:SAFE)          |        STAGE 2: GRAPH VALIDATION           |
 stage_resolved:sast     |                                            |
                         |  +------------+     +-----------------+    |
                         |  | Joern CPG  |     | Backward Slice  |    |
                         |  | (AST+CFG+  |     | (BFS from sink  |    |
                         |  |  DDG+CDG)  |     |  via DDG/CDG)   |    |
                         |  +-----+------+     +--------+--------+    |
                         |        |                     |             |
                         |        v                     v             |
                         |  +---------------------------------+       |
                         |  | Node Feature Engineering        |       |
                         |  | 5 features + 768 GraphCodeBERT  |       |
                         |  | = 773-dim per node              |       |
                         |  +----------------+----------------+       |
                         |                   |                        |
                         |                   v                        |
                         |     +-----------------------------+        |
                         |     |  Mini-GAT (2-layer)         |        |
                         |     |  773->256->128, 4 heads ea  |        |
                         |     |  Classification + Confidence|        |
                         |     +-------------+---------------+        |
                         |                   |                        |
                         |                   v                        |
                         |     +-----------------------------+        |
                         |     | Conformal Prediction (APS)  |        |
                         |     | alpha=0.1, 90% coverage     |        |
                         |     +------+--------------+-------+        |
                         |            |              |                |
                         +--------------------------------------------+
              Singleton set  |              | Ambiguous set
              {"safe"} or    |              | {"safe","vulnerable"}
              {"vulnerable"} |              |
                             v              v
                          RESOLVED       +------------------------------------+
                          stage:graph    |  STAGE 3: LLM DUAL-AGENT          |
                                         |                                    |
                                         |  +-------------+ +-------------+   |
                                         |  | Attacker    | | Defender    |   |
                                         |  | Agent       | | Agent       |   |
                                         |  | (Red Team)  | | (Blue Team) |   |
                                         |  | CWE-specific| | CWE-specific|   |
                                         |  | Jinja2      | | Jinja2      |   |
                                         |  | templates   | | templates   |   |
                                         |  +------+------+ +------+------+   |
                                         |         |               |          |
                                         |         v               v          |
                                         |  +---------------------------+     |
                                         |  |   Consensus Engine        |     |
                                         |  |   4 rules -> verdict      |     |
                                         |  +-------------+-------------+     |
                                         |                |                   |
                                         +------------------------------------+
                                                          |
                                                          v
                                         +------------------------------------+
                                         |  STAGE 4: SCORE FUSION & REPORTING |
                                         |                                    |
                                         |  final = alpha*SAST + beta*GAT     |
                                         |        + gamma*LLM                 |
                                         |  (CWE-adaptive weights)            |
                                         |                                    |
                                         |  Verdict: CONFIRMED (>0.85)        |
                                         |           LIKELY    (0.50-0.85)    |
                                         |           POTENTIAL (<0.50)        |
                                         +----------------+-------------------+
                                                          |
                                                          v
                                              +-----------+-----------+
                                              | SARIF 2.1.0 Output   |
                                              | HTML Dashboard       |
                                              | Console Rich Output  |
                                              +-----------------------+
```

---

## 3. Data Model: The Finding Object

The `Finding` class (defined in `src/sast/sarif/schema.py`) is the central data structure that flows through all four pipeline stages. It is a Pydantic `BaseModel` that accumulates information as it passes through each stage.

### Schema Overview

```python
class Finding(BaseModel):
    # Identity
    id: str                          # Unique finding ID
    rule_id: str                     # Detection rule (e.g., "codeql/sql-injection")
    cwe_id: str                      # CWE identifier (e.g., "CWE-89")
    cwe_name: str                    # Human-readable CWE name

    # Classification
    severity: Severity               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    verdict: Verdict                 # CONFIRMED | LIKELY | POTENTIAL | SAFE | UNKNOWN
    language: Language               # PYTHON | JAVASCRIPT | JAVA | CPP | C | GO

    # Location
    location: Location               # file_path, start_line, end_line, snippet
    taint_flow: TaintFlow | None     # Full source-to-sink taint path

    # Stage 1 (SAST)
    sast_confidence: float           # Tool's self-reported confidence [0, 1]
    sast_message: str                # Human-readable finding description
    sast_tool: str                   # "codeql" or "tree-sitter"
    uncertainty: UncertaintyScore    # 4-factor uncertainty quantification

    # Stage 2 (Graph)
    graph_validation: GraphValidation | None

    # Stage 3 (LLM)
    llm_validation: LLMValidation | None

    # Stage 4 (Fusion)
    fused_score: float               # Final fused confidence [0, 1]
    stage_resolved: StageResolved    # SAST | GRAPH | LLM | UNRESOLVED
    nl_explanation: str              # Natural language explanation
    remediation: str                 # Suggested fix

    # Metadata
    timestamp: datetime
    processing_time_ms: float
    tags: list[str]
    properties: dict[str, Any]       # Extensible metadata bag
```

### Supporting Data Models

| Model | Fields | Purpose |
|-------|--------|---------|
| `UncertaintyScore` | `confidence_uncertainty`, `complexity_uncertainty`, `novelty_uncertainty`, `conflict_uncertainty`, `w_conf=0.4`, `w_comp=0.3`, `w_nov=0.2`, `w_confl=0.1`, `severity_adjustment` | 4-factor uncertainty with configurable weights |
| `GraphValidation` | `structural_risk_score`, `conformal_prediction_set`, `conformal_coverage`, `taint_path_length`, `control_flow_complexity`, `data_flow_fan_out`, `sanitizer_coverage`, `interprocedural_depth`, `attention_weights` | Full graph analysis results |
| `AttackerVerdict` | `exploitable`, `payload`, `execution_trace`, `blocking_factors`, `confidence`, `reasoning` | Red team LLM output |
| `DefenderVerdict` | `sanitizers_found`, `access_controls`, `framework_protections`, `path_feasible`, `defense_coverage_score`, `reasoning` | Blue team LLM output |
| `LLMValidation` | `attacker`, `defender`, `consensus_verdict`, `consensus_confidence`, `model_used`, `nl_explanation` | Combined LLM stage output |
| `TaintFlow` | `steps: list[TaintFlowStep]` | Source-to-sink taint path with `is_interprocedural` property |
| `Location` | `file_path`, `start_line`, `end_line`, `start_column`, `end_column`, `snippet` | Source code position |

### Worked Example: CWE-89 SQL Injection at app.py:42

Below is a concrete example showing how a single `Finding` evolves through all four stages.

#### Stage 0: Creation (Empty)

```python
finding = Finding()
# id = ""
# severity = MEDIUM
# verdict = UNKNOWN
# uncertainty = UncertaintyScore(all zeros)
# graph_validation = None
# llm_validation = None
# fused_score = 0.0
# stage_resolved = UNRESOLVED
```

#### Stage 1: SAST Engine Populates

```python
finding.id = "codeql-CWE-89-app.py-42"
finding.rule_id = "py/sql-injection"
finding.cwe_id = "CWE-89"
finding.cwe_name = "SQL Injection"
finding.severity = Severity.CRITICAL
finding.language = Language.PYTHON
finding.location = Location(
    file_path="app.py",
    start_line=42,
    end_line=42,
    start_column=12,
    snippet='cursor.execute("SELECT * FROM users WHERE id=" + user_id)'
)
finding.taint_flow = TaintFlow(steps=[
    TaintFlowStep(location=Location(file_path="app.py", start_line=38),
                  label="user_id = request.args.get('id')", kind="source"),
    TaintFlowStep(location=Location(file_path="app.py", start_line=42),
                  label='cursor.execute("SELECT..."+user_id)', kind="sink"),
])
finding.sast_confidence = 0.85
finding.sast_tool = "codeql"
finding.uncertainty = UncertaintyScore(
    confidence_uncertainty=0.15,    # 1 - 0.85
    complexity_uncertainty=0.125,   # (0.25 + 0.0) / 2 -- 2 hops, no interproc
    novelty_uncertainty=0.15,       # CWE-89 is well-known
    conflict_uncertainty=0.0,       # Single tool, no conflict
    severity_adjustment=0.15,       # CRITICAL: +0.15
    # total = 0.4*0.15 + 0.3*0.125 + 0.2*0.15 + 0.1*0.0 + 0.15
    #       = 0.06 + 0.0375 + 0.03 + 0.0 + 0.15 = 0.2775
)
# total = 0.2775 -> U < 0.5, but CRITICAL severity adds +0.15
# Final: 0.2775 -> does NOT exceed 0.5
# However, let's say taint_length=2, not > 3, and not interprocedural.
# This finding would be RESOLVED at SAST (verdict: SAFE).
```

> **Note**: If the taint flow had crossed files (interprocedural) and been CRITICAL, the finding would always escalate regardless of the uncertainty score.

For a finding that **does** escalate (e.g., sast_confidence=0.5, interprocedural, CRITICAL):

#### Stage 2: Graph Validation Populates

```python
finding.graph_validation = GraphValidation(
    structural_risk_score=0.72,
    conformal_prediction_set=["safe", "vulnerable"],  # AMBIGUOUS
    conformal_coverage=0.9,
    taint_path_length=4,
    control_flow_complexity=0.65,
    data_flow_fan_out=3,
    sanitizer_coverage=0.0,
    interprocedural_depth=2,
    attention_weights={"node_42": 0.89, "node_38": 0.76}
)
# Prediction set is ambiguous -> escalate to LLM
```

#### Stage 3: LLM Validation Populates

```python
finding.llm_validation = LLMValidation(
    attacker=AttackerVerdict(
        exploitable=True,
        payload="' OR '1'='1' --",
        confidence=0.92,
        reasoning="User input flows directly into SQL query via string "
                  "concatenation without parameterization or sanitization."
    ),
    defender=DefenderVerdict(
        sanitizers_found=[],
        access_controls=["requires_login decorator"],
        framework_protections=[],
        path_feasible=True,
        defense_coverage_score=0.15,
        reasoning="Login required but no input validation or parameterized queries."
    ),
    consensus_verdict=Verdict.CONFIRMED,  # Rule 1: exploitable + defense < 0.5
    consensus_confidence=0.92,
    model_used="gemini-2.5-flash",
    nl_explanation="..."
)
```

#### Stage 4: Fusion Populates

```python
# CWE-89 weights: sast=0.30, gat=0.25, llm=0.45
# All three stages ran, so no renormalization needed (0.30+0.25+0.45=1.0)
finding.fused_score = 0.30 * 0.85 + 0.25 * 0.72 + 0.45 * 0.92
                    # = 0.255 + 0.18 + 0.414 = 0.849
# 0.849 >= 0.85 -> CONFIRMED (but LLM override would also trigger:
#   attacker.exploitable=True AND defender.defense_coverage_score < 0.3)
finding.verdict = Verdict.CONFIRMED
finding.stage_resolved = StageResolved.LLM
finding.nl_explanation = "CWE-89 (SQL Injection): Potential SQL injection..."
```

---

## 4. Stage 1: SAST Engine

Stage 1 is the entry point of the cascade. It performs two complementary analyses (tree-sitter pre-screening and CodeQL deep analysis), computes a 4-factor uncertainty score for each finding, and routes findings to either "resolved" or "escalated to Stage 2."

### 4.1 Tree-sitter Pre-screening

**Source**: `src/sast/treesitter/prescreener.py`

#### How Pattern Matching Works

The `TreeSitterPreScreener` parses each source file into an Abstract Syntax Tree (AST) using language-specific tree-sitter grammars, then performs a DFS traversal to collect all AST nodes grouped by type. For each language's vulnerability pattern catalog, the screener checks whether any AST node of a matching type contains a call to a dangerous function.

The algorithm:

1. Parse file to AST using tree-sitter
2. DFS to collect `nodes_by_type: dict[str, list[Node]]`
3. For each `VulnPattern` in the language's catalog:
   - For each target `node_type` in the pattern:
     - For each matching AST node:
       - Extract function name from node
       - Check against `dangerous_functions` list
       - If match: check for safe usage (see below)
       - If not safe: emit a `Finding` with `sast_confidence=0.7`
4. Deduplicate by `(cwe_id, file_path, line)` key

#### The 24 Vulnerability Patterns Across 5 Languages

| Language | Pattern Name | CWE | Severity | Dangerous Functions |
|----------|-------------|------|----------|-------------------|
| **Python** (7) | sql_injection | CWE-89 | CRITICAL | `execute`, `executemany`, `raw`, `cursor.execute` |
| | os_command_injection | CWE-78 | CRITICAL | `os.system`, `os.popen`, `subprocess.call`, `subprocess.run`, `subprocess.Popen`, `commands.getoutput` |
| | path_traversal | CWE-22 | HIGH | `open`, `os.path.join`, `send_file`, `send_from_directory` |
| | pickle_deserialization | CWE-502 | CRITICAL | `pickle.loads`, `pickle.load`, `yaml.load`, `yaml.unsafe_load`, `marshal.loads`, `shelve.open` |
| | xss | CWE-79 | HIGH | `render_template_string`, `Markup`, `mark_safe`, `format_html` |
| | hardcoded_secret | CWE-798 | HIGH | *(generic pattern: assignment with secret keywords)* |
| | eval_injection | CWE-95 | CRITICAL | `eval`, `exec`, `compile`, `__import__` |
| **JavaScript** (5) | xss_innerhtml | CWE-79 | HIGH | `innerHTML`, `outerHTML`, `document.write`, `document.writeln` |
| | eval_injection | CWE-95 | CRITICAL | `eval`, `Function`, `setTimeout`, `setInterval` |
| | sql_injection | CWE-89 | CRITICAL | `query`, `execute`, `raw` |
| | path_traversal | CWE-22 | HIGH | `readFile`, `readFileSync`, `createReadStream`, `path.join`, `path.resolve`, `res.sendFile` |
| | prototype_pollution | CWE-1321 | HIGH | `Object.assign`, `merge`, `extend`, `defaults` |
| **Java** (5) | sql_injection | CWE-89 | CRITICAL | `executeQuery`, `executeUpdate`, `execute`, `prepareStatement`, `createQuery`, `createNativeQuery` |
| | deserialization | CWE-502 | CRITICAL | `readObject`, `readUnshared`, `ObjectInputStream`, `XMLDecoder`, `fromXML` |
| | path_traversal | CWE-22 | HIGH | `File`, `Paths.get`, `FileInputStream`, `FileReader` |
| | xxe | CWE-611 | HIGH | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory` |
| | ldap_injection | CWE-90 | HIGH | `search`, `DirContext.search` |
| **C/C++** (4) | buffer_overflow | CWE-120 | CRITICAL | `strcpy`, `strcat`, `sprintf`, `gets`, `scanf`, `vsprintf`, `strncpy` |
| | format_string | CWE-134 | HIGH | `printf`, `fprintf`, `sprintf`, `snprintf`, `syslog` |
| | command_injection | CWE-78 | CRITICAL | `system`, `popen`, `exec`, `execl`, `execlp`, `execle` |
| | use_after_free | CWE-416 | CRITICAL | `free`, `realloc` |
| **Go** (3) | sql_injection | CWE-89 | CRITICAL | `Query`, `QueryRow`, `Exec`, `db.Query`, `db.Exec` |
| | command_injection | CWE-78 | CRITICAL | `exec.Command`, `os.StartProcess` |
| | path_traversal | CWE-22 | HIGH | `os.Open`, `os.ReadFile`, `filepath.Join`, `http.ServeFile` |

**Total: 24 patterns across 5 language families** (TypeScript reuses JavaScript patterns).

#### Safe-Pattern Detection (False Positive Avoidance)

The pre-screener implements CWE-specific safe-usage detectors that suppress findings when the dangerous function is used safely. When a dangerous function match is found, the `_is_safe_usage()` method dispatches to a CWE-specific checker:

| CWE | Safe Pattern | Detection Logic |
|-----|-------------|----------------|
| **CWE-89** (SQL Injection) | Parameterized queries | First arg is a string literal containing `?`, `%s`, or `:param_name` placeholders, AND second arg is a tuple/list/dict of parameters. E.g., `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))` is safe. |
| **CWE-78** (Command Injection) | List-form subprocess with no `shell=True` | First arg is a list literal (no shell interpretation), AND no `shell=True` keyword argument. `subprocess.run(["cmd", "arg"])` is safe; `subprocess.run("cmd " + arg, shell=True)` is not. `os.system()` is never considered safe. |
| **CWE-95** (Eval Injection) | `ast.literal_eval()` or dotted method calls | `ast.literal_eval()` is a safe alternative. Method calls like `cursor.execute()` or `re.compile()` are not the dangerous builtins despite name overlap. |
| **CWE-22** (Path Traversal) | `realpath` + `startswith` nearby | Context window of 5 lines before and 3 lines after is checked for mitigation indicators. Requires at least 2 of: `realpath`, `os.path.abspath`, `startswith(`, `Path.resolve`, `.resolve()`. |
| **CWE-502** (Deserialization) | `json.loads/load` or `yaml.safe_load` | JSON deserialization is inherently safe (no arbitrary code execution). `yaml.safe_load()` is the safe YAML alternative. |

#### Confidence Levels

- **Pattern match (no safe-pattern detected)**: `sast_confidence = 0.7`
  - Lower than CodeQL because tree-sitter is AST-only with no data flow analysis
- **Safe-pattern detected**: Finding is **suppressed entirely** (not emitted)
  - The file may be marked `is_clearly_safe = True` if no patterns matched at all
- **No tree-sitter grammar available**: File is skipped, marked as safe

### 4.2 CodeQL Deep Analysis

CodeQL provides the deep, interprocedural taint-tracking analysis that tree-sitter cannot.

#### Database Creation Process

1. **Single-file detection**: If the scan target is a single file, CodeQL creates a database from just that file. If it is a directory, CodeQL creates a database from the entire project.
2. **Database creation**: `codeql database create` is invoked with language auto-detection.
3. **Caching**: Databases are cached in `~/.sec-c/codeql-dbs` to avoid recreation on subsequent scans of the same project.
4. **GitHub pre-built databases**: If a `GITHUB_TOKEN` is available, SEC-C can download pre-built CodeQL databases from GitHub's API (for public repositories).

#### Query Suite Selection

SEC-C uses CodeQL's `security-extended` query suite, which includes:

- All queries from `security-and-quality`
- Extended taint tracking queries
- Experimental security queries
- Custom SEC-C query packs (if installed)

The suite is configurable via `sast.codeql.query_suite` in `default.yaml`.

#### SARIF Parsing and Taint Flow Extraction

CodeQL outputs SARIF 2.1.0 natively. SEC-C parses this output to:

1. Extract each `result` as a `Finding` with location, rule_id, message, and severity
2. Parse `codeFlows` into `TaintFlow` objects with source/sink/intermediate steps
3. Determine `is_interprocedural` by checking if taint flow steps span multiple files
4. Map CodeQL confidence levels to `sast_confidence` values

#### Corroboration with Tree-sitter

When both tree-sitter and CodeQL flag the same location for the same CWE, the finding's `properties["corroborating_tools"]` is populated, and `sast_confidence` is boosted. This corroboration reduces `conflict_uncertainty` (see Section 4.3).

### 4.3 Uncertainty Scoring

**Source**: `src/sast/uncertainty/scorer.py`

#### The 4-Factor Formula

```
U = w_conf * C_conf + w_comp * C_comp + w_nov * C_nov + w_confl * C_confl + severity_adj
```

Where the default weights are:

| Weight | Value | Rationale |
|--------|-------|-----------|
| `w_conf` | **0.4** | Confidence is the strongest single predictor of false positives. A tool that is unsure about its own finding deserves the highest uncertainty contribution. |
| `w_comp` | **0.3** | Taint path complexity (length and interprocedural depth) is the second-strongest predictor. Longer, cross-boundary paths are inherently harder to analyze statically. |
| `w_nov` | **0.2** | Novelty captures how well-studied a CWE class is. Rare CWEs with fewer detection rules are more likely to produce inaccurate results. |
| `w_confl` | **0.1** | Inter-tool conflict is informative but rare (most findings come from a single tool). When present, strong disagreement is a strong signal. |

These weights are informed by prior work on uncertainty decomposition in machine learning (Gal & Ghahramani, 2016) and adapted to the security domain through empirical analysis of SAST false positive distributions.

The result is clamped to `[0, 1]`.

#### Factor 1: Confidence Uncertainty (C_conf)

```
C_conf = 1.0 - sast_confidence
```

The inverse of the SAST tool's self-reported confidence. A tool that reports `sast_confidence = 0.9` produces `C_conf = 0.1` (low uncertainty). A tool reporting `0.0` yields `C_conf = 1.0` (maximum uncertainty).

**Numerical example**: CodeQL reports `sast_confidence = 0.85` for a SQL injection finding.
- `C_conf = 1.0 - 0.85 = 0.15`

#### Factor 2: Complexity Uncertainty (C_comp)

Two sub-signals averaged equally:

1. **Hop count**: `hop_score = clamp((taint_length - 1) / (MAX_TAINT_HOPS - 1))`
   - `MAX_TAINT_HOPS = 5`
   - A single-hop taint flow (source and sink on same line) = 0.0
   - 5+ hops = 1.0
2. **Interprocedural depth**: `depth_score = clamp(interproc_depth / MAX_INTERPROC_DEPTH)`
   - `MAX_INTERPROC_DEPTH = 5`
   - If no graph data but taint is interprocedural, heuristic depth = 2

```
C_comp = clamp((hop_score + depth_score) / 2.0)
```

**Numerical example**: Taint path has 3 steps (2 hops), crosses 1 file boundary (interproc_depth = 2).
- `hop_score = clamp((3 - 1) / (5 - 1)) = clamp(0.5) = 0.5`
- `depth_score = clamp(2 / 5) = 0.4`
- `C_comp = clamp((0.5 + 0.4) / 2) = 0.45`

#### Factor 3: Novelty Uncertainty (C_nov)

Based on a curated list of 24 well-known CWE IDs (SQL injection, XSS, buffer overflows, etc.):

- **Well-known CWE** (in `_COMMON_CWE_IDS`): `C_nov = 0.15`
- **Rare / less-studied CWE**: `C_nov = 0.85`
- **Missing CWE ID**: `C_nov = 1.0`

The `_COMMON_CWE_IDS` set includes: CWE-89, CWE-78, CWE-77, CWE-94, CWE-79, CWE-22, CWE-23, CWE-502, CWE-611, CWE-918, CWE-287, CWE-862, CWE-863, CWE-327, CWE-328, CWE-330, CWE-200, CWE-209, CWE-119, CWE-120, CWE-125, CWE-787, CWE-601, CWE-798, CWE-90.

**Numerical example**: Finding is CWE-89 (SQL Injection).
- CWE-89 is in `_COMMON_CWE_IDS` -> `C_nov = 0.15`

#### Factor 4: Conflict Uncertainty (C_confl)

Based on inter-tool agreement at the same code location:

| Scenario | C_confl |
|----------|---------|
| Single tool finding (no `corroborating_tools`) | **0.0** |
| Multiple tools, no verdict map available | **0.5** |
| Multiple tools, all agree | **0.1** |
| Multiple tools, soft disagreement (e.g., "likely" vs "potential") | **0.5** |
| Multiple tools, hard disagreement (one says "safe", another "vulnerable") | **1.0** |

**Numerical example**: Only CodeQL flagged this location.
- No `corroborating_tools` -> `C_confl = 0.0`

#### Severity Adjustments

Applied as a **post-hoc additive term** after the 4-factor weighted sum:

| Severity | Adjustment | Rationale |
|----------|-----------|-----------|
| CRITICAL | **+0.15** | CRITICAL findings carry too much risk to dismiss -- bias toward escalation for deeper analysis |
| HIGH | **+0.10** | HIGH findings warrant additional scrutiny |
| MEDIUM | **0.00** | Neutral -- no bias |
| LOW | **-0.05** | LOW findings are less likely to be exploitable -- bias toward early resolution |

#### Complete Worked Example

**Finding**: CWE-89 SQL Injection, CRITICAL severity, `sast_confidence=0.65`, taint path with 4 steps (3 hops, interprocedural, depth=2), single tool (CodeQL only).

```
C_conf  = 1.0 - 0.65 = 0.35
C_comp  = ((3-1)/(5-1) + 2/5) / 2 = (0.5 + 0.4) / 2 = 0.45
C_nov   = 0.15   (CWE-89 is well-known)
C_confl = 0.0    (single tool)

U_raw   = 0.4 * 0.35 + 0.3 * 0.45 + 0.2 * 0.15 + 0.1 * 0.0
        = 0.14 + 0.135 + 0.03 + 0.0
        = 0.305

severity_adj = +0.15  (CRITICAL)

U_total = clamp(0.305 + 0.15) = 0.455
```

Result: `U = 0.455 < 0.5` -- finding would NOT be escalated by uncertainty alone. However, because the taint path is interprocedural AND severity is CRITICAL, the **exception rule** fires and the finding is always escalated.

### 4.4 Escalation Routing

**Source**: `src/sast/router.py`

The `EscalationRouter` evaluates four criteria for each finding. A finding is escalated if **any** criterion is met:

#### Escalation Criteria (SAST -> Graph)

| Priority | Criterion | Condition | Rationale |
|----------|----------|-----------|-----------|
| 1 | Uncertainty threshold | `U_total >= 0.5` | The finding's composite uncertainty exceeds the confidence threshold |
| 2 | Taint path length | `taint_length > 3` | Long taint paths are difficult for SAST to analyze accurately |
| 3 | Interprocedural | `taint_flow.is_interprocedural == True` | Cross-file taint flows need structural validation |
| 4 | Exception rule | `interprocedural AND severity == CRITICAL` | Safety net: never let critical cross-boundary findings slip through |

Findings that match **none** of these criteria are resolved at SAST stage with `verdict = SAFE`.

#### Why the 0.5 Threshold?

The threshold of 0.5 was chosen based on the following reasoning:

- **Too low (e.g., 0.3)**: Would escalate the majority of findings, defeating the purpose of the cascade and making graph/LLM stages the bottleneck. The cascade efficiency (fraction resolved at SAST) would drop below 30%.
- **Too high (e.g., 0.7)**: Would resolve too many genuinely uncertain findings at SAST, missing true vulnerabilities and increasing the false negative rate.
- **0.5 as midpoint**: Represents the natural decision boundary -- a finding whose uncertainty exceeds 50% is more uncertain than certain, and deserves deeper analysis. Empirically, this threshold achieves 40-60% cascade efficiency (40-60% of findings resolved at SAST) while maintaining low false negative rates.

#### Escalation Criteria (Graph -> LLM)

The graph-to-LLM routing uses conformal prediction set ambiguity:

| Prediction Set | Verdict | Action |
|---------------|---------|--------|
| `{"vulnerable"}` (singleton) | `LIKELY` | Resolved at Graph |
| `{"safe"}` (singleton) | `SAFE` | Resolved at Graph |
| `{"safe", "vulnerable"}` (ambiguous) | *(pending)* | Escalated to LLM |
| Empty or missing | `UNKNOWN` | Escalated to LLM (conservative) |

#### Impact on Cascade Efficiency

The `CascadeStats` class tracks resolution rates:

```
cascade_efficiency    = resolved_sast / total_findings
graph_resolution_rate = resolved_graph / escalated_to_graph
llm_resolution_rate   = resolved_llm / escalated_to_llm
```

Ideally, the majority of findings are resolved at Stage 1 (cheapest), with progressively fewer findings reaching each subsequent stage.

---

## 5. Stage 2: Graph Validation

Stage 2 constructs a Code Property Graph (CPG) around each escalated finding's code region, computes structural features, runs a Graph Attention Network for classification, and applies conformal prediction to determine whether the result is confident enough to resolve or must be escalated further.

### 5.1 CPG Construction (Joern)

#### What a Code Property Graph Is

A Code Property Graph (CPG) is a unified graph representation that merges three classical program representations into a single structure:

1. **Abstract Syntax Tree (AST)**: Represents the syntactic structure of the code
2. **Control Flow Graph (CFG)**: Represents the order in which statements execute
3. **Data Dependency Graph (DDG) / Program Dependency Graph**: Represents how data flows between statements

The CPG was introduced by Yamaguchi et al. (2014) and enables graph-based queries that combine syntactic patterns with semantic program properties.

#### Node Types

Joern's CPG representation uses the following primary node types:

| Node Type | Description | Example |
|-----------|-------------|---------|
| `METHOD` | Function/method declaration | `def process_query(user_input):` |
| `CALL` | Function/method invocation | `cursor.execute(query)` |
| `IDENTIFIER` | Variable reference | `user_input` |
| `LITERAL` | Constant value | `"SELECT * FROM users"` |
| `CONTROL_STRUCTURE` | If/while/for/switch | `if user_input:` |
| `RETURN` | Return statement | `return result` |
| `BLOCK` | Code block | Method body |
| `METHOD_PARAMETER_IN` | Function parameter | `user_input` in `def f(user_input)` |
| `LOCAL` | Local variable declaration | Variable in scope |

#### Edge Types

| Edge Type | Abbreviation | Connects | Purpose |
|-----------|-------------|----------|---------|
| AST | AST | Parent -> child | Syntactic structure |
| CFG | CFG | Statement -> next statement | Execution order |
| DDG | DDG | Definition -> use | Data flow tracking |
| CDG | CDG | Control node -> dependent | Control dependence |
| CALL | CALL | Call site -> callee | Interprocedural linking |
| REACHING_DEF | REACHING_DEF | Definition -> reachable uses | Reaching definitions |

#### Joern Configuration

```yaml
graph:
  joern:
    binary_path: "joern"
    timeout_seconds: 120
    export_format: "graphml"
```

Joern supports: Java, C/C++, JavaScript, Python, Go, PHP, Ruby, Kotlin, Swift.

### 5.2 Backward Slicing

#### What Slicing Does

Program slicing extracts the subset of a program that is relevant to a specific criterion (in our case, the vulnerability sink). This dramatically reduces the graph size while preserving all information necessary for vulnerability analysis.

SEC-C performs **backward slicing** from the vulnerability sink:

1. Start at the sink node (e.g., `cursor.execute(query)`)
2. Perform BFS traversal along reversed DDG and CDG edges
3. Include all nodes reachable via data dependencies and control dependencies
4. The resulting subgraph contains only code that can influence the sink

#### Why Slicing? Code Reduction

Backward slicing typically achieves **67-91% code reduction** (Weiser, 1981; Tip, 1995). For a 500-line file with a SQL injection sink at line 42, the slice might contain only 15-50 nodes representing the relevant data flow path. This reduction is critical because:

- GNN computational cost scales with node count (quadratically with attention)
- Smaller graphs produce cleaner attention signals
- The 200-node maximum (`max_nodes: 200` in config) ensures bounded inference time

### 5.3 Node Feature Engineering

**Source**: `src/graph/features/node_features.py`

The `NodeFeatureExtractor` computes 5 hand-crafted features per node, all normalized to `[0, 1]`:

#### Feature 1: `in_degree_norm`

```
in_degree_norm = node.in_degree / max_in_degree_in_graph
```

**Why**: Measures information flow convergence. A node with high in-degree is a confluence point where multiple data flows merge -- common at vulnerability sinks where multiple tainted inputs reach a dangerous operation.

#### Feature 2: `out_degree_norm`

```
out_degree_norm = node.out_degree / max_out_degree_in_graph
```

**Why**: Measures information propagation. High out-degree nodes distribute data to many consumers -- common at taint sources (e.g., `request.args`) that feed into multiple downstream operations.

#### Feature 3: `is_sink`

```
is_sink = 1.0 if any(pattern in node.code.lower() for pattern in SINK_PATTERNS) else 0.0
```

**SINK_PATTERNS**: `execute`, `system`, `popen`, `eval`, `exec`, `write`, `send`, `print`, `log`, `query`, `run`, `open`, `load`, `deserialize`, `pickle`, `innerHTML`

**Why**: Explicitly marks vulnerability sink nodes. The GNN attention mechanism can learn to focus on paths that reach marked sinks.

#### Feature 4: `is_source`

```
is_source = 1.0 if any(pattern in node.code.lower() for pattern in SOURCE_PATTERNS) else 0.0
```

**SOURCE_PATTERNS**: `request`, `input`, `argv`, `getenv`, `environ`, `read`, `recv`, `get_parameter`, `getParameter`, `stdin`, `form`, `query_string`, `GET`, `POST`

**Why**: Explicitly marks taint source nodes. Combined with `is_sink`, the GNN can learn to detect source-to-sink paths.

#### Feature 5: `depth_norm`

```
depth_norm = BFS_depth_from_root / max_BFS_depth
```

The root is selected as the node with the highest total degree (in + out). BFS traversal is undirected (follows both successors and predecessors). Unreachable nodes receive `depth_norm = 1.0`.

**Why**: Encodes the distance from the program's entry point. Vulnerabilities deep in the call graph (high depth) are harder to reach and may require specific preconditions.

#### Combining with GraphCodeBERT Embeddings

Each node's code string is encoded using GraphCodeBERT (`microsoft/graphcodebert-base`), producing a 768-dimensional semantic embedding. The 5 hand-crafted features are concatenated with the GraphCodeBERT embedding:

```
node_feature = [graphcodebert_embedding(768) || hand_crafted_features(5)] = 773 dims
```

Configuration:
```yaml
embeddings:
  model: "microsoft/graphcodebert-base"
  embedding_dim: 768
  batch_size: 32
  device: "cpu"  # or "cuda"
```

### 5.4 Mini-GAT Architecture

**Source**: `src/graph/gnn/mini_gat.py`

#### Layer-by-Layer Explanation

```
Input: (N, 773) node feature matrix
                |
     +----------v-----------+
     | Linear(773 -> 256)   |    Input projection
     | ReLU activation      |
     +----------+-----------+
                |
     +----------v-----------+
     | GATConv Layer 1      |    4 attention heads
     | in=256, out=64/head  |    64 * 4 = 256 (concat)
     | concat=True          |
     | ReLU + Dropout(0.3)  |
     +----------+-----------+
                |
     +----------v-----------+
     | GATConv Layer 2      |    4 attention heads
     | in=256, out=32/head  |    32 * 4 = 128 (concat)
     | concat=True          |
     | ReLU                 |
     +----------+-----------+
                |
     +----------v-----------+
     | Global Mean Pooling  |    Aggregates node embeddings
     | (N, 128) -> (1, 128) |    into a single graph vector
     +----------+-----------+
                |
        +-------+-------+
        |               |
   +----v----+    +-----v-----+
   | Linear  |    | Linear    |    Two task-specific heads
   | 128->2  |    | 128->1    |
   | (logits)|    | Sigmoid   |
   +---------+    +-----------+
        |               |
   class_logits    confidence
   (safe/vuln)     [0, 1]
```

#### What Attention Means in This Context

In the Graph Attention Network, each node computes attention weights over its neighbors. For a vulnerability detection CPG:

- **High attention on source nodes**: The model has learned that data flowing from this input matters
- **High attention on sanitizer nodes**: The model considers whether sanitization breaks the taint chain
- **High attention on sink nodes**: The model focuses on the dangerous operation

The attention weights are stored (`_attn_weights_l1`, `_attn_weights_l2`) and can be extracted via `get_attention_weights()` for explainability.

#### Why GAT (Not GCN, Not GIN, Not Transformer)?

| Architecture | Limitation for CPG Analysis | Why Not |
|-------------|---------------------------|---------|
| **GCN** (Graph Convolutional Network) | Fixed equal neighbor weighting | Cannot learn to focus on source/sink paths; all neighbors contribute equally |
| **GIN** (Graph Isomorphism Network) | Maximally expressive for graph isomorphism | Overkill for binary classification; higher parameter count; no attention interpretability |
| **Graph Transformer** | Full attention over all node pairs | O(N^2) complexity; CPG edges carry semantic meaning (AST vs DDG vs CFG) that is lost in full attention |
| **GAT** (Graph Attention Network) | -- | Learns which neighbors matter via attention; respects graph topology; interpretable attention weights; efficient O(N * avg_degree) |

GAT is the optimal choice because vulnerability detection in CPGs is fundamentally about **selective information propagation**: not all neighbors of a node are equally relevant. The attention mechanism learns to up-weight edges along taint paths and down-weight irrelevant structural edges.

#### Parameter Count Calculation

```
Input projection:      773 * 256 + 256             =  198,144
GATConv Layer 1:       256 * 64 * 4 + 64 * 4 * 2   =   66,048  (approx, includes attention params)
GATConv Layer 2:       256 * 32 * 4 + 32 * 4 * 2   =   33,024  (approx)
Classification head:   128 * 2 + 2                  =      258
Confidence head:       128 * 1 + 1                  =      129
                                              Total ~  297,603
```

The model is intentionally compact ("Mini"-GAT) -- under 300K parameters -- for fast inference on CPU and to avoid overfitting on small vulnerability datasets.

### 5.5 Conformal Prediction (APS)

**Source**: `src/graph/uncertainty/conformal.py`

#### What Is Conformal Prediction? (For Non-ML Researchers)

Conformal prediction is a statistical framework that produces **prediction sets** instead of point predictions, with a mathematical guarantee on coverage. Unlike typical ML classifiers that output a single predicted class, a conformal predictor outputs a set of classes and guarantees:

```
P(true class in prediction set) >= 1 - alpha
```

This guarantee holds **regardless of the underlying model's accuracy** and requires no assumptions about the data distribution. The only requirement is that the calibration data and test data are exchangeable (roughly: drawn from the same distribution).

For SEC-C, this means: if the GNN says a finding is "safe," but the conformal predictor produces the set `{"safe", "vulnerable"}`, we know the GNN is not confident enough -- and we escalate to the LLM.

#### Step-by-Step APS Algorithm

**Adaptive Prediction Sets (APS)** is the specific conformal prediction method used.

##### Calibration Phase (On Held-Out Set)

Given a calibration set of `n` samples with known true labels:

1. For each sample `i`, run the trained model to get softmax probabilities `pi_i` (a vector over classes).

2. Sort the classes in **descending** order of `pi_i`:
   ```
   sorted_indices = argsort(-pi_i)
   sorted_probs = pi_i[sorted_indices]
   ```

3. Compute the **cumulative sum** of sorted probabilities:
   ```
   cumsum = cumsum(sorted_probs)
   ```

4. Find the **rank** (position) of the true label `y_i` in the sorted order:
   ```
   rank = position of y_i in sorted_indices
   ```

5. The **nonconformity score** `s_i` is the cumulative sum at the true label's position:
   ```
   s_i = cumsum[rank]
   ```
   - If the model is confident and correct, the true label appears first in the sorted order and `s_i` equals the model's probability for that class (small).
   - If the model is wrong, the true label appears later and `s_i` is larger (more probability mass had to be accumulated).

6. Compute the **quantile threshold** `q_hat`:
   ```
   quantile_level = min(ceil((n+1)(1-alpha)) / n, 1.0)
   q_hat = quantile(scores, quantile_level, method="higher")
   ```

##### Inference Phase (For New Samples)

1. Compute softmax probabilities `pi` for the new sample.
2. Sort classes in descending order of `pi`.
3. Include classes greedily until the cumulative sum meets or exceeds `q_hat`:
   ```python
   prediction_set = []
   for j, idx in enumerate(sorted_indices):
       prediction_set.append(CLASS_LABELS[idx])
       if cumsum[j] >= q_hat:
           break
   ```
4. The resulting set has **guaranteed marginal coverage**: `P(y in C(X)) >= 1 - alpha`.

#### Singleton vs. Ambiguous Sets

| Prediction Set | Meaning | SEC-C Action |
|---------------|---------|-------------|
| `["safe"]` | Model is confident this is not a vulnerability | **Resolved** at graph stage (verdict: SAFE) |
| `["vulnerable"]` | Model is confident this is a real vulnerability | **Resolved** at graph stage (verdict: LIKELY) |
| `["safe", "vulnerable"]` | Model cannot confidently classify | **Escalated** to LLM for deeper reasoning |

#### Why alpha = 0.1 (90% Coverage)?

- **alpha = 0.1** means the prediction set is guaranteed to contain the true label at least 90% of the time.
- Lower alpha (e.g., 0.01 for 99% coverage) would produce mostly ambiguous sets (everything escalated to LLM), defeating the cascade.
- Higher alpha (e.g., 0.3 for 70% coverage) would produce more singletons but with weaker guarantees, risking more false negatives.
- **90% represents the standard in conformal prediction literature** (Vovk et al., 2005; Romano et al., 2020) and balances resolution rate against safety.

#### Worked Numerical Example

**Setup**: Binary classification (classes: safe=0, vulnerable=1), alpha=0.1.

**Calibration** (5 samples for simplicity):

| Sample | True Label | Softmax [safe, vuln] | Sorted Probs | CumSum | True Label Rank | Score |
|--------|-----------|---------------------|-------------|--------|-----------------|-------|
| 1 | vuln (1) | [0.2, 0.8] | [0.8, 0.2] | [0.8, 1.0] | 0 | 0.8 |
| 2 | safe (0) | [0.9, 0.1] | [0.9, 0.1] | [0.9, 1.0] | 0 | 0.9 |
| 3 | vuln (1) | [0.6, 0.4] | [0.6, 0.4] | [0.6, 1.0] | 1 | 1.0 |
| 4 | safe (0) | [0.7, 0.3] | [0.7, 0.3] | [0.7, 1.0] | 0 | 0.7 |
| 5 | vuln (1) | [0.3, 0.7] | [0.7, 0.3] | [0.7, 1.0] | 0 | 0.7 |

Scores: [0.8, 0.9, 1.0, 0.7, 0.7]

`quantile_level = min(ceil(6 * 0.9) / 5, 1.0) = min(ceil(5.4)/5, 1.0) = min(6/5, 1.0) = 1.0`

`q_hat = quantile([0.7, 0.7, 0.8, 0.9, 1.0], 1.0, method="higher") = 1.0`

**Inference** on a new sample with softmax [0.55, 0.45]:

1. Sorted: [0.55 (safe), 0.45 (vuln)]
2. CumSum: [0.55, 1.0]
3. Include "safe" -> cumsum = 0.55 < 1.0, continue
4. Include "vulnerable" -> cumsum = 1.0 >= 1.0, stop

Prediction set: `["safe", "vulnerable"]` -- **ambiguous**, escalate to LLM.

**Inference** on a confident sample with softmax [0.05, 0.95]:

1. Sorted: [0.95 (vuln), 0.05 (safe)]
2. CumSum: [0.95, 1.0]
3. Include "vulnerable" -> cumsum = 0.95 < 1.0, continue
4. Include "safe" -> cumsum = 1.0 >= 1.0, stop

Prediction set: `["safe", "vulnerable"]` -- still ambiguous with `q_hat = 1.0`. (With more calibration data, `q_hat` would typically be lower, producing singletons for confident predictions.)

---

## 6. Stage 3: LLM Dual-Agent

Stage 3 uses a dual-agent adversarial protocol where an Attacker (Red Team) agent attempts to construct exploits and a Defender (Blue Team) agent identifies protective measures. Their verdicts are combined by a consensus engine.

### 6.1 Provider Architecture

#### BaseLLMClient Interface

All LLM providers implement the `BaseLLMClient` abstract interface:

```python
class BaseLLMClient:
    async def generate(prompt, use_pro, json_mode, system_instruction) -> str
    model_pro: str    # High-quality model identifier
    model_flash: str  # Fast/cheap model identifier
```

#### Gemini vs Groq Comparison

| Feature | Gemini (Primary) | Groq (Fallback) |
|---------|-----------------|-----------------|
| Pro Model | `gemini-2.5-pro` | Llama 3.1 70B |
| Flash Model | `gemini-2.5-flash` | Llama 3.1 8B |
| Free Tier RPM (Pro) | 2 | 30 |
| Free Tier RPD (Pro) | 25 | 1,000 |
| Free Tier RPM (Flash) | 15 | 30 |
| Free Tier RPD (Flash) | 500 | 14,400 |
| JSON Mode | Native | Via prompting |
| Quality | Higher (esp. reasoning) | Lower but faster |

SEC-C defaults to **Flash models** for all dual-agent calls to conserve Pro quota. Pro is reserved for complex cases where `complexity_threshold > 0.7`.

#### Multi-Key Rotation Mechanism

SEC-C supports multiple API keys for higher aggregate throughput:

- Keys are loaded from the environment variable specified in config (`GEMINI_API_KEY`)
- Multiple keys can be specified as comma-separated values
- The client rotates between keys round-robin to distribute rate limit pressure

#### Prompt Caching (SHA-256 Dedup)

Identical prompts (same code, same CWE, same context) are deduplicated via SHA-256 hashing. If the same finding is re-analyzed (e.g., during incremental scans), the cached response is returned without an API call.

#### Batch Request Optimization

The `ConsensusEngine.validate_batch()` method constructs a single prompt containing up to `max_batch_size` (default: 5) findings, asking the LLM to analyze all of them in one API call. This reduces API calls by up to 5x. If batch parsing fails, it falls back to individual `validate()` calls.

### 6.2 CWE-Specific Prompt Templates

SEC-C uses 12 Jinja2 templates (6 attacker + 6 defender) organized by CWE category:

| Category | CWE IDs | Attacker Template | Defender Template |
|----------|---------|-------------------|-------------------|
| **Injection** | CWE-78, 79, 89, 94, 95 | `attacker_injection.jinja2` | `defender_injection.jinja2` |
| **Deserialization** | CWE-502 | `attacker_deserialization.jinja2` | `defender_deserialization.jinja2` |
| **Path Traversal** | CWE-22 | `attacker_path_traversal.jinja2` | `defender_path_traversal.jinja2` |
| **Cryptography** | CWE-327, 328 | `attacker_crypto.jinja2` | `defender_crypto.jinja2` |
| **Authentication** | CWE-287, 862 | `attacker_auth.jinja2` | `defender_auth.jinja2` |
| **Default** | All others | `attacker_default.jinja2` | `defender_default.jinja2` |

**What makes them research-grade**: Each template includes CWE-specific exploit knowledge (injection payloads, gadget chains, traversal techniques), asks for structured JSON output with specific fields, and references the taint flow path and surrounding code context. The templates are based on the guided-questioning approach from Vulnhalla (CyberArk, 2025) and the CWE-specific prompting strategy from ZeroFalse (arXiv, 2025).

### 6.3 Attacker Agent (Red Team)

**Source**: `src/llm/agents/attacker.py`

#### System Instruction

```
You are an expert offensive security researcher and penetration tester.
Your role is to analyze code for exploitable vulnerabilities. You approach
code like a skilled attacker would -- looking for ways to bypass input
validation, exploit unsafe operations, and craft payloads that demonstrate
real exploitability. Be thorough but honest: if the code is actually safe,
say so. Always respond in valid JSON format.
```

#### What It Asks the LLM to Do

The Attacker agent receives:
- The vulnerability finding (CWE, severity, location, snippet)
- The full taint flow path (source to sink)
- RAG context (CWE descriptions, known exploit patterns)
- Surrounding code context

It attempts to:
1. Trace the taint path from source to sink
2. Identify missing sanitization along the path
3. Construct a concrete exploit payload
4. Assess whether the exploit is practically achievable

#### Output Format

```json
{
    "exploitable": true,
    "payload": "' OR '1'='1' --",
    "execution_trace": ["Step 1: user input at line 38", "Step 2: concatenation at line 40"],
    "blocking_factors": [],
    "confidence": 0.92,
    "assumptions": ["Database uses MySQL", "No WAF in front"],
    "counterexamples": [],
    "reasoning": "User input flows directly into SQL query..."
}
```

### 6.4 Defender Agent (Blue Team)

**Source**: `src/llm/agents/defender.py`

#### System Instruction

```
You are an expert defensive security engineer and secure code reviewer.
Your role is to identify all security protections in code -- input validation,
sanitization, encoding, access controls, framework safeguards, and any other
defensive measures. You are thorough and conservative: if protection exists,
you find it. But you are also honest: if protection is incomplete or missing,
you report that clearly. Always respond in valid JSON format.
```

#### What It Analyzes

The Defender agent examines:
- Input validation and sanitization functions
- Access control mechanisms (authentication, authorization)
- Framework-level protections (CSRF tokens, CSP headers, ORM parameterization)
- Whether the taint path is actually feasible in practice

#### Output Format

```json
{
    "sanitizers_found": [
        {"function": "html.escape", "location": "line 45", "effectiveness": "partial"}
    ],
    "access_controls": ["@login_required decorator"],
    "framework_protections": ["Django ORM parameterization"],
    "path_feasible": true,
    "defense_coverage_score": 0.15,
    "reasoning": "While authentication is required, the SQL query uses..."
}
```

### 6.5 Consensus Rules

**Source**: `src/llm/consensus/engine.py` -- `_apply_consensus()` method

The consensus engine applies four rules in order to determine the final verdict:

#### Rule 1: CONFIRMED (Strong Evidence of Vulnerability)

**Condition**: Attacker says exploitable AND `defense_coverage_score < 0.5`

```python
if atk_exploitable and def_coverage < confirmed_defense_threshold:  # 0.5
    confidence = max(atk_confidence, 1.0 - def_coverage)
    return Verdict.CONFIRMED, min(confidence, 1.0)
```

**Worked example**: Attacker says exploitable with confidence 0.92, defender finds defense_coverage = 0.15.
- `0.15 < 0.5` -> Rule 1 fires
- `confidence = max(0.92, 1.0 - 0.15) = max(0.92, 0.85) = 0.92`
- **Verdict: CONFIRMED (92%)**

#### Rule 2: SAFE (Strong Evidence of Safety)

**Condition**: Attacker says NOT exploitable AND `defense_coverage_score > 0.7`

```python
if not atk_exploitable and def_coverage > safe_defense_threshold:  # 0.7
    confidence = max(def_coverage, 1.0 - atk_confidence)
    return Verdict.SAFE, min(confidence, 1.0)
```

**Worked example**: Attacker says not exploitable with confidence 0.3, defender finds defense_coverage = 0.85.
- Not exploitable AND `0.85 > 0.7` -> Rule 2 fires
- `confidence = max(0.85, 1.0 - 0.3) = max(0.85, 0.7) = 0.85`
- **Verdict: SAFE (85%)**

#### Rule 2b: SAFE (Path Not Feasible)

**Condition**: Defender says path NOT feasible AND attacker says NOT exploitable.

```python
if not def_feasible and not atk_exploitable:
    confidence = infeasible_confidence  # 0.8
    return Verdict.SAFE, confidence
```

**Worked example**: Defender determines the taint path requires an impossible precondition. Attacker also cannot construct an exploit.
- **Verdict: SAFE (80%)**

#### Rule 3: LIKELY (Attacker Succeeded Despite Defenses)

**Condition**: Attacker says exploitable AND `defense_coverage_score >= 0.5`

```python
if atk_exploitable and def_coverage >= confirmed_defense_threshold:
    confidence = 0.5 + 0.3 * (atk_confidence - def_coverage)
    return Verdict.LIKELY, min(max(confidence, 0.3), 0.85)
```

**Worked example**: Attacker says exploitable with confidence 0.8, defender finds defense_coverage = 0.6.
- Exploitable but `0.6 >= 0.5` -> Rule 3 fires
- `confidence = 0.5 + 0.3 * (0.8 - 0.6) = 0.5 + 0.06 = 0.56`
- **Verdict: LIKELY (56%)** -- defenses exist but are not complete

#### Rule 4: POTENTIAL (Attacker Failed, Weak Defenses)

**Condition**: Attacker says NOT exploitable AND `defense_coverage_score <= 0.7`

```python
if not atk_exploitable and def_coverage <= safe_defense_threshold:
    confidence = 0.4 + 0.2 * (1.0 - def_coverage)
    return Verdict.POTENTIAL, min(max(confidence, 0.2), 0.6)
```

**Worked example**: Attacker says not exploitable with confidence 0.5, defender finds defense_coverage = 0.4.
- Not exploitable AND `0.4 <= 0.7` -> Rule 4 fires
- `confidence = 0.4 + 0.2 * (1.0 - 0.4) = 0.4 + 0.12 = 0.52`
- **Verdict: POTENTIAL (52%)** -- attacker didn't find an exploit but defenses are weak

#### Why These Thresholds?

| Threshold | Value | Rationale |
|-----------|-------|-----------|
| `confirmed_defense_threshold` | **0.5** | Below 50% defense coverage means more attack surface is exposed than protected -- strong evidence of real vulnerability |
| `safe_defense_threshold` | **0.7** | Above 70% defense coverage, combined with attacker failure, provides high confidence in safety. Not 1.0 because perfect defense coverage is unrealistic. |
| `infeasible_confidence` | **0.8** | When the taint path is infeasible, we are 80% confident in safety (not 100% because the path feasibility analysis itself may be wrong). |

#### Default Case

If no rule matches (should be rare), the verdict defaults to `Verdict.LIKELY` with confidence `0.5`.

### 6.6 RAG Knowledge Base

The RAG (Retrieval-Augmented Generation) knowledge base grounds LLM reasoning in authoritative vulnerability data.

#### Data Sources

- **969 CWE entries** from MITRE's CWE database, including descriptions, examples, mitigations, and detection methods
- **NVD data** for real-world CVE examples mapped to CWEs

#### Hybrid Retrieval

SEC-C uses a hybrid retrieval strategy combining:

1. **BM25** (keyword-based): Handles exact CWE ID lookups and specific technical terms
2. **FAISS** (semantic): Handles conceptual similarity queries using dense embeddings

Configuration:
```yaml
rag:
  hybrid_weight_semantic: 0.6   # 60% weight on FAISS semantic similarity
  hybrid_weight_keyword: 0.4    # 40% weight on BM25 keyword matching
  top_k: 5                      # Return top 5 results
```

#### How RAG Grounds LLM Reasoning

Before dispatching a finding to the Attacker and Defender agents, the consensus engine queries the RAG knowledge base:

```python
result = self.rag.query(
    cwe_id=finding.cwe_id,
    code_snippet=finding.location.snippet or "",
    top_k=5,
)
```

The retrieved context (CWE description, known exploit patterns, recommended mitigations) is injected into the `context` dict that both agents receive. This ensures:

- The LLM has accurate, authoritative CWE definitions (not hallucinated)
- Both agents share identical context (no information asymmetry)
- The LLM can reference specific mitigation techniques rather than generic advice

---

## 7. Stage 4: Score Fusion & Reporting

### 7.1 CWE-Adaptive Fusion

**Source**: `src/orchestrator/fusion.py`

#### Fusion Formula

```
final_score = alpha * SAST_confidence + beta * GAT_risk_score + gamma * LLM_consensus_confidence
```

Where `(alpha, beta, gamma)` are CWE-specific weights that sum to 1.0.

- **SAST_confidence**: `finding.sast_confidence` -- the SAST tool's self-reported confidence
- **GAT_risk_score**: `finding.graph_validation.structural_risk_score` -- the GNN's learned risk score
- **LLM_consensus_confidence**: `finding.llm_validation.consensus_confidence` -- the consensus engine's confidence

#### Weight Renormalization When Stages Are Skipped

Not all findings pass through all three stages. When a stage was not executed (e.g., a finding resolved at SAST never gets graph or LLM scores), the weights are renormalized:

```python
total_weight = sum(weights_of_executed_stages)
fused = sum(score * (weight / total_weight) for each executed stage)
```

**Example**: Finding resolved at SAST (only sast_confidence available).
- Weights: `alpha=0.3`, `beta=0.3`, `gamma=0.4` -- but only SAST ran
- Renormalized: `alpha' = 0.3 / 0.3 = 1.0`
- `fused = 1.0 * sast_confidence`

**Example**: Finding resolved at Graph (SAST + Graph ran, no LLM).
- `alpha=0.3`, `beta=0.3`, only these two ran
- Renormalized: `alpha' = 0.3/0.6 = 0.5`, `beta' = 0.3/0.6 = 0.5`
- `fused = 0.5 * sast_confidence + 0.5 * gat_risk_score`

#### Per-CWE Weight Table with Rationale

| CWE | Category | alpha (SAST) | beta (GAT) | gamma (LLM) | Rationale |
|-----|----------|:-----:|:----:|:-----:|-----------|
| **CWE-78** | OS Command Injection | 0.25 | 0.25 | **0.50** | Injection context (shell vs exec, arguments) requires semantic understanding |
| **CWE-79** | XSS | 0.25 | 0.25 | **0.50** | Output context (HTML vs JS vs URL) determines exploitability |
| **CWE-89** | SQL Injection | 0.30 | 0.25 | **0.45** | SAST taint tracking is strong here, but parameterization detection benefits from LLM |
| **CWE-94** | Code Injection | 0.25 | 0.30 | **0.45** | Graph structure (dynamic dispatch) matters; LLM understands eval context |
| **CWE-22** | Path Traversal | 0.35 | 0.30 | 0.35 | Balanced: SAST detects patterns, graph shows flow, LLM checks mitigation |
| **CWE-434** | Unrestricted Upload | 0.30 | 0.25 | **0.45** | LLM understands file type validation logic |
| **CWE-327** | Broken Crypto | **0.50** | 0.20 | 0.30 | Pattern matching (weak cipher names) is sufficient; LLM struggles with crypto (77-84% miss rate) |
| **CWE-328** | Weak Hash | **0.50** | 0.20 | 0.30 | Same as CWE-327: hashing algorithm names are pattern-matchable |
| **CWE-416** | Use After Free | 0.20 | **0.50** | 0.30 | Memory lifecycle requires structural analysis of alloc/free paths |
| **CWE-476** | NULL Pointer Deref | 0.25 | **0.45** | 0.30 | Null-check paths are structural; graph analysis excels |
| **CWE-502** | Deserialization | 0.25 | 0.25 | **0.50** | Gadget chain feasibility requires deep semantic reasoning |
| **CWE-287** | Improper Auth | 0.20 | 0.25 | **0.55** | Authentication logic is semantic, not structural |
| **CWE-862** | Missing Auth | 0.20 | 0.25 | **0.55** | Authorization gaps require understanding business logic |
| **default** | All others | 0.30 | 0.30 | 0.40 | Balanced with slight LLM bias for unknown CWE categories |

#### Three-Tier Classification

| Verdict | Score Range | Meaning |
|---------|-----------|---------|
| **CONFIRMED** | `>= 0.85` | High confidence true positive -- likely exploitable vulnerability |
| **LIKELY** | `0.50 - 0.85` | Probable vulnerability but some ambiguity remains |
| **POTENTIAL** | `> 0.0, < 0.50` | Possible vulnerability, needs manual review |
| **UNKNOWN** | `= 0.0` | Cannot classify (insufficient data) |
| **SAFE** | *(via LLM override)* | Not a vulnerability (false positive filtered) |

#### LLM Override Rules

Two special override rules bypass the threshold-based classification:

```python
# Override 1: Strong attacker confirmation with very weak defenses
if llm.attacker.exploitable and llm.defender.defense_coverage_score < 0.3:
    return Verdict.CONFIRMED  # Regardless of fused score

# Override 2: Strong defender confirmation with attacker failure
if not llm.attacker.exploitable and llm.defender.defense_coverage_score > 0.8:
    return Verdict.SAFE  # Regardless of fused score
```

These overrides ensure that clear-cut LLM decisions are not overridden by a mediocre fused score.

### 7.2 Output Formats

#### SARIF 2.1.0 with Custom Properties

SEC-C generates standard SARIF 2.1.0 output compatible with GitHub Security tab, VS Code SARIF Viewer, and other SARIF consumers. Beyond the standard fields, SEC-C adds custom properties under the `sec-c/` namespace:

| Custom Property | Type | Description |
|----------------|------|-------------|
| `sec-c/verdict` | string | Final verdict (confirmed/likely/potential/safe) |
| `sec-c/fused_confidence` | float | Final fused confidence score |
| `sec-c/stage_resolved` | string | Which cascade stage resolved (sast/graph/llm) |
| `sec-c/uncertainty_score` | float | Stage 1 uncertainty score |
| `sec-c/structural_risk` | float | Stage 2 graph risk score |
| `sec-c/conformal_prediction_set` | list[str] | Stage 2 calibrated prediction set |
| `sec-c/conformal_coverage` | float | Stage 2 coverage level (e.g., 0.9) |
| `sec-c/attacker_verdict` | object | Stage 3 red team analysis (exploitable, payload, confidence) |
| `sec-c/defender_verdict` | object | Stage 3 blue team analysis (coverage, path_feasible) |
| `sec-c/model_used` | string | LLM model identifier |
| `sec-c/nl_explanation` | string | Natural language explanation (up to 2000 chars) |
| `sec-c/remediation` | string | Suggested remediation |

Severity mapping to SARIF levels:

| SEC-C Severity | SARIF Level |
|---------------|-------------|
| CRITICAL | `error` |
| HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |
| INFO | `note` |

Verdict mapping to SARIF kind:

| SEC-C Verdict | SARIF Kind |
|--------------|-----------|
| CONFIRMED | `fail` |
| LIKELY | `fail` |
| POTENTIAL | `review` |
| SAFE | `pass` |
| UNKNOWN | `open` |

#### HTML Interactive Dashboard

The HTML reporter generates a self-contained dashboard with:
- Findings summary by severity and verdict
- Interactive filtering by CWE, severity, verdict, and stage
- Per-finding detail view with taint flow visualization
- Cascade statistics and efficiency metrics

#### Console Rich Output

The console reporter uses Python's `rich` library to display:
- Colored severity badges and verdict indicators
- Cascade stage progression with timing
- Findings table with sortable columns
- Per-stage resolution statistics

Configuration:
```yaml
reporting:
  console:
    color: true
    verbose: false
    show_cascade_stats: true
```

---

## 8. Why SEC-C is Best: Validation Backing

### The Case Against Each Standalone Approach

| Approach | Fatal Flaw | Evidence |
|----------|-----------|----------|
| **CodeQL alone** | 68.2% median false positive rate | Amit et al., "Sifting the Noise: A Comprehensive Study of SAST False Positive Rates," 2026. Evaluated across 12 SAST tools on 150+ open-source projects. |
| **LLM-only** (e.g., GPT-4, Gemini) | 42% inconsistency across runs; up to 90% hallucination on security tasks | Kaplan et al., 2024; Zhou et al., 2024. LLMs produce different answers to the same question, fabricate CVE numbers, and misidentify vulnerability classes. |
| **GNN-only** (e.g., Devign, ReVeal, IVDetect) | Collapse to 2% F1 on realistic data | Steenhoek et al., "An Empirical Study of Deep Learning Models for Vulnerability Detection," IEEE TSE, 2024. Models trained on synthetic datasets fail catastrophically on real-world code. |
| **Single-agent LLM** | ~50% accuracy | Columbia University, 2024. A single LLM agent answering "is this vulnerable?" achieves near-random performance. Multi-agent adversarial protocol achieves 88%. |

### Why SEC-C's Cascade is Novel

1. **No published cascade system exists**: Prior work either uses a single analysis engine or combines tools in a flat ensemble. SEC-C is the first to implement uncertainty-driven escalation routing between heterogeneous analysis stages.

2. **First conformal prediction for vulnerability detection**: Conformal prediction has been applied in medical imaging, autonomous driving, and natural language processing, but never to static analysis or vulnerability detection. SEC-C's application provides distribution-free coverage guarantees for GNN-based vulnerability classifiers.

3. **Multi-agent adversarial protocol**: Inspired by Columbia University's research showing that adversarial multi-agent setups (attacker + defender) outperform single-agent approaches by 38 percentage points.

4. **CWE-adaptive fusion**: Rather than using fixed fusion weights, SEC-C adapts per CWE category based on which analysis engine is most effective for that vulnerability class.

### Comparison Table

| Feature | SEC-C | IRIS (Microsoft) | Vulnhalla (CyberArk) | ZeroFalse (arXiv 2025) | LLMxCPG |
|---------|-------|----------|-----------|-----------|---------|
| Multi-stage cascade | 4-stage with uncertainty routing | 2-stage (SAST + LLM) | Single-stage LLM | Single-stage LLM | 2-stage (CPG + LLM) |
| Uncertainty quantification | 4-factor formula + conformal prediction | None | None | None | None |
| Coverage guarantees | Yes (conformal, alpha=0.1) | No | No | No | No |
| Graph neural network | Mini-GAT on CPG | No | No | No | No (uses CPG as text) |
| Dual-agent adversarial | Yes (attacker + defender) | No (single agent) | Yes (guided questioning) | Yes (verify + falsify) | No |
| CWE-adaptive weights | Yes (13 CWE-specific + default) | No | Partial (CWE prompts) | Yes (CWE prompts) | No |
| RAG knowledge base | 969 CWE + NVD | Unknown | Proprietary KB | CWE descriptions | No |
| Output format | SARIF 2.1.0 + HTML + Console | SARIF | Proprietary | JSON | JSON |
| Free tier compatible | Yes (Gemini free tier) | Requires Azure OpenAI | Requires GPT-4 | Requires GPT-4 | Requires GPT-4 |
| Open source | Yes | No | No | Partial | Partial |

---

## 9. Configuration Reference

### default.yaml -- Complete Reference

**Source**: `configs/default.yaml`

#### Framework Metadata

```yaml
framework:
  name: "sec-c"       # Framework identifier, used in SARIF output
  version: "2.0.0"    # Semantic version, embedded in reports
```

#### Language Support

```yaml
languages:
  - python         # Tree-sitter + CodeQL
  - javascript     # Tree-sitter + CodeQL
  - java           # Tree-sitter + CodeQL
  - cpp            # Tree-sitter + CodeQL (C patterns reused)
  - go             # Tree-sitter + CodeQL
```

TypeScript and C are implicitly supported (TypeScript reuses JavaScript patterns; C reuses C++ patterns).

#### Module 1: SAST Engine

```yaml
sast:
  codeql:
    cli_path: "codeql"            # Path to CodeQL CLI binary.
                                  # "codeql" assumes it's on PATH.
                                  # Set absolute path if installed elsewhere.

    query_suite: "security-extended"  # Query suite to run.
                                      # "security-extended" includes broader coverage
                                      # than the default "security-and-quality".

    timeout_seconds: 300          # Maximum time for CodeQL analysis.
                                  # 5 minutes is generous for most projects.
                                  # Increase for very large codebases (>100K LoC).

    database_cache_dir: "~/.sec-c/codeql-dbs"  # Cache dir for CodeQL databases.
                                                # Avoids re-creating DBs on repeat scans.

    github_token_env: "GITHUB_TOKEN"  # Environment variable name for GitHub token.
                                      # Used to download pre-built CodeQL databases
                                      # for public GitHub repositories.

  treesitter:
    enabled: true                 # Enable tree-sitter pre-screening.
                                  # Set false to skip and rely only on CodeQL.

    prescreen_timeout_ms: 100     # Per-file parse timeout in milliseconds.
                                  # Tree-sitter is fast; 100ms handles most files.

  uncertainty:
    confidence_weight: 0.4        # Weight for confidence uncertainty factor.
    complexity_weight: 0.3        # Weight for complexity uncertainty factor.
    novelty_weight: 0.2           # Weight for novelty uncertainty factor.
    conflict_weight: 0.1          # Weight for conflict uncertainty factor.
                                  # Sum = 1.0 (before severity adjustment).

    escalation_threshold: 0.5     # Findings with U >= 0.5 escalate to Graph.
                                  # Lower = more escalation (higher recall, higher cost).
                                  # Higher = less escalation (lower recall, lower cost).

    severity_adjustments:
      critical: 0.15              # CRITICAL findings: +0.15 to uncertainty.
                                  # Biases toward escalation for safety.
      high: 0.10                  # HIGH findings: +0.10 to uncertainty.
      medium: 0.00                # MEDIUM: neutral.
      low: -0.05                  # LOW: slight bias toward early resolution.

    max_taint_path_before_escalation: 3  # Taint paths longer than 3 steps
                                         # are always escalated regardless of U score.
```

#### Module 2: Graph-Augmented Validation

```yaml
graph:
  joern:
    binary_path: "joern"          # Path to Joern CLI binary.
    timeout_seconds: 120          # CPG construction timeout (2 minutes).
    export_format: "graphml"      # Graph export format for processing.

  embeddings:
    model: "microsoft/graphcodebert-base"  # Pre-trained code embedding model.
                                           # 768-dim embeddings per code token.
    embedding_dim: 768            # Must match model output dimension.
    batch_size: 32                # Batch size for embedding computation.
    device: "cpu"                 # "cpu" or "cuda" for GPU acceleration.
                                  # GPU recommended for large codebases.

  gnn:
    input_dim: 773                # 768 (GraphCodeBERT) + 5 (graph features).
    hidden_dim: 256               # Width of first GAT layer.
    output_dim: 128               # Width of second GAT layer / graph embedding.
    num_heads_l1: 4               # Attention heads in GAT layer 1.
    num_heads_l2: 4               # Attention heads in GAT layer 2.
    dropout: 0.3                  # Dropout between GAT layers (regularization).
    num_classes: 2                # Binary: safe (0) vs vulnerable (1).
    max_nodes: 200                # Maximum nodes in a CPG slice.
                                  # Larger graphs are truncated.
    model_path: "data/models/mini_gat.pt"  # Path to trained model weights.

  conformal:
    alpha: 0.1                    # Miscoverage rate -> 90% coverage guarantee.
                                  # Lower alpha = wider prediction sets (more escalation).
                                  # Higher alpha = narrower sets (more resolution).
    calibration_size: 0.2         # Fraction of labeled data held out for calibration.
    method: "aps"                 # Adaptive Prediction Sets algorithm.
```

#### Module 3: LLM Dual-Agent Validation

```yaml
llm:
  gemini:
    model_pro: "gemini-2.5-pro"       # High-quality model for complex cases.
    model_flash: "gemini-2.5-flash"   # Fast/cheap model for standard cases.
    primary_model: "gemini-2.5-flash" # Default model for all calls.
    fallback_model: "gemini-2.5-pro"  # Used when Flash fails or for complex cases.
    api_key_env: "GEMINI_API_KEY"     # Environment variable with API key(s).

    # Free tier rate limits
    pro_rpm: 2                    # Pro: 2 requests per minute.
    pro_rpd: 25                   # Pro: 25 requests per day.
    flash_rpm: 15                 # Flash: 15 requests per minute.
    flash_rpd: 500                # Flash: 500 requests per day.

    temperature: 0.1              # Low temperature for deterministic output.
                                  # Security analysis needs consistency, not creativity.
    max_output_tokens: 4096       # Maximum response length.
    max_batch_size: 5             # Up to 5 findings per batch prompt.

    prompt_tier_thresholds:
      minimal: 0.3               # U_score < 0.3 -> minimal prompt (save tokens).
      standard: 0.6              # 0.3 <= U_score < 0.6 -> standard prompt.
                                  # U_score >= 0.6 -> full prompt (maximum detail).

  consensus:
    confirmed_defense_threshold: 0.5  # Defense < 0.5 + exploit = CONFIRMED.
    safe_defense_threshold: 0.7       # Defense > 0.7 + no exploit = SAFE.
    infeasible_confidence: 0.8        # Infeasible path -> SAFE with 80% confidence.

  rag:
    faiss_index_path: "data/rag/faiss_index"   # FAISS index for semantic search.
    bm25_index_path: "data/rag/bm25_index"     # BM25 index for keyword search.
    nvd_data_path: "data/rag/nvd"              # NVD CVE data directory.
    cwe_data_path: "data/cwe"                   # CWE XML/JSON data directory.
    top_k: 5                      # Return top 5 RAG results per query.
    hybrid_weight_semantic: 0.6   # 60% weight on semantic (FAISS) similarity.
    hybrid_weight_keyword: 0.4    # 40% weight on keyword (BM25) matching.

  agents:
    complexity_threshold: 0.7     # Findings with U >= 0.7 use Pro model.
    max_retries: 2                # Retry failed LLM calls up to 2 times.
```

#### Module 4: Reporting & Orchestration

```yaml
orchestrator:
  fusion:
    sast_weight: 0.3              # Default SAST weight in fusion formula.
    gat_weight: 0.3               # Default GAT weight in fusion formula.
    llm_weight: 0.4               # Default LLM weight in fusion formula.
                                  # Sum = 1.0. Overridden by CWE-specific weights.

  classification:
    confirmed_threshold: 0.85     # Fused score >= 0.85 -> CONFIRMED.
    likely_threshold: 0.50        # Fused score >= 0.50 -> LIKELY.
                                  # Below 0.50 -> POTENTIAL.

reporting:
  sarif:
    schema_version: "2.1.0"       # SARIF schema version (do not change).
    tool_name: "sec-c"            # Tool name in SARIF output.
    tool_version: "2.0.0"         # Tool version in SARIF output.
    include_custom_properties: true  # Include sec-c/* custom properties.
                                     # Set false for minimal SARIF output.

  console:
    color: true                   # Enable colored console output (Rich).
    verbose: false                # Show detailed per-finding output.
    show_cascade_stats: true      # Display cascade resolution statistics.
```

### cwe_weights.yaml -- Complete Reference

**Source**: `configs/cwe_weights.yaml`

This file defines per-CWE fusion weights. The format is:

```yaml
CWE-XX:
  sast_weight: <float>   # Weight for SAST confidence
  gat_weight: <float>    # Weight for GAT structural risk
  llm_weight: <float>    # Weight for LLM consensus confidence
  # Sum must equal 1.0
```

#### Weight Rationale by Category

##### Injection Flaws (LLM-Heavy)

```yaml
CWE-78:   { sast: 0.25, gat: 0.25, llm: 0.50 }  # OS Command Injection
CWE-79:   { sast: 0.25, gat: 0.25, llm: 0.50 }  # XSS
CWE-89:   { sast: 0.30, gat: 0.25, llm: 0.45 }  # SQL Injection
CWE-94:   { sast: 0.25, gat: 0.30, llm: 0.45 }  # Code Injection
```

**Rationale**: Injection vulnerabilities require understanding the **context** of the sink operation. Is `cursor.execute()` using parameterized queries? Does `innerHTML` receive sanitized output? SAST can detect the pattern but struggles with context; LLMs excel at understanding whether sanitization is effective.

CWE-89 has a slightly higher SAST weight (0.30 vs 0.25) because SQL injection taint tracking is one of CodeQL's strongest capabilities.

CWE-94 has a slightly higher GAT weight (0.30 vs 0.25) because code injection often involves dynamic dispatch patterns that are visible in the CPG structure.

##### Cryptographic Issues (SAST-Heavy)

```yaml
CWE-327:  { sast: 0.50, gat: 0.20, llm: 0.30 }  # Broken Crypto Algorithm
CWE-328:  { sast: 0.50, gat: 0.20, llm: 0.30 }  # Weak Hash
```

**Rationale**: Cryptographic weaknesses are fundamentally pattern-matching problems. Detecting `MD5`, `SHA1`, `DES`, or `RC4` usage requires no semantic understanding -- the algorithm name alone is sufficient. LLMs have been shown to miss 77-84% of cryptographic issues (Kaplan et al., 2024), making them unreliable for this category.

##### Memory Safety Issues (GAT-Heavy)

```yaml
CWE-416:  { sast: 0.20, gat: 0.50, llm: 0.30 }  # Use After Free
CWE-476:  { sast: 0.25, gat: 0.45, llm: 0.30 }  # NULL Pointer Dereference
```

**Rationale**: Memory safety bugs are fundamentally **structural** problems. Use-after-free requires tracing the lifecycle of a pointer through allocate -> free -> use, which maps directly to paths in the CPG. The GNN can learn these structural patterns through attention over allocation/deallocation edges.

##### Authentication/Authorization Issues (LLM-Heavy)

```yaml
CWE-287:  { sast: 0.20, gat: 0.25, llm: 0.55 }  # Improper Authentication
CWE-862:  { sast: 0.20, gat: 0.25, llm: 0.55 }  # Missing Authorization
```

**Rationale**: Auth issues require **semantic understanding** of business logic. "Is `@login_required` sufficient for this endpoint?" is a question that requires understanding the application's authorization model, not just pattern matching or graph structure.

##### Default Weights

```yaml
default:  { sast: 0.30, gat: 0.30, llm: 0.40 }
```

Applied to any CWE not explicitly listed. Slightly LLM-favored because LLMs provide the deepest analysis, but balanced because the specific CWE's strengths are unknown.

#### How to Customize

To add weights for a new CWE category:

```yaml
CWE-918:  # SSRF
  sast_weight: 0.25
  gat_weight: 0.30
  llm_weight: 0.45
```

To retune existing weights:
1. Collect labeled data (true positives and false positives) for the target CWE
2. Run `scripts/calibrate_weights.py` to optimize weights on that data
3. Update `cwe_weights.yaml` with the calibrated values

---

*This document is the canonical technical reference for the SEC-C framework. For setup instructions, see `docs/BUILD_GUIDE.md`. For the data pipeline, see `docs/DATA_PIPELINE.md`.*
