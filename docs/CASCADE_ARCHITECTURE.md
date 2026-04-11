# Sec-C: 4-Stage Cascade Architecture — How It Works

> Step-by-step walkthrough of how a vulnerability finding flows through all 4 stages.
> Covers detection, filtering, resolution, escalation, configuration, and architectural strengths.

---

## The Core Idea

Not every finding needs the same depth of analysis. A hardcoded password (`CWE-798`) is trivially detectable by pattern matching — there is no reason to invoke a GNN or call an LLM API for it. But an SQL injection behind three layers of input sanitization (`CWE-89`) genuinely needs semantic analysis to determine if the sanitizers are sufficient.

The cascade resolves findings at the **cheapest possible stage**. Only ambiguous findings escalate to more expensive analysis.

```
Source Code
    │
    ▼
┌─────────────────────────────┐
│  STAGE 1: SAST Pre-Screener │  Cost: <100ms, Free
│  Tree-sitter + CodeQL        │  Resolves: ~75% of findings
└─────────────┬───────────────┘
              │ Escalated (U ≥ 0.5)
              ▼
┌─────────────────────────────┐
│  STAGE 2: Graph Validator    │  Cost: 1-3s, Free (local)
│  Joern CPG + Mini-GAT + APS  │  Resolves: ~15% of findings
└─────────────┬───────────────┘
              │ Ambiguous (prediction set = both classes)
              ▼
┌─────────────────────────────┐
│  STAGE 3: LLM Dual-Agent    │  Cost: 5-15s, API calls
│  Attacker + Defender + RAG   │  Resolves: ~5-10% of findings
└─────────────┬───────────────┘
              │ All findings (resolved or not)
              ▼
┌─────────────────────────────┐
│  STAGE 4: Score Fusion       │  Cost: <10ms
│  CWE-Adaptive Weights        │  Produces final verdict
│  + SARIF + HTML + Console     │
└─────────────────────────────┘
```

---

## Stage 1: SAST Pre-Screening

### What Happens

1. **Tree-sitter pattern matching** scans every source file for 24 known vulnerability patterns across 5 languages (Python, JavaScript, Java, C/C++, Go). This runs in <100ms per file.

2. **CodeQL taint analysis** (if installed) performs deeper source-to-sink tracking — following data from user input through function calls to dangerous operations (SQL queries, shell commands, file writes). Timeout: 300 seconds.

3. Each detected pattern becomes a **Finding object** with:
   - Location (file, line, column, code snippet)
   - CWE ID and name
   - SAST confidence score (0.0–1.0)
   - Taint flow path (if tracked)
   - Severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)

4. The **Uncertainty Scorer** computes a 4-factor uncertainty score for each finding:

   ```
   U = 0.4 × (1 - sast_confidence)           ← How unsure is the tool?
     + 0.3 × (taint_length / 5 + depth / 5)   ← How complex is the data flow?
     + 0.2 × novelty                           ← Is this a common or rare CWE?
     + 0.1 × conflict                          ← Do multiple tools agree?
     + severity_adjustment                     ← CRITICAL: +0.15, HIGH: +0.10, LOW: -0.05
   ```

5. The **Escalation Router** decides the fate of each finding:

### Resolution vs. Escalation Decision

| Condition | Decision | Why |
|-----------|----------|-----|
| U < 0.5, short taint, single-file | **RESOLVED at SAST** | High confidence, simple flow — no deeper analysis needed |
| U ≥ 0.5 | **ESCALATED to Graph** | Tool is uncertain — needs structural validation |
| Taint path > 3 hops | **ESCALATED to Graph** | Complex data flow — SAST can't track reliably |
| Interprocedural (crosses files) | **ESCALATED to Graph** | Cross-file flows are blind spots for SAST |
| Interprocedural + CRITICAL severity | **ALWAYS ESCALATED** | Safety-critical — never skip deeper analysis |

### What Gets Attached to Resolved Findings

- `stage_resolved = SAST`
- `verdict = SAFE` (if low uncertainty) or based on SAST confidence
- `cvss_base_score` from CWE default table (15 pre-computed CWE vectors)
- No graph or LLM validation (not needed)

### Configuration

| Parameter | Value | File |
|-----------|-------|------|
| Escalation threshold | 0.5 | `configs/default.yaml` → `sast.uncertainty.escalation_threshold` |
| Confidence weight | 0.4 | `configs/default.yaml` → `sast.uncertainty.confidence_weight` |
| Complexity weight | 0.3 | `configs/default.yaml` → `sast.uncertainty.complexity_weight` |
| Novelty weight | 0.2 | `configs/default.yaml` → `sast.uncertainty.novelty_weight` |
| Conflict weight | 0.1 | `configs/default.yaml` → `sast.uncertainty.conflict_weight` |
| Max taint hops | 3 | `configs/default.yaml` → `sast.uncertainty.max_taint_path` |
| Tree-sitter timeout | 100ms | `configs/default.yaml` → `sast.treesitter.prescreen_timeout_ms` |
| CodeQL timeout | 300s | `configs/default.yaml` → `sast.codeql.timeout_seconds` |

### Key Source Files

- `src/sast/engine.py` — orchestrates Tree-sitter + CodeQL
- `src/sast/treesitter/prescreener.py` — 24-pattern pre-screener
- `src/sast/uncertainty/scorer.py` — 4-factor uncertainty computation
- `src/sast/router.py` — escalation routing logic

---

## Stage 2: Graph-Augmented Validation

### What Happens

Only findings that were **escalated from Stage 1** enter Stage 2. This is the first cost filter — ~75% of findings never reach this stage.

1. **Code Property Graph (CPG) construction**: Joern (or tree-sitter fallback) builds a unified graph combining:
   - Abstract Syntax Tree (AST) — code structure
   - Control Flow Graph (CFG) — execution paths
   - Data Flow Graph (DFG) — variable propagation

2. **Backward program slicing**: Starting from the vulnerability sink (the dangerous operation), the slicer traces backward through the CPG to identify only the relevant subgraph. This dramatically reduces the graph size — a 10,000-node program might produce a 50-node backward slice.

3. **Feature extraction**: For each node in the slice:
   - **GraphCodeBERT embedding** (768 dimensions) — semantic code representation from Microsoft's pre-trained model
   - **5 structural features** — node degree, in-degree, out-degree, betweenness centrality, node type encoding
   - Combined: **773-dimensional feature vector** per node

4. **Mini-GAT inference**: The 2-layer Graph Attention Network processes the subgraph:
   - Layer 1: GATConv(773, 256, 4 heads) → 1024-dim with attention-weighted aggregation
   - Layer 2: GATConv(1024, 128, 4 heads, concat=False) → 128-dim
   - Global mean pooling → single 128-dim graph representation
   - Classification head → P(safe), P(vulnerable) via softmax
   - Confidence head → calibrated confidence via sigmoid

5. **Conformal prediction (APS)**: Instead of trusting the raw softmax output, Adaptive Prediction Sets produces a **set of plausible labels** with a coverage guarantee:
   - If the model is confident: prediction set = {"safe"} or {"vulnerable"} (singleton)
   - If the model is uncertain: prediction set = {"safe", "vulnerable"} (ambiguous)
   - **Guarantee**: P(true label ∈ prediction set) ≥ 90% for any data distribution

### Resolution vs. Escalation Decision

| Conformal Prediction Set | Decision | Why |
|--------------------------|----------|-----|
| Singleton {"safe"} | **RESOLVED at Graph** — verdict = SAFE | Model is confident this is not vulnerable |
| Singleton {"vulnerable"} | **RESOLVED at Graph** — verdict = LIKELY | Model is confident this is vulnerable |
| Both {"safe", "vulnerable"} | **ESCALATED to LLM** | Model cannot decide — needs semantic analysis |
| No graph validation available | **ESCALATED to LLM** | Graceful degradation — skip to next stage |

### What Gets Attached to Resolved Findings

- `stage_resolved = GRAPH`
- `graph_validation.structural_risk_score` — CPG-based risk
- `graph_validation.conformal_prediction_set` — the prediction set
- `graph_validation.conformal_coverage` — coverage level
- `graph_validation.attention_weights` — which edges the GAT focused on (explainability)

### Configuration

| Parameter | Value | File |
|-----------|-------|------|
| GraphCodeBERT model | microsoft/graphcodebert-base | `configs/default.yaml` → `graph.embeddings.model` |
| Embedding dimension | 768 | `configs/default.yaml` → `graph.embeddings.embedding_dim` |
| GNN input dimension | 773 | `configs/default.yaml` → `graph.gnn.input_dim` |
| Hidden dimension | 256 | `configs/default.yaml` → `graph.gnn.hidden_dim` |
| Attention heads (L1/L2) | 4 / 4 | `configs/default.yaml` → `graph.gnn.num_heads_l1/l2` |
| Max nodes per graph | 200 | `configs/default.yaml` → `graph.gnn.max_nodes` |
| Conformal alpha | 0.1 (90% coverage) | `configs/default.yaml` → `graph.conformal.alpha` |
| Conformal method | APS | `configs/default.yaml` → `graph.conformal.method` |
| Model path | data/models/mini_gat.pt | `configs/default.yaml` → `graph.gnn.model_path` |
| Joern timeout | 120s | `configs/default.yaml` → `graph.joern.timeout` |

### Key Source Files

- `src/graph/gnn/graph_validator.py` — Stage 2 orchestrator
- `src/graph/cpg/builder.py` — Joern CPG construction
- `src/graph/slicing/slicer.py` — backward program slicing
- `src/graph/features/embeddings.py` — GraphCodeBERT encoding
- `src/graph/features/node_features.py` — 5 structural features
- `src/graph/gnn/mini_gat.py` — 2-layer GAT architecture
- `src/graph/uncertainty/conformal.py` — APS conformal prediction

---

## Stage 3: LLM Dual-Agent Validation

### What Happens

Only findings that were **ambiguous at Stage 2** enter Stage 3. This is the second cost filter — only ~5-25% of original findings reach this point.

1. **RAG knowledge retrieval**: Before the agents run, the consensus engine queries the hybrid knowledge base:
   - **FAISS** (semantic search) — embed the CWE ID + code snippet, find nearest vectors among 200K+ NVD entries and 900+ CWE entries
   - **BM25** (keyword search) — keyword match on the same query
   - **Reciprocal Rank Fusion** — combine both result lists: `RRF = 1/(60+rank_faiss) + 1/(60+rank_bm25)`
   - Returns: top-5 relevant CVE examples, CWE description, OWASP category, mitigation guidance

2. **Prompt tier selection**: Based on the finding's uncertainty score, the system selects how much context to include in the LLM prompt:

   | Uncertainty | Tier | What's Included | ~Tokens |
   |-------------|------|-----------------|---------|
   | U < 0.3 | Minimal | Code snippet + CWE name | 500 |
   | 0.3 ≤ U < 0.6 | Standard | + taint path + CWE description | 1,500 |
   | U ≥ 0.6 | Full | + RAG context (CVE examples, mitigations) | 3,000 |

3. **Attacker Agent (Red Team)** analyzes the finding:
   - Prompt: "You are a security researcher. Is this vulnerability exploitable? What attack vector exists?"
   - Uses CWE-category-specific Jinja2 templates (injection, crypto, deserialization, etc.)
   - Output: `AttackerVerdict` — exploitable (bool), payload, execution trace, confidence, CVSS sub-metrics (AV, AC, PR, UI)

4. **Defender Agent (Blue Team)** analyzes the same finding independently:
   - Prompt: "You are a security engineer. Is this code adequately defended? What sanitizers exist?"
   - Same RAG context as the attacker (identical information)
   - Output: `DefenderVerdict` — defense_coverage_score, sanitizers found, path_feasible, CVSS sub-metrics (S, C, I, A)

5. **Consensus Engine** applies 4 rules to combine both verdicts:

   | Rule | Condition | Verdict | Confidence |
   |------|-----------|---------|------------|
   | 1 | Attacker: exploitable + Defender: coverage < 0.5 | **CONFIRMED** | max(atk_conf, 1 - def_cov) |
   | 2 | Attacker: NOT exploitable + Defender: coverage > 0.7 | **SAFE** | max(def_cov, 1 - atk_conf) |
   | 2b | Path infeasible + NOT exploitable | **SAFE** | 0.8 (fixed) |
   | 3 | Attacker: exploitable + Defender: coverage ≥ 0.5 | **LIKELY** | 0.5 + 0.3×(atk_conf - def_cov) |
   | 4 | Attacker: NOT exploitable + Defender: coverage ≤ 0.7 | **POTENTIAL** | 0.4 + 0.2×(1 - def_cov) |

6. **CVSS v3.1 computation**: The 8 sub-metrics from both agents are combined to compute a CVSS base score (0.0–10.0) and severity rating (None/Low/Medium/High/Critical).

7. **Evidence narrative**: A plain-language explanation is constructed for stakeholders — combining attacker evidence, defender findings, and CVSS context into a readable narrative.

### What Gets Attached to Resolved Findings

- `stage_resolved = LLM`
- `llm_validation.attacker` — full AttackerVerdict
- `llm_validation.defender` — full DefenderVerdict
- `llm_validation.consensus_verdict` — CONFIRMED / LIKELY / POTENTIAL / SAFE
- `llm_validation.consensus_confidence` — 0.0–1.0
- `llm_validation.cvss_base_score` — e.g., 9.1
- `llm_validation.cvss_vector` — e.g., "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
- `llm_validation.evidence_narrative` — human-readable explanation

### Configuration

| Parameter | Value | File |
|-----------|-------|------|
| Primary LLM | gemini-2.5-flash | `configs/default.yaml` → `llm.gemini.primary_model` |
| Fallback LLM | gemini-2.5-pro | `configs/default.yaml` → `llm.gemini.model_pro` |
| Temperature | 0.1 | `configs/default.yaml` → `llm.gemini.temperature` |
| Max output tokens | 4096 | `configs/default.yaml` → `llm.gemini.max_output_tokens` |
| Flash RPM (free tier) | 15 | `configs/default.yaml` → `llm.gemini.flash_rpm` |
| Flash RPD (free tier) | 500 | `configs/default.yaml` → `llm.gemini.flash_rpd` |
| Max batch size | 5 | `configs/default.yaml` → `llm.consensus.max_batch_size` |
| Confirmed threshold | defense_coverage < 0.5 | `configs/default.yaml` → `llm.consensus.confirmed_defense_threshold` |
| Safe threshold | defense_coverage > 0.7 | `configs/default.yaml` → `llm.consensus.safe_defense_threshold` |
| RAG top-k | 5 | `configs/default.yaml` → `llm.rag.top_k` |
| Hybrid weight (semantic) | 0.6 | Knowledge base config |
| Hybrid weight (keyword) | 0.4 | Knowledge base config |

### Key Source Files

- `src/llm/consensus/engine.py` — consensus orchestrator + 4 rules
- `src/llm/agents/attacker.py` — red team agent
- `src/llm/agents/defender.py` — blue team agent
- `src/llm/agents/base.py` — base agent (prompt construction, tier selection)
- `src/llm/api/gemini_client.py` — Gemini API integration
- `src/llm/consensus/cvss.py` — CVSS v3.1 base score calculator
- `src/llm/rag/knowledge_base.py` — hybrid FAISS + BM25 retrieval
- `src/llm/context/assembler.py` — context builder for prompts
- `src/llm/prompts/templates/` — CWE-category-specific Jinja2 templates

---

## Stage 4: Score Fusion & Reporting

### What Happens

All findings — whether resolved at Stage 1, 2, or 3 — converge here for final scoring and output.

1. **CWE-adaptive score fusion**: The fused score combines evidence from all stages that analyzed the finding:

   ```
   fused_score = (α × sast_confidence + β × gat_risk_score + γ × llm_consensus_score) / (α + β + γ)
   ```

   Weights (α, β, γ) vary by CWE category:

   | CWE Category | SAST (α) | GAT (β) | LLM (γ) | Why |
   |-------------|----------|---------|---------|-----|
   | Injection (78, 79, 89) | 0.25 | 0.25 | 0.50 | LLM understands context (parameterized queries, encoding) |
   | Crypto (327, 328) | 0.50 | 0.20 | 0.30 | SAST detects weak algorithms by pattern (MD5, SHA1) |
   | Memory (416, 476) | 0.20 | 0.50 | 0.30 | Graph captures use-after-free, null deref flows |
   | Auth (287, 862) | 0.20 | 0.25 | 0.55 | LLM understands access control semantics |
   | Default | 0.30 | 0.30 | 0.40 | Balanced with slight LLM edge |

   If a stage was skipped (finding resolved earlier), its weight is redistributed to the stages that did run.

2. **Three-tier classification**:

   | Fused Score | Verdict | Meaning |
   |-------------|---------|---------|
   | ≥ 0.85 | **CONFIRMED** | High confidence — real vulnerability, prioritize fix |
   | 0.50 – 0.84 | **LIKELY** | Moderate confidence — probable vulnerability, review recommended |
   | 0.01 – 0.49 | **POTENTIAL** | Low confidence — possible issue, investigate if time permits |
   | 0.0 | **UNKNOWN** | No analysis completed |

3. **Report generation** (one or more outputs):
   - **SARIF 2.1.0** — machine-readable JSON standard, compatible with GitHub Code Scanning, VS Code SARIF Viewer. Includes custom `sec-c/*` properties for cascade metadata.
   - **HTML dashboard** — self-contained single-file interactive report. Sorting, filtering by stage/verdict/severity. CVSS badges, evidence modals, cascade breakdown visualization.
   - **Console output** — Rich terminal tables with color-coded severity and verdict. Real-time cascade progress during scan.

### Configuration

| Parameter | Value | File |
|-----------|-------|------|
| Default SAST weight | 0.3 | `configs/default.yaml` → `orchestrator.fusion.sast_weight` |
| Default GAT weight | 0.3 | `configs/default.yaml` → `orchestrator.fusion.gat_weight` |
| Default LLM weight | 0.4 | `configs/default.yaml` → `orchestrator.fusion.llm_weight` |
| Confirmed threshold | 0.85 | `configs/default.yaml` → `orchestrator.classification.confirmed_threshold` |
| Likely threshold | 0.50 | `configs/default.yaml` → `orchestrator.classification.likely_threshold` |
| CWE weight file | configs/cwe_weights.yaml | Per-CWE weight overrides (15 CWEs + default) |
| SARIF schema version | 2.1.0 | `configs/default.yaml` → `reporting.sarif.schema_version` |

### Key Source Files

- `src/orchestrator/fusion.py` — CWE-adaptive score fusion engine
- `src/reporting/sarif_reporter.py` — SARIF 2.1.0 export
- `src/reporting/html_reporter.py` — interactive HTML dashboard
- `src/reporting/console_reporter.py` — terminal tables
- `src/reporting/scan_display.py` — real-time cascade progress

---

## Cascade Metrics

### Observed Performance (Python test suite, 56 samples)

| Stage | Findings Entering | Resolved Here | Escalated | % of Total |
|-------|-------------------|---------------|-----------|------------|
| SAST | 24 | 18 | 6 | 75% resolved |
| Graph | 6 | 0* | 6 | 0%* |
| LLM | 6 | 6 | 0 | 25% resolved |
| **Total** | **24** | **24** | **0** | **100%** |

*Graph stage resolves 0 because the GNN model's conformal prediction currently produces 100% ambiguous sets (V2/V4 training issue — V5 fix targets 20-40% singletons).

### Target Performance (After V5 GNN Fix)

| Stage | Expected Resolution |
|-------|-------------------|
| SAST | ~75-80% |
| Graph | ~10-15% |
| LLM | ~5-10% |

### Cost Savings

| Approach | LLM API Calls (per 100 findings) | Cost Estimate |
|----------|----------------------------------|---------------|
| LLM-only (no cascade) | 100 calls | $10-40 |
| Sec-C cascade | ~5-25 calls | $0.50-2.00 |
| **Savings** | **75-95% fewer calls** | **85-95% cost reduction** |

---

## Why This Architecture Is Good

### 1. Cost-Proportional Analysis

Each stage is progressively more expensive. The cascade ensures you only pay the higher cost for findings that genuinely need it. A hardcoded API key (CWE-798) gets resolved in <100ms at Stage 1. A complex injection through three abstraction layers gets the full treatment at Stage 3 — but that's 5% of findings, not 100%.

### 2. Mathematically Principled Routing

The escalation decision is not ad-hoc. The 4-factor uncertainty score quantifies exactly why a finding needs deeper analysis (tool uncertainty, flow complexity, pattern rarity, tool disagreement). The conformal prediction at Stage 2 provides a formal coverage guarantee — not just a threshold, but a statistical contract.

### 3. Swappable Components

Every stage is independently replaceable:

| Component | Current Implementation | Can Be Swapped For |
|-----------|----------------------|---------------------|
| SAST engine | Tree-sitter + CodeQL | Semgrep, SonarQube, Fortify, any SARIF-producing tool |
| GNN model | Mini-GAT (2-layer, 4-head) | R-GAT, GIN, GGNN, any PyG-compatible model |
| Embeddings | GraphCodeBERT | CodeBERT, StarCoder, UniXcoder, any 768-dim encoder |
| Conformal method | APS | RAPS, THR, any TorchCP-compatible method |
| LLM provider | Gemini 2.5 Flash | GPT-4, Claude, Groq Llama, any chat completion API |
| RAG backend | FAISS + BM25 | ChromaDB, Pinecone, Elasticsearch, any retrieval system |
| Agent protocol | Attacker/Defender dual | Single agent, multi-agent debate, any consensus protocol |
| Output format | SARIF + HTML + Console | Any reporting format |

This is achieved through abstraction layers:
- `BaseLLMClient` — abstract class that Gemini and Groq both implement
- `BaseSecurityAgent` — abstract class that Attacker and Defender both implement
- `GraphValidator` — wraps any GNN model that produces (logits, confidence)
- `KnowledgeBase` — wraps any retrieval backend that returns documents

### 4. Graceful Degradation

The framework runs even when components are missing:

| Missing Component | What Happens |
|-------------------|-------------|
| CodeQL not installed | Tree-sitter-only SAST (reduced depth, but still works) |
| Joern not installed | Tree-sitter-based approximate graphs (lower quality CPG) |
| GNN model file absent | Stage 2 skipped — findings escalate directly to LLM |
| No LLM API key | Stage 3 skipped — findings remain at their Stage 1/2 verdict |
| No RAG index | LLM agents run without knowledge context (still functional) |
| No GPU | CPU fallback for GNN inference and embeddings |

This means a new user can `pip install -e .` and immediately run `sec-c scan` with zero external dependencies — they get Stage 1 analysis. As they add tools (CodeQL, Joern, API keys), more stages activate automatically.

### 5. Explainability at Every Stage

Each stage contributes interpretable evidence:

| Stage | Explainability Output |
|-------|----------------------|
| SAST | Rule ID, CWE, taint flow path, uncertainty breakdown (4 factors) |
| Graph | GAT attention weights (which edges matter), structural risk score, conformal prediction set |
| LLM | Attacker reasoning (exploit path), Defender reasoning (sanitizer analysis), evidence narrative |
| Fusion | Per-stage scores, CWE-adaptive weights used, final fused score, CVSS vector |

A security engineer can trace exactly why a finding was classified as CONFIRMED: "SAST found a taint path from user input to SQL query (confidence 0.7, uncertainty 0.6 → escalated). Graph analysis was ambiguous (prediction set = both classes → escalated). Attacker agent identified a union-based injection vector. Defender found no parameterized queries. Consensus: CONFIRMED at 0.92 confidence. CVSS 9.1 (AV:N/AC:L/PR:N/UI:N)."

### 6. CWE-Aware Intelligence

The framework treats different vulnerability types differently because they respond differently to different analysis methods:

- **Crypto weaknesses** (CWE-327, 328): SAST detects MD5/SHA1 by pattern matching. LLMs often miss these (77-84% miss rate in studies). So SAST gets 50% weight.
- **Injection flaws** (CWE-78, 79, 89): Whether user input reaches a SQL query depends on context — parameterized queries, ORM layers, encoding functions. LLMs understand this context. So LLM gets 50% weight.
- **Memory safety** (CWE-416, 476): Use-after-free and null dereference depend on control flow ordering — which the CPG captures structurally. So Graph gets 50% weight.

This is not a fixed heuristic. The weights are configurable per CWE in `configs/cwe_weights.yaml` and can be empirically calibrated.

### 7. Async Pipeline

The orchestrator (`PipelineOrchestrator`) is fully async:
- Stage 1 runs async SAST analysis
- Stage 2 can validate multiple findings concurrently
- Stage 3 supports batch LLM calls (up to 5 findings per API call) to maximize throughput within rate limits
- Real-time display shows progress per stage as the scan runs

### 8. Reproducible Configuration

Every threshold, weight, timeout, and model path is externalized to `configs/default.yaml`. No magic numbers in code. A researcher can:
- Change the escalation threshold from 0.5 to 0.3 (more aggressive escalation)
- Swap alpha from 0.1 to 0.05 (tighter conformal coverage, 95% guarantee)
- Switch LLM from Flash to Pro for higher-stakes analysis
- Adjust CWE weights based on empirical calibration

All without touching source code.

---

## Finding Lifecycle Summary

```
Finding created (SAST detection)
  │
  ├─ U < 0.5 → RESOLVED AT SAST → verdict assigned → CVSS from defaults
  │
  └─ U ≥ 0.5 → ESCALATED TO GRAPH
       │
       ├─ Singleton prediction set → RESOLVED AT GRAPH → verdict from conformal
       │
       └─ Ambiguous prediction set → ESCALATED TO LLM
            │
            ├─ Attacker + Defender → Consensus → RESOLVED AT LLM
            │   └─ CVSS computed, evidence narrative built
            │
            └─ API failure → UNRESOLVED (graceful degradation)
  │
  ALL FINDINGS → Score Fusion → Classification → SARIF + HTML + Console
```

Every finding ends in one of 4 states:
- **CONFIRMED** (fused ≥ 0.85) — fix this
- **LIKELY** (fused 0.50–0.84) — review this
- **POTENTIAL** (fused < 0.50) — investigate if time permits
- **UNRESOLVED** — analysis incomplete (tool missing or API failure)
