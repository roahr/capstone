# Sec-C: Technical Metrics Reference

> Every number, formula, threshold, weight, and dimension in the framework.
> Source files noted for each value so you can verify against the codebase.

---

## 1. Uncertainty Scoring (4-Factor Model)

**Source**: `src/sast/uncertainty/scorer.py`, `configs/default.yaml`

### Formula

```
U_total = w_conf × C_confidence + w_comp × C_complexity + w_nov × C_novelty + w_confl × C_conflict + S_adj
```

### Weights

| Factor | Weight | What It Measures |
|--------|--------|-----------------|
| Confidence | 0.4 | `1 - sast_confidence` (how unsure the SAST tool is) |
| Complexity | 0.3 | Taint path length + interprocedural depth, normalized |
| Novelty | 0.2 | Is this CWE pattern well-known (0.15) or rare (0.85)? |
| Conflict | 0.1 | Do multiple tools agree (0.1) or disagree (1.0)? |

### Severity Adjustments (additive, post-computation)

| Severity | Adjustment |
|----------|------------|
| CRITICAL | +0.15 |
| HIGH | +0.10 |
| MEDIUM | +0.00 |
| LOW | -0.05 |

### Thresholds

| Parameter | Value | Effect |
|-----------|-------|--------|
| Escalation threshold | 0.5 | U >= 0.5 sends finding to Graph stage |
| Max taint path before escalation | 3 | Taint paths > 3 hops always escalate |

### Novelty Constants

| CWE Category | Novelty Score | Examples |
|--------------|--------------|---------|
| Well-known (25 CWEs) | 0.15 | CWE-79, CWE-89, CWE-78, CWE-22, CWE-502, CWE-327, CWE-287 |
| Rare (everything else) | 0.85 | Any CWE not in the well-known list |

### Complexity Sub-Factors

| Parameter | Max Value | Formula |
|-----------|-----------|---------|
| Max taint hops | 5 | `min(taint_path_length / 5, 1.0)` |
| Max interprocedural depth | 5 | `min(depth / 5, 1.0)` |

### Conflict Scores

| Condition | Score |
|-----------|-------|
| Single tool only | 0.0 |
| Multiple tools agree | 0.1 |
| Multiple tools disagree | 1.0 |

---

## 2. Mini-GAT Architecture

**Source**: `src/graph/gnn/mini_gat.py`, `configs/default.yaml`

| Parameter | Value |
|-----------|-------|
| Input dimension | 773 (768 GraphCodeBERT + 5 structural features) |
| Hidden dimension | 256 |
| Output dimension | 128 |
| Layer 1 | GATConv(773, 256, heads=4) → 1024-dim output (4×256) |
| Layer 1 activation | ReLU + dropout(0.3) |
| Layer 2 | GATConv(1024, 128, heads=4, concat=False) → 128-dim |
| Layer 2 activation | ReLU |
| Pooling | Global mean pooling |
| Classification head | Linear(128, 2) + Softmax |
| Confidence head | Linear(128, 1) + Sigmoid |
| Max nodes per graph | 200 |
| Number of classes | 2 (safe=0, vulnerable=1) |

### 5 Structural Features

Appended to the 768-dim GraphCodeBERT embedding for each node:
1. Node degree
2. In-degree
3. Out-degree
4. Betweenness centrality
5. Node type encoding

### GraphCodeBERT Embedding

| Parameter | Value |
|-----------|-------|
| Model | microsoft/graphcodebert-base |
| Embedding dimension | 768 |
| Batch size | 32 |
| Parameters | 125M |

---

## 3. Conformal Prediction (APS)

**Source**: `src/graph/uncertainty/conformal.py`, `configs/default.yaml`

| Parameter | Value |
|-----------|-------|
| Method | APS (Adaptive Prediction Sets) |
| Alpha (mis-coverage rate) | 0.1 |
| Coverage guarantee | >= 90% (1 - alpha) |
| Calibration set size | 20% of data |

### APS Algorithm

**Calibration**:
1. For each calibration sample: compute softmax probability vector
2. Sort classes in descending probability order
3. Compute cumulative sum of sorted probabilities
4. Nonconformity score = cumulative sum at true label position
5. Quantile level = ceil((n+1)(1-alpha)) / n
6. Threshold = quantile of nonconformity scores at quantile level

**Inference**:
1. Compute softmax, sort classes descending
2. Include classes until cumulative probability exceeds threshold
3. Singleton set → resolved at Graph stage
4. Multi-label set → ambiguous, escalated to LLM

---

## 4. LLM Configuration

**Source**: `configs/default.yaml`, `src/llm/api/gemini_client.py`

### Gemini API

| Parameter | Value |
|-----------|-------|
| Primary model | gemini-2.5-flash |
| Fallback model | gemini-2.5-pro |
| Temperature | 0.1 |
| Max output tokens | 4096 |
| Max batch size | 5 findings/call |

### Rate Limits (Free Tier)

| Model | RPM | RPD |
|-------|-----|-----|
| Flash | 15 | 500 |
| Pro | 2 | 25 |

### Prompt Tier Selection

| Uncertainty Score | Tier | Approx. Tokens |
|-------------------|------|----------------|
| U < 0.3 | Minimal | ~500 (code + CWE name) |
| 0.3 <= U < 0.6 | Standard | ~1500 (+ taint path + CWE description) |
| U >= 0.6 | Full | ~3000 (+ RAG context) |

### Consensus Thresholds

| Parameter | Value | Usage |
|-----------|-------|-------|
| Confirmed defense threshold | 0.5 | Defense coverage below this + attacker exploitable = CONFIRMED |
| Safe defense threshold | 0.7 | Defense coverage above this + attacker non-exploitable = SAFE |
| Infeasible confidence | 0.8 | Confidence assigned when path is infeasible |
| Complexity routing threshold | 0.7 | U > 0.7 routes to Pro model instead of Flash |

---

## 5. CVSS v3.1 Computation

**Source**: `src/llm/consensus/cvss.py`

### Sub-Metric Multipliers

**Attack Vector (AV)**: Network=0.85, Adjacent=0.62, Local=0.55, Physical=0.20

**Attack Complexity (AC)**: Low=0.77, High=0.44

**Privileges Required (PR)**:
- Scope Unchanged: None=0.85, Low=0.62, High=0.27
- Scope Changed: None=0.85, Low=0.68, High=0.50

**User Interaction (UI)**: None=0.85, Required=0.62

**Impact (C/I/A)**: None=0.0, Low=0.22, High=0.56

### Formula

```
ISS = 1.0 - ((1 - C) × (1 - I) × (1 - A))

If Scope = Changed:
  Impact = 7.52 × (ISS - 0.029) - 3.25 × ((ISS - 0.02)^15)
  Base = min(1.08 × (Impact + Exploitability), 10.0)

If Scope = Unchanged:
  Impact = 6.42 × ISS
  Base = min(Impact + Exploitability, 10.0)

Exploitability = 8.22 × AV × AC × PR × UI
```

### Severity Ranges

| Rating | Score Range |
|--------|-----------|
| Critical | 9.0 – 10.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |
| None | 0.0 |

### CWE Default CVSS Vectors (15 CWEs)

| CWE | AV | AC | PR | UI | S | C | I | A | Expected Score |
|-----|----|----|----|----|---|---|---|---|---------------|
| CWE-89 (SQL Injection) | N | L | N | N | U | H | H | N | 9.1 |
| CWE-78 (OS Command Inj.) | N | L | N | N | U | H | H | H | 9.8 |
| CWE-79 (XSS) | N | L | N | R | C | L | L | N | 6.1 |
| CWE-22 (Path Traversal) | N | L | N | N | U | H | N | N | 7.5 |
| CWE-502 (Deserialization) | N | L | N | N | U | H | H | H | 9.8 |
| CWE-798 (Hardcoded Creds) | N | L | N | N | U | H | H | H | 9.8 |
| CWE-327 (Broken Crypto) | N | L | N | N | U | H | N | N | 7.5 |
| CWE-94 (Code Injection) | N | L | N | N | U | H | H | H | 9.8 |
| CWE-120 (Buffer Overflow) | N | L | N | N | U | H | H | H | 9.8 |
| CWE-134 (Format String) | N | L | N | N | U | H | H | H | 9.8 |
| CWE-416 (Use After Free) | L | H | L | N | U | H | H | H | 7.0 |
| CWE-611 (XXE) | N | L | N | N | U | H | N | N | 7.5 |
| CWE-90 (LDAP Injection) | N | L | N | N | U | H | H | N | 9.1 |
| CWE-1321 (Prototype Pollution) | N | L | N | N | U | L | L | L | 7.3 |
| Default (Generic) | N | L | N | N | U | L | L | N | 6.5 |

---

## 6. Score Fusion Weights

**Source**: `src/orchestrator/fusion.py`, `configs/cwe_weights.yaml`

### Default Formula

```
fused_score = (α × sast_confidence + β × gat_risk_score + γ × llm_consensus_score) / (α + β + γ)
```

### CWE-Adaptive Weights

| CWE | Category | SAST (α) | GAT (β) | LLM (γ) | Rationale |
|-----|----------|----------|---------|---------|-----------|
| CWE-78 | OS Command Injection | 0.25 | 0.25 | 0.50 | LLM understands shell context |
| CWE-79 | XSS | 0.25 | 0.25 | 0.50 | LLM understands DOM context |
| CWE-89 | SQL Injection | 0.30 | 0.25 | 0.45 | LLM + SAST taint both strong |
| CWE-94 | Code Injection | 0.25 | 0.30 | 0.45 | Graph captures eval patterns |
| CWE-22 | Path Traversal | 0.35 | 0.30 | 0.35 | Balanced — taint + structure |
| CWE-327 | Broken Crypto | 0.50 | 0.20 | 0.30 | SAST pattern detection strong |
| CWE-328 | Weak Hash | 0.50 | 0.20 | 0.30 | SAST pattern detection strong |
| CWE-416 | Use After Free | 0.20 | 0.50 | 0.30 | Graph catches memory flows |
| CWE-476 | NULL Pointer Deref | 0.25 | 0.45 | 0.30 | Graph catches control flow |
| CWE-502 | Deserialization | 0.25 | 0.25 | 0.50 | LLM understands object context |
| CWE-287 | Improper Auth | 0.20 | 0.25 | 0.55 | LLM understands auth semantics |
| CWE-862 | Missing Auth | 0.20 | 0.25 | 0.55 | LLM understands access control |
| CWE-434 | File Upload | 0.30 | 0.25 | 0.45 | LLM understands file handling |
| Default | Unknown CWEs | 0.30 | 0.30 | 0.40 | Balanced with LLM slight edge |

### Classification Thresholds

| Verdict | Fused Score Range |
|---------|-------------------|
| CONFIRMED | >= 0.85 |
| LIKELY | 0.50 – 0.84 |
| POTENTIAL | 0.01 – 0.49 |
| UNKNOWN | 0.0 |

---

## 7. RAG Knowledge Base

**Source**: `src/llm/rag/knowledge_base.py`, `src/llm/rag/nvd_indexer.py`

| Parameter | Value |
|-----------|-------|
| NVD entries indexed | 200,000+ |
| CWE entries indexed | 900+ |
| Semantic search | FAISS (inner product, all-MiniLM-L6-v2 embeddings) |
| Keyword search | BM25 (Okapi BM25) |
| Fusion method | Reciprocal Rank Fusion (k=60) |
| Hybrid weight (semantic) | 0.6 |
| Hybrid weight (keyword) | 0.4 |
| Top-k results | 5 |

---

## 8. Test Suite Coverage

**Source**: `sample_testcases/manifest.yaml`, `tests/`

### Sample Test Cases

| Language | True Positives | False Positives | Total |
|----------|---------------|-----------------|-------|
| Python | 6 | 6 | 12 |
| JavaScript | 6 | 6 | 12 |
| Java | 6 | 6 | 12 |
| C/C++ | 5 | 5 | 10 |
| Go | 5 | 5 | 10 |
| **Total** | **28** | **28** | **56** |

### False Positive Difficulty Tiers

| Tier | Count | Resolution Stage | Example |
|------|-------|-----------------|---------|
| Basic | 10 | SAST (Stage 1) | Parameterized SQL queries |
| Contextual | 9 | Graph (Stage 2) | os.path.realpath validation |
| Adversarial | 9 | LLM (Stage 3) | eval() with regex guard |

### CWE Coverage (13 CWEs)

CWE-22, CWE-78, CWE-79, CWE-89, CWE-90, CWE-94, CWE-95, CWE-120, CWE-134, CWE-416, CWE-502, CWE-611, CWE-798

### Automated Tests

| Category | Count |
|----------|-------|
| Total tests | 287 |
| Unit tests | ~250 (test_sast, test_graph, test_llm, test_orchestrator) |
| Integration tests | ~37 (test_pipeline, end-to-end) |

---

## 9. Cascade Performance (Observed)

**Source**: End-to-end runs on sample_testcases/python/

| Metric | Value |
|--------|-------|
| Total findings (Python) | 24 |
| Resolved at SAST | 18 (75%) |
| Escalated to Graph | 6 (25%) |
| Resolved at Graph | 0 (model not deployed) |
| Escalated to LLM | 6 (25%) |
| LLM-validated | 6 (100% of escalated) |
| CVSS scores produced | Yes (per-finding) |

### CVSS Validation Results

| CWE | Computed Score | Severity | NVD Reference |
|-----|---------------|----------|---------------|
| CWE-89 (SQL Injection) | 9.1 | CRITICAL | Matches NVD typical |
| CWE-79 (XSS) | 6.1 | MEDIUM | Matches NVD typical |
| CWE-78 (OS Command Inj.) | 9.8 | CRITICAL | Matches NVD typical |

---

## 10. Industry Baseline Comparison Numbers

**Source**: `docs/RESEARCH_BRIEF.md`, published literature

| Tool | False Positive Rate | Precision |
|------|-------------------|-----------|
| SonarQube | 94.6% | 5.4% |
| Semgrep | 74.8% | 25.2% |
| CodeQL | 68.2% | 31.8% |
| Industry average (Ghost Security 2025) | 91% | 9% |
| Sec-C target | <15% | >85% |
