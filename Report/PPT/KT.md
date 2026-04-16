# Knowledge Transfer: Multi-Stage Code Security Framework

**A Complete Walkthrough · From Research Inception to Production Deployment**

> **Format note:** This is the full technical KT document (~35 minutes read-aloud pace). A condensed 20-minute "highlights" script is included at the end for the live handoff session. ML and security fundamentals are assumed; everything else is explained from first principles.

> **Purpose:** Bring a new team member from zero knowledge to working competence. The chronological structure is deliberate — every design choice is introduced alongside the problem it solved, so the reader understands *why* the code looks the way it does.

---

## TABLE OF CONTENTS

| # | Section | Read-aloud time |
|---|---|---|
| 1 | The Hook: Why This Project Exists | 1:30 |
| 2 | The Research Journey: How We Got Here | 1:30 |
| 3 | Architecture Overview: The Four Stages | 3:00 |
| 4 | The GNN Deep Dive: V1 through V6 | 6:00 |
| 5 | Conformal Prediction: The Core Innovation | 3:00 |
| 6 | The LLM Stage: Dual-Agent Consensus | 3:00 |
| 7 | CWE-Adaptive Fusion: Why Different Bugs Need Different Tools | 2:00 |
| 8 | Live Evaluation and Results | 3:00 |
| 9 | Engineering Lessons from the Road | 3:00 |
| 10 | Limitations and Future Work | 2:00 |
| 11 | Closing: What to Remember | 1:00 |
| — | 20-Minute Condensed Script | — |

---

## 1. THE HOOK: Why This Project Exists

### The problem, as of April 2026

Application security has a structural arithmetic problem.

- The National Vulnerability Database published **48,448 CVEs in 2025** (up 20% YoY); roughly half were never fully analyzed.
- **Ghost Security's 2025 scan of 3,000+ repositories found 91% of SAST alerts were false positives.** Per-tool rates: CodeQL 68.2%, Semgrep 74.8%, SonarQube 94.6%.
- A typical SOC receives **~4,400 alerts per shift**; analysts can meaningfully investigate 8–12. **62% of alerts are ignored.**
- Cybercrime cost: **~$10.5T globally in 2025** (Cybersecurity Ventures, broad definition).
- Average US data breach cost: **$10.22M** (IBM 2025).

### Why prior work stopped short

Academia tried ML. ICSE 2025's **PrimeVul** study showed models reporting 68% F1 on BigVul dropped to **3.09%** on deduplicated realistic data. **Real-Vul** (IEEE TSE 2024) confirmed: precision drops of up to 95 points.

Industry tried LLMs. **LLM4Vuln** (2024) documented ~90% hallucination rates under their evaluation. **Steenhoek et al.** (2024) measured 47–76% inconsistency across repeated tasks. **Veracode's 2025 GenAI report**: only 12–13% of AI-generated code is secure against XSS.

The surveyed hybrids (IRIS, Vulnhalla, ZeroFalse, LLMxCPG) apply LLMs uniformly to every finding. Nobody decides *when* to escalate.

### Our reframing

Vulnerability detection is not a classification problem. It is a triage problem. Route each finding to the cheapest analysis capable of resolving it confidently. Escalate only when the current stage is measurably uncertain. Everything downstream follows from this.

---

## 2. THE RESEARCH JOURNEY: How We Got Here

### Semester 1 (Aug–Nov 2025): The Foundation

Started with a literature survey: traditional SAST (Fortify, Checkmarx, Coverity), CodeQL's query-based taint analysis, and Yamaguchi et al.'s Code Property Graph paper (2014). Identified five research gaps: no selective escalation, no calibrated uncertainty, no adversarial LLM validation, fixed fusion weights, no free-tier multi-language option.

Phase 1 delivered a working SAST pre-screener: 24 Tree-sitter patterns across 5 languages, CodeQL taint integration, SARIF 2.1.0 output.

### Semester 2 (Jan–Apr 2026): The Build

- **Jan 15–21**: Proposed the three-analysis-stage cascade (SAST → Graph → LLM) with uncertainty-driven escalation. Defined the 4-factor uncertainty score.
- **Jan 22–28**: GNN architecture decision. Started with Mini-GAT; Xu et al. (2019) moved us to GIN.
- **Feb 15–21**: Built CPG construction, conformal prediction layer, GNN training pipeline. V1 and V2 trained.
- **Feb 22**: Key pivot — shifted from research prototype to production CLI tool. Inspired by Claude Code UX. Added Typer, Rich, prompt-toolkit.
- **Mar 1–14**: Dual-agent LLM, consensus engine, hybrid RAG.
- **Mar 15–28**: CVSS v3.1 scoring, HTML dashboard, natural-language explanations. V3 and V4 trained.
- **Apr 1–8**: V5 label-smoothing fix. V6 deployment calibration. Phase 2 report.

### Four aha moments that shaped the design

1. **The uncertainty formula is not a hyperparameter.** Four factors — confidence, complexity, novelty, conflict — with weights 0.4/0.3/0.2/0.1 survived every redesign. They correspond to distinct failure modes of SAST tools.
2. **Conformal prediction changes what the GNN should optimize for.** It does not need to be right; it needs to know when it is sure.
3. **Label smoothing and conformal prediction are mathematically incompatible.** This finding cost three F1 points but unlocked the coverage guarantee.
4. **Offline calibration does not transfer to deployment.** Backward slicing shrinks inference graphs by 83%. Conformal layers require deployment-time recalibration. This is itself a contribution.

---

## 3. ARCHITECTURE OVERVIEW: The Four Stages

### Stage 1 — SAST Pre-Screening (<100 ms)

**Input:** source code. **Output:** findings with uncertainty scores.

Components:
- **Tree-sitter patterns**: 24 hand-crafted AST patterns across 5 languages.
- **CodeQL taint analysis**: optional; when installed, adds inter-procedural data-flow tracking.
- **Uncertainty scorer**: computes $U$ for every finding.
- **Escalation router**: $U \geq 0.5$ escalates to Stage 2; `taint_length > 3` or `interprocedural ∧ CRITICAL` always escalates.

Findings with $U < 0.5$ resolve here with verdict SAFE. On live evaluation: 85% of findings.

### Stage 2 — Graph-Augmented Validation (2–10 s)

**Input:** escalated findings. **Output:** classification + conformal prediction set.

Pipeline:
1. **Joern CPG construction**: unifies AST, CFG, DDG, CDG. When Joern is unavailable, the builder falls back to a Tree-sitter-based approximation (explained in §3.1 below).
2. **Backward slicing**: BFS from the sink, depth ≤ 10; typical 67–91% graph reduction.
3. **Feature extraction**: 768-dim GraphCodeBERT embeddings + 6 structural features → **774-dim** per node.
4. **MiniGINv3 classification**: 3 GIN layers, residual connections, dual pooling → 768-dim graph embedding → classification head + auxiliary confidence head. 2.4M parameters.
5. **APS conformal prediction**: singleton → resolve; ambiguous → escalate.

#### 3.1. Graceful degradation when Joern is missing

When `joern-cli` is not on the system path, the CPG builder emits a warning and constructs an approximate graph from Tree-sitter AST only. You **lose**: inter-procedural call edges (CALL / REACHING_DEF), data-dependency edges (DDG) derived from Joern's solver, and control-dependency edges (CDG). You **keep**: AST structure, local control-flow edges, and statement-level node types. The GNN still runs, but its input is structurally poorer. In testing, degraded-mode F1 drops roughly 8–12 absolute points. The framework treats Joern as strongly recommended but not required.

### Stage 3 — LLM Dual-Agent Validation (5–15 s)

**Input:** ambiguous findings. **Output:** structured verdict + CVSS.

Flow: RAG retrieval → prompt assembly (CWE-specific templates, three tiers by $U$) → parallel attacker/defender dispatch → consensus engine (5 rules) → CVSS v3.1 computation.

### Stage 4 — CWE-Adaptive Fusion (<1 ms)

$$S_{\text{fused}} = \alpha \cdot S_{\text{SAST}} + \beta \cdot S_{\text{Graph}} + \gamma \cdot S_{\text{LLM}}$$

Weights are configured per CWE category. Classification thresholds: CONFIRMED ≥ 0.85, LIKELY ≥ 0.50, POTENTIAL < 0.50.

Output formats: SARIF 2.1.0 for CI/CD, interactive HTML dashboard, console tables.

---

## 4. THE GNN DEEP DIVE: V1 through V6

This is the longest section because the GNN story carries the most technical density and the most instructive lessons.

### 4.1. The V2-to-V3 feature-vector transition

Before walking through the versions, one table that reconciles a common confusion: the input dimension changed from 773 to 774 between V2 and V3. Here is what changed:

| | V2 (GAT) | V3+ (GIN) |
|---|---|---|
| Architecture | 2-layer GAT, 4 heads | 3-layer GIN |
| GraphCodeBERT dim | 768 | 768 |
| Structural features | 5: in_deg_norm, out_deg_norm, is_sink, is_source, depth_norm | 6: + `language_id` |
| **Total input dim** | **773** | **774** |
| Parameters | 298K | 2,375,046 |

The `language_id` feature was added in V3 when the corpus expanded beyond C/C++ dominance. The file is named `src/graph/gnn/mini_gat.py` for git-history continuity; the class inside is `MiniGINv3`. Do not be surprised by the filename.

### 4.2. V1 — Juliet Baseline (March 2026)

- **Dataset**: Juliet Test Suite only. ~1,500 synthetic C/C++ samples.
- **Architecture**: Mini-GAT (2-layer, 4-head attention, 256 → 128 dims).
- **Result**: F1 = 0.9999.
- **Interpretation**: Juliet is templated synthetic code. 99.99% F1 is textbook memorization. We discarded V1 without further evaluation; the number was a warning.

**Lesson one:** synthetic data is a tutorial, not a validation set.

### 4.3. V2 — GAT Multi-Language Baseline

- **Dataset**: ~1,700 multi-source samples.
- **Architecture**: Mini-GAT. 298K parameters. 773-dim input.
- **Hyperparameters**: Focal loss ($\gamma=2$) + class weights (vulnerable × 2.0), LR 1e-3, batch 64.
- **Result**: F1 = 0.560, Precision 0.397, Recall 0.951, AUC 0.744.

**Diagnosis:** The model predicted almost everything as vulnerable. Two causes:
1. **Focal loss + class weights stacked**: both mechanisms down-weight easy negatives; stacking over-suppressed the safe-class gradient.
2. **GAT's weighted-mean aggregation is not injective.** Xu et al. (2019, ICLR) proved it cannot distinguish structurally distinct neighborhoods. Code graphs often differ by a single missing bounds check (one fewer edge) — exactly the pattern GAT conflates.

**Decision:** switch the architecture and simplify the loss.

### 4.4. V3 — The GIN Architectural Shift

- **Dataset**: 3,032 graphs (1,819 training).
- **Architecture**: MiniGINv3. 3-layer GIN with MLP(384 → 768 → 384) per layer, residual connections, BatchNorm, dropout 0.4, dual pooling → 768-dim → classification head. 2.4M parameters.
- **Input dim**: 774 (768 CodeBERT + 6 structural).
- **Loss**: CrossEntropy + label smoothing 0.1.
- **Result**: F1 = 0.653 (+17% absolute over V2), AUC = 0.623, Conformal singletons = 0.22%.

**What GIN gains:** sum aggregation is provably injective, as expressive as 1-Weisfeiler-Leman. For code graphs where a missing bounds check or a missing validation is a missing edge, injectivity preserves the distinction.

**What V3 still lacked:** a configuration bug capped per-language training data at 3,000 samples, silently discarding 20,000 available C/C++ samples. We spent a week tuning regularization before finding the one-line fix.

### 4.5. V4 — The Dataset Expansion Breakthrough

- **Config change**: `max_per_language` from 3,000 to 20,000.
- **Dataset**: 20,753 graphs (12,452 training); sources: BigVul (5,777), DiverseVul (4,935), Juliet-C (3,611), CrossVul (3,428), Devign (3,002). 7× increase over V3.
- **Architecture**: unchanged from V3.
- **Hyperparameter adjustments**: dropout 0.4 → 0.35, patience 25 → 20.
- **Result**: **F1 = 0.781**, AUC = 0.826, Precision = 0.675, Recall = 0.926.
- **Per-CWE highlights**:
  - CWE-476 (Null Pointer Dereference): 0.926
  - CWE-787 (Out-of-Bounds Write): 0.895
  - CWE-416 (Use After Free): 0.872
  - CWE-362 (Race Condition): 0.800

+20% absolute F1 from data scale alone. But conformal singletons remained 0% — the classifier was converging; the uncertainty estimator was not. The story of *why* is in §4.6, and it also explains why V3's rate of 0.22% collapsed further to 0% at V4: V4's better-calibrated softmax pushed more calibration samples into the compressed-band regime where APS cannot produce singletons. Higher accuracy made the conformal pathology worse.

### 4.6. V5 — The Conformal Breakthrough

**The diagnosis.** Label smoothing 0.1 compresses softmax outputs into a narrow [0.5, 0.6] band. At 74% accuracy, 26% of calibration samples are misranked. For $\alpha = 0.1$ (90% coverage target), the 90th-percentile quantile must hit 1.0, making the condition `cumsum ≥ 1.0` unreachable for binary softmax. Hence 0% singletons.

**The fix.**
1. **Remove label smoothing.** Hard labels `[1, 0]` / `[0, 1]` allow wide logit gaps.
2. **Add Conformal Temperature Scaling (ConfTS)** (Dabah et al. 2024). Post-hoc temperature optimized not for NLL (Guo et al. 2017) but for minimum APS set size subject to coverage ≥ 90%.
3. **Grid search** $T \in [0.05, 3.0]$ over 75 candidates on the validation split. Selected $T = 0.10$ (92.0% coverage, 53.7% singletons on validation).

**Result:**
- **Dataset**: 21,150 graphs (12,689 training). **V5 = V4 + 222 VUDENC + 175 CVEfixes = 20,753 + 222 + 175 = 21,150.** Both Python loaders were fixed in V5 (VUDENC and CVEfixes store labels as lists, not scalars); this unlocked 397 additional Python samples.
- **F1 = 0.750**, AUC = 0.781, Python F1 = 0.836.
- **Conformal offline**: 69.1% singletons (calibration), 67.7% singletons (test), 84.3% coverage (test).

The 3-point F1 drop from V4 was a deliberate trade: we accept slightly worse classification in exchange for the model producing decisive outputs that APS can use. This is the thesis in a single design decision.

### 4.7. V6 — Deployment Calibration (A Contribution, Not a Bug-Fix)

The most honest finding of the entire project: offline singletons of 69.1% dropped to roughly 2% at deployment. We documented three root causes and three corresponding engineering adjustments, and we treat this lesson as one of the contributions.

**Root cause 1 — backward slicing creates distribution shift.**
Training used 10–300 node function graphs; the live cascade passes backward-sliced subgraphs of 1–6 nodes. The GNN's structural features (degree, depth) have radically different statistics on a 4-node slice than on a 200-node function. Conformal calibration performed offline on full graphs does not transfer.
**Adjustment:** pass the full CPG (with `max_nodes = 300` as a safety bound) instead of the backward-sliced subgraph.

**Root cause 2 — $T = 0.10$ eliminated the natural uncertainty signal.**
Aggressive sharpening made every prediction near-binary. Every output became a singleton regardless of true confidence. The cascade needs ambiguous predictions to route findings to the LLM; $T = 0.10$ collapsed that signal.
**Adjustment:** $T = 0.95$ (mild sharpening) preserves the natural uncertainty distribution.

**Root cause 3 — threshold = 1.0 is mathematically unreachable for binary softmax.**
For finite logits, $P(\text{top class}) < 1.0$ strictly. The condition `cumsum ≥ 1.0` can only satisfy via floating-point overflow, not by actual confidence.
**Adjustment:** threshold = 0.95 is a principled confidence gate (singletons require ≥ 95% model confidence).

**What V6 gave us.** On 15 live repositories, 184 findings: SAST 157 (85%), GNN 4 (2%), LLM 23 (13%), unresolved 0. At deployment, the conformal layer operates as a **conservative escalation gate** rather than a primary resolution mechanism. The cascade absorbs this outcome gracefully: Stage 3 handles what Stage 2 does not route as singletons, and Stage 1 already caught the easy cases. We now view conformal calibration as a deployment-time activity, not a one-time training artifact. Documenting this shift is itself a contribution.

### 4.8. What to remember from the GNN story

Every version fixed one thing and uncovered the next. Architecture (V2 → V3). Data (V3 → V4). Calibration (V4 → V5). Deployment (V5 → V6). The thesis is not V4's 0.781 F1; it is the demonstration that a principled cascade can operate on imperfect components and still deliver the economic and architectural benefits.

---

## 5. CONFORMAL PREDICTION: The Core Innovation

### The idea in plain language

Every binary classifier outputs a softmax score. You choose a threshold. Below it, predict safe; above it, predict vulnerable. The threshold is arbitrary. The model might be 51% confident on one sample and 99% confident on another; the threshold treats them identically.

Conformal prediction replaces the single threshold with a **prediction set**. One label → model is confident. Two labels → model is uncertain. The set is produced with a mathematical coverage guarantee: the true label lies in the set with probability at least $1 - \alpha$. The guarantee holds **under the exchangeability assumption** between calibration and test data, with no parametric assumptions beyond that.

### The APS algorithm

**Calibration.** For each calibration sample $i$:
1. Compute softmax $\pi_i$.
2. Sort classes in descending order of $\pi$.
3. Compute cumulative sum.
4. Nonconformity score $s_i$ = cumulative sum at the position where the true label appears.

**Quantile.** $\hat{q} = \text{Quantile}(\{s_i\}, \lceil (n+1)(1-\alpha) \rceil / n)$, method = "higher", clamped to 1.0.

**Inference.** For a new sample: compute softmax, sort, include classes greedily until cumulative sum ≥ $\hat{q}$.

**Guarantee.** $P(y_{\text{true}} \in C(X)) \geq 1 - \alpha$ under exchangeability.

### Why it is the first application to vulnerability detection

No prior system in this domain provides a coverage guarantee. CodeQL says "severity: high"; you trust or don't. A GNN says "0.73 vulnerable"; you threshold at 0.5. These are heuristics. APS replaces them with a theorem, conditional on a stated assumption.

### The label smoothing discovery in depth

Label smoothing targets `[0.933, 0.067]` instead of `[1, 0]`. The optimizer minimizes cross-entropy toward soft targets. The model's logits stabilize around values producing softmax outputs near the smoothed targets. Logit gaps stay small. Softmax outputs stay compressed.

For APS this is fatal. The model may be correct 74% of the time, but nonconformity scores cluster around 0.55 for correct predictions and 1.0 for wrong ones. Since 26% of calibration samples are wrong (score 1.0), the 90th-percentile quantile lands at 1.0. Binary softmax cannot reach 1.0 exactly, so no prediction ever triggers a singleton.

The fix: accept slightly worse classification (F1 0.781 → 0.750) for decisive outputs. This is design alignment between the training objective and the calibration objective.

### ConfTS and the deployment gap

Guo et al. (2017) introduced temperature scaling to fix overconfident networks; their method optimizes $T$ for NLL, typically yielding $T > 1$ (softening). Our model had the opposite problem — underconfidence. ConfTS (Dabah et al. 2024) optimizes $T$ to minimize mean APS set size subject to coverage, which finds $T < 1$ (sharpening) for underconfident models.

Grid search: $T = 0.10$ on validation (92% coverage, 54% singletons). Deployed at $T = 0.95$ after discovering that aggressive sharpening destroyed the uncertainty signal in live inference. The 0.10-to-0.95 adjustment is not a retreat; it is a documented finding that conformal calibration is deployment-conditional.

---

## 6. THE LLM STAGE: Dual-Agent Consensus

### The problem with single-model LLM inference

Ask an LLM "is this code vulnerable?" The answer depends on prompt framing. Prompt it as a security auditor, it finds bugs everywhere. Prompt it as a code reviewer, it finds few. The model is not lying; it is pattern-completing the prompt. Steenhoek et al. measured 47–76% inconsistency.

### The solution: opposing perspectives

**Attacker agent** (red team system prompt): "Your job is to construct an exploit. If you cannot build one, the finding is a false positive." Outputs:
- `exploitable: bool`
- `payload: str | None`
- `execution_trace: list[str]`
- `confidence: float`
- CVSS exploitability metrics: **AV** (Attack Vector), **AC** (Attack Complexity), **PR** (Privileges Required), **UI** (User Interaction)

**Defender agent** (blue team system prompt): "Your job is to find every protection: sanitizers, access controls, framework safeguards." Outputs:
- `sanitizers_found: list[dict]`
- `defense_coverage_score: float` in [0, 1]
- `path_feasible: bool`
- CVSS impact metrics: **S** (Scope), **C** (Confidentiality), **I** (Integrity), **A** (Availability)

Both see the same finding, the same code context, the same RAG-retrieved CVE/CWE documentation.

### The five consensus rules

| Rule | Condition | Verdict | Confidence |
|---|---|---|---|
| R1 | exploitable ∧ coverage < 0.5 | CONFIRMED | $\max(c_{\text{atk}}, 1 - d_{\text{cov}})$ |
| R2 | ¬exploitable ∧ coverage > 0.7 | SAFE | $\max(d_{\text{cov}}, 1 - c_{\text{atk}})$ |
| R2b | ¬exploitable ∧ path infeasible | SAFE | 0.8 (fixed) |
| R3 | exploitable ∧ coverage ≥ 0.5 | LIKELY | $0.5 + 0.3(c_{\text{atk}} - d_{\text{cov}})$, clamped [0.3, 0.85] |
| R4 | ¬exploitable ∧ coverage ≤ 0.7 | POTENTIAL | $0.4 + 0.2(1 - d_{\text{cov}})$, clamped [0.2, 0.6] |

The rules encode a security-engineering truth: a finding is confirmed when an attacker can succeed and defenders cannot cover the attack; it is safe when defenders clearly cover or the path is infeasible; everything else is graded uncertainty.

### RAG grounding

Both agents receive the same top-5 NVD/CWE documents, fetched via hybrid retrieval:
- **FAISS** semantic index (`all-MiniLM-L6-v2`, weight 0.6)
- **BM25** keyword index (weight 0.4)
- **Reciprocal Rank Fusion** with $k = 60$: $\text{RRF}(d) = \sum_r \frac{w_r}{k + \text{rank}_r(d)}$

Shared context is the anti-hallucination mechanism. An agent cannot invent a CVE; retrieved documents constrain what it can reference.

### CVSS v3.1 scoring

From combined sub-metrics:
$$\text{ISS} = 1 - (1-C)(1-I)(1-A)$$
$$\text{Impact}_{\text{unchanged}} = 6.42 \cdot \text{ISS}$$
$$\text{Impact}_{\text{changed}} = 7.52(\text{ISS} - 0.029) - 3.25(\text{ISS} - 0.02)^{15}$$
$$\text{Exploitability} = 8.22 \cdot AV \cdot AC \cdot PR \cdot UI$$
$$\text{Base Score} = \text{roundup}(\min(\text{Impact} + \text{Exploitability}, 10))$$

Default CVSS vectors exist for 14 common CWEs for findings resolved before Stage 3.

---

## 7. CWE-ADAPTIVE FUSION: Why Different Bugs Need Different Tools

Different vulnerability types have different detection profiles. Injection vulnerabilities depend on semantic context (is the input parameterized? is it HTML-escaped?), so LLMs shine. Cryptographic weaknesses are pattern-detectable (MD5, SHA1, DES); SAST shines, and Veracode reports LLMs miss 77–84% of them. Memory safety issues live in control-flow structure; graph analysis shines.

Per-CWE weight profiles encode this empirical knowledge:

| CWE Family | Examples | $\alpha$ (SAST) | $\beta$ (GIN) | $\gamma$ (LLM) | Dominant |
|---|---|---|---|---|---|
| Injection | CWE-78, 79, 89, 94 | 0.25 | 0.25 | **0.50** | LLM |
| Crypto | CWE-327, 328 | **0.50** | 0.20 | 0.30 | SAST |
| Memory | CWE-416, 476 | 0.20 | **0.50** | 0.30 | Graph |
| Auth | CWE-287, 862 | 0.20 | 0.25 | **0.55** | LLM |
| Path | CWE-22, 434 | 0.35 | 0.30 | 0.35 | Balanced |
| Default | — | 0.30 | 0.30 | 0.40 | Balanced |

Fusion formula: $S_{\text{fused}} = \alpha \cdot S_{\text{SAST}} + \beta \cdot S_{\text{GIN}} + \gamma \cdot S_{\text{LLM}}$.

Classification thresholds: CONFIRMED ≥ 0.85, LIKELY ≥ 0.50, POTENTIAL < 0.50.

The weights are configured from domain expertise and published modality strengths, not empirically calibrated. Bayesian optimization over labeled data is the next step.

---

## 8. LIVE EVALUATION AND RESULTS

### The setup

15 open-source repositories spanning Python, JavaScript, Java, C/C++, Go. 184 findings total. Hardware: consumer i5-12400, 16 GB RAM. GNN training on Google Colab T4 GPU (free tier).

### Cascade resolution

```
SAST      157 findings   (85%)   resolved in <100 ms each
Graph       4 findings   ( 2%)   singleton conformal outputs
LLM        23 findings   (13%)   dual-agent consensus applied
Unresolved  0 findings   ( 0%)
```

Every finding received a verdict. 87.5% fewer LLM API calls than a uniform full-LLM approach.

**What this evaluation measures:** triage efficiency (what fraction resolves at each stage). **What it does not measure:** detection precision/recall on the full cascade, because the 184 findings were not ground-truth labeled. That measurement is priority one in future work.

### Cost analysis

| Approach | API calls | Cost (Gemini 2.5 Pro paid tier) | Time |
|---|---|---|---|
| Full-LLM | 184 | ~$10–40 | ~30 min |
| Our cascade | 23 | ~$0.50–2.00 | ~5 min LLM work |

On the free tier, the comparison is about rate-limit survivability: the cascade reliably completes under 15 RPM / 500 RPD caps where a uniform approach throttles. Either way, the architecture is robust to component performance: even if the GNN resolved zero findings, SAST alone would still save 85%.

### GNN classification metrics

| Metric | V2 | V3 | V4 | V5 |
|---|---|---|---|---|
| F1 | 0.560 | 0.653 | **0.781** | 0.750 |
| Precision | 0.397 | 0.544 | 0.675 | 0.643 |
| Recall | 0.951 | 0.815 | 0.926 | 0.899 |
| AUC-ROC | 0.744 | 0.623 | **0.826** | 0.781 |

V4 represents peak classification. V5 trades 3 F1 points for a functional conformal layer.

### Per-CWE (V4)

| CWE | F1 |
|---|---|
| CWE-476 Null Pointer Dereference | 0.926 |
| CWE-787 Out-of-Bounds Write | 0.895 |
| CWE-416 Use After Free | 0.872 |
| CWE-362 Race Condition | 0.800 |

Memory safety consistently above 0.87 — validating the graph-heavy fusion weight profile for that category.

### Conformal prediction

| Configuration | Singleton % | Coverage |
|---|---|---|
| V2 (α = 0.3, T = 1.0) | 0% | — |
| V3 (α = 0.2, T = 1.0) | 0.22% | — |
| V4 (α = 0.1, T = 1.0) | 0% | — |
| V5 offline (α = 0.1, T = 0.10) | 69.1% cal / 67.7% test | 86.4% / 84.3% |
| V6 deployed (α = 0.1, T = 0.95, thr = 0.95) | ~2% live | conservative routing |

### Research question outcomes (honest framing)

- **RQ1** (uncertainty reduces escalation): answered. 85% Stage-1 resolution on 184 live findings.
- **RQ2** (conformal provides meaningful uncertainty): answered. 69.1% offline singletons; functional deployment routing, with documented distribution-shift lessons.
- **RQ3** (dual-agent outperforms single-LLM): **architecturally validated through live integration**. Isolated ablation comparing single-agent and dual-agent configurations is scoped as the immediate next empirical step.
- **RQ4** (CWE-adaptive beats fixed fusion): **architecturally validated** via application to every live finding. Empirical calibration via Bayesian optimization is scoped as the immediate next step.
- **RQ5** (cascade improves cost-accuracy): answered on cost (87.5% LLM reduction); accuracy side awaits ground-truth labeling and OWASP Benchmark evaluation.

---

## 9. ENGINEERING LESSONS FROM THE ROAD

A fair handoff must record the instructive decisions honestly. The following five moments shaped the final architecture; future contributors should read them before re-treading the same paths.

### 9.1. The synthetic-data trap (V1)

99.99% F1 on Juliet. We threw it away before anyone could celebrate. Synthetic benchmarks are tutorials, not validations. **Rule:** always include realistic out-of-distribution data in every evaluation pipeline, from day one.

### 9.2. The focal-loss interaction (V2)

Focal loss is designed for class imbalance; class weights do the same thing. Stacking both mechanisms over-suppresses the safe-class gradient. The model collapsed to 95% recall, 40% precision. **Rule:** do not compose imbalance-handling mechanisms. Pick one and tune.

### 9.3. The one-line config that cost a week (V3)

`max_per_language: 3000` in a YAML. Silently capped C/C++ at 3K despite 23K samples available. A week of tuning regularization, learning rates, and model capacity yielded nothing. The fix was one line. **Rule:** audit what fraction of your data actually reaches training. Log sample counts at every pipeline stage.

### 9.4. The label-smoothing lesson (V4 → V5)

The subtlest lesson in the project. Label smoothing helps classification metrics by preventing logit overconfidence. It breaks conformal prediction by compressing the logit gap conformal needs to rank predictions. Three days to diagnose, one line to fix, three F1 points to pay. **Rule:** when your calibration layer disagrees with your classification metric, the training objective and the calibration objective are misaligned.

### 9.5. The deployment recalibration lesson (V5 → V6)

Offline 69% singletons became live 2% singletons. We nearly published the offline number. The live evaluation caught the gap. Three fixes: full CPG instead of backward slice (distribution alignment), $T = 0.95$ instead of $T = 0.10$ (uncertainty preservation), threshold 0.95 instead of 1.0 (mathematical achievability). The cascade still works because Stage 3 absorbs what Stage 2 does not route. **Rule:** conformal calibration is a deployment-time activity, not a one-time training artifact. Live telemetry is the only honest calibration signal.

---

## 10. LIMITATIONS AND FUTURE WORK

### What is verified

- 85% of findings resolve at Stage 1 in under 100 ms on the live evaluation set.
- The GNN achieves F1 = 0.781 at peak (V4) and F1 = 0.750 with the conformal layer enabled (V5).
- The live cascade handles 184 findings across 15 repositories, 5 languages, with 100% resolution and 87.5% LLM-call savings.
- The framework is free-tier operable, multi-language, and degrades gracefully when any component is unavailable.

### What requires qualification

- **Training bias.** 94.6% of training data is C/C++. Python F1 = 0.836 rests on ~60 test samples. JavaScript, Java, and Go evaluations have fewer than 30 test samples each. Cross-language claims are preliminary.
- **Coverage guarantee.** Offline test coverage is 84.3%, approaching the 90% theoretical target. The exchangeability assumption underlying the guarantee relaxes when inference-time graph distribution differs from calibration-time distribution. We disclose this openly.
- **RQ3/RQ4.** Dual-agent consensus and CWE-adaptive fusion were validated through integration in the live cascade. Isolated ablations are scoped as immediate next experiments.
- **No ground-truth labels on the 184 live findings.** We measure triage efficiency on this set, not detection precision. The 56-case curated test suite remains available for labeled evaluation and is the bridge to the OWASP Benchmark study.
- **No OWASP Benchmark v1.2 evaluation yet.** The standard 2,740-case SAST benchmark is the priority external validity test.

### The six planned next steps

1. **Cross-validated ConfTS** with 5-fold temperature search to close the coverage gap.
2. **PrimeVul integration** — resolve the HuggingFace loader issue, add ~8K deduplicated samples.
3. **OWASP Benchmark v1.2** head-to-head with commercial tools.
4. **Bayesian optimization** of CWE fusion weights over labeled data.
5. **DAST integration** as optional Stage 5 for runtime exploit confirmation.
6. **IDE extensions** (VS Code, JetBrains) for real-time SAST annotations.

---

## 11. CLOSING: What to Remember

### The five things that matter most

1. **Triage is the right frame.** Classification asks "is this vulnerable?" Triage asks "do we know enough?" The cascade is the answer to the second question.
2. **Uncertainty is a first-class signal.** The four-factor score (confidence, complexity, novelty, conflict) with weights 0.4/0.3/0.2/0.1 is the routing primitive. Every stage feeds back into it.
3. **Conformal prediction is the trust mechanism.** It lets the GNN say "I don't know" in a mathematically rigorous way, and the framework documents when those assumptions transfer to deployment and when they do not.
4. **Adversarial agents beat single-model inference.** The attacker/defender protocol with five consensus rules is deterministic even when the LLMs are not.
5. **The cascade is robust to component failure.** 85% resolution at Stage 1 means the economic case holds even if later stages degrade.

### Entry points for a new contributor

- `src/sast/uncertainty/scorer.py` — the four-factor formula
- `src/sast/router.py` — the escalation rules
- `src/graph/gnn/mini_gat.py` — the `MiniGINv3` class (filename legacy; architecture is GIN)
- `src/graph/uncertainty/conformal.py` — APS calibration and inference
- `src/llm/consensus/engine.py` — the five consensus rules
- `src/llm/agents/attacker.py` / `defender.py` — the dual-agent prompts
- `src/orchestrator/fusion.py` — CWE-adaptive fusion
- `configs/default.yaml` — every threshold, every weight
- `configs/cwe_weights.yaml` — the 14 fusion profiles
- `docs/GNN_History/` — the full training history for the receipts

### One last thing

When you read the code, notice the pattern: every module has a configuration, a Pydantic data model, and a clean interface. This was deliberate. A framework that runs in research mode and production mode must be configurable without being fragile. Inherit the discipline.

---

## APPENDIX A — Key Numbers at a Glance

| Category | Value |
|---|---|
| Uncertainty weights | 0.4 / 0.3 / 0.2 / 0.1 |
| Escalation threshold | $U \geq 0.5$ |
| Severity adjustments | +0.15 CRITICAL, +0.10 HIGH, 0 MED, −0.05 LOW |
| GNN input dimension | 774 (768 GraphCodeBERT + 6 structural) |
| GNN architecture | MiniGINv3, 3 GIN layers, 2.4M parameters |
| Conformal $\alpha$ | 0.1 (90% coverage target) |
| ConfTS temperature (deployed) | 0.95 |
| Conformal threshold (deployed) | 0.95 |
| V4 peak F1 / AUC | 0.781 / 0.826 |
| V5 deployed F1 / AUC | 0.750 / 0.781 |
| V5 offline singletons | 69.1% (cal), 67.7% (test) |
| V6 live singletons | ~2% (conservative routing) |
| Live cascade distribution | 85% / 2% / 13% / 0% |
| LLM cost reduction (paid tier) | 87.5% |
| Cost per scan (paid Gemini 2.5 Pro) | $0.50–$2.00 vs $10–$40 |
| Free-tier caps | 15 RPM / 500 RPD (Gemini 2.5 Flash) |
| Dataset total | 21,150 graphs, 12,689 training |
| Consensus thresholds | 0.5 (confirmed), 0.7 (safe), 0.8 (infeasible) |
| Fusion defaults | 0.30 SAST / 0.30 Graph / 0.40 LLM |
| Classification thresholds | ≥ 0.85 CONFIRMED, ≥ 0.50 LIKELY |
| RAG weights | 0.6 FAISS / 0.4 BM25, RRF k = 60 |
| Knowledge base | 200,000+ NVD entries, 900+ CWE entries |

---

## APPENDIX B — 20-Minute Condensed Script

For the live handoff session, read this script at a natural pace. It hits the top 12 concepts in 20 minutes and points to the full document for depth.

### 0:00–2:00 · **Framing (2 min)**

"The field has been treating vulnerability detection as a classification problem. We argue it should be treated as a triage problem. Route each finding to the cheapest analysis that can resolve it. Escalate only when uncertain. That single reframe organizes the rest of the framework."

### 2:00–4:00 · **The Four Stages (2 min)**

"Stage 1 is SAST: tree-sitter patterns plus CodeQL taint, producing findings with uncertainty scores. Stage 2 is a Joern CPG plus a MiniGIN classifier wrapped in conformal prediction. Stage 3 is a dual-agent LLM with RAG. Stage 4 fuses with CWE-adaptive weights. A finding escalates only when the current stage cannot resolve it."

### 4:00–7:00 · **The GNN Story (3 min)**

"V1 on Juliet scored 99.99% F1. We threw it away. V2 was a GAT with degenerate precision. V3 switched to GIN for injective aggregation and gained 17 F1 points. V4 removed a one-line config cap on training data and gained another 20. V5 removed label smoothing, losing 3 F1 points to gain a functional conformal layer. V6 is the deployed configuration with live calibration."

### 7:00–10:00 · **Conformal Prediction (3 min)**

"Conformal prediction gives a coverage guarantee: the true label lies in the prediction set with probability at least 1 minus alpha, under exchangeability. We use APS with alpha = 0.1. Singletons resolve at Stage 2; ambiguous sets escalate. Our discovery was that label smoothing compresses the logits conformal needs; removing it unlocked the guarantee."

### 10:00–12:00 · **The Deployment Lesson (2 min)**

"Offline we had 69% singletons. Live we had 2%. Three causes: backward slicing shrinks graphs 83%, T = 0.10 kills natural uncertainty, and threshold = 1.0 is unreachable for binary softmax. We now view conformal calibration as deployment-conditional. The cascade handles the low live singleton rate by design: Stage 3 absorbs what Stage 2 does not route."

### 12:00–14:00 · **The LLM Stage (2 min)**

"Single-LLM inference is sensitive to prompt framing. We use two agents with adversarial objectives. An attacker tries to build an exploit; a defender catalogs sanitizers. Both see the same RAG context from 200,000 CVEs. Five deterministic consensus rules reconcile them. This is the red-team/blue-team pattern from security operations, applied to automated triage."

### 14:00–15:30 · **CWE-Adaptive Fusion (1.5 min)**

"Different vulnerabilities respond to different tools. Injection wants LLMs. Crypto wants SAST. Memory safety wants graphs. Fourteen per-CWE weight profiles encode this. The weights are expert-configured; empirical calibration is the next step."

### 15:30–17:30 · **Live Results (2 min)**

"Fifteen repositories, five languages, 184 findings. SAST resolved 85%, GNN 2%, LLM 13%, zero unresolved. 87.5% fewer API calls than a uniform approach. Peak GNN F1 of 0.781 on realistic multi-language data. Memory safety CWEs above 0.87 F1, validating the graph-heavy fusion for that family."

### 17:30–19:00 · **Honest Limitations (1.5 min)**

"Training is 94.6% C/C++. Python and Go evaluations are preliminary. Offline conformal coverage is 84%, short of the 90% target. RQ3 and RQ4 are architecturally validated, not ablated. No ground-truth labels on the 184 live findings. These are the next experiments, not hidden flaws."

### 19:00–20:00 · **Entry Points (1 min)**

"Read `scorer.py` for the uncertainty formula, `mini_gat.py` for the GIN (yes, the filename is legacy), `conformal.py` for APS, `engine.py` for the consensus rules. `configs/default.yaml` holds every threshold. `docs/GNN_History/` has the full training record. Start there."

---

*End of knowledge transfer document. Main walkthrough (sections 1–11) reads in approximately 35 minutes at a natural pace. The condensed 20-minute script in Appendix B is the one to use for the live handoff session.*
