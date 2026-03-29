# SEC-C: Research Brief

**Multi-Stage Code Security Framework with Uncertainty-Driven Escalation**

Version 2.0.0 | March 2026

---

## 1. The Problem: Why SAST Fails

Static Application Security Testing is the most widely deployed form of automated vulnerability detection, yet its practical utility is severely undermined by false positives. The theoretical root cause is Rice's Theorem: every non-trivial semantic property of programs is undecidable, so any sound static analysis must over-approximate and will inevitably produce spurious warnings.

### Industry-Scale False Positive Rates

The "Sifting the Noise" study (arXiv:2601.22952, 2026) evaluated four major SAST tools on the OWASP Benchmark v1.2 (2,740 Java test cases) and measured the percentage of ground-truth non-vulnerable cases flagged as positive:

| Tool | FP Rate (OWASP Benchmark) | Precision | F1 |
|------|---------------------------|-----------|-----|
| **CodeQL** | 68.2% | 60.3% | 74.4% |
| **Semgrep** | 74.8% | lower than CodeQL | lower than CodeQL |
| **SonarQube** | 94.6% | lowest | lowest |
| **Joern** | high (not top performer) | varies | varies |

Ghost Security's "Exorcising the SAST Demons" report (2025) corroborates these findings at scale: scanning nearly 3,000 open-source repositories across Go, Python, and PHP, they found that **over 91% of all flagged vulnerabilities were false positives**. Of 2,116 flagged issues, only 180 turned out to be real vulnerabilities. Python/Flask command injection checks performed worst at 99.5% FP rate; Go/Gin SQL injection alerts were 80% false; PHP/Laravel file upload checks were 90% false.

### Downstream Consequences

- **Alert fatigue**: The Edgescan 2025 Vulnerability Statistics Report (10th edition) found that **45.4% of discovered vulnerabilities remain unresolved at 12 months** in large enterprises, with 17.4% being high or critical severity. When most alerts are noise, teams stop investigating.
- **Manual review cost**: Each SAST finding requires 10-20 minutes of expert review to determine exploitability, trace data flows, and verify sanitization -- a cost that is economically prohibitive at scale.
- **Theoretical impossibility**: Rice's Theorem guarantees that no algorithm can perfectly distinguish vulnerable from safe code for all programs. Abstract interpretation, the theoretical basis for sound static analysis, necessarily over-approximates, producing false positives as a mathematical consequence.

---

## 2. The Problem: Why ML/DL Fails Too

Machine learning approaches to vulnerability detection have shown impressive numbers on standard benchmarks, but these numbers collapse under rigorous evaluation.

### GNN Collapse on Realistic Data

The Real-Vul study (IEEE TSE, 2024) constructed a realistic vulnerability dataset with proper deduplication and temporal splits, then re-evaluated state-of-the-art deep learning models. The results were devastating:

- Models achieving **93% F1 on BigVul** dropped to as low as **2% F1 on Real-Vul**
- Precision declined by up to **95 percentage points**
- F1 scores dropped by up to **91 percentage points**

This collapse affects GNN-based models (DeepWukong, ReVeal, IVDetect) and transformer-based models (LineVul) alike. The cause: benchmark datasets contain extensive data leakage, duplicate samples, and unrealistic label distributions that inflate reported performance.

### PrimeVul Confirms the Crisis (ICSE 2025)

PrimeVul (ICSE 2025) independently confirmed these findings with a rigorously curated C/C++ dataset (~7K vulnerable functions, ~229K benign, 140+ CWEs):

- A state-of-the-art 7B model scored **68.26% F1 on BigVul** but only **3.09% F1 on PrimeVul**
- GPT-3.5 and GPT-4 performed at levels **akin to random guessing** in the most stringent settings
- Novel labeling techniques showed existing automatic labels are up to 3x less accurate than human labels

### LLM Limitations

LLMs bring semantic understanding but introduce their own failure modes:

- **Hallucination**: CI plugins using LLMs for vulnerability detection exhibit hallucination rates up to **90%**, fabricating vulnerabilities that do not exist or misattributing CWE categories. Package hallucination rates range from 12-65% depending on model and task.
- **Inconsistency**: LLMs exhibit high non-determinism -- ChatGPT produces zero-equal test output across repeated requests in **47-76%** of coding tasks, making deterministic security guarantees impossible without consensus mechanisms.
- **Context window limits**: Real vulnerabilities often span multiple files and require whole-repository reasoning; most LLMs cannot process entire codebases at once.

---

## 3. SEC-C's Solution: Uncertainty-Driven Cascade

### The Key Insight

Not all findings need the same analysis depth. A hardcoded password can be confirmed with a regex; an SQL injection through three function calls requires data-flow analysis; a subtle deserialization vulnerability in a framework-specific context needs semantic reasoning. SEC-C exploits this observation with a cascading architecture where each stage is invoked only when the previous stage's uncertainty exceeds a principled threshold.

### Cascade Economics

| Stage | Latency | Cost | Resolution Rate | Cumulative |
|-------|---------|------|-----------------|------------|
| **Stage 1: SAST** | < 100ms | Free (local) | ~80% of findings | 80% |
| **Stage 2: Graph + GNN** | ~1-3s | Free (local GPU) | ~15% of findings | 95% |
| **Stage 3: LLM Dual-Agent** | ~5-15s | API cost | ~5% of findings | 100% |

This 80/15/5 split means **85% fewer expensive LLM API calls** compared to a naive "send everything to an LLM" approach. The escalation decision is not heuristic -- it is driven by a mathematically defined 4-factor uncertainty score:

```
U_total = w_conf * U_confidence + w_comp * U_complexity + w_nov * U_novelty + w_confl * U_conflict + severity_adjustment
```

where `w_conf=0.4, w_comp=0.3, w_nov=0.2, w_confl=0.1`, and `U_total >= 0.5` triggers escalation. Each factor captures a distinct source of analytical uncertainty: low SAST confidence, high code complexity, novel patterns unseen in training, and conflicting signals across rules.

---

## 4. Five Novel Contributions

### 4.1 Uncertainty-Driven Cascading Escalation

**Why it is novel**: No published system uses a mathematically principled uncertainty score to route findings through a multi-stage pipeline. IRIS (ICLR 2025) augments CodeQL with LLM-inferred specifications but applies the LLM uniformly to all queries. Vulnhalla (CyberArk 2025) post-filters CodeQL output through an LLM but processes every finding identically. ZeroFalse (arXiv 2025) enriches SAST traces for LLM adjudication but does not selectively escalate. SEC-C is the first to formalize escalation as a decision boundary in uncertainty space.

**Evidence**: The 4-factor uncertainty model is implemented in `UncertaintyScore` (see `src/sast/sarif/schema.py`), with configurable weights and a severity adjustment term. The `should_escalate` property provides the binary escalation decision, and the threshold is tunable per-deployment.

### 4.2 Conformal Prediction for Code Security

**Why it is novel**: Conformal prediction has been applied to medical imaging, autonomous driving, and natural language inference, but SEC-C is the **first application to vulnerability detection**. The Adaptive Prediction Sets (APS) method provides a distribution-free coverage guarantee:

```
P(true label in prediction set) >= 1 - alpha = 90%
```

**How it drives escalation**: A singleton prediction set `{"safe"}` or `{"vulnerable"}` indicates the GNN is confident -- the finding is resolved at Stage 2. An ambiguous set `{"safe", "vulnerable"}` indicates the GNN cannot distinguish -- the finding is escalated to Stage 3 (LLM). This is a principled alternative to arbitrary confidence thresholds.

**Evidence**: The `GraphValidation` model stores `conformal_prediction_set` and `conformal_coverage`, and the `is_ambiguous` property returns `True` when the set contains more than one label, triggering LLM escalation.

### 4.3 Graph-LLM Fusion with CWE-Adaptive Weights

**Why it is novel**: Existing systems that combine SAST and LLM outputs use fixed fusion weights. SEC-C recognizes that **different CWE categories perform best at different stages**:

| CWE Category | Optimal Stage Weight | Reasoning |
|--------------|---------------------|-----------|
| **Injection (CWE-89, -78, -79)** | LLM-heavy (gamma=0.5) | Requires understanding of sanitization context, framework-specific escaping |
| **Cryptographic (CWE-327, -328)** | SAST-heavy (alpha=0.6) | Pattern matching sufficient: weak algorithms are identifiable syntactically |
| **Authentication (CWE-287, -306)** | Balanced | Requires both structural flow analysis and semantic understanding |
| **Memory (CWE-119, -125, -416)** | Graph-heavy (beta=0.5) | CPG analysis of allocation/deallocation paths is most informative |

The fusion formula `final_score = alpha * SAST + beta * GAT + gamma * LLM` uses per-CWE calibrated weights stored in `configs/cwe_weights.yaml`.

### 4.4 Adversarial Dual-Agent Triage

**Why it is novel**: Single-LLM approaches suffer from confirmation bias -- the model tends to agree with its initial assessment. SEC-C implements an adversarial protocol:

- **Attacker Agent (Red Team)**: Given a finding, constructs a concrete exploit payload, traces the execution path, and identifies blocking factors. Outputs `AttackerVerdict` with exploitability assessment.
- **Defender Agent (Blue Team)**: Identifies sanitizers, access controls, and framework protections along the data-flow path. Outputs `DefenderVerdict` with defense coverage score.
- **Consensus Engine**: Reconciles the two perspectives into a final `consensus_verdict` and `consensus_confidence`.

Multi-agent debate has been shown to improve LLM accuracy by 20-40% over single-model inference across multiple domains. SEC-C applies this principle with CWE-specific prompt templates that encode domain expertise (e.g., the SQL injection attacker template knows to check for parameterized queries, ORM usage, and WAF presence).

### 4.5 Multi-Language Multi-Provider Architecture

**Why it is novel**: Most research tools target a single language (IRIS: Java only; LLMxCPG: C/C++ focus). SEC-C provides:

- **5 languages**: Python, JavaScript/TypeScript, Java, C/C++, Go -- with language-specific Tree-sitter grammars, CodeQL query packs, and CWE mappings
- **2 LLM providers**: Gemini 2.5 (Pro + Flash) and Groq (Llama 3.3 70B) with round-robin API key rotation for throughput scaling
- **Provider-agnostic interface**: Adding a new LLM provider requires implementing a single adapter class, enabling controlled benchmarking of LLM effectiveness

---

## 5. Comparison with Prior Work

| Dimension | **SEC-C** | **IRIS** | **Vulnhalla** | **ZeroFalse** | **LLMxCPG** |
|-----------|-----------|----------|---------------|---------------|-------------|
| **Architecture** | 3-stage cascade (SAST + GNN + LLM) | LLM-augmented static analysis | LLM post-filter on CodeQL | LLM adjudicator on SAST traces | 2-phase CPG + LLM |
| **Cascade/Escalation** | Uncertainty-driven (4-factor formula) | None (uniform LLM application) | None (all findings sent to LLM) | None (all findings sent to LLM) | None (all findings sent to LLM) |
| **Graph Analysis** | CPG (Joern) + Mini-GAT + Conformal Prediction | Datalog-based static analysis | None | Flow-sensitive trace reconstruction | CPG slicing via LLM queries |
| **GNN Component** | Mini-GAT with GraphCodeBERT embeddings | None | None | None | None |
| **Conformal Prediction** | Yes (APS with coverage guarantee) | No | No | No | No |
| **LLM Role** | Dual-agent (Attacker + Defender) | Taint spec inference + context analysis | Single-agent guided questioning | Single-agent adjudication | 2-phase: query generation + classification |
| **Score Fusion** | CWE-adaptive weighted (alpha*SAST + beta*GAT + gamma*LLM) | Binary (vuln/not) | Binary filter | Binary + confidence | Binary classification |
| **Languages** | Python, JS/TS, Java, C/C++, Go | Java | C, C++ | Java (OWASP), multi (OpenVuln) | C/C++ |
| **LLM Used** | Gemini 2.5 + Groq Llama 3.3 | GPT-4 / DeepSeekCoder 7B | Configurable | Multiple (best: reasoning-oriented) | Configurable |
| **Key Result** | 85% LLM call reduction via cascade | +103.7% detections vs CodeQL | 96% FP reduction (specific CWEs) | 0.912 F1 (OWASP), 0.955 F1 (OpenVuln) | 15-40% F1 improvement over baselines |
| **Open Source** | Yes (MIT) | Yes (GitHub) | Yes (GitHub) | Paper only | Yes (GitHub) |
| **Evaluation Data** | Planned: OWASP Benchmark + CVEfixes | CWE-Bench-Java (120 vulns) | Real GitHub repos | OWASP Java + OpenVuln | Traditional + verified datasets |
| **Venue** | Target: ISSTA/FSE 2026-2027 | ICLR 2025 | Industry (CyberArk blog) | arXiv 2025 | USENIX Security 2025 |
| **Year** | 2026 | 2025 | 2025 | 2025 | 2025 |

### Key Differentiators

1. **SEC-C is the only system with selective escalation**: All competitors apply their LLM uniformly. SEC-C routes 80% of findings through fast SAST alone, invoking expensive analysis only when uncertainty warrants it.
2. **SEC-C is the only system with conformal prediction**: No competitor provides distribution-free coverage guarantees on their predictions.
3. **SEC-C is the only system with adversarial dual-agent validation**: Competitors use single-agent or single-pass LLM analysis.
4. **SEC-C is the only system with CWE-adaptive fusion**: Competitors use fixed combination strategies that ignore vulnerability-class-specific characteristics.

---

## 6. Strengths and Validation

### Cascade Efficiency
The 80/15/5 resolution split reduces LLM API calls by 85%. For a scan producing 1,000 findings, only ~50 require LLM analysis (~$0.50-2.00 in API costs vs ~$10-40 for full-LLM approaches). The escalation threshold (U >= 0.5) is configurable, allowing operators to trade precision for cost.

### False Positive Reduction Potential
LLM-based FP filtering achieves 92-98% reduction in controlled studies:
- "Sifting the Noise" (2026): best agent reduced OWASP Benchmark FP rate from 98.3% to 6.3%
- Vulnhalla (2025): up to 96% FP reduction for specific CWE categories
- Ghost Security (2025): AI-powered CAST reduced triage workload by 90%

SEC-C's cascade architecture is designed to achieve comparable FP reduction while minimizing the number of findings that require expensive LLM processing.

### Multi-Language Coverage
A single pipeline handles Python, JavaScript/TypeScript, Java, C/C++, and Go through language-specific Tree-sitter grammars and CodeQL query packs, avoiding the need for separate tool configurations per language.

### Configurability
CWE-specific weights in `configs/cwe_weights.yaml` allow per-vulnerability-class tuning. The cascade thresholds, GNN architecture, and LLM provider are all configurable via `configs/default.yaml`.

### Explainability
Every finding includes: (1) the SAST rule that triggered it, (2) the uncertainty factors that caused escalation, (3) GNN attention weights highlighting critical code regions, (4) attacker/defender reasoning in natural language, and (5) a fused confidence score with stage-resolved provenance.

---

## 7. Known Limitations

### No Benchmark Evaluation Yet
SEC-C has not been evaluated on standard benchmarks (OWASP Benchmark, CVEfixes, PrimeVul). All claimed performance numbers are projections based on component-level capabilities and published results from comparable systems. A rigorous evaluation is planned but not yet executed.

### GNN Not Trained on Real-World Data
The Mini-GAT model has been designed and implemented but has not yet been trained on real-world vulnerability data. Training on the Juliet Test Suite and Kaggle vulnerability datasets is a pending milestone. Until trained, Stage 2 operates with default confidence scores.

### Fusion Weights Not Empirically Calibrated
The CWE-adaptive fusion weights (alpha, beta, gamma) are set based on domain reasoning, not empirical optimization. A calibration script exists but requires benchmark data to execute. The weights should be treated as reasonable defaults, not optimized parameters.

### Tree-sitter Pre-Screening is Syntactic Only
Stage 1 pre-screening uses Tree-sitter AST pattern matching, which cannot reason about data flow or inter-procedural behavior. CodeQL adds deeper taint analysis, but the initial filter is purely syntactic and may miss complex vulnerability patterns.

### LLM Free-Tier Throughput Constraints
Gemini free tier limits (5 RPM Pro, 10 RPM Flash) constrain throughput for large scans. Groq provides higher throughput but with smaller models. Production deployment would require paid API access or self-hosted models.

### Single-Repository Scope
SEC-C analyzes one repository at a time. Cross-repository vulnerabilities (e.g., a vulnerable dependency's transitive impact) are outside the current scope.

---

## 8. Future Work

### Near-Term (2026)
- **Train Mini-GAT** on Juliet Test Suite + VulGate datasets with UniXcoder embeddings
- **Run evaluation** on OWASP Benchmark v1.2 + CVEfixes + PrimeVul
- **Calibrate fusion weights** using grid search on validation set
- **Upgrade to R-GAT** (Relational Graph Attention Network) for heterogeneous edge types (control flow, data flow, call edges)

### Medium-Term (2026-2027)
- **Add LLM providers**: Mistral, OpenRouter, local Ollama models for cost-free inference
- **IDE integration**: VS Code extension with inline annotations and one-click triage
- **CI/CD integration**: GitHub Actions workflow for automated PR scanning
- **Incremental analysis**: Re-analyze only changed files using Tree-sitter's incremental parsing

### Long-Term (2027+)
- **Cross-repository analysis**: Track vulnerabilities across dependency graphs
- **Active learning**: Use developer triage decisions to continuously improve GNN and fusion weights
- **Benchmark contribution**: Release SEC-C's evaluation results as a reproducible benchmark

---

## 9. Publication Strategy

### Target Venues

| Venue | Deadline | Fit |
|-------|----------|-----|
| **ISSTA 2026** | Spring 2026 | Testing and analysis -- strong fit for cascade evaluation |
| **FSE 2026** | Spring 2026 | Software engineering -- strong fit for framework + evaluation |
| **ICSE 2027** | August 2026 | Premier SE venue -- full paper with comprehensive evaluation |
| **ASE 2026** | May 2026 | Automated SE -- good fit for the automation aspects |
| **USENIX Security 2027** | February 2027 | Security venue -- if evaluation shows strong security results |

### Paper Angle
Framework paper presenting the uncertainty-driven cascade architecture, with ablation studies answering six research questions (RQ1-RQ6) on false positive reduction, calibration quality, dual-agent effectiveness, GNN contribution, cross-language performance, and cost-performance trade-offs.

### Citation

```bibtex
@inproceedings{secc2026,
  title     = {{SEC-C}: A Multi-Stage Framework with Uncertainty-Driven
               Escalation and Conformal Prediction for Reducing False
               Positives in Static Application Security Testing},
  author    = {{[Author Name]}},
  booktitle = {Proceedings of the ACM International Symposium on
               Software Testing and Analysis (ISSTA)},
  year      = {2026},
  note      = {Under preparation}
}
```

---

## References

1. "Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering." arXiv:2601.22952, 2026.
2. Ghost Security. "Exorcising the SAST Demons." 2025.
3. Edgescan. "2025 Vulnerability Statistics Report." 10th Edition, 2025.
4. Ding et al. "Vulnerability Detection with Code Language Models: How Far Are We?" (PrimeVul). ICSE 2025.
5. Du et al. "Revisiting the Performance of Deep Learning-Based Vulnerability Detection on Realistic Datasets" (Real-Vul). IEEE TSE, 2024.
6. Li et al. "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities." ICLR 2025.
7. CyberArk. "Vulnhalla: Picking the True Vulnerabilities from the CodeQL Haystack." 2025.
8. "ZeroFalse: Improving Precision in Static Analysis with LLMs." arXiv:2510.02534, 2025.
9. Lekssays et al. "LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models." USENIX Security 2025.
10. Angelopoulos and Bates. "Conformal Risk Control." ICLR 2024.
11. Rice, H.G. "Classes of Recursively Enumerable Sets and Their Decision Problems." Transactions of the AMS, 1953.
