# Sec-C Research Landscape Report
## PhD Prototype Planning: Multi-Stage Vulnerability Detection Framework

**Compiled:** March 2026
**Purpose:** Research planning for Sec-C PhD prototype
**Scope:** Open-source SAST frameworks, cascade architectures, SARIF ecosystem, tech stack, evaluation methodology, novelty assessment

---

## Table of Contents

1. [Open-Source SAST Frameworks Comparison](#1-open-source-sast-frameworks-comparison)
2. [Multi-Stage / Cascade Security Analysis Systems](#2-multi-stage--cascade-security-analysis-systems)
3. [SARIF Ecosystem](#3-sarif-ecosystem)
4. [Recommended Prototype Tech Stack](#4-recommended-prototype-tech-stack)
5. [Evaluation Methodology](#5-evaluation-methodology)
6. [PhD Novelty Assessment](#6-phd-novelty-assessment)
7. [Key References](#7-key-references)

---

## 1. Open-Source SAST Frameworks Comparison

### Head-to-Head Comparison Matrix

| Criterion | Semgrep OSS | CodeQL | Joern | Bandit | Pylint Security |
|-----------|-------------|--------|-------|--------|-----------------|
| **Language** | OCaml/Python | QL (custom) | Scala/Java | Python | Python |
| **Languages Supported** | 30+ | 12 (deep) | C/C++/Java/Python/JS/Kotlin | Python only | Python only |
| **Analysis Depth** | Pattern matching | Semantic/dataflow | CPG-based | AST-only | AST-only |
| **Taint Analysis** | Yes (Pro only in some modes) | Yes (deep) | Yes (CPG queries) | No | No |
| **Custom Rule Difficulty** | Easy (YAML, minutes) | Hard (QL language, days) | Moderate (Scala DSL) | Moderate (Python AST) | Moderate (checkers) |
| **Median CI Scan Time** | ~10 seconds | Minutes to 30+ min | 19s (small projects) | Very fast | Very fast |
| **Memory Usage** | ~150MB | ~450MB | Variable | Low | Low |
| **Requires Compilation** | No | Yes | No (fuzzy parsing) | No | No |
| **CPG Generation** | No | Internal | Yes (exportable) | No | No |
| **SARIF Output** | Yes | Yes | No (custom format) | Yes (via plugin) | No |
| **Extensibility for Research** | High | High | Very High | Moderate | Low |
| **License** | LGPL-2.1 | MIT (CLI), custom (queries) | Apache-2.0 | Apache-2.0 | GPL-2.0 |
| **Best For** | Fast CI gates | Deep semantic analysis | CPG research, custom analysis | Python-specific quick checks | Style + basic security |

### Detailed Assessment

#### Semgrep OSS
- **Strengths:** Fastest scan times (~10s median). Rules written in YAML, making them accessible. Supports 30+ languages. Strong community with 3,000+ pre-built rules. SARIF output native.
- **Weaknesses:** Deepest taint tracking features are in the paid tier (Semgrep Pro). Pattern matching cannot reason about complex inter-procedural flows. Limited graph-based analysis.
- **Research Use:** Best as a fast first-pass filter in a cascade. Can be the Stage 1 "fast SAST" component.

#### CodeQL
- **Strengths:** Deepest semantic analysis of any open-source tool. Full inter-procedural taint tracking. GitHub integration is excellent. Strong academic adoption. Highest F1 score on OWASP Benchmark v1.2 (tested on 2,740 Java test cases in the "Sifting the Noise" study, arXiv:2601.22952).
- **Weaknesses:** Requires source compilation into a database (slow). QL query language has a steep learning curve. Memory-intensive (~450MB). Database creation is a blocking step.
- **Research Use:** Best as a deep analysis engine (Stage 1 or Stage 2). SARIF output feeds directly into downstream processing.

#### Joern
- **Strengths:** Purpose-built for vulnerability research. Generates exportable Code Property Graphs. Fuzzy parsing (no compilation needed). CPG specification is well-documented and extensible. Can export graphs to Neo4j for Python-based analysis. Scala-based query language is powerful.
- **Weaknesses:** Smaller community than Semgrep/CodeQL. Python language support is less mature than C/C++. Performance can degrade on very large codebases. No native SARIF output.
- **Research Use:** Best for CPG-centric research. Ideal if you need to extract and manipulate code graphs directly. Can replace custom CPG construction.

#### Bandit
- **Strengths:** Python-exclusive focus. Very fast (10,000 LOC/sec). Plugin architecture allows custom detectors. 88% recall with 12% FPR. Good for Python-specific security patterns. Active maintenance.
- **Weaknesses:** AST-only analysis (no dataflow). Cannot track taint propagation. Limited to surface-level pattern detection. No inter-procedural analysis.
- **Research Use:** Useful as a fast pre-filter for Python code. Could serve as the quickest tier in a cascade.

#### Pylint Security Plugins
- **Strengths:** Familiar to Python developers. Extensive plugin ecosystem. Good for code quality + security combined.
- **Weaknesses:** Not designed for security analysis. 65% accuracy, 5,000 LOC/sec. No taint tracking. No vulnerability-specific features.
- **Research Use:** Not recommended as a base for security research.

### Recommendation for Sec-C

**Primary base: CodeQL + Tree-sitter (your current approach is correct)**

Rationale:
- CodeQL provides the deepest semantic analysis and native SARIF output
- Tree-sitter provides fast, incremental parsing for the quick first stage
- This combination maps directly to your cascade architecture (fast filter + deep analysis)
- Both are well-established in academic papers, improving credibility

**Secondary consideration: Joern for CPG generation**

If you find that building your own CPG construction is too time-consuming, Joern's CPG can be exported and consumed by your GNN pipeline. However, your existing custom CPG builder (Phase 1) gives you more control over the graph schema and is better aligned with your heterogeneous GAT requirements.

**Use Bandit as a comparison baseline** in evaluation, not as a framework component.

---

## 2. Multi-Stage / Cascade Security Analysis Systems

### Existing Cascade Architectures in Literature

#### 2.1 Industry: LinkedIn's SAST Pipeline (2026)

LinkedIn redesigned their SAST pipeline using GitHub Actions, running CodeQL and Semgrep in **parallel** (not cascade), with results normalized via SARIF. Key architectural decisions:
- Semgrep for fast PR-level gates (pattern matching)
- CodeQL in nightly builds for deeper dataflow analysis
- Both produce SARIF, merged into GitHub's Security tab
- Lightweight stub workflows delegate to centralized configs
- Enforcement via repository rulesets that block merges

**Difference from Sec-C:** LinkedIn uses parallel execution, not hierarchical escalation. There is no uncertainty-driven routing.

#### 2.2 Government/Defense: COLSA Tiered Software Analysis

The defense sector uses a formalized 4-tier approach:
1. **Low Assurance:** Automated scans on code commit (hours)
2. **Vetted:** Analyst reviews to eliminate false positives, assign risk scores (days)
3. **Deep Analysis:** Comprehensive multi-tool analysis (days-weeks)
4. **Malware/Forensic:** Manual reverse engineering (weeks)

**Difference from Sec-C:** This is a human-in-the-loop tiered process, not automated. Sec-C automates the escalation decision using uncertainty quantification.

#### 2.3 Research: LLM-Driven FP Reduction as a Cascade Stage

Multiple 2025 papers demonstrate using LLMs as a post-SAST validation layer:
- **SAST-Genius (arXiv:2509.15433):** Fine-tuned Llama 3 8B on vetted FP/TP data. Reduced false positives from 225 to 20 (11x improvement). Reduced analyst triage time by 91%.
- **ZeroFalse (arXiv:2510.02534):** Treats SAST outputs as structured contracts enriched with flow-sensitive traces. Best model achieves F1 of 0.912 on OWASP Java Benchmark, 0.955 on OpenVuln.
- **Semgrep Assistant Memories (2025):** ML-based triage that handles ~20% of all triage work by filtering false positives. Claims to move toward "zero false positive SAST."
- **Datadog Bits AI:** LLM-based false positive filtering that reasons about broader code context.
- **"Sifting the Noise" (arXiv:2601.22952):** Tested LLM agents for FP filtering. Advanced prompting (CoT, Self-Consistency) enables flagging up to 62.5% of false positives without missing genuine vulnerabilities.

**Key insight for Sec-C:** The SAST-then-LLM-validation pattern is emerging but is typically two-stage (SAST + LLM). Nobody has published a three-stage system with uncertainty-driven routing between SAST, GNN, and LLM. This is your novelty gap.

#### 2.4 Research: HMS-IDS (Hybrid Multi-Stage Intrusion Detection)

In the network security domain, multi-stage cascade systems are more common:
- Integrates supervised and unsupervised learning
- 99.49% accuracy for known attacks, 98.93% for unknown
- Uses a fast filter stage followed by deep analysis

**Relevance to Sec-C:** The cascade principle is proven in network IDS but has not been rigorously applied to SAST with uncertainty-driven escalation.

#### 2.5 Research: GRACE (2024)

GRACE empowers LLM-based vulnerability detection with graph structure and in-context learning:
- Three modules: demonstration selection, graph structure representation (AST+PDG+CFG), enhanced vulnerability detection
- Outperforms six baselines by at least 28.65% F1 on Devign, ReVeal, Big-Vul
- Combines graph structure with LLM reasoning

**Difference from Sec-C:** GRACE is a single-stage system that feeds graph info to an LLM. It does not use a cascade or uncertainty-driven escalation.

#### 2.6 Research: Vul-LMGNNs (2024, Information Fusion)

Fuses code language models with online-distilled GNNs:
- CPG-based structural extraction with gated GNNs
- CodeLMs initialize node embeddings
- Online knowledge distillation between student/teacher GNNs
- Outperforms 17 state-of-the-art approaches

**Difference from Sec-C:** Vul-LMGNNs is a single monolithic model, not a cascade. No uncertainty quantification or escalation.

### Summary: Gap Analysis for Cascade Architectures

| System | Stages | Uncertainty-Driven? | GNN Stage? | LLM Stage? | Automated? |
|--------|--------|---------------------|------------|------------|------------|
| LinkedIn Pipeline | 2 (parallel) | No | No | No | Yes |
| COLSA Tiered | 4 | No (manual) | No | No | Partially |
| SAST-Genius | 2 | No | No | Yes | Yes |
| ZeroFalse | 2 | No | No | Yes | Yes |
| GRACE | 1 | No | Implicit (graph features) | Yes | Yes |
| Vul-LMGNNs | 1 | No | Yes | Implicit (LM embeddings) | Yes |
| HMS-IDS | 2+ | Partially | No | No | Yes |
| **Sec-C (proposed)** | **3** | **Yes** | **Yes** | **Yes** | **Yes** |

**Conclusion:** No published system combines all three stages (SAST + GNN + LLM) with uncertainty-driven escalation. This is a genuine research gap.

---

## 3. SARIF Ecosystem

### 3.1 Standard Status

SARIF 2.1.0 is an approved OASIS standard (not just a draft). It defines a JSON-based schema for representing static analysis results with rich metadata including:
- Rule definitions and descriptions
- Location information (file, line, column, region)
- Code flow / taint path representation
- Fix suggestions
- Taxonomies (CWE mappings)
- Tool information and configuration

### 3.2 SARIF Producers (Tools That Output SARIF)

| Tool | SARIF Quality | Notes |
|------|---------------|-------|
| **CodeQL** | Excellent | Full taint flow, CWE mapping, fix suggestions |
| **Semgrep** | Good | Rule metadata, location, severity |
| **SonarQube** | Good | Via export plugins |
| **ESLint** | Basic | Via SARIF formatter |
| **Bandit** | Basic | Via bandit-sarif plugin |
| **Checkmarx** | Good | Commercial |
| **Veracode** | Good | Commercial |
| **CMake** | Basic | Added in CMake 4.0 (2025) |
| **MSVC Compiler** | Good | Structured diagnostics |
| **Cycode** | Good | Commercial |
| **Fluid Attacks** | Good | Commercial |

### 3.3 SARIF Consumers (Tools That Ingest SARIF)

| Consumer | Integration Quality | Notes |
|----------|---------------------|-------|
| **GitHub Code Scanning** | Excellent | Native SARIF upload via API |
| **GitHub Security Tab** | Excellent | Aggregates all SARIF uploads |
| **VS Code SARIF Viewer** | Good | Extension for viewing results |
| **Visual Studio** | Good | Native SARIF support |
| **Azure DevOps** | Good | Pipeline integration |
| **GitLab** | Moderate | SARIF import available |
| **SARIF Web Viewer** | Good | Microsoft's online viewer |
| **DefectDojo** | Good | Vulnerability management platform |

### 3.4 Python SARIF Libraries

| Library | PyPI Package | Maintainer | Purpose |
|---------|-------------|------------|---------|
| **sarif-om** | `sarif-om` | Microsoft | Object model classes generated from SARIF JSON schema. Read/write SARIF programmatically. |
| **sarif-tools** | `sarif-tools` | Microsoft | CLI + Python library for analyzing/manipulating SARIF files. Diff, summary, trend analysis. |
| **jschema-to-python** | `jschema-to-python` | Microsoft | Code generator that produced sarif-om from schema. |

### 3.5 Assessment: Can We Build a Unified Reporting Layer Around SARIF?

**Yes, and this is a strong architectural choice.** Reasons:

1. **Industry convergence:** Both CodeQL and Semgrep output SARIF. GitHub consumes SARIF natively. LinkedIn's 2026 pipeline normalizes everything to SARIF.
2. **Rich schema:** SARIF 2.1.0 supports taint flows (codeFlows), confidence scores (rank/level), CWE mappings (taxa), and fix suggestions -- everything Sec-C needs.
3. **Python tooling exists:** `sarif-om` provides the object model; `sarif-tools` provides manipulation utilities.
4. **Extensibility:** SARIF supports custom properties via `properties` bags on any object, allowing Sec-C to add uncertainty scores, GNN confidence, LLM explanations without breaking compatibility.
5. **Publication advantage:** Using an industry standard format makes your research artifacts reusable and your tool interoperable.

**Recommended approach for Sec-C:**
- Stage 1 (SAST) outputs SARIF with initial findings + uncertainty scores in custom properties
- Stage 2 (GNN) enriches the same SARIF with GNN confidence, attention weights, graph features
- Stage 3 (LLM) adds natural language explanations, remediation guidance
- Final output is a single SARIF 2.1.0 file uploadable to GitHub or any SARIF consumer
- Use `sarif-om` for programmatic construction, add Sec-C-specific extensions via `properties`

### 3.6 SARIF Schema Extension for Sec-C

```json
{
  "properties": {
    "sec-c": {
      "stage": "gnn",
      "uncertainty_score": 0.72,
      "escalated_from": "sast",
      "gnn_confidence": 0.85,
      "attention_weights": [0.9, 0.3, 0.1],
      "classification": "likely_vulnerable",
      "llm_explanation": null,
      "triage_tier": "confirmed"
    }
  }
}
```

---

## 4. Recommended Prototype Tech Stack

### 4.1 Complete Stack Recommendation

| Layer | Technology | Version | License | Purpose | Single-Machine? |
|-------|------------|---------|---------|---------|-----------------|
| **Language** | Python | 3.11+ | PSF | Primary implementation language | Yes |
| **Package Manager** | uv | Latest | MIT | Fast dependency management (you're already using it) | Yes |
| **Parsing** | tree-sitter + py-tree-sitter | 0.21+ | MIT | Fast incremental parsing for Stage 1 | Yes |
| **SAST Engine** | CodeQL CLI | Latest | MIT (CLI) | Deep semantic analysis, taint tracking | Yes |
| **CPG Construction** | Custom (your Phase 1) or Joern export | - | - | Code Property Graph generation | Yes |
| **Graph Library** | NetworkX | 3.x | BSD | Graph construction and manipulation | Yes |
| **GNN Framework** | PyTorch Geometric (PyG) | 2.5+ | MIT | Heterogeneous GAT implementation | Yes (GPU recommended) |
| **Code Embeddings** | GraphCodeBERT (microsoft/graphcodebert-base) | HuggingFace | MIT | 768-dim code-aware embeddings | Yes (GPU helps) |
| **LLM Integration** | Anthropic API (Claude) or Ollama (local) | - | - | Semantic validation in Stage 3 | Yes |
| **Vector DB (RAG)** | FAISS | Latest | MIT | Similarity search for RAG retrieval | Yes |
| **SARIF** | sarif-om + sarif-tools | PyPI | MIT | Unified reporting layer | Yes |
| **Testing** | pytest + pytest-cov | Latest | MIT | Test suite with coverage | Yes |
| **ML Experiment Tracking** | Weights & Biases (free tier) or MLflow | Latest | Free/Apache-2.0 | Training metrics, hyperparameter tracking | Yes |
| **Data Processing** | pandas + numpy | Latest | BSD | Dataset processing | Yes |
| **Visualization** | matplotlib + seaborn | Latest | BSD/BSD | Result visualization for papers | Yes |
| **GPU** | CUDA 12.1+ | - | Proprietary | GNN + embedding computation | Single GPU sufficient |

### 4.2 LLM Options (Free/Low-Cost for PhD)

| Option | Cost | Latency | Quality | Single-Machine? |
|--------|------|---------|---------|-----------------|
| **Ollama + Llama 3.1 8B** | Free | ~2-5s | Good for validation | Yes (needs 8GB+ VRAM) |
| **Ollama + CodeLlama 13B** | Free | ~3-8s | Good for code | Yes (needs 16GB+ VRAM) |
| **Anthropic Claude API** | ~$3/MTok input | ~1-3s | Excellent | Yes (API call) |
| **OpenAI GPT-4o-mini** | ~$0.15/MTok | ~1-2s | Very Good | Yes (API call) |
| **Google Gemini Flash** | Free tier available | ~1-2s | Good | Yes (API call) |
| **DeepSeek Coder V2** | Free (open source) | ~2-5s | Good for code | Yes (via Ollama) |

**Recommendation:** Use Ollama with a local model for development and reproducibility. Use a commercial API (Claude or GPT-4o-mini) for final evaluation runs where quality matters for publication. Budget approximately $50-100 for API costs during final evaluation.

### 4.3 Hardware Requirements

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **RAM** | 16 GB | 32 GB | GraphCodeBERT + PyG can be memory-hungry |
| **GPU** | 8 GB VRAM (RTX 3060) | 16 GB VRAM (RTX 4080) | For GNN training + embeddings |
| **Storage** | 50 GB | 100 GB | Datasets + model checkpoints |
| **CPU** | 8 cores | 16 cores | CodeQL database creation is CPU-bound |

### 4.4 Six-Month Development Timeline

| Month | Phase | Deliverable | Key Tech |
|-------|-------|-------------|----------|
| **Month 1** | Dataset + Infrastructure | Curated Python vulnerability dataset, SARIF pipeline | pandas, sarif-om, CVEfixes |
| **Month 2** | GNN Core | CPG-to-PyG pipeline, basic GAT model training | PyG, GraphCodeBERT, NetworkX |
| **Month 3** | GNN Refinement | Heterogeneous GAT with multi-task heads, uncertainty quantification | PyG, conformal prediction |
| **Month 4** | LLM Integration | RAG setup, LLM validation agent, cascade coordinator | FAISS, Ollama/API, LangChain |
| **Month 5** | Integration + Evaluation | End-to-end pipeline, benchmark evaluation, ablation studies | Full stack |
| **Month 6** | Paper Writing + Polish | Paper draft, visualizations, reproducibility package | LaTeX, matplotlib |

### 4.5 Key Risk Mitigations

| Risk | Mitigation |
|------|------------|
| GNN training takes too long | Use small graph sizes (<500 nodes). GraphCodeBERT embeddings are pre-computed. |
| LLM API costs spiral | Use local Ollama for development. API only for final eval. |
| Dataset quality issues | Use CVEfixes (highest label accuracy) as primary. Cross-reference CWE labels with NVD. |
| Single-machine memory limits | Process files individually, not batch. Use gradient accumulation for training. |
| CodeQL database creation is slow | Pre-build databases for all benchmark projects. Cache aggressively. |

---

## 5. Evaluation Methodology

### 5.1 Standard Benchmarks Used in Top Papers

| Benchmark | Language | Size | Ground Truth Quality | Used By |
|-----------|----------|------|---------------------|---------|
| **CVEfixes** | Multi (Python subset available) | 5,495 CVEs, 211K+ Python statements | Highest accuracy among auto-collected | DetectVul, VUDENC |
| **VUDENC** | Python only | 14,686 projects, 7 CWE types | Good (manual verification of fixes) | VUDENC, DetectVul |
| **PrimeVul** | C/C++ | ~7K vuln + ~229K benign | Comparable to human-verified | ICSE 2025 |
| **DiverseVul** | C/C++ | Superset of Devign+ReVeal+BigVul+CrossVul+CVEfixes | Mixed (deduped, but some label issues) | RAID 2023 |
| **BigVul** | C/C++ | Large | Low (only 25% label accuracy) | Many, but quality concerns |
| **Devign** | C/C++ | ~27K functions | Moderate | Devign, GRACE, many |
| **ReVeal** | C/C++ | ~18K functions | Moderate | ReVeal, GRACE |
| **OWASP Benchmark v1.2** | Java | 2,740 test cases | Excellent (synthetic, known ground truth) | SAST tool comparison |
| **CASTLE** | Multi | 250 programs, 25 CWEs | Excellent (hand-crafted) | TASE 2025 |
| **Juliet Test Suite** | C/C++/Java | ~64K test cases | Excellent (NIST synthetic) | NIST evaluations |
| **PythonSecurityEval** | Python | 470 prompt-function pairs | Good | LLM evaluation |
| **SecurityEval** | Multi | Mining-based | Moderate | MSR4PS 2022 |

**Recommendation for Sec-C:** Use CVEfixes (Python subset) + VUDENC as primary benchmarks. Use Juliet Test Suite for controlled experiments. Use PythonSecurityEval for LLM stage evaluation.

### 5.2 Critical Warning: Benchmark Inflation

The PrimeVul paper (ICSE 2025) revealed a devastating finding: **a state-of-the-art 7B model scored 68.26% F1 on BigVul but only 3.09% F1 on PrimeVul.** This 22x performance gap is caused by:
- High duplication rates in legacy benchmarks
- Poor label accuracy (BigVul: only 25%)
- Data leakage from non-chronological splits
- Inconsistent CWE annotations

**Implication for Sec-C:** You MUST use rigorous benchmarks with verified labels. Report results on multiple benchmarks. Use chronological train/test splits. Acknowledge dataset limitations in your paper.

The ISSTA 2025 paper "On Benchmarking in Machine Learning for Vulnerability Detection" provides further guidance on proper evaluation methodology.

### 5.3 Metrics Beyond Precision/Recall

| Metric | What It Measures | Why It Matters | Used In |
|--------|-----------------|----------------|---------|
| **Precision** | TP / (TP + FP) | False positive rate (alert fatigue) | All papers |
| **Recall** | TP / (TP + FN) | Detection coverage (missed vulns) | All papers |
| **F1 Score** | Harmonic mean of P and R | Balanced measure | All papers |
| **AUC-ROC** | Discrimination ability | Threshold-independent performance | Most papers |
| **False Positive Rate (FPR)** | FP / (FP + TN) | Direct measure of noise | OWASP Benchmark |
| **True Positive Rate (TPR)** | Same as Recall | Direct measure of detection | OWASP Benchmark |
| **CWE-Weighted F1** | F1 per CWE type | Performance across vulnerability classes | Recent papers |
| **Latency (median/P95)** | End-to-end analysis time | Practical usability | Industry tools |
| **Throughput** | LOC/second | Scalability | Industry tools |
| **Escalation Rate** | % findings routed to deeper stages | Efficiency of cascade | **Novel to Sec-C** |
| **Cost per Finding** | Compute cost per true positive | Resource efficiency | Emerging |
| **Explanation Quality** | Human-rated explanation usefulness | Practical value | LLM-based tools |
| **OWASP Benchmark Score** | (TPR - FPR) / 2 | Standardized SAST comparison | OWASP |

### 5.4 Evaluation Design for Sec-C

**Required experiments for publication at ISSTA/FSE/ICSE:**

1. **RQ1: Detection Effectiveness**
   - Compare Sec-C end-to-end F1/Precision/Recall against baselines (CodeQL alone, Semgrep alone, Bandit, GRACE, Vul-LMGNNs)
   - Use CVEfixes Python subset + VUDENC
   - Report per-CWE breakdown

2. **RQ2: False Positive Reduction**
   - Measure FPR of Sec-C vs. CodeQL alone vs. Semgrep alone
   - Target: 60%+ FP reduction (your stated goal)
   - Use OWASP Benchmark or Juliet for controlled measurement

3. **RQ3: Cascade Efficiency**
   - Measure: what % of findings are resolved at each stage?
   - Measure: latency at each stage
   - Demonstrate that the 80/15/5 split holds
   - Show compute cost savings vs. running all stages on all findings

4. **RQ4: Uncertainty Calibration**
   - Measure: are uncertainty scores well-calibrated? (calibration plots)
   - Measure: does higher uncertainty correlate with actual difficulty?
   - Show that escalation decisions are correct (escalated findings are genuinely harder)

5. **RQ5: Ablation Study**
   - Sec-C without GNN stage
   - Sec-C without LLM stage
   - Sec-C without uncertainty-driven escalation (all findings go through all stages)
   - Sec-C with different uncertainty thresholds

6. **RQ6: Real-World Case Studies**
   - Run on known-vulnerable Python projects (e.g., CVE repositories)
   - Show detection of real CVEs that individual tools miss
   - Include qualitative examples of explanations

### 5.5 Statistical Rigor

Top venues require:
- **Multiple runs** with different random seeds (report mean and std dev)
- **Statistical significance tests** (Wilcoxon signed-rank or McNemar's test)
- **Effect size** measures (Cohen's d or Cliff's delta)
- **Cross-validation** or chronological splits (never random splits for temporal data)
- **Reproducibility package** (code, data, configs, random seeds)

---

## 6. PhD Novelty Assessment

### 6.1 What Already Exists (Not Novel)

| Technique | Status | Key Papers |
|-----------|--------|------------|
| GNN on CPG for vulnerability detection | Well-explored | Devign (2019), ReGVD (ICSE 2022), HAGNN (2025) |
| LLM for vulnerability detection | Extensively studied (91.3% of 208 papers) | Survey: Springer 2025, 208 papers |
| CodeBERT/GraphCodeBERT embeddings for code | Standard practice | Microsoft (2020, 2021) |
| SAST + LLM for FP reduction | Emerging (2025) | SAST-Genius, ZeroFalse, Semgrep Assistant |
| Code Property Graphs | Established | Yamaguchi et al. (2014), Joern |
| Multi-task learning for vulnerability detection | Exists | Various 2023-2025 papers |

### 6.2 What Is Genuinely Novel in Sec-C

#### Novelty 1: Three-Stage Cascade with Uncertainty-Driven Escalation (STRONG)

**Why it's novel:** No published system combines SAST + GNN + LLM in a hierarchical cascade with formal uncertainty quantification driving escalation decisions. The closest works are:
- Two-stage SAST+LLM systems (SAST-Genius, ZeroFalse) -- but no GNN stage
- Combined LM+GNN models (Vul-LMGNNs, GRACE) -- but monolithic, not cascade
- Multi-stage IDS (HMS-IDS) -- but in network domain, not code analysis

**The gap:** Nobody has formally studied WHEN to escalate from pattern matching to structural analysis to semantic reasoning, nor quantified the compute-accuracy tradeoff of doing so.

**Publication potential:** HIGH. This is a systems contribution with clear ablation experiments.

#### Novelty 2: Uncertainty Quantification for Code Vulnerability Detection (STRONG)

**Why it's novel:** Conformal prediction and calibrated uncertainty estimation have not been applied to code vulnerability detection. The 4-factor uncertainty formula (confidence, complexity, novelty, conflict) is original. Applying conformal prediction to provide statistical coverage guarantees for vulnerability findings would be a first.

**The gap:** All existing ML-based vulnerability detectors output a single probability or binary label. None provide calibrated uncertainty estimates or prediction sets with coverage guarantees.

**Publication potential:** HIGH. Uncertainty quantification is a hot topic in ML safety, and applying it to code security is timely.

#### Novelty 3: Cost-Aware Inference Routing (MODERATE-HIGH)

**Why it's novel:** The explicit optimization of the compute-accuracy tradeoff (80% resolved in <100ms, 15% in ~1s, 5% in ~10s) with formal cost modeling is new in this domain.

**The gap:** Existing tools either run everything through the same pipeline or use hard-coded thresholds. No system formally optimizes routing based on cost AND uncertainty.

**Publication potential:** MODERATE-HIGH. Interesting but needs strong experimental validation.

#### Novelty 4: Multi-Modal Evidence Fusion (MODERATE)

**Why it's novel:** Combining structural evidence (GNN attention weights), semantic evidence (LLM reasoning), and historical evidence (RAG over CVE database) with explicit confidence calibration across modalities.

**The gap:** GRACE feeds graph structure to an LLM, but does not fuse evidence from independent sources with calibrated confidence. Vul-LMGNNs fuses LM+GNN but without uncertainty calibration.

**Caution:** This needs to be clearly differentiated from simple ensemble methods.

### 6.3 What Would NOT Be Novel (Avoid Claiming)

- "We use GNNs on code graphs" -- done many times
- "We use LLMs for vulnerability detection" -- 91.3% of recent papers do this
- "We achieve higher F1 than baselines" -- incremental improvement alone is not a contribution
- "We use SARIF for reporting" -- engineering, not research
- "We support multiple languages" -- engineering scope, not novelty

### 6.4 Recommended Thesis Framing

**Title suggestion:** "Uncertainty-Driven Cascade Analysis for Software Vulnerability Detection: Combining Static Analysis, Graph Neural Networks, and Large Language Models"

**Core thesis statement:** "An uncertainty-aware multi-stage analysis system that routes code through progressively more expensive analysis stages based on calibrated confidence scores can achieve higher precision than any individual stage while maintaining high recall and reducing median analysis time by 85%."

**Three publishable contributions:**
1. **The cascade architecture** with formal uncertainty-driven escalation (systems paper: ISSTA/FSE)
2. **Uncertainty quantification** for code vulnerability detection using conformal prediction (ML paper: ICSE/ASE)
3. **Empirical study** of the compute-accuracy tradeoff in multi-stage vulnerability detection (empirical paper: ESEC/FSE)

### 6.5 Closest Competing Work to Monitor

| Paper/System | Year | Threat to Novelty | Differentiation |
|--------------|------|-------------------|-----------------|
| GRACE | 2024 | Combines graph + LLM | Single-stage, no cascade, no uncertainty |
| Vul-LMGNNs | 2024 | Combines LM + GNN | Monolithic, no cascade, no LLM validation |
| SAST-Genius | 2025 | SAST + LLM cascade | Two-stage only, no GNN, no uncertainty |
| ZeroFalse | 2025 | SAST + LLM validation | Two-stage only, no GNN, no uncertainty |
| ReDetect | 2025 | LLM + GNN + static analysis | Smart contracts only, different architecture |
| DetectVul | 2024 | Python statement-level detection | GNN only, no cascade |
| Semgrep AI | 2025 | AI-powered FP filtering | Commercial, no GNN, no cascade |

### 6.6 Risk Assessment

| Risk | Level | Mitigation |
|------|-------|------------|
| Someone publishes a 3-stage cascade before you | MODERATE | Move fast. Your uncertainty-driven routing is the key differentiator. |
| GNN stage doesn't add enough value over SAST+LLM | LOW-MODERATE | Ablation study will show this. If GNN adds even 5% precision, it justifies the architecture. |
| Uncertainty calibration doesn't work well on code | LOW | Conformal prediction has theoretical guarantees. Even weak calibration is publishable as a negative result. |
| Python-only scope limits impact | LOW | Most code security papers focus on C/C++. Python focus is actually a gap. |
| Reviewers question practical scalability | MODERATE | Show it works on real projects (10K+ LOC). Emphasize the 80/15/5 split reduces cost. |

---

## 7. Key References

### Foundational Papers
- Yamaguchi et al., "Modeling and Discovering Vulnerabilities with Code Property Graphs" (IEEE S&P 2014) - Original CPG paper
- Zhou et al., "Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks" (NeurIPS 2019)
- Li et al., "VulDeePecker: A Deep Learning-Based System for Vulnerability Detection" (NDSS 2018)

### GNN + Code Models
- Vul-LMGNNs, "Fusing Language Models and Online-Distilled Graph Neural Networks for Code Vulnerability Detection" (Information Fusion 2025)
- GRACE, "Empowering LLM-based Software Vulnerability Detection with Graph Structure and In-Context Learning" (JSS 2024)
- ReGVD, "Revisiting Graph Neural Networks for Vulnerability Detection" (ICSE 2022)
- SCL-CVD, "Supervised Contrastive Learning for Code Vulnerability Detection via GraphCodeBERT" (Computers & Security 2024)

### LLM for Vulnerability Detection
- "Large Language Model for Vulnerability Detection and Repair: Literature Review and Roadmap" (arXiv 2024, survey of 208 papers)
- "From Large to Mammoth: A Comparative Evaluation of LLMs" (NDSS 2025)
- SecureQwen, "Leveraging LLMs for Vulnerability Detection in Python Codebases" (Computers & Security 2024)

### False Positive Reduction
- SAST-Genius, "LLM-Driven Hybrid Static Analysis Framework" (arXiv:2509.15433, 2025)
- ZeroFalse, "Improving Precision in Static Analysis with LLMs" (arXiv:2510.02534, 2025)
- "Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering" (arXiv:2601.22952, 2025)

### Benchmarks and Evaluation
- PrimeVul, "Vulnerability Detection with Code Language Models: How Far Are We?" (ICSE 2025)
- SecVulEval, "Benchmarking LLMs for Real-World C/C++ Vulnerability Detection" (arXiv:2505.19828, 2025)
- DiverseVul, "A New Vulnerable Source Code Dataset" (RAID 2023)
- CASTLE, "Benchmarking Dataset for Static Code Analyzers and LLMs towards CWE Detection" (TASE 2025)
- "On Benchmarking in Machine Learning for Vulnerability Detection" (ISSTA 2025)
- VUDENC, "Vulnerability Detection with Deep Learning on a Natural Codebase for Python" (IST 2021)

### Uncertainty Quantification
- "Verifiably Robust Conformal Prediction" (Pattern Recognition 2025)
- "Conformal Prediction: A Data Perspective" (ACM Computing Surveys 2025)

### Industry/Tools
- LinkedIn SAST Pipeline with CodeQL + Semgrep (InfoQ, Feb 2026)
- Datadog LLM-based False Positive Filtering (2025)
- Semgrep Assistant Memories (2025)

---

## Appendix A: Quick-Start Commands

```bash
# Install core dependencies
uv add tree-sitter py-tree-sitter networkx torch torch-geometric
uv add transformers sarif-om sarif-tools faiss-cpu
uv add pandas numpy matplotlib seaborn pytest pytest-cov

# For local LLM (optional)
# Install Ollama from https://ollama.com
ollama pull llama3.1:8b
ollama pull codellama:13b

# For CodeQL
# Download from https://github.com/github/codeql-cli-binaries
codeql database create mydb --language=python --source-root=./target
codeql database analyze mydb --format=sarif-latest --output=results.sarif

# For Joern (if needed for CPG comparison)
# Download from https://github.com/joernio/joern
joern --script export-cpg.sc --params inputPath=./target
```

## Appendix B: Existing Sec-C Assets (Phase 1)

From your completed Phase 1, you already have:
- Tree-sitter SAST engine with multi-tier detection (D:/Capstone/ts-python-sast/)
- CodeQL integration with SARIF parser at 97% coverage (D:/Capstone/Sec-C/src/sec_c/infrastructure/codeql/)
- CPG schema with 6 node types, 12 edge types at 98% coverage (D:/Capstone/Sec-C/src/sec_c/core/graph/)
- SAST agent with 4-factor uncertainty quantification at 98% coverage
- 70 tests, 93% overall coverage
- Real-world validation: 67% detection on flask-vuln (vs. 0% traditional tools)

**These assets map directly to Stage 1 of the cascade.** Phase 2 (GNN) and Phase 3 (LLM) build on top of this foundation.

---

*Report compiled March 2026. Sources verified against web searches conducted on the same date.*
