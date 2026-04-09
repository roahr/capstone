# Sec-C: Project Evolution — From Concept to Framework

> Standalone reference for anyone needing the full project timeline, key decisions, and pivots.
> No prior knowledge required.

---

## What Is Sec-C?

Sec-C is a **multi-stage code security framework** that detects vulnerabilities in source code using a 4-module cascade:

1. **SAST** (Static Analysis) — fast, cheap, catches obvious issues
2. **Graph** (GNN + Conformal Prediction) — structural analysis of code property graphs
3. **LLM** (Dual-Agent Attacker/Defender) — semantic understanding via Gemini 2.5
4. **Reporting** (Score Fusion + SARIF + HTML) — combines all stages into a final verdict

The key innovation: **uncertainty-driven escalation** — findings are resolved at the cheapest possible stage. Only ambiguous cases escalate to more expensive analysis. This reduces LLM API calls by ~85%.

---

## Timeline: Semester 1 (Aug–Nov 2025)

### Phase 1 Scope: SAST Pipeline Foundation

| Period | What Happened | Key Output |
|--------|---------------|------------|
| Aug–Sep 2025 | Literature survey: SAST tools (Fortify, Checkmarx, Coverity), CodeQL, CPGs (Yamaguchi 2014) | Identified 5 research gaps |
| Sep–Oct 2025 | Built Tree-sitter pre-screening engine with 24 vulnerability patterns | Pattern matching across 5 languages |
| Oct 2025 | Integrated CodeQL for taint analysis (source→sink tracking) | Taint engine with 4-tier detection |
| Oct–Nov 2025 | SARIF 2.1.0 output format, rule engine, call graph | CI/CD-ready reporting |
| Nov 2025 | Phase 1 report submitted | 5 chapters, 13 references |

### Phase 1 Deliverables
- Tree-sitter-based SAST with 9 built-in security rules
- Intraprocedural taint analysis with 4-tier confidence scoring
- CodeQL integration for CPG construction (6-step pipeline)
- SARIF 2.1.0 output with CI exit codes
- 9/11 vulnerable patterns detected in tests, 2/2 safe paths verified

### Phase 1 Report Structure
- Chapter 1: Introduction (alert fatigue crisis, 30-50% FP rates)
- Chapter 2: Literature Review (traditional SAST, CPGs, taint analysis)
- Chapter 3: Methodology (4-stage architecture proposed)
- Chapter 4: Implementation (Tree-sitter + CodeQL pipeline)
- Chapter 5: Conclusion (Phase 2 roadmap: GNN + LLM + Fusion)

---

## Timeline: Semester 2 (Jan–Apr 2026)

### Phase 2 Scope: Graph + LLM + Fusion + Full Tool

| Week | Planned Task | Mentor Suggestion | Status |
|------|-------------|-------------------|--------|
| Jan 1-7 | Revisited Sem-1 findings, fixed pattern matching issues | Survey recent AI-assisted SAST | Sem-1 handoff done |
| Jan 8-14 | Studied multi-agent LLM validation and conformal prediction theory | Formalize conformal prediction gap | Survey in progress |
| Jan 15-21 | Drafted research questions, proposed 3-stage cascade architecture | Formalize uncertainty model | Architecture proposed |
| Jan 22-28 | Redesigned GNN as graph attention network (Mini-GAT) | Keep model lightweight for free-tier GPU | GNN redesign done |
| Feb 1-7 | Integrated deep taint analysis with uncertainty scoring | Consider per-CWE weight calibration | SAST extended |
| Feb 8-14 | Designed CWE-adaptive score fusion engine | Start drafting problem statement | Slow week |
| Feb 15-21 | Built CPG construction, conformal prediction, GNN training notebook | Review Claude Code security approach | Training pipeline ready |
| Feb 22-28 | **Key pivot**: decided to build as full interactive CLI tool (inspired by Claude Code UX) | Use dual-agent approach for LLM | Tool vision defined |
| Mar 1-7 | Implemented attacker/defender dual-agent LLM validation | Add knowledge retrieval with CVE/CWE data | Dual-agent working |
| Mar 8-14 | Built hybrid RAG knowledge base (FAISS semantic + BM25 keyword) | Build output layer for reports | Knowledge base ready |
| Mar 15-21 | Built interactive CLI (prompt-toolkit), HTML dashboard, console reports | Prepare sample codebases for testing | Reporting complete |
| Mar 22-28 | Added CVSS v3.1 severity scoring, XAI evidence narratives | Plan benchmark evaluation | Integration testing |
| Apr 1-8 | Report generation skill, documentation, GNN V5 planning | — | Current |

---

## Key Design Decisions and Pivots

### Decision 1: Uncertainty-Driven Cascade (Jan 2026)
- **What**: Instead of running all 3 analysis stages on every finding, use a 4-factor uncertainty score to decide which findings need deeper analysis.
- **Why**: Running LLM on every finding is expensive (rate-limited, slow). Most findings (~75%) are obvious enough for SAST to resolve.
- **Formula**: `U = 0.4·confidence + 0.3·complexity + 0.2·novelty + 0.1·conflict + severity_adjustment`
- **Threshold**: `U >= 0.5` triggers escalation to next stage.

### Decision 2: Mini-GAT over GCN (Jan 2026)
- **What**: Chose Graph Attention Networks over Graph Convolutional Networks.
- **Why**: Attention mechanism assigns learned edge importance — distinguishes security-relevant data flows from benign ones. GCN treats all edges equally.
- **Architecture**: 773-dim input → 256 hidden (4 heads) → 128 output (4 heads) → classification + confidence heads.

### Decision 3: Conformal Prediction for Code Security (Feb 2026)
- **What**: Applied Adaptive Prediction Sets (APS) to the GNN output to get calibrated prediction sets with coverage guarantees.
- **Why**: First application of conformal prediction to vulnerability detection. Provides formal guarantee: P(true label in prediction set) >= 90%.
- **Cascade impact**: Singleton sets (e.g., {"safe"}) = resolved at Graph stage. Multi-label sets ({"safe", "vulnerable"}) = ambiguous, escalated to LLM.

### Decision 4: Dual-Agent LLM (Feb-Mar 2026)
- **What**: Two specialized LLM agents — Attacker (red team, exploit analysis) and Defender (blue team, sanitizer analysis) — with a consensus engine.
- **Why**: Single-LLM classification is biased. Adversarial framing maps naturally to security: one tries to break it, the other defends it. Research shows 20-40% accuracy improvement.
- **Protocol**: 4 consensus rules combining both verdicts into a final decision.

### Decision 5: Pivot to Full Interactive Tool (Feb 22, 2026)
- **What**: Shifted from "research prototype" to "polished interactive CLI tool" inspired by Claude Code's UX.
- **Why**: The user wanted a demo-worthy tool, not just a research script. Interactive mode with autocomplete, live metrics, HTML reports.
- **Impact**: Added Typer CLI, Rich console output, prompt-toolkit REPL, self-contained HTML dashboard.

### Decision 6: CWE-Adaptive Fusion Weights (Feb-Mar 2026)
- **What**: Different CWE categories get different weights for the score fusion formula `α·SAST + β·GAT + γ·LLM`.
- **Why**: Injection CWEs benefit most from LLM context understanding (LLM-heavy). Crypto CWEs are detectable by patterns alone (SAST-heavy). Memory CWEs need structural analysis (Graph-heavy).
- **Implementation**: Per-CWE weight table in `configs/cwe_weights.yaml`.

### Decision 7: CVSS v3.1 + Evidence Narratives (Mar 2026)
- **What**: Added CVSS v3.1 base score computation from LLM sub-metrics + plain-language evidence narratives for stakeholders.
- **Why**: Practical scoring (CVSS is industry standard) + XAI (explainability for non-technical stakeholders who need to understand why a finding matters).

---

## GNN Training Evolution

### V1: Juliet Test Suite Only (Mar 2026, Kaggle)
- **Dataset**: 54,147 samples, Juliet only, C/C++ and Java
- **Result**: 0.9999 Accuracy, 0.9999 F1
- **Problem**: Massively overfitted — Juliet is synthetic/templated code. Not generalizable.
- **Conformal**: 10% singletons, 90% ambiguous (threshold = 1.0)

### V2: Multi-Source Dataset (Mar 2026, Kaggle)
- **Dataset**: 11,339 samples from CVEfixes + DiverseVul + Devign + Juliet (5 languages)
- **Result**: 0.5705 Accuracy, 0.5601 F1 (realistic, not overfitted)
- **Problems identified**:
  - Early stopping on val_loss instead of val_F1 (stopped at epoch 18 while F1 still improving)
  - Focal Loss + class weights double-stacked (model collapsed to predict "vulnerable" for everything)
  - 100% ambiguous conformal prediction (0% singletons)

### V3-V4: Incremental Improvements (Mar-Apr 2026)
- V3: Additional dataset sources, architecture tweaks
- V4: 8 datasets attempted (3 failed to load: PrimeVul, VUDENC, CVEfixes), F1 ~0.78 but conformal still broken (0% singletons)

### V5: Planned Fix (Apr 2026)
- Remove label smoothing (compresses logit gaps, prevents confident predictions)
- Add temperature scaling (ConfTS) to sharpen softmax outputs
- Fix 3 broken dataset loaders
- Target: 20-40% singleton rate, making the cascade actually functional

---

## Current State (April 2026)

### What Works End-to-End
- Full cascade: SAST → Graph → LLM → Fusion → Report
- 24 findings on Python test cases, 75% resolved at SAST, 25% LLM-validated
- CVSS scoring: CWE-89 → 9.1 CRITICAL, CWE-79 → 6.1 MEDIUM, CWE-78 → 9.8 CRITICAL
- 287 tests passing
- 56 sample test cases across 5 languages with ground truth
- RAG: 200K+ NVD entries, 900+ CWE entries indexed
- Interactive CLI with autocomplete, HTML dashboard, SARIF output

### What's Pending
- GNN V5 training (fix conformal prediction singleton rate)
- Benchmark evaluation on OWASP Benchmark / CVEfixes test split
- Cross-language integration testing (currently deep-tested on Python only)
- Fusion weight empirical calibration
- Paper draft (methodology + evaluation sections)

---

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | 3.11+ |
| Data Models | Pydantic | v2 |
| SAST | Tree-sitter + CodeQL | 0.23+ / v2.0+ |
| Graph | Joern + NetworkX | v4.0 / 3.0+ |
| GNN | PyTorch + PyTorch Geometric | 2.0+ / 2.5+ |
| Embeddings | GraphCodeBERT | microsoft/graphcodebert-base |
| Conformal | TorchCP | 0.2+ |
| LLM | Gemini 2.5 (google-genai SDK) | 1.0+ |
| RAG | FAISS + BM25 | 1.7+ / 0.2+ |
| CLI | Typer + Rich + prompt-toolkit | 0.9+ / 13.0+ / 3.0+ |
| Output | SARIF OM + Jinja2 | 1.0+ / 3.0+ |

---

## File Structure Overview

```
sec-c/
├── src/
│   ├── sast/          # Module 1: SAST engine, uncertainty scoring, routing
│   ├── graph/         # Module 2: CPG, GNN, conformal prediction, slicing
│   ├── llm/           # Module 3: Agents, consensus, CVSS, RAG, prompts
│   ├── orchestrator/  # Pipeline coordinator, score fusion
│   ├── reporting/     # SARIF, HTML, console output
│   └── cli/           # Typer CLI, interactive REPL
├── configs/           # YAML configuration (thresholds, weights, models)
├── tests/             # Unit + integration tests (287 passing)
├── notebooks/         # GNN training notebooks (V1-V5)
├── sample_testcases/  # 56 test cases across 5 languages
├── docs/              # Documentation (this file + others)
├── Report/            # LaTeX reports (Phase 1 submitted, Phase 2 in progress)
└── scripts/           # Setup scripts (CodeQL, Joern, RAG)
```

---

## Supervisor and University

- **University**: Shiv Nadar University Chennai
- **Supervisor**: Dr. K.B. Sundharakumar
- **HOD**: Dr. T. Nagarajan
- **Branch**: Computer Science and Engineering (Cybersecurity)
- **Degree**: Bachelor of Technology
- **Team**: 3 members (Aditya B, Roahith R, Vishal Murugan DBS)
