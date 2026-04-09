# Sec-C: Report Writing Guide

> How to write the Phase 2 PhD report. Covers chapter structure, anti-plagiarism rules, LaTeX conventions, visual elements, and reference bank.
> For anyone on the team who needs to write or review report content.

---

## Report Overview

| Property | Value |
|----------|-------|
| Title | Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection — Phase II Report |
| University | Shiv Nadar University Chennai |
| Supervisor | Dr. K.B. Sundharakumar |
| Branch | CSE (Cybersecurity) |
| Target length | 80-120 pages |
| LaTeX template | `Report/Phase_2/main.tex` |
| Phase 1 reference | `Report/Phase_1/` (submitted Nov 2025) |

---

## Chapter Structure and Page Targets

| Chapter | Title | Pages | Focus |
|---------|-------|-------|-------|
| 1 | Introduction | 10-12 | Background, problem statement, motivation, 5 contributions |
| 2 | Literature Survey | 12-15 | GNNs, LLMs, conformal prediction, multi-agent — NEW lit only |
| 3 | Methodology | 20-25 | Complete 4-stage cascade design (most critical chapter) |
| 4 | Experiments and Results | 15-20 | GNN training, cascade evaluation, CVSS, baselines |
| 5 | Conclusion | 4-5 | Contributions, limitations, future work |
| — | Appendix | 10-15 | Configuration, schema, SARIF samples, prompt templates |
| — | Abstract | 1 | Write LAST (after all chapters) |
| — | Bibliography | 2-3 | 25-30 new references minimum |

---

## Anti-Plagiarism and AI Detection Rules

### Banned Phrases (Never Use)

| Phrase | Why It's Flagged | Use Instead |
|--------|-----------------|-------------|
| "delve" / "delves into" | Top AI-detection signal | "examine", "investigate", "analyze" |
| "landscape" (metaphor) | ChatGPT crutch word | "field", "domain", "area" |
| "moreover" / "furthermore" (paragraph start) | Generic filler | Start with the subject directly |
| "it's worth noting" | AI padding | State the fact directly |
| "plays a crucial/pivotal role" | Vague inflation | "determines", "controls", specific verb |
| "cutting-edge" / "state-of-the-art" | Without citation = flagged | "recent" + cite the specific work |
| "harness the power of" | Marketing speak | "use", "apply", "employ" |
| "leverage" (verb = "use") | Corporate jargon | "use", "apply", "exploit" (technical) |
| "a myriad of" / "plethora of" | ChatGPT vocabulary | Specific count or "several", "multiple" |
| "in today's rapidly evolving" | Cliched opener | State the specific change with a date |
| "paradigm shift" | Overused buzzword | Describe the specific change |
| "revolutionize" / "game-changer" | Hyperbole | Describe improvement with numbers |
| "in conclusion" | AI closing signal | Use specific summative language |
| "comprehensive" / "extensive" (without data) | Empty claim | Give the actual count or scope |
| "robust" (without defining what it withstands) | Vague adjective | Specify the property and threat |
| "novel" (more than 2x per chapter) | Over-claiming | "new", "original", "previously unexplored" |
| "significantly" (without statistical test) | Unsubstantiated | Give exact numbers/percentages |

### Required Writing Patterns

1. **Active voice default**: "The framework computes..." not "X is computed by..."
2. **Passive only for conventions**: "The model was trained on..." (standard academic)
3. **Sentence length variation**: Mix 8-12 word short with 20-30 word compound. No three same-length in a row.
4. **First person plural**: "We set alpha to 0.1 because..." "We chose GAT over GCN because..."
5. **Concrete numbers always**: "54,147 samples" not "a large dataset". "287 tests" not "extensive testing".
6. **Trade-off discussion**: Every design choice must state what was chosen, what was rejected, and why.
7. **Codebase vocabulary**: Use actual names — `Finding`, `UncertaintyScore`, `PipelineOrchestrator`, `compute_uncertainty()`.
8. **Real citations with findings**: "Zhou et al. achieved 63.69% accuracy on Devign" not "Zhou et al. proposed a GNN approach".
9. **Hedging**: "Our results suggest..." not "Our results prove..."
10. **Varied paragraph openings**: Subject, prepositional phrase, conditional, result — vary the structure.

---

## LaTeX Conventions (Phase 2 Template)

### Document Setup
```latex
\documentclass[a4paper, 12pt]{extreport}
\usepackage{times}       % Times New Roman
% Body text wrapped in \doublespacing{...}
% Margins: top=30mm, bottom=25mm, left=35mm, right=20mm
```

### Headings
```latex
\chapter{\uppercase{Chapter Title}}
\section{\uppercase{Section Title}}
\subsection{Subsection Title}          % normal case
\subsubsection{Sub-subsection Title}   % normal case
```

### Figures
```latex
\begin{figure}[H]
    \centering
    \includegraphics[width=0.85\linewidth]{Figures/figure_name.png}
    \caption{Descriptive caption.}
    \label{fig:figure_name}
\end{figure}
```
Reference: `Figure~\ref{fig:figure_name}`

### Tables
```latex
\begin{table}[H]
    \centering
    \caption{Caption above table.}
    \label{tab:table_name}
    \begin{tabular}{lccr}
        \toprule
        \textbf{Col 1} & \textbf{Col 2} \\
        \midrule
        Data & Data \\
        \bottomrule
    \end{tabular}
\end{table}
```

### Equations
```latex
\begin{equation}
    U = 0.4 \cdot C_{\text{conf}} + 0.3 \cdot C_{\text{comp}} + 0.2 \cdot C_{\text{nov}} + 0.1 \cdot C_{\text{confl}} + S_{\text{adj}}
    \label{eq:uncertainty}
\end{equation}
```

### Code Listings
```latex
\begin{lstlisting}[language=Python, caption={Description}, label={lst:label}]
def compute_uncertainty(finding: Finding) -> UncertaintyScore:
    ...
\end{lstlisting}
```

### Algorithms
```latex
\begin{algorithm}[H]
    \caption{Algorithm Name}
    \label{alg:name}
    \begin{algorithmic}[1]
        \Require inputs
        \Ensure outputs
        \State do something
    \end{algorithmic}
\end{algorithm}
```

### Citations
```latex
Zhou et al.~\cite{devign2019} achieved 63.69\% accuracy...
```
Output `\bibitem` entries at end of each chapter for adding to `main.tex`.

---

## Visual Elements Needed

### Required Diagrams (TikZ)

| Diagram | Chapter | What It Shows |
|---------|---------|---------------|
| Cascade Architecture | Ch 1, 3 | 4-stage flow with escalation paths and percentages |
| Finding Lifecycle | Ch 3 | State machine: NEW → SAST/Graph/LLM resolved → Fused |
| Mini-GAT Architecture | Ch 3 | Neural network layers (773→256→128→2 + confidence) |
| Dual-Agent Interaction | Ch 3 | Attacker + Defender → Consensus Engine → Verdict |
| Training Curves | Ch 4 | Loss/F1 over epochs (dual y-axis pgfplots) |
| Confusion Matrix | Ch 4 | TP/FP/TN/FN colored grid |
| Cascade Funnel | Ch 4 | Progressive filtering (100% → 25% → 5%) |
| Baseline Comparison | Ch 4 | Grouped bars: Precision/Recall/F1 per tool |

### Image Placeholders

For screenshots and generated figures that need to be added manually:
- HTML dashboard screenshot
- CLI scan output screenshot
- Interactive REPL screenshot
- SARIF JSON sample
- RAG retrieval example

Use placeholder format:
```latex
% PLACEHOLDER: [Description] → save as Figures/filename.png
\begin{figure}[H]
    \centering
    \fbox{\parbox{0.8\linewidth}{\centering\vspace{3cm}
    \textbf{[Figure: Description]}\vspace{3cm}}}
    \caption{Caption.}
    \label{fig:label}
\end{figure}
```

---

## Reference Bank (30+ Sources)

### GNN for Vulnerability Detection
1. Zhou, Y. et al. (2019). **Devign**: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks. *NeurIPS 32*. [F1=63.69% on Devign dataset]
2. Nguyen, V. et al. (2022). **ReGVD**: Revisiting Graph Neural Networks for Vulnerability Detection. *IEEE TSE*. [Regex+GNN hybrid]
3. Fu, M. & Tantithamthavorn, C. (2022). **LineVul**: A Transformer-based Line-Level Vulnerability Prediction. *MSR 2022*. [Line-level granularity]
4. Chakraborty, S. et al. (2021). Deep Learning based Vulnerability Detection: Are We There Yet? *IEEE TSE*. [CPGNN, honest evaluation]
5. Li, Y. et al. (2021). Vulnerability Detection with Fine-Grained Interpretations. *ESEC/FSE*.

### LLM for Code Security
6. Sun, Y. et al. (2024). **LLM4Vuln**: A Unified Evaluation Framework for Decoupling and Enhancing LLMs' Vulnerability Reasoning. *arXiv:2401.16185*.
7. Ding, Y. et al. (2024). Vulnerability Detection with Code Language Models: How Far Are We? *ICSE 2025*. [PrimeVul: 3.09% F1 on realistic data]
8. Protectai (2024). **VulnHuntr**: Autonomous AI Vulnerability Discovery. *GitHub*.
9. Thapa, C. et al. (2022). Transformer-based Language Models for Software Vulnerability Detection. *ACSAC*.
10. Steenhoek, B. et al. (2024). A Comprehensive Study of LLMs for Vulnerability Detection. *arXiv:2403.17218*.

### Conformal Prediction
11. Angelopoulos, A.N. & Bates, S. (2023). Conformal Prediction: A Gentle Introduction. *Foundations and Trends in ML*.
12. Vovk, V., Gammerman, A., & Shafer, G. (2005). Algorithmic Learning in a Random World. *Springer*.
13. Romano, Y., Sesia, M., & Candes, E. (2020). Classification with Valid and Adaptive Coverage. *NeurIPS*.
14. Barber, R.F. et al. (2023). Conformal Prediction Beyond Exchangeability. *Annals of Statistics*.

### Code Representation
15. Yamaguchi, F. et al. (2014). Modeling and Discovering Vulnerabilities with Code Property Graphs. *IEEE S&P*. [CPG foundation]
16. Feng, Z. et al. (2020). **CodeBERT**: A Pre-Trained Model for Programming and Natural Languages. *EMNLP*.
17. Guo, D. et al. (2021). **GraphCodeBERT**: Pre-training Code Representations with Data Flow. *ICLR*. [768-dim, data-flow aware]

### Multi-Agent Systems
18. Du, Y. et al. (2023). Improving Factuality and Reasoning through Multiagent Debate. *arXiv:2305.14325*.
19. Liang, T. et al. (2023). Encouraging Divergent Thinking through Multi-Agent Debate. *arXiv:2305.19118*.

### Tools
20. Semgrep (2024). Lightweight Static Analysis. *Semgrep Inc.*
21. GitHub (2024). **CodeQL**: Semantic Code Analysis Engine.
22. Snyk (2024). Developer Security Platform. *Snyk Ltd.*
23. NIST (2023). National Vulnerability Database. *nvd.nist.gov*.

### Datasets
24. NSA/NIST (2017). **Juliet Test Suite** for C/C++ and Java.
25. Bhandari, G. et al. (2021). **CVEfixes**: Automated Collection of Vulnerabilities and Their Fixes. *PROMISE 2021*.
26. Chen, L. et al. (2023). **DiverseVul**: A New Vulnerable Source Code Dataset. *RAID*.
27. Zhou, Y. et al. (2019). **Devign Dataset**. (Function-level C from QEMU/FFmpeg).
28. Fan, J. et al. (2020). **BigVul**: A C/C++ Code Vulnerability Dataset with Code Changes. *MSR 2020*.

### Industry Reports
29. Johnson, B. et al. (2013). Why Don't Software Developers Use Static Analysis Tools to Find Bugs? *ICSE*. [30-50% FP, developer non-adoption]
30. Ghost Security (2025). AI SAST False Positive Analysis. [91% FP across 3,000 repos]

---

## Chapter-by-Chapter Content Guide

### Chapter 1: Introduction
- **Do**: Recap Phase 1 in 2 paragraphs, present 5 contributions with metrics
- **Don't**: Repeat Phase 1 content. Just reference it.
- **Include**: Uncertainty formula, cascade overview diagram, contribution list with numbers
- **Read**: `docs/PROJECT_EVOLUTION.md`, `docs/NOVEL_CONTRIBUTIONS.md`

### Chapter 2: Literature Survey
- **Do**: Cover GNNs, LLMs, conformal prediction, multi-agent systems — all NEW
- **Don't**: Duplicate Phase 1 lit review (SAST tools, CPGs, taint analysis already covered)
- **Include**: Comparison table (Sec-C vs 7+ systems), research gap identification
- **Read**: `docs/NOVEL_CONTRIBUTIONS.md`, `docs/GNN_TRAINING_RESULTS.md`

### Chapter 3: Methodology
- **Do**: Full technical design of all 4 stages with formulas from actual code
- **Don't**: Hallucinate any numbers — read the source files
- **Include**: 4+ algorithm pseudocode blocks, 4+ TikZ diagrams, complete data model
- **Read**: `docs/SYSTEM_DATA_MODEL.md`, `docs/TECHNICAL_METRICS.md`

### Chapter 4: Experiments
- **Do**: Present V1 and V2 GNN results honestly, with critical analysis
- **Don't**: Hide V2's lower numbers — frame them as honest evaluation
- **Include**: Training curves, confusion matrices, per-language tables, baseline comparison
- **Read**: `docs/GNN_TRAINING_RESULTS.md`, `docs/TECHNICAL_METRICS.md`

### Chapter 5: Conclusion
- **Do**: Restate contributions with final metrics, honest limitations
- **Don't**: Start with "In conclusion." Use specific summative language.
- **Include**: 5 limitations, 6 future work items
- **Read**: `docs/NOVEL_CONTRIBUTIONS.md` (limitations section)

---

## Baseline Comparison Tools

For Chapter 4 (Section 4.8), compare Sec-C against:

| Tool | Type | What to Compare |
|------|------|----------------|
| Semgrep | Open-source SAST | Pattern-based, no ML, fast |
| CodeQL (standalone) | Open-source SAST | Taint analysis, no ML, deep |
| Snyk | Commercial SAST | Mixed analysis, proprietary ML |
| LLM-only (no cascade) | Experimental | Gemini on raw code, no SAST/Graph pre-filtering |
| Sec-C (full cascade) | This work | All 4 stages with uncertainty routing |

Compare across: Precision, Recall, F1, False Positive Rate, Analysis Time, Multi-Language Support, Explainability, Cost.

---

## Quick Reference: Where to Find What

| I need... | Read this file |
|-----------|---------------|
| Project timeline, decisions, pivots | `docs/PROJECT_EVOLUTION.md` |
| All numbers, formulas, thresholds | `docs/TECHNICAL_METRICS.md` |
| GNN training data (V1/V2 epoch tables) | `docs/GNN_TRAINING_RESULTS.md` |
| Data model, pipeline flow, consensus rules | `docs/SYSTEM_DATA_MODEL.md` |
| Novel contributions, research gaps, comparison | `docs/NOVEL_CONTRIBUTIONS.md` |
| Writing rules, chapter specs, references | `docs/REPORT_WRITING_GUIDE.md` (this file) |
| Full architecture deep-dive | `docs/ARCHITECTURE.md` |
| Live demo commands and talking points | `docs/hehe.md` |
| Weekly progress for mentor meetings | `docs/weekly_progress.md` |
| Research brief for publications | `docs/RESEARCH_BRIEF.md` |
| Report generation agent skill | `.claude/skills/generate-report.md` |
