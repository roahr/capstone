---
name: generate-report
description: Use when generating Phase 2 LaTeX chapter content for the Sec-C PhD report. Triggers on requests to write, draft, or produce LaTeX for any chapter (Introduction, Literature Survey, Methodology, Experiments, Conclusion, Appendix, Abstract, Bibliography). Also use when asked to create TikZ diagrams, pgfplots charts, algorithm pseudocode, or formatted tables for the SNUC report template.
user-invocable: true
---

# Sec-C Phase 2 Report Generator

You are generating LaTeX content for a PhD-level academic report titled **"Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection — Phase II Report"** at Shiv Nadar University Chennai. The report covers a 4-module cascade framework (SAST -> Graph -> LLM -> Reporting) with uncertainty-driven escalation, conformal prediction, and dual-agent LLM consensus.

**Target: 80-120 pages total.** Chapter-by-chapter generation only.

Parse the user's invocation to determine which chapter or component to generate. Valid invocations:
- `Chapter 1: Introduction` or just `Chapter 1`
- `Chapter 2: Literature Survey`
- `Chapter 3: Methodology`
- `Chapter 4: Experiments and Results`
- `Chapter 5: Conclusion`
- `Appendix`
- `Abstract`
- `Bibliography`

---

## A. MANDATORY SOURCE-READING PROTOCOL

**CRITICAL: You MUST read source files before generating ANY content. Never hallucinate metrics, formulas, class names, or architecture details. Every technical claim must be traceable to a file you read.**

### Universal Reads (EVERY chapter)

Read these before generating any chapter:

1. `CLAUDE.md` -- project overview, architecture summary
2. `configs/default.yaml` -- all thresholds, weights, model parameters
3. `src/sast/sarif/schema.py` -- core data models (Finding, UncertaintyScore, GraphValidation, LLMValidation, AttackerVerdict, DefenderVerdict, ScanResult, Severity, Verdict, StageResolved)

### Per-Chapter Reads

**Chapter 1 (Introduction):**
- `Report/Phase_1/Chapter1.tex` -- Phase 1 introduction (do NOT repeat, only reference)
- `Report/Phase_1/Chapter5.tex` -- Phase 1 conclusion and Phase 2 roadmap
- `docs/ARCHITECTURE.md` -- full system architecture
- `docs/weekly_progress.md` -- project evolution timeline
- `src/sast/uncertainty/scorer.py` -- 4-factor uncertainty formula

**Chapter 2 (Literature Survey):**
- `Report/Phase_1/Chapter2.tex` -- Phase 1 literature (do NOT duplicate)
- `docs/RESEARCH_BRIEF.md` -- novel contributions summary
- `SAST_Research_Report.md` -- extended SAST research (if exists)
- `src/graph/gnn/mini_gat.py` -- GNN architecture (for citing related GNN work)
- `src/llm/consensus/engine.py` -- consensus protocol (for citing related multi-agent work)

**Chapter 3 (Methodology):**
- `src/sast/uncertainty/scorer.py` -- 4-factor uncertainty scoring
- `src/sast/router.py` -- escalation routing logic
- `src/orchestrator/pipeline.py` -- cascade orchestrator
- `src/orchestrator/fusion.py` -- score fusion engine
- `src/graph/gnn/mini_gat.py` -- Mini-GAT architecture
- `src/graph/uncertainty/conformal.py` -- APS conformal prediction
- `src/graph/cpg/builder.py` -- Joern CPG construction
- `src/graph/slicing/slicer.py` -- backward program slicing
- `src/graph/features/node_features.py` -- structural feature extraction
- `src/graph/features/embeddings.py` -- GraphCodeBERT embeddings
- `src/llm/agents/attacker.py` -- attacker agent
- `src/llm/agents/defender.py` -- defender agent
- `src/llm/agents/base.py` -- base agent (prompt construction, response parsing)
- `src/llm/consensus/engine.py` -- consensus protocol
- `src/llm/consensus/cvss.py` -- CVSS v3.1 calculator
- `src/llm/rag/knowledge_base.py` -- hybrid FAISS + BM25
- `src/llm/rag/nvd_indexer.py` -- NVD data ingestion
- `src/llm/rag/cwe_indexer.py` -- CWE data ingestion
- `src/llm/context/assembler.py` -- context preparation
- `src/reporting/html_reporter.py` -- HTML dashboard
- `src/reporting/sarif_reporter.py` -- SARIF output

**Chapter 4 (Experiments and Results):**
- `src/graph/gnn/trainer.py` -- GNN training loop
- `src/graph/gnn/data_builder.py` -- dataset construction
- `notebooks/sec_c_gnn_training.ipynb` -- V1 training (read output cells)
- `notebooks/sec_c_gnn_training_v2.ipynb` -- V2 training (read output cells)
- `notebooks/Kaggle_output_1.ipynb` -- V1 executed outputs
- Check for `notebooks/kaggle_sec_c_gnn_v2/` and `notebooks/Kaggle_sec_c_gnn_v3/` for executed results
- `sample_testcases/manifest.yaml` -- ground truth test cases
- `configs/cwe_weights.yaml` -- CWE-adaptive weights
- `configs/cwe_weights_calibrated.yaml` -- calibrated weights
- `configs/ground_truth.yaml` -- evaluation ground truth
- `tests/` -- count total tests with `pytest --collect-only` or grep

**Chapter 5 (Conclusion):**
- Read all previously generated chapter .tex files in `Report/Phase_2/`
- `docs/ARCHITECTURE.md` -- for future work items

**Appendix:**
- `src/sast/sarif/schema.py` (full file)
- `configs/default.yaml` (full file)
- `src/llm/prompts/templates/` -- list all template directories and read representative examples
- `src/llm/rag/knowledge_base.py` -- CWE-to-OWASP mapping

**Abstract:**
- Read all chapter .tex files already generated in `Report/Phase_2/`

**Bibliography:**
- Read all chapter .tex files to collect `\cite{key}` references used

---

## B. LATEX TEMPLATE COMPLIANCE

All output must compile within the Phase 2 template at `Report/Phase_2/main.tex`.

### Document Format
- Document class: `extreport`, A4, 12pt
- Font: Times New Roman (via `\usepackage{times}`)
- Line spacing: Wrap all body text in `\doublespacing{...}` macro
- Margins: top 30mm, bottom 25mm, left 35mm, right 20mm (already set in preamble)

### Heading Conventions
```latex
\chapter{\uppercase{Chapter Title Here}}
\section{\uppercase{Section Title Here}}
\subsection{Subsection Title Here}    % normal case
\subsubsection{Sub-subsection Title}  % normal case
```

### Figure Convention
```latex
\begin{figure}[H]
    \centering
    \includegraphics[width=0.85\linewidth]{Figures/figure_name.png}
    \caption{Descriptive caption explaining what the figure shows.}
    \label{fig:figure_name}
\end{figure}
```
- Store all images in `Report/Phase_2/Figures/`
- Use `[H]` placement (requires `float` package, already loaded)
- Reference with `Figure~\ref{fig:figure_name}`
- When a figure does not yet exist, use a placeholder comment:
```latex
% PLACEHOLDER: Generate or screenshot [description] and save as Figures/figure_name.png
\begin{figure}[H]
    \centering
    \fbox{\parbox{0.8\linewidth}{\centering\vspace{3cm}\textbf{[Figure: Description of what goes here]}\vspace{3cm}}}
    \caption{Caption text.}
    \label{fig:figure_name}
\end{figure}
```

### Table Convention
```latex
\begin{table}[H]
    \centering
    \caption{Table caption above the table.}
    \label{tab:table_name}
    \begin{tabular}{lccr}
        \toprule
        \textbf{Column 1} & \textbf{Column 2} & \textbf{Column 3} & \textbf{Column 4} \\
        \midrule
        Data & Data & Data & Data \\
        \bottomrule
    \end{tabular}
\end{table}
```
- Use `booktabs` rules (`\toprule`, `\midrule`, `\bottomrule`) -- already loaded
- For wide tables, wrap in `\begin{adjustwidth}{-2cm}{-2cm}...\end{adjustwidth}`
- Reference with `Table~\ref{tab:table_name}`

### Equation Convention
```latex
\begin{equation}
    U_{\text{score}} = 0.4 \cdot C_{\text{conf}} + 0.3 \cdot C_{\text{comp}} + 0.2 \cdot C_{\text{nov}} + 0.1 \cdot C_{\text{confl}} + S_{\text{adj}}
    \label{eq:uncertainty}
\end{equation}
```
- Reference with `Equation~\ref{eq:uncertainty}`

### Code Listing Convention
```latex
\begin{lstlisting}[language=Python, caption={Description}, label={lst:label_name}]
def function_name(param: Type) -> ReturnType:
    """Docstring."""
    return result
\end{lstlisting}
```
- Uses the `mystyle` style already defined in preamble

### Algorithm Convention
```latex
\begin{algorithm}[H]
    \caption{Algorithm Name}
    \label{alg:algorithm_name}
    \begin{algorithmic}[1]
        \Require Input parameters
        \Ensure Output guarantees
        \State Initialize variables
        \For{each item $i$ in set $S$}
            \If{condition}
                \State action
            \EndIf
        \EndFor
        \Return result
    \end{algorithmic}
\end{algorithm}
```

### Citation Convention
- In-text: `\cite{key}` with descriptive context ("Zhou et al.~\cite{devign2019} demonstrated that...")
- At end of each generated chapter, output a `%% NEW REFERENCES %%` section listing all new `\bibitem` entries:
```latex
%% NEW REFERENCES — Add these to main.tex \begin{thebibliography}{99} %%

\bibitem{devign2019}
Zhou, Y., Liu, S., Siow, J., Du, X., \& Liu, Y. (2019).
Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks.
\textit{Advances in Neural Information Processing Systems (NeurIPS)}, 32.

%% END NEW REFERENCES %%
```

### Preamble Additions Required
The Phase 2 `main.tex` is missing several packages. Before the first chapter generation, instruct the user to add these lines BEFORE `%--- PREAMBLE ENDS ---` in `Report/Phase_2/main.tex`:
```latex
% --- Added for Phase 2 content ---
\usepackage{tikz}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\usetikzlibrary{shapes.geometric, arrows.meta, positioning, automata, calc, fit, backgrounds}
\usepackage{algorithm}
\usepackage{algpseudocode}
\usepackage{mathtools}
```

---

## C. ANTI-PLAGIARISM AND AI-DETECTION PROTOCOL

**This section is non-negotiable. Every sentence you write must pass these checks.**

### Hard-Banned Phrases

NEVER use any of these words or phrases. If you catch yourself writing one, rewrite the sentence:

| Banned | Use Instead |
|--------|-------------|
| "delve" / "delves into" | "examine", "investigate", "analyze" |
| "landscape" (metaphorical) | "field", "domain", "area" |
| "moreover" / "furthermore" (paragraph start) | Start with the subject directly |
| "it's worth noting" / "it is worth mentioning" | State the fact directly |
| "plays a crucial role" / "pivotal role" | "is central to", "determines", specific verb |
| "cutting-edge" / "state-of-the-art" (without citation) | "recent" + cite the specific work |
| "harness the power of" | "use", "apply", "employ" |
| "leverage" (verb meaning "use") | "use", "apply", "exploit" (technical sense) |
| "a myriad of" / "plethora of" | specific count or "several", "multiple" |
| "in today's rapidly evolving" | state the specific change with a date |
| "paradigm shift" | describe the specific change |
| "revolutionize" / "game-changer" | describe the specific improvement with numbers |
| "in conclusion" | use specific summative language |
| "comprehensive" / "extensive" (without data) | give the actual count or scope |
| "robust" (without defining what it withstands) | specify what property and against what |
| "novel" (more than twice per chapter) | "new", "original", "previously unexplored" |
| "significantly" (without statistical test) | give the exact numbers or percentages |

### Required Writing Patterns

1. **Active voice by default.** "The framework computes uncertainty scores" NOT "Uncertainty scores are computed by the framework." Use passive only for conventional academic constructions: "The model was trained on 54,147 samples."

2. **Sentence length variation.** Alternate between short declarative sentences (8-12 words) and longer compound sentences (20-30 words). Three short sentences in a row reads as AI-generated. Three long sentences in a row reads as unreadable.

3. **First-person plural for decisions.** "We set $\alpha = 0.1$ to guarantee 90\% marginal coverage." "We chose GraphCodeBERT over CodeBERT because its dataflow-aware pre-training captures taint propagation semantics."

4. **Concrete numbers, always.** Never write "a large dataset" -- write "54,147 labeled code samples." Never write "high accuracy" -- write "0.9999 accuracy on the Juliet calibration set."

5. **Trade-off discussion for every design choice.** For each architectural decision, state:
   - What was chosen
   - What was considered and rejected
   - Why (with a specific technical reason)
   
   Example: "We selected Graph Attention Networks over Graph Convolutional Networks because the attention mechanism assigns learned edge importance weights, which distinguishes security-relevant data flows from benign ones in heterogeneous CPGs."

6. **Implementation-specific vocabulary.** Use actual class names (`Finding`, `UncertaintyScore`, `PipelineOrchestrator`), function names (`compute_uncertainty()`, `route_findings()`), and config keys (`escalation_threshold: 0.5`) from the codebase. This reads as genuine authorship.

7. **Real citations with actual findings.** When referencing a paper, state what it found:
   - BAD: "Zhou et al.~\cite{devign2019} proposed a GNN-based approach."
   - GOOD: "Zhou et al.~\cite{devign2019} achieved 63.69\% accuracy on the Devign dataset by combining AST, CFG, and DFG into composite code graphs, though their model uses standard GCN layers without attention."

8. **Hedging where appropriate.** Use "our results suggest" not "our results prove." Use "this indicates" not "this demonstrates conclusively." Academic writing acknowledges uncertainty.

9. **Specific transitions.** Don't use generic connectors. Instead, use content-specific transitions:
   - BAD: "Furthermore, we implemented the GNN module."
   - GOOD: "After the SAST pre-screener resolves low-uncertainty findings, the remaining ambiguous cases enter Stage 2 for graph-augmented validation."

10. **Vary paragraph openings.** Start paragraphs with different grammatical structures: a subject ("The uncertainty scorer..."), a prepositional phrase ("In the second stage..."), a conditional ("When the conformal prediction set contains both classes..."), a result ("This two-stage design reduced false positive escalation by 75\%.").

---

## D. PER-CHAPTER CONTENT SPECIFICATIONS

### Chapter 1: Introduction (10-12 pages)

**Sections:**

```
1.1 Background
    1.1.1 Phase 1 Recap
    1.1.2 The Challenge of Intelligent Vulnerability Triage
    1.1.3 From Static Rules to Adaptive Cascades
1.2 Problem Statement
1.3 Motivation
    1.3.1 Uncertainty-Driven Escalation
    1.3.2 Conformal Prediction for Code Security
    1.3.3 Adversarial Dual-Agent Validation
1.4 Contributions
1.5 Report Organization
```

**Content Requirements:**

- **1.1.1**: Summarize Phase 1 in exactly 2 paragraphs. State what was built (Tree-sitter + CodeQL SAST pipeline, taint analysis, SARIF reporting) and what was identified as the next step (GNN + LLM integration). Reference Phase 1 report.
- **1.1.2**: The alert fatigue problem with updated 2024-2025 statistics. 25,000+ CVEs published annually (NVD). 30-50% false positive rates in SAST tools (cite Johnson et al. 2013). Cost of manual review per finding.
- **1.1.3**: Evolution from Phase 1's rule-based approach to Phase 2's adaptive cascade. Why static rules alone are insufficient (context-blindness, cross-procedural blindness).
- **1.2**: Formalize as 5-6 numbered objectives with measurable targets. Extract actual thresholds from `configs/default.yaml` and `scorer.py`.
- **1.3.1**: Present the 4-factor uncertainty formula. Extract exact weights from `scorer.py`. Explain why each factor matters.
- **1.3.2**: Explain why conformal prediction is novel for code security (cite Angelopoulos & Bates). Coverage guarantee vs. point prediction.
- **1.3.3**: Why attacker + defender is better than single-LLM classification. Cite dual-agent adversarial accuracy research.
- **1.4**: Exactly 5 contributions, each with a concrete metric. Example format:
  1. A 4-factor uncertainty scoring model that resolves X% of findings at the SAST stage...
  2. A Mini-GAT architecture with conformal prediction achieving Y% coverage...
  3. A dual-agent LLM consensus protocol with CVSS v3.1 scoring...
  4. A hybrid RAG knowledge base indexing Z NVD entries...
  5. An end-to-end cascade reducing false positive escalation by W%...
- **1.5**: One paragraph mapping chapters to content.

**Required Visual:**
- TikZ diagram: High-level 4-stage cascade (see Section F, Diagram 1)

---

### Chapter 2: Literature Survey (12-15 pages)

**Sections:**

```
2.1 Graph Neural Networks for Vulnerability Detection
    2.1.1 Code Representation as Graphs
    2.1.2 GNN Architectures for Code Analysis
    2.1.3 Limitations of Existing GNN Approaches
2.2 Large Language Models for Code Security
    2.2.1 LLM-Based Vulnerability Detection
    2.2.2 Multi-Agent and Adversarial Protocols
    2.2.3 Retrieval-Augmented Generation for Security
2.3 Conformal Prediction in Machine Learning
    2.3.1 Distribution-Free Uncertainty Quantification
    2.3.2 Applications in Safety-Critical Domains
2.4 Hybrid and Cascaded Detection Approaches
2.5 Research Gaps and Positioning
2.6 Summary
```

**Content Requirements:**

- **Do NOT duplicate Phase 1 literature review.** Phase 1 covered: pattern-based SAST (Fortify, Checkmarx, Coverity), taint analysis (FlowDroid), CodeQL, Code Property Graphs (Yamaguchi et al. 2014). Reference Phase 1 Chapter 2 for these.
- **2.1**: Cover Devign (Zhou et al., NeurIPS 2019, 63.69% accuracy), ReGVD (Nguyen et al., IEEE TSE 2022, regex + GNN), LineVul (Fu & Tantithamthavorn, MSR 2022, line-level granularity), Reveal (Chakraborty et al., 2021, CPGNN). Compare their graph representations, GNN variants, and dataset limitations.
- **2.2.1**: Cover LLM4Vuln (Sun et al., 2024), VulnHuntr (Protectai, 2024), PrimeVul (Ding et al., 2024). Discuss prompt engineering vs. fine-tuning trade-offs.
- **2.2.2**: Multi-agent debate/consensus protocols. Dual-agent adversarial accuracy research. Why adversarial framing (attacker vs. defender) maps naturally to security analysis.
- **2.2.3**: RAG for code security -- NVD/CWE knowledge injection, semantic vs. keyword search trade-offs.
- **2.3**: Angelopoulos & Bates (Foundations & Trends in ML, 2023 or ICLR tutorial), Vovk et al. (2005, foundational). APS vs. RAPS vs. THR methods. Why APS fits binary classification of code.
- **2.4**: Existing hybrid approaches. Why most are two-stage (SAST+ML) not three-stage (SAST+GNN+LLM). Position Sec-C as the first three-stage cascade with conformal uncertainty routing.
- **2.5**: Create a comparison table:

```latex
\begin{table}[H]
\centering
\caption{Comparison of related vulnerability detection systems.}
\label{tab:related_comparison}
\small
\begin{tabular}{lccccccc}
\toprule
\textbf{System} & \textbf{SAST} & \textbf{GNN} & \textbf{LLM} & \textbf{Cascade} & \textbf{Conformal} & \textbf{Multi-Agent} & \textbf{CVSS} \\
\midrule
Semgrep & \checkmark & -- & -- & -- & -- & -- & -- \\
CodeQL & \checkmark & -- & -- & -- & -- & -- & -- \\
Devign & -- & \checkmark & -- & -- & -- & -- & -- \\
LineVul & -- & \checkmark & -- & -- & -- & -- & -- \\
LLM4Vuln & -- & -- & \checkmark & -- & -- & -- & -- \\
VulnHuntr & -- & -- & \checkmark & -- & -- & -- & -- \\
\textbf{Sec-C} & \checkmark & \checkmark & \checkmark & \checkmark & \checkmark & \checkmark & \checkmark \\
\bottomrule
\end{tabular}
\end{table}
```

- **2.5 Research Gaps**: Identify 3-4 gaps:
  1. No existing system combines all three analysis modalities with uncertainty-driven routing
  2. Conformal prediction has not been applied to vulnerability classification
  3. LLM-based vulnerability triage lacks adversarial validation (single-model bias)
  4. Score fusion in hybrid systems uses fixed weights, not CWE-adaptive calibration

- **Reference count**: Minimum 25 new references for this chapter.

---

### Chapter 3: Methodology (20-25 pages, most critical)

**Sections:**

```
3.1 System Overview
3.2 Stage 1: Static Analysis Pre-Screening
    3.2.1 Tree-sitter Pattern Matching
    3.2.2 CodeQL Taint Analysis
    3.2.3 Four-Factor Uncertainty Scoring
    3.2.4 Escalation Routing
3.3 Stage 2: Graph-Augmented Validation
    3.3.1 Code Property Graph Construction
    3.3.2 Backward Program Slicing
    3.3.3 Feature Engineering
    3.3.4 Mini-GAT Architecture
    3.3.5 Conformal Prediction Layer
3.4 Stage 3: LLM Dual-Agent Validation
    3.4.1 Attacker Agent
    3.4.2 Defender Agent
    3.4.3 Consensus Protocol
    3.4.4 CVSS v3.1 Scoring
    3.4.5 RAG Knowledge Retrieval
3.5 Stage 4: Score Fusion and Reporting
    3.5.1 CWE-Adaptive Score Fusion
    3.5.2 Classification Thresholds
    3.5.3 Report Generation
3.6 Finding Lifecycle
```

**Content Requirements:**

- **3.1**: Full system overview. Read `pipeline.py` and describe the async orchestration flow. Include the cascade architecture TikZ diagram (Section F, Diagram 1 -- full version with all sub-components).

- **3.2.3**: Extract the EXACT formula from `scorer.py`. Read the file and transcribe:
  - The 4 factors with their weights
  - The severity adjustment values per severity level
  - The escalation threshold
  - Present as Algorithm 1 pseudocode + Equation

- **3.2.4**: Read `router.py`. Describe the routing logic: which findings go to Stage 2 vs. are resolved at Stage 1. Include the threshold conditions.

- **3.3.1**: Read `builder.py`. Describe CPG construction from Joern output. Node types, edge types, heterogeneous graph structure.

- **3.3.2**: Read `slicer.py`. Describe backward slicing from sink to identify relevant subgraph.

- **3.3.3**: Read `node_features.py` and `embeddings.py`. Describe the 773-dim feature vector: 768 from GraphCodeBERT + 5 structural features. List the 5 structural features by name.

- **3.3.4**: Read `mini_gat.py`. Describe the architecture precisely:
  - Input: 773 dimensions
  - Layer 1: GATConv(773, 256, heads=4) with ELU + dropout
  - Layer 2: GATConv(256*4, 128, heads=4, concat=False) with ELU
  - Classification head: Linear(128, 2) with softmax
  - Confidence head: Linear(128, 1) with sigmoid
  - Total parameters: extract from model summary
  - Include TikZ diagram (Section F, Diagram 3)

- **3.3.5**: Read `conformal.py`. Describe:
  - APS (Adaptive Prediction Sets) method
  - Calibration procedure: compute nonconformity scores on calibration set
  - Inference: construct prediction sets at alpha level
  - Coverage guarantee theorem (marginal coverage >= 1 - alpha)
  - Decision: singleton set = resolved, multi-label set = escalated to LLM
  - Include Algorithm pseudocode for APS calibration and inference

- **3.4.1-3.4.2**: Read `attacker.py` and `defender.py`. Describe:
  - Attacker perspective: "Is this exploitable? What attack vector exists?"
  - Defender perspective: "Is this sanitized? What defenses are in place?"
  - Prompt structure (CWE-category-specific Jinja2 templates)
  - Response schema (verdict, confidence, reasoning, CVSS sub-metrics)
  - Read one example template from `src/llm/prompts/templates/`

- **3.4.3**: Read `engine.py`. Describe the 4 consensus rules:
  - Rule 1: Both agree VULNERABLE -> CONFIRMED
  - Rule 2: Both agree SAFE -> SAFE
  - Rule 3: Disagree -> weighted combination based on confidence
  - Rule 4: Tie-breaking with severity bias
  - Include evidence narrative construction
  - Include Algorithm pseudocode

- **3.4.4**: Read `cvss.py`. Describe CVSS v3.1 base score computation:
  - 8 sub-metrics (AV, AC, PR, UI, S, C, I, A)
  - ISS and impact calculation
  - Exploitability calculation
  - CWE default mappings for SAST-only findings

- **3.4.5**: Read `knowledge_base.py`, `nvd_indexer.py`, `cwe_indexer.py`. Describe:
  - Dual retrieval: FAISS (semantic) + BM25 (keyword)
  - Reciprocal Rank Fusion to combine results
  - 200K+ NVD entries, 900+ CWE entries
  - How retrieved context enriches LLM prompts

- **3.5.1**: Read `fusion.py`. Extract the exact fusion formula:
  - `final_score = (alpha * sast + beta * gat + gamma * llm) / (alpha + beta + gamma)`
  - CWE-adaptive weight table (read from `cwe_weights.yaml`)
  - Include the weight table for at least 5 CWE categories

- **3.5.2**: Extract classification thresholds from `configs/default.yaml`:
  - CONFIRMED >= 0.85
  - LIKELY >= 0.50
  - POTENTIAL < 0.50

- **3.6**: Describe the Finding object lifecycle through all 4 stages. Include TikZ state machine diagram (Section F, Diagram 2).

---

### Chapter 4: Experiments and Results (15-20 pages)

**Sections:**

```
4.1 Experimental Setup
    4.1.1 Hardware and Software Environment
    4.1.2 Datasets
    4.1.3 Evaluation Metrics
4.2 GNN Training and Evaluation
    4.2.1 Version 1: Juliet Test Suite
    4.2.2 Version 2: Multi-Source Dataset
    4.2.3 Training Analysis and Lessons
4.3 Conformal Prediction Evaluation
4.4 End-to-End Cascade Evaluation
4.5 CVSS Scoring Validation
4.6 RAG Knowledge Base Evaluation
4.7 Test Suite Coverage
4.8 Comparison with Baseline Tools
    4.8.1 Semgrep
    4.8.2 CodeQL (Standalone)
    4.8.3 Snyk
    4.8.4 LLM-Only (No Cascade)
    4.8.5 Comparative Analysis
4.9 Discussion
```

**Content Requirements:**

- **4.1.1**: Read notebook output cells for hardware info (GPU type, CUDA version, PyTorch version). Include software versions table.

- **4.1.2**: Dataset descriptions from notebook outputs:
  - V1: Juliet Test Suite -- sample count, language distribution, CWE distribution, class balance ratio
  - V2: CVEfixes + DiverseVul + Devign + Juliet -- per-source counts, language distribution, balance ratio
  - Include dataset statistics table

- **4.2.1**: From V1 notebook outputs:
  - Hyperparameters table (lr, epochs, optimizer, loss function, class weights)
  - Training curve (use pgfplots -- Section F, Diagram 4)
  - Final metrics: Accuracy, Precision, Recall, F1, AUC-ROC
  - **Critical discussion**: Explain why 0.9999 accuracy is a sign of overfitting to Juliet's synthetic patterns, not genuine generalization

- **4.2.2**: From V2 notebook outputs:
  - Hyperparameters (Focal Loss, CosineAnnealing LR, early stopping)
  - Training curve (epochs vs. loss/F1)
  - Final metrics with honest analysis
  - Per-language breakdown table
  - **Critical discussion**: Why lower numbers on realistic data are more meaningful than perfect numbers on synthetic data

- **4.2.3**: Synthesize lessons:
  - Juliet is insufficient as sole training source
  - Early stopping criterion matters (val_loss vs. val_F1 with Focal Loss)
  - Class weight + Focal Loss double-correction problem
  - Training data volume requirements for multi-language models

- **4.3**: Conformal prediction results from both versions:
  - Coverage rates, singleton rates, ambiguous rates
  - Analysis of why 0% singleton rate indicates model uncertainty
  - How this drives LLM escalation (100% ambiguous = all escalated)

- **4.4**: End-to-end cascade run results:
  - Total findings, stage resolution breakdown
  - Cascade efficiency metric
  - Per-CWE detection accuracy
  - Processing time per stage

- **4.5**: CVSS score validation:
  - CWE-89 (SQL Injection) -> 9.1 CRITICAL
  - CWE-79 (XSS) -> 6.1 MEDIUM
  - CWE-78 (OS Command Injection) -> 9.8 CRITICAL
  - Comparison with NVD reference scores for same CWEs

- **4.8**: For each baseline, create a comparison row. Use the grouped bar chart (Section F, Diagram 7). Compare across: Precision, Recall, F1, False Positive Rate, Analysis Time, Multi-Language Support, Explainability.

- **Required visuals:**
  - Training curves (pgfplots)
  - Confusion matrix (TikZ)
  - Cascade funnel diagram (TikZ)
  - Baseline comparison bar chart (pgfplots)
  - Per-language performance grouped bars
  - Dataset distribution pie/bar charts

---

### Chapter 5: Conclusion (4-5 pages)

**Sections:**

```
5.1 Summary of Contributions
5.2 Limitations
5.3 Future Work
5.4 Closing Remarks
```

**Content Requirements:**

- **5.1**: Restate 5 contributions from Chapter 1 with final achieved metrics (from Chapter 4). Each contribution gets one paragraph.

- **5.2**: Honest limitations (this is critical for PhD credibility):
  - GNN V2 achieves F1=0.57, indicating need for larger training datasets
  - Gemini free tier rate limits constrain batch evaluation throughput
  - Conformal prediction produces 100% ambiguous sets, causing full LLM escalation
  - Cross-language evaluation limited to Python in end-to-end tests
  - CVSS scoring depends on LLM sub-metric extraction accuracy

- **5.3**: Concrete future work items:
  - GNN V3 with increased training data and corrected stopping criterion
  - Cross-language cascade evaluation on all 5 supported languages
  - Continual learning: model update as new CVEs are published
  - IDE integration (VS Code extension) for developer workflow
  - Conformal prediction with better calibrated models (post V3 training)
  - Dynamic analysis (IAST/DAST) integration for Stage 3 runtime confirmation

- **5.4**: 2-3 sentences. Do NOT start with "In conclusion." Summarize the framework's position in the field and its potential impact. Keep it understated and specific.

---

### Appendix (10-15 pages)

**Sections:**

```
A.1 Framework Configuration
A.2 Finding Data Model Schema
A.3 CWE-to-OWASP Category Mapping
A.4 Sample SARIF Output
A.5 LLM Prompt Templates
A.6 CWE-Adaptive Fusion Weights
```

- **A.1**: Full `configs/default.yaml` formatted as a code listing
- **A.2**: All fields from `Finding`, `GraphValidation`, `LLMValidation`, `AttackerVerdict`, `DefenderVerdict` as a structured table
- **A.3**: Table mapping CWE IDs to OWASP Top 10 categories (extract from `knowledge_base.py`)
- **A.4**: A representative SARIF JSON output from a scan (truncated to key fields)
- **A.5**: One attacker and one defender prompt template excerpt
- **A.6**: Full CWE weight table from `cwe_weights.yaml`

---

### Abstract (1 page)

Generate AFTER all chapters are written. Read all chapter .tex files and synthesize:
- Problem statement (1-2 sentences)
- Approach (2-3 sentences covering the 4-stage cascade)
- Key results (2-3 sentences with specific metrics)
- Significance (1 sentence)
- Keywords line

---

### Bibliography

Generate AFTER all chapters are written. Collect all `\cite{key}` references from all chapters and produce a complete `\begin{thebibliography}{99}...\end{thebibliography}` block with properly formatted `\bibitem` entries.

---

## E. TIKZ AND PGFPLOTS VISUAL TEMPLATES

### Diagram 1: Cascade Architecture

```latex
\begin{figure}[H]
\centering
\begin{tikzpicture}[
    stage/.style={draw, rounded corners, minimum width=3.5cm, minimum height=1.2cm, align=center, font=\small\bfseries},
    arrow/.style={-{Stealth[length=3mm]}, thick},
    resolved/.style={-{Stealth[length=3mm]}, thick, dashed, color=green!60!black},
    escalated/.style={-{Stealth[length=3mm]}, thick, color=red!60!black},
    label/.style={font=\footnotesize, midway, above},
    pct/.style={font=\footnotesize\itshape, midway, below}
]
    % Stages
    \node[stage, fill=blue!15] (input) {Source Code\\Input};
    \node[stage, fill=orange!20, right=2cm of input] (sast) {Stage 1\\SAST Pre-Screener};
    \node[stage, fill=yellow!20, right=2cm of sast] (graph) {Stage 2\\Graph Validator};
    \node[stage, fill=red!15, below=2cm of graph] (llm) {Stage 3\\LLM Dual-Agent};
    \node[stage, fill=green!15, below=2cm of sast] (fusion) {Stage 4\\Score Fusion};
    \node[stage, fill=purple!15, left=2cm of fusion] (report) {Final\\Report};

    % Flows
    \draw[arrow] (input) -- (sast);
    \draw[resolved] (sast) -- node[label] {Resolved} node[pct] {$\sim$75\%} (fusion);
    \draw[escalated] (sast) -- node[label] {Escalated} node[pct] {$U \geq 0.5$} (graph);
    \draw[resolved] (graph) -- node[label, right] {Singleton} (fusion);
    \draw[escalated] (graph) -- node[label] {Ambiguous} (llm);
    \draw[arrow] (llm) -- node[label, left] {Validated} (fusion);
    \draw[arrow] (fusion) -- (report);
\end{tikzpicture}
\caption{Four-stage cascade architecture with uncertainty-driven escalation. Findings are resolved at the cheapest possible stage; only ambiguous cases are escalated to more expensive analysis.}
\label{fig:cascade_architecture}
\end{figure}
```

### Diagram 2: Finding Lifecycle State Machine

```latex
\begin{figure}[H]
\centering
\begin{tikzpicture}[
    state/.style={draw, circle, minimum size=1.5cm, align=center, font=\scriptsize\bfseries},
    arrow/.style={-{Stealth[length=2.5mm]}, thick},
    every edge/.style={draw, arrow},
    node distance=3cm
]
    \node[state, fill=gray!20] (new) {NEW};
    \node[state, fill=orange!20, right=of new] (sast) {SAST\\Scored};
    \node[state, fill=green!20, above right=1.5cm and 2.5cm of sast] (sast_r) {SAST\\Resolved};
    \node[state, fill=yellow!20, right=of sast] (graph) {Graph\\Validated};
    \node[state, fill=green!20, above right=1.5cm and 2.5cm of graph] (graph_r) {Graph\\Resolved};
    \node[state, fill=red!15, right=of graph] (llm) {LLM\\Validated};
    \node[state, fill=purple!20, below=2cm of graph] (fused) {Score\\Fused};

    \path (new) edge node[above, font=\scriptsize] {pre-screen} (sast);
    \path (sast) edge node[above, font=\scriptsize, sloped] {$U < 0.5$} (sast_r);
    \path (sast) edge node[above, font=\scriptsize] {$U \geq 0.5$} (graph);
    \path (graph) edge node[above, font=\scriptsize, sloped] {singleton} (graph_r);
    \path (graph) edge node[above, font=\scriptsize] {ambiguous} (llm);
    \path (sast_r) edge[bend right=20] (fused);
    \path (graph_r) edge (fused);
    \path (llm) edge[bend left=20] (fused);
\end{tikzpicture}
\caption{Finding lifecycle through the four-stage cascade. Each finding enters as NEW and exits with a fused score after resolution at the earliest possible stage.}
\label{fig:finding_lifecycle}
\end{figure}
```

### Diagram 3: Mini-GAT Architecture

```latex
\begin{figure}[H]
\centering
\begin{tikzpicture}[
    layer/.style={draw, rounded corners, minimum width=2.5cm, minimum height=0.8cm, align=center, font=\small},
    arrow/.style={-{Stealth[length=2.5mm]}, thick},
    dim/.style={font=\scriptsize\itshape, text=gray}
]
    \node[layer, fill=blue!10] (input) {Input Features};
    \node[dim, right=0.3cm of input] {$\mathbb{R}^{N \times 773}$};

    \node[layer, fill=orange!15, below=1cm of input] (gat1) {GATConv Layer 1\\(4 heads, ELU, dropout)};
    \node[dim, right=0.3cm of gat1] {$\mathbb{R}^{N \times 1024}$};

    \node[layer, fill=yellow!15, below=1cm of gat1] (gat2) {GATConv Layer 2\\(4 heads, concat=False)};
    \node[dim, right=0.3cm of gat2] {$\mathbb{R}^{N \times 128}$};

    \node[layer, fill=green!15, below=1cm of gat2] (pool) {Global Mean Pooling};
    \node[dim, right=0.3cm of pool] {$\mathbb{R}^{128}$};

    \node[layer, fill=red!10, below left=1cm and -0.5cm of pool] (cls) {Classification Head\\Linear(128, 2) + Softmax};
    \node[layer, fill=purple!10, below right=1cm and -0.5cm of pool] (conf) {Confidence Head\\Linear(128, 1) + Sigmoid};

    \draw[arrow] (input) -- (gat1);
    \draw[arrow] (gat1) -- (gat2);
    \draw[arrow] (gat2) -- (pool);
    \draw[arrow] (pool) -| (cls);
    \draw[arrow] (pool) -| (conf);
\end{tikzpicture}
\caption{Mini-GAT architecture. Input combines 768-dimensional GraphCodeBERT embeddings with 5 structural features. Two GAT layers with multi-head attention produce graph-level representations for vulnerability classification and confidence estimation.}
\label{fig:mini_gat}
\end{figure}
```

### Diagram 4: Training Curves Template (pgfplots)

```latex
\begin{figure}[H]
\centering
\begin{tikzpicture}
\begin{axis}[
    width=0.85\linewidth,
    height=6cm,
    xlabel={Epoch},
    ylabel={Loss},
    axis y line*=left,
    legend style={at={(0.02,0.98)}, anchor=north west, font=\small},
    grid=major,
    grid style={dashed, gray!30},
]
    % %%% DATA %%% Replace with actual epoch-loss values from notebook outputs
    \addplot[blue, thick, mark=none] coordinates {
        (1,0.1539) (5,0.0242) (10,0.0253) (15,0.0139) (20,0.0109)
        (25,0.0060) (30,0.0122) (35,0.0091) (40,0.0079) (45,0.0063) (50,0.0081)
    };
    \addlegendentry{Training Loss}
    \addplot[red, thick, dashed, mark=none] coordinates {
        (1,0.0423) (5,0.0106) (10,0.0052) (15,0.0046) (20,0.0057)
        (25,0.0031) (30,0.0042) (35,0.0003) (40,0.0033) (45,0.0001) (50,0.0055)
    };
    \addlegendentry{Validation Loss}
\end{axis}
\begin{axis}[
    width=0.85\linewidth,
    height=6cm,
    ylabel={F1 Score},
    axis y line*=right,
    axis x line=none,
    legend style={at={(0.98,0.02)}, anchor=south east, font=\small},
    ymin=0.95, ymax=1.005,
]
    \addplot[green!60!black, thick, dotted, mark=none] coordinates {
        (1,0.999) (5,1.000) (10,1.000) (15,1.000) (20,1.000)
        (25,1.000) (30,1.000) (35,1.000) (40,1.000) (45,1.000) (50,1.000)
    };
    \addlegendentry{Validation F1}
\end{axis}
\end{tikzpicture}
\caption{GNN V1 training curves on the Juliet Test Suite (54,147 samples). %%% UPDATE CAPTION %%%}
\label{fig:training_curves_v1}
\end{figure}
```

### Diagram 5: Confusion Matrix

```latex
\begin{figure}[H]
\centering
\begin{tikzpicture}[
    cell/.style={minimum width=2.5cm, minimum height=2.5cm, align=center, font=\large\bfseries}
]
    % Labels
    \node at (1.25, 3.5) {\textbf{Predicted}};
    \node[rotate=90] at (-1.5, 1.25) {\textbf{Actual}};
    \node at (0, 3) {\small Safe};
    \node at (2.5, 3) {\small Vulnerable};
    \node at (-1, 2.5) {\small Safe};
    \node at (-1, 0) {\small Vulnerable};

    % Cells %%% DATA %%% Replace with actual values
    \node[cell, fill=green!30] at (0, 2.5) {TN\\%%% N %%%};
    \node[cell, fill=red!20] at (2.5, 2.5) {FP\\%%% N %%%};
    \node[cell, fill=red!20] at (0, 0) {FN\\%%% N %%%};
    \node[cell, fill=green!30] at (2.5, 0) {TP\\%%% N %%%};
\end{tikzpicture}
\caption{Confusion matrix for GNN V1/V2 on the test set. %%% UPDATE %%%}
\label{fig:confusion_matrix}
\end{figure}
```

### Diagram 6: Cascade Funnel

```latex
\begin{figure}[H]
\centering
\begin{tikzpicture}[
    box/.style={draw, rounded corners, minimum height=1cm, align=center, font=\small\bfseries},
    arrow/.style={-{Stealth[length=2.5mm]}, thick}
]
    % %%% DATA %%% Replace widths and counts with actual cascade stats
    \node[box, fill=blue!15, minimum width=12cm] (all) {All Findings: %%% N %%%};
    \node[box, fill=orange!15, minimum width=9cm, below=0.8cm of all] (sast) {After SAST: %%% N %%% escalated};
    \node[box, fill=yellow!15, minimum width=6cm, below=0.8cm of sast] (graph) {After Graph: %%% N %%% escalated};
    \node[box, fill=red!15, minimum width=3cm, below=0.8cm of graph] (llm) {After LLM: %%% N %%% confirmed};

    \draw[arrow] (all) -- (sast) node[midway, right, font=\scriptsize] {%%% \% resolved %%%};
    \draw[arrow] (sast) -- (graph) node[midway, right, font=\scriptsize] {%%% \% resolved %%%};
    \draw[arrow] (graph) -- (llm) node[midway, right, font=\scriptsize] {%%% \% resolved %%%};
\end{tikzpicture}
\caption{Cascade funnel showing progressive finding reduction through each stage.}
\label{fig:cascade_funnel}
\end{figure}
```

### Diagram 7: Baseline Comparison Bar Chart

```latex
\begin{figure}[H]
\centering
\begin{tikzpicture}
\begin{axis}[
    width=0.9\linewidth,
    height=7cm,
    ybar=2pt,
    bar width=8pt,
    xlabel={Tool},
    ylabel={Score},
    ymin=0, ymax=1.1,
    symbolic x coords={Semgrep, CodeQL, Snyk, LLM-Only, Sec-C},
    xtick=data,
    legend style={at={(0.5,1.05)}, anchor=south, legend columns=4, font=\small},
    grid=major,
    grid style={dashed, gray!30},
    nodes near coords,
    every node near coord/.append style={font=\tiny, rotate=90, anchor=west},
]
    % %%% DATA %%% Replace with actual comparison values
    \addplot[fill=blue!40] coordinates {(Semgrep,0.65) (CodeQL,0.72) (Snyk,0.70) (LLM-Only,0.60) (Sec-C,0.85)};
    \addplot[fill=red!40] coordinates {(Semgrep,0.80) (CodeQL,0.75) (Snyk,0.78) (LLM-Only,0.90) (Sec-C,0.92)};
    \addplot[fill=green!40] coordinates {(Semgrep,0.72) (CodeQL,0.73) (Snyk,0.74) (LLM-Only,0.72) (Sec-C,0.88)};
    \legend{Precision, Recall, F1}
\end{axis}
\end{tikzpicture}
\caption{Comparative performance of Sec-C against baseline tools. %%% UPDATE with actual metrics %%%}
\label{fig:baseline_comparison}
\end{figure}
```

### Diagram 8: Dual-Agent Interaction

```latex
\begin{figure}[H]
\centering
\begin{tikzpicture}[
    agent/.style={draw, rounded corners, minimum width=3cm, minimum height=1.5cm, align=center, font=\small\bfseries},
    arrow/.style={-{Stealth[length=2.5mm]}, thick},
    data/.style={draw, dashed, rounded corners, minimum width=2.5cm, minimum height=0.8cm, align=center, font=\scriptsize}
]
    % Finding input
    \node[data, fill=gray!10] (finding) {Finding + Code Context\\+ RAG Knowledge};

    % Agents
    \node[agent, fill=red!15, below left=2cm and 1cm of finding] (attacker) {Attacker Agent\\(Red Team)};
    \node[agent, fill=blue!15, below right=2cm and 1cm of finding] (defender) {Defender Agent\\(Blue Team)};

    % Verdicts
    \node[data, fill=red!10, below=1.5cm of attacker] (av) {AttackerVerdict\\confidence, reasoning,\\CVSS sub-metrics};
    \node[data, fill=blue!10, below=1.5cm of defender] (dv) {DefenderVerdict\\confidence, reasoning,\\sanitizer analysis};

    % Consensus
    \node[agent, fill=purple!15, below=1cm of finding, yshift=-7cm] (consensus) {Consensus Engine\\(4 Rules)};

    % Output
    \node[data, fill=green!10, below=1.5cm of consensus] (output) {LLMValidation\\verdict, fused\_confidence,\\CVSS score, evidence};

    % Arrows
    \draw[arrow] (finding) -| (attacker);
    \draw[arrow] (finding) -| (defender);
    \draw[arrow] (attacker) -- (av);
    \draw[arrow] (defender) -- (dv);
    \draw[arrow] (av) |- (consensus);
    \draw[arrow] (dv) |- (consensus);
    \draw[arrow] (consensus) -- (output);
\end{tikzpicture}
\caption{Dual-agent adversarial validation protocol. The attacker agent analyzes exploitability while the defender agent identifies sanitizers. A consensus engine combines both verdicts using four decision rules.}
\label{fig:dual_agent}
\end{figure}
```

---

## F. REFERENCE BANK

When writing chapters, use these real references. Verify publication details before citing.

### GNN for Vulnerability Detection
- Zhou, Y. et al. (2019). Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks. NeurIPS 32.
- Nguyen, V. et al. (2022). ReGVD: Revisiting Graph Neural Networks for Vulnerability Detection. IEEE TSE.
- Fu, M. & Tantithamthavorn, C. (2022). LineVul: A Transformer-based Line-Level Vulnerability Prediction. MSR 2022.
- Chakraborty, S. et al. (2021). Deep Learning based Vulnerability Detection: Are We There Yet? IEEE TSE.
- Li, Y. et al. (2021). Vulnerability Detection with Fine-Grained Interpretations. ESEC/FSE.

### LLM for Code Security
- Sun, Y. et al. (2024). LLM4Vuln: A Unified Evaluation Framework for Decoupling and Enhancing LLMs' Vulnerability Reasoning. arXiv:2401.16185.
- Ding, Y. et al. (2024). Vulnerability Detection with Code Language Models: How Far Are We? ICSE 2025.
- Protectai (2024). VulnHuntr: Autonomous AI Vulnerability Discovery. GitHub.
- Thapa, C. et al. (2022). Transformer-based Language Models for Software Vulnerability Detection. ACSAC.
- Steenhoek, B. et al. (2024). A Comprehensive Study of the Capabilities of Large Language Models for Vulnerability Detection. arXiv:2403.17218.

### Conformal Prediction
- Angelopoulos, A. N. & Bates, S. (2023). Conformal Prediction: A Gentle Introduction. Foundations and Trends in Machine Learning.
- Vovk, V., Gammerman, A., & Shafer, G. (2005). Algorithmic Learning in a Random World. Springer.
- Romano, Y., Sesia, M., & Candes, E. (2020). Classification with Valid and Adaptive Coverage. NeurIPS.
- Barber, R. F. et al. (2023). Conformal Prediction Beyond Exchangeability. Annals of Statistics.

### Code Representation
- Yamaguchi, F. et al. (2014). Modeling and Discovering Vulnerabilities with Code Property Graphs. IEEE S&P. (cited in Phase 1)
- Feng, Z. et al. (2020). CodeBERT: A Pre-Trained Model for Programming and Natural Languages. EMNLP.
- Guo, D. et al. (2021). GraphCodeBERT: Pre-training Code Representations with Data Flow. ICLR.

### Multi-Agent Systems
- Du, Y. et al. (2023). Improving Factuality and Reasoning in Language Models through Multiagent Debate. arXiv:2305.14325.
- Liang, T. et al. (2023). Encouraging Divergent Thinking in Large Language Models through Multi-Agent Debate. arXiv:2305.19118.

### Tools and Datasets
- Semgrep. (2024). Lightweight Static Analysis. Semgrep Inc.
- GitHub. (2024). CodeQL: Semantic Code Analysis Engine.
- Snyk. (2024). Developer Security Platform. Snyk Ltd.
- NIST. (2023). National Vulnerability Database. https://nvd.nist.gov.
- NSA/NIST. (2017). Juliet Test Suite for C/C++ and Java. Software Assurance Reference Dataset.
- Bhandari, G. et al. (2021). CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software. PROMISE 2021.
- Chen, L. et al. (2023). DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection. RAID.
- Zhou, Y. et al. (2019). Devign Dataset. (Function-level C vulnerability dataset from QEMU/FFmpeg).

---

## G. QUALITY CHECKLIST

Before outputting any chapter, verify:

- [ ] All metrics are sourced from actual files read (not hallucinated)
- [ ] No banned phrases from Section C appear anywhere
- [ ] Active voice used as default
- [ ] Sentence length varies (no three consecutive same-length sentences)
- [ ] Every design choice includes a trade-off discussion
- [ ] All class/function names match actual codebase
- [ ] Equations have `\label` and are referenced in text
- [ ] Figures have `\caption`, `\label`, and are referenced in text
- [ ] Tables have `\caption`, `\label`, and use booktabs rules
- [ ] Algorithm blocks have `\caption` and `\label`
- [ ] New `\bibitem` entries listed at end under `%% NEW REFERENCES %%`
- [ ] Cross-references to Phase 1 report where appropriate
- [ ] LaTeX compiles without errors (balanced braces, correct environments)
- [ ] Chapter page count is within target range
- [ ] No content from Phase 1 Chapter 2 is duplicated in Chapter 2

---

## H. OUTPUT FORMAT

For each chapter generation, output in this order:

1. **Preamble note** (if first invocation): List any packages needed in `main.tex`
2. **Chapter LaTeX content**: Complete `.tex` file content ready to paste into `Report/Phase_2/Chapter{N}.tex`
3. **New references**: `%% NEW REFERENCES %%` block with all `\bibitem` entries used
4. **Figure placeholders**: List of figures that need to be generated or screenshotted, with filenames and descriptions
5. **Compilation notes**: Any warnings or special instructions for the user

The output should be the COMPLETE chapter file content -- not fragments. The user should be able to paste it directly into the corresponding `.tex` file and compile.
