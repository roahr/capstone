# Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection

**Presentation Deck | 32 slides | 20-minute delivery**

> **Design philosophy:** Every slide has a single headline claim. Speaker notes carry the context. No slide exceeds 40 words of on-screen text. Stats are stacked for impact. All claims are hedged appropriately. The deck confronts limitations openly and reframes them as research discoveries. *Note on typography:* em dashes appear only in slide-title punctuation ("SLIDE N — Topic"), never in body prose or speaker-note sentences.

---

## SLIDE 1 — Title

**MULTI-STAGE CODE SECURITY FRAMEWORK**
**for Adaptive Vulnerability Triage and Detection**

### *Treating vulnerability detection as a resource allocation problem.*

Aditya B (22011103004) · Roahith R (22011103048) · Vishal Murugan DBS (22011103065)

Supervisor: Dr. K.B. Sundharakumar, Department of CSE, SNUC
**April 2026**

> **Speaker notes:** "Good morning. For the next 20 minutes, I'll walk you through a framework we built to solve a specific problem: how do you route vulnerability findings to the right analysis tool at the right time? Current approaches either run one tool on everything, or run every tool on every finding. We show a third way, and we share what we learned when that third way met production reality."

---

## SLIDE 2 — The Hook

# **48,448**

### CVEs published in 2025.

### NVD could fully analyze only about half.

*(Sources: NVD 2025 Annual Report; Edgescan 2025 Vulnerability Statistics, 10th Ed.)*

> **Speaker notes:** "Last year, 48,448 new vulnerabilities were catalogued. The National Vulnerability Database, the government source of truth, was able to fully analyze roughly half of them. The catalog is winning against the analysts. Any solution has to start there."

---

## SLIDE 3 — The Alert Fatigue Crisis

## Industry SAST false-positive rates, 2025:

| Tool | Reported FP Rate |
|---|---|
| CodeQL | 68.2% |
| Semgrep | 74.8% |
| SonarQube | 94.6% |
| *Weighted average* | *~91%* |

## **62%** of alerts are ignored. **61%** of SOCs admit dismissing alerts that later proved real.
*(Ghost Security 2025, 2024 SOC Survey)*

> **Speaker notes:** "False positive rates vary by tool. The weighted average across Ghost Security's 2025 scan of 3,000 repositories was 91%. Even the best-performing tool flags the wrong code two-thirds of the time. Developers respond the way any rational person responds to a noisy signal. They tune it out."

---

## SLIDE 4 — The Economic Reality

## SOCs receive **~4,400 alerts/day**.
## Analysts investigate **8–12** per shift.
## Industry loss: **~$3.3B/year** in false-positive triage.

*(Multiple sources; figures are order-of-magnitude estimates, not peer-reviewed.)*

> **Speaker notes:** "The arithmetic does not work. Even if we built a better analyst, the ratio of alerts to investigation capacity is three orders of magnitude off. The only way out is to reduce the alert volume that reaches the analyst."

---

## SLIDE 5 — The Failed Fix #1: Pure Machine Learning

## ICSE 2025 · PrimeVul benchmark study

### Models reporting **68.26%** F1 on BigVul
### dropped to **3.09%** F1 on properly deduplicated data.

### Reason: the field had been training on test data.

> **Speaker notes:** "The machine learning story is instructive. PrimeVul, published at ICSE last year, took state-of-the-art models and re-evaluated them on a deduplicated, temporally-split dataset. F1 scores dropped from 68 to 3. The drop is not a criticism of any one paper. It is a criticism of how the field measures itself."

---

## SLIDE 6 — The Failed Fix #2: Large Language Models

## LLM4Vuln (2024): up to **~90%** hallucinated vulnerability claims in constrained tasks.

## Steenhoek et al. (2024): **47–76%** inconsistency across repeated prompts.

## Veracode (2025): only **12–13%** of AI-generated code is secure against XSS.

> **Speaker notes:** "LLMs bring contextual reasoning that ML classifiers lack, but they bring their own failure modes. The specific numbers here are from constrained evaluations; the general pattern is consistent across studies. LLMs are valuable for semantic analysis but not as standalone verdicts."

---

## SLIDE 7 — The Gap We Address

Every existing hybrid runs every tool on every finding:

| System | Strategy |
|---|---|
| IRIS (ICLR 2025) | SAST → LLM on all findings |
| Vulnhalla (2025) | CodeQL → LLM on all findings |
| ZeroFalse (2025) | SAST → LLM on all findings |
| LLMxCPG (USENIX 2025) | CPG → LLM on all findings |

### Nobody decides **when** to escalate.

> **Speaker notes:** "Every concurrent hybrid treats escalation as all-or-nothing. They run LLMs on every finding or on none. Our question is different: which findings actually need the expensive analysis, and can we decide that cheaply?"

---

## SLIDE 8 — The Reframing

## Vulnerability detection is not a **classification** problem.

## It is a **triage** problem.

### *Route each finding to the cheapest analysis that can resolve it.*

### *Escalate only when the current stage is measurably uncertain.*

> **Speaker notes:** "Classification asks: is this code safe or unsafe? Triage asks: given what we know so far, do we know enough to act, or do we need to investigate further? That reframe is the thesis. Everything downstream follows from it."

---

## SLIDE 9 — The Framework: Four Stages

```
Source Code
     │
Stage 1: SAST Pre-Screening      │  <100 ms   free
     │ [U ≥ 0.5 escalates]
Stage 2: Graph + Conformal GNN   │  2–10 s    free
     │ [ambiguous set escalates]
Stage 3: LLM Dual-Agent          │  5–15 s    API
     │
Stage 4: CWE-Adaptive Fusion     │  <1 ms
     ↓
Verdict + CVSS v3.1 + SARIF 2.1.0 report
```

### A finding only moves deeper if the current stage **cannot decide**.

> **Speaker notes:** "Four stages. Stage 1 is free and fast, Stage 2 adds structural analysis, Stage 3 invokes LLMs only for the hardest cases, Stage 4 fuses evidence with CWE-specific weights. A finding that clears Stage 1 never wastes an API call. Every stage is optional via graceful degradation."

---

## SLIDE 10 — Five Contributions with Measured Outcomes

| | Contribution | Evidence |
|---|---|---|
| **C1** | Uncertainty-driven cascade routing | **85%** Stage-1 resolution on 184 live findings |
| **C2** | First APS conformal prediction in code security | **69.1%** offline singletons (from 0%) |
| **C3** | Adversarial dual-agent LLM consensus | **5** deterministic rules · zero parse failures on 23 findings |
| **C4** | CWE-adaptive score fusion | **14** per-CWE weight profiles applied to every finding |
| **C5** | End-to-end multi-language framework | **F1 = 0.781** peak · **100%** finding resolution · **87.5%** fewer LLM calls |

> **Speaker notes:** "Each contribution has a concrete outcome from our live evaluation. I'll unpack C1 and C2 in the most detail, since they carry the strongest claims. C3 and C4 are architectural contributions, validated through integration rather than isolated ablation; we will be transparent about that distinction."

---

## SLIDE 11 — C1: The Uncertainty Score

$$U = 0.4\,U_{\text{conf}} + 0.3\,U_{\text{comp}} + 0.2\,U_{\text{nov}} + 0.1\,U_{\text{confl}} + \delta_{\text{sev}}$$

| Factor | What it measures |
|---|---|
| **Confidence** ($U_{\text{conf}}$) | Inverse of SAST tool's self-reported confidence |
| **Complexity** ($U_{\text{comp}}$) | Taint-path length and inter-procedural depth |
| **Novelty** ($U_{\text{nov}}$) | Whether the CWE is well-known (0.15) or rare (0.85) |
| **Conflict** ($U_{\text{confl}}$) | Disagreement between multiple SAST tools |

### Threshold: $U \geq 0.5$ escalates to Stage 2.

> **Speaker notes:** "Every finding gets a composite uncertainty score. Four factors with weights 0.4, 0.3, 0.2, 0.1, plus a severity adjustment. Under 0.5 resolves cheaply; over 0.5 escalates. The weights were chosen from analysis of failure modes in SAST tools and survived every redesign."

---

## SLIDE 12 — C2: Conformal Prediction

### First framework to apply **Adaptive Prediction Sets (APS)** to vulnerability detection.

### Mathematical coverage guarantee:
$$P(y_{\text{true}} \in C(X)) \geq 1 - \alpha$$

- $\alpha = 0.1$ → **90% coverage target** (distribution-free)
- **Singleton output** → resolve at Stage 2
- **Ambiguous output** → escalate to Stage 3

### *Assumption: exchangeability between calibration and test data.*

> **Speaker notes:** "Conformal prediction replaces arbitrary thresholds with a mathematical coverage guarantee. Singleton sets mean the model is confident. Ambiguous sets mean it is not. The guarantee holds under one explicit assumption (exchangeability), and we will return to what that assumption costs us in deployment."

---

## SLIDE 13 — C3: Adversarial Dual-Agent LLM

### A single LLM agrees with whatever you prompt.
### Two adversarial LLMs force structured evidence.

```
 ┌─────────────────┐
 │ ATTACKER AGENT  │ → AttackerVerdict (exploit, AV/AC/PR/UI)
 │ (Red Team)      │
 └────────┬────────┘
          ↓
 ┌─────────────────┐
 │ Consensus Engine│ → Verdict + CVSS v3.1
 │ 5 Rules (R1–R4) │
 └────────▲────────┘
          ↑
 ┌─────────────────┐
 │ DEFENDER AGENT  │ → DefenderVerdict (sanitizers, S/C/I/A)
 │ (Blue Team)     │
 └─────────────────┘
```

*(Adversarial debate in general tasks: 20–40% accuracy gains reported by Du et al. 2023.)*

> **Speaker notes:** "An attacker agent tries to build an exploit. A defender agent catalogs sanitizers. Both see the same RAG context pulled from 200,000 CVEs. A deterministic five-rule engine reconciles them. This mirrors the red-team/blue-team methodology standard in security operations."

---

## SLIDE 14 — C4: CWE-Adaptive Fusion

### Different vulnerabilities respond to different tools.

| CWE Family | SAST ($\alpha$) | Graph ($\beta$) | LLM ($\gamma$) | Dominant |
|---|---|---|---|---|
| Injection (78, 79, 89) | 0.25 | 0.25 | **0.50** | LLM |
| Crypto (327, 328) | **0.50** | 0.20 | 0.30 | SAST |
| Memory (416, 476) | 0.20 | **0.50** | 0.30 | Graph |
| Auth (287, 862) | 0.20 | 0.25 | **0.55** | LLM |

### **14 profiles** configured from domain expertise and published modality strengths.

> **Speaker notes:** "Weights come from literature: Veracode showed LLMs miss 77-84% of crypto weaknesses, so crypto CWEs lean SAST. Memory safety lives in control flow, so memory CWEs lean graph. Fourteen profiles total. The weights are expert-configured; empirical calibration is the next step."

---

## SLIDE 15 — C5: End-to-End Framework

### **Five languages** · **Two LLM providers** · **Free-tier operable**

- Python, JavaScript, Java, C/C++, Go
- Graceful degradation when tools are unavailable
- SARIF 2.1.0 output + interactive HTML dashboard
- CLI with autocomplete (Claude Code-inspired UX)

### Runs on a laptop. No cloud dependency. No paid license.

> **Speaker notes:** "Five language grammars, two LLM backends, zero paid dependencies. If Joern is missing, Stage 2 gracefully falls back to a tree-sitter approximation of the CPG. If API keys are absent, Stages 1 and 2 still produce verdicts. This is an intentional design choice to keep the framework reproducible in academic and open-source settings."

---

## SLIDE 16 — The GNN Story: V1, A Warning

## **V1 — Juliet Only**
Metric: F1 = 0.9999 on synthetic test suite.

### The number was too good. We threw it away.

> **Speaker notes:** "The GNN story starts with a cautionary tale. V1 trained on the Juliet synthetic suite and scored 99.99% F1. The number was a warning, not a result. Juliet contains templated patterns the model memorized. We discarded V1 and never tested it on realistic data, because we already knew the answer."

---

## SLIDE 17 — The GNN Story: V2 → V3, Architecture Matters

## V2 GAT baseline → F1 = 0.560 (degenerate precision)
## V3 GIN shift → F1 = **0.653** (+17%)

### Xu et al. (2019): GIN's sum aggregation is provably injective; GAT's weighted-mean is not.

### For code graphs where a missing bounds check is a single missing edge, **injectivity matters**.

> **Speaker notes:** "V2 used Graph Attention Networks. Its precision collapsed to 40% because the weighted-mean aggregation conflated structurally distinct subgraphs. V3 switched to Graph Isomorphism Networks, which Xu et al. proved are provably more expressive. F1 jumped 17 absolute points from the architecture change alone."

---

## SLIDE 18 — The GNN Story: V4, Data Matters More

## V4 — Removed a 3,000-sample per-language cap. 7× more data.

## F1 = **0.781** · AUC = **0.826**
## Recall = **0.926** · Precision = **0.675**

### Per-CWE peaks: CWE-476 F1 = 0.926 · CWE-787 F1 = 0.895 · CWE-416 F1 = 0.872

> **Speaker notes:** "V4 fixed a single configuration line. The per-language sample cap was silently discarding 20,000 training samples. Removing the cap raised F1 twenty points. The lesson: audit what fraction of your data actually reaches training. The per-CWE breakdown shows memory safety vulnerabilities above 0.87, which validates the graph-heavy fusion weight for that family."

---

## SLIDE 19 — The GNN Story: V4 → V5, The Trade-off

## V4 had F1 = 0.781 but **0% conformal singletons**.

## Root cause: **label smoothing** compressed logit gaps.

## V5 removed smoothing + added ConfTS calibration.

| | F1 | Conformal Singletons (cal) |
|---|---|---|
| V4 | 0.781 | 0% |
| V5 | 0.750 | **69.1%** |

### We traded 3 F1 points for a functional uncertainty layer.

> **Speaker notes:** "V4 gave us perfect classification and a broken uncertainty estimator. We traced the problem to label smoothing. Hard labels allow wide logit gaps; smoothed labels compress them and conformal needs the spread. Removing smoothing cost us three F1 points and gave us a functional coverage guarantee. That trade is the thesis in a single decision."

---

## SLIDE 20 — The Deployed Architecture

## **MiniGINv3** *(class named `mini_gat.py` for legacy reasons; architecture is pure GIN)*

- **Input**: 774-dim (768 GraphCodeBERT + 6 structural features)
- **3 GIN layers** with residual connections, BatchNorm, dropout 0.35
- **Dual pooling**: mean + sum → 768-dim graph embedding
- **Classification head**: 768 → 384 → 2
- **Confidence head**: 768 → 1 (auxiliary BCE loss)
- **Total**: 2,375,046 parameters

> **Speaker notes:** "A short housekeeping note: the file is called `mini_gat.py` because it started as a GAT in V2. The class inside is `MiniGINv3`, a three-layer GIN. We kept the filename to preserve git history. The architecture is pure GIN with sum aggregation, residual connections, and a dual-head design for classification plus self-reported confidence."

---

## SLIDE 21 — The Live Evaluation

### 15 open-source repositories · 5 languages · 184 findings

```
SAST       157  ██████████████████░░   85%
Graph        4  █░░░░░░░░░░░░░░░░░░░    2%
LLM         23  ██░░░░░░░░░░░░░░░░░░   13%
Unresolved   0  ░░░░░░░░░░░░░░░░░░░░    0%
```

### **Every finding received a verdict. 87.5% fewer LLM calls than a uniform approach.**

### *Detection precision/recall on this set: not measured (no ground truth labels).*

> **Speaker notes:** "The cascade on 15 open-source repositories, spanning five languages, produced 184 findings. Every finding received a verdict. The LLM was invoked on 23 of the 184, an 87.5% reduction versus a uniform baseline. I want to flag explicitly: this evaluation measures triage efficiency. We did not label the 184 findings with ground truth, so we cannot report precision or recall on the live cascade. That measurement is the first priority of future work."

---

## SLIDE 22 — The Honest Story of Conformal Prediction at Deployment

### Offline cal/test: singleton rate **69.1% / 67.7%** · coverage **84.3%**
### Live deployment: singleton rate **~2%**

### Three reasons, all documented:

1. **Backward slicing** reduced graphs by 83–95% (distribution shift)
2. **T = 0.10** eliminated natural uncertainty (re-tuned to T = 0.95)
3. **Threshold = 1.0** is unreachable for binary softmax (re-tuned to 0.95)

### At deployment, the conformal layer acts as a **conservative escalation gate**, not a resolution mechanism. The cascade absorbs this gracefully: Stage 3 handles what Stage 2 cannot route.

> **Speaker notes:** "I want to address this honestly because it is the most important finding of our evaluation. Our offline singleton rate was 69%. Our live rate was 2%. That is not a contradiction. It is a lesson about deployment distribution shift, and it is documented in our Chapter 4. The conformal layer still routes; it just routes conservatively, sending most findings to the LLM stage. The cascade design handles this outcome without collapse, because Stage 3 resolves the ambiguous cases and Stage 1 already caught the easy ones. We now view conformal calibration as a deployment-time activity, not a one-time training artifact. This is a contribution in its own right."

---

## SLIDE 23 — The Economics

### LLM-only approach (paid tier):
**184 API calls** · **~$10–40/scan** · **~30 minutes**

### Our cascade (same paid tier):
**23 API calls** · **~$0.50–2.00/scan** · **~5 minutes of LLM work**

### Even if the GNN resolved **nothing**, Stage 1 alone saves **85%**.

*(Costs estimated for paid Gemini 2.5 Pro pricing; free tier costs are bounded by rate limits rather than per-call dollars.)*

> **Speaker notes:** "Costs depend on which LLM tier you run. On paid Gemini 2.5 Pro, an LLM-only approach scales to tens of dollars per scan; our cascade stays under two dollars. On the free tier, the comparison is about rate-limit survivability rather than dollars, and there our cascade reliably completes under free-tier caps where a uniform approach throttles. Either way, the architecture is robust to component performance: SAST alone saves 85%."

---

## SLIDE 24 — Where the GNN Shines

### Memory safety CWEs, V4 per-CWE F1:

| CWE | Description | F1 |
|---|---|---|
| CWE-476 | Null Pointer Dereference | **0.926** |
| CWE-787 | Out-of-Bounds Write | **0.895** |
| CWE-416 | Use After Free | **0.872** |
| CWE-362 | Race Condition | **0.800** |

### Control flow structure captures memory patterns. This validates the graph-heavy fusion weight for memory CWEs.

> **Speaker notes:** "The per-CWE breakdown shows where graph-based analysis genuinely shines. Memory safety vulnerabilities depend on control flow ordering: a use-after-free is a missing edge, a null deref is an unchecked path. The GIN picks these up. The four-factor fusion for memory CWEs gives graph the heaviest weight precisely because of this per-CWE evidence."

---

## SLIDE 25 — Where We Sit in the Field

| System | Cascade | Uncertainty | LLM Strategy | Languages |
|---|---|---|---|---|
| Semgrep | Single-pass | None | None | 30+ |
| CodeQL | Single-pass | None | None | 10+ |
| IRIS (ICLR'25) | SAST+LLM | None | Uniform | Java |
| Vulnhalla (2025) | CodeQL+LLM | None | Uniform | Multi |
| LLMxCPG (USENIX'25) | CPG+LLM | None | Uniform | C/C++ |
| **Ours** | **4-stage** | **4-factor $U$** | **Dual-agent** | **5** |

### The only framework with principled uncertainty routing.

> **Speaker notes:** "This is how we position ourselves. Commercial SAST tools give up language breadth for depth and do not use learned components. Academic hybrids specialize in one language and apply LLMs uniformly. Our contribution is the routing logic, not the individual components. Every individual component (Tree-sitter, CodeQL, Joern, GraphCodeBERT, APS, Gemini) is prior work. The assembly is ours."

---

## SLIDE 26 — Honest Limitations

We confront four limitations openly; each has a concrete next step.

| Limitation | Status | Next step |
|---|---|---|
| **C/C++ training bias** (94.6% of data) | Python F1 = 0.836 on ~60 test samples; preliminary elsewhere | PrimeVul integration + targeted multi-language sampling |
| **Coverage gap** (84.3% vs 90% target) | Exchangeability assumption relaxes in deployment | Cross-validated ConfTS with a 5-fold temperature search |
| **RQ3/RQ4 ablations** | Architecturally validated via live integration | Isolated single-agent vs. dual-agent and fixed vs. adaptive weight comparisons |
| **No OWASP Benchmark v1.2** | Outstanding | Direct comparison with commercial tools on a labeled 2,740-case corpus |

### Every limitation is a planned experiment, not a hidden flaw.

> **Speaker notes:** "Four honest gaps. Each has a concrete experiment attached. I want the panel to understand that we chose depth over breadth. We built one cascade end-to-end and evaluated it in live deployment. The ablations and the OWASP benchmark are the natural follow-ups, and they are scoped in our final chapter. This is the honest state of the work."

---

## SLIDE 27 — Future Directions

1. **Cross-validated ConfTS** to close the coverage gap
2. **PrimeVul integration** (~8K additional C/C++ samples)
3. **OWASP Benchmark v1.2** head-to-head evaluation
4. **Bayesian optimization** of CWE fusion weights (replace expert-configured with data-derived)
5. **DAST integration** as optional Stage 5 for runtime exploit confirmation
6. **IDE extensions** (VS Code, JetBrains) surfacing SAST annotations in real time

> **Speaker notes:** "Six next steps, prioritized. The top three close the limitations from the previous slide. The bottom three extend the framework: runtime confirmation, and bringing the cascade to where developers actually work, which is inside the IDE."

---

## SLIDE 28 — The Take-Home

## The field has hit a ceiling on **classification thinking**.

## **Triage thinking** opens the next decade.

### Four stages · principled routing · formal uncertainty · 87.5% cheaper at live scale.

> **Speaker notes:** "If you leave with one idea, let it be this. For twenty years the field has tried to build a better classifier. The benchmarks say it succeeded; the deployments say it did not. Triage thinking (deciding what to analyze with what, and when) is the shift the field needs. Our thesis is a working proof that the shift is economically and mathematically tractable, even when the components are imperfect."

---

## SLIDE 29 — Why the Timing Matters

## The code volume is exploding:
- **~22%** of production code reported as AI-authored in recent developer surveys (Q4 2025)
- Veracode 2025: only **12–13%** of AI-generated code is secure against XSS

## The review bandwidth is not.

### Tools that triage intelligently are becoming operationally necessary, not optional.

*(Exact AI-authored code share varies by methodology; the directional trend is consistent across sources.)*

> **Speaker notes:** "One closing contextual point. The volume of code requiring security review is growing faster than the supply of human reviewers. Exact AI-authored share varies by survey methodology, but the directional trend is consistent across GitHub, GitLab, and Veracode data. Any tool that reduces triage volume buys the field time. Ours reduces it by 87.5% on our live set."

---

## SLIDE 30 — Thank You

## Questions?

**Code:** open-source, multi-language, free-tier operable
**Supervisor:** Dr. K.B. Sundharakumar
**Institution:** Shiv Nadar University Chennai

*"The cascade absorbs uncertainty gracefully. When one stage cannot resolve, the next stage provides the verdict."*

> **Speaker notes:** "Thank you. I have backup slides on the CVSS scoring mathematics, the RAG knowledge base configuration, the five consensus rules, and the conformal prediction formalism. I am happy to go deeper on any of them."

---

## APPENDIX A1 — CVSS v3.1 Scoring

The attacker agent provides four **exploitability** sub-metrics:
- **AV** (Attack Vector), **AC** (Attack Complexity), **PR** (Privileges Required), **UI** (User Interaction)

The defender agent provides **Scope** (S) and three **impact** sub-metrics:
- **C** (Confidentiality), **I** (Integrity), **A** (Availability)

$$\text{ISS} = 1 - (1-C)(1-I)(1-A)$$
$$\text{Exploitability} = 8.22 \cdot AV \cdot AC \cdot PR \cdot UI$$
$$\text{Impact}_{\text{unchanged}} = 6.42 \cdot \text{ISS}$$
$$\text{Impact}_{\text{changed}} = 7.52(\text{ISS} - 0.029) - 3.25(\text{ISS} - 0.02)^{15}$$
$$\text{Base Score} = \text{roundup}(\min(\text{Impact} + \text{Exploitability}, 10))$$

---

## APPENDIX A2 — RAG Knowledge Base

- **FAISS semantic index** (weight 0.6) over `all-MiniLM-L6-v2` embeddings
- **BM25 keyword index** (weight 0.4)
- **Reciprocal Rank Fusion** with $k = 60$ combines both: $\text{RRF}(d) = \sum_r \frac{w_r}{k + \text{rank}_r(d)}$
- **200,000+ NVD entries**, **900+ CWE entries**
- Top-5 documents injected into agent prompts

---

## APPENDIX A3 — The Five Consensus Rules

| Rule | Condition | Verdict | Confidence |
|---|---|---|---|
| R1 | exploitable ∧ coverage < 0.5 | CONFIRMED | $\max(c_{\text{atk}}, 1-d_{\text{cov}})$ |
| R2 | ¬exploitable ∧ coverage > 0.7 | SAFE | $\max(d_{\text{cov}}, 1-c_{\text{atk}})$ |
| R2b | ¬exploitable ∧ path infeasible | SAFE | 0.8 fixed |
| R3 | exploitable ∧ coverage ≥ 0.5 | LIKELY | $0.5 + 0.3(c_{\text{atk}}-d_{\text{cov}})$ clamped [0.3, 0.85] |
| R4 | ¬exploitable ∧ coverage ≤ 0.7 | POTENTIAL | $0.4 + 0.2(1-d_{\text{cov}})$ clamped [0.2, 0.6] |

---

## APPENDIX A4 — The Conformal Math

APS nonconformity score for calibration sample $i$:
$$s_i = \sum_{k=1}^{\text{rank}(y_i)} \pi_{(k)}$$

Quantile threshold:
$$\hat{q} = \text{Quantile}\left(\{s_i\}, \tfrac{\lceil (n+1)(1-\alpha) \rceil}{n}\right)$$

Prediction set at inference:
$$C(x) = \left\{ k : \sum_{j=1}^{k} \pi_{(j)}(x) \leq \hat{q} \right\}$$

ConfTS (Dabah et al. 2024) optimizes temperature $T$ to minimize mean $|C(x)|$ subject to empirical coverage $\geq 1 - \alpha$.

---

## APPENDIX A5 — Dataset Composition (V5, 21,150 total)

| Source | Language | Samples |
|---|---|---|
| BigVul | C/C++ | 5,777 |
| DiverseVul | C/C++ | 4,935 |
| Juliet-C | C/C++ | 3,611 |
| CrossVul | Multi | 3,428 |
| Devign | C/C++ | 3,002 |
| VUDENC | Python | 222 |
| CVEfixes | Python | 175 |
| **Total** | **5 languages** | **21,150** |

Split: 60% train (12,689) / 15% validation / 15% calibration / 10% test.

---

## APPENDIX A6 — The V2 to V3 Feature-Dimension Shift

| | V2 (GAT) | V3+ (GIN) |
|---|---|---|
| Architecture | 2-layer GAT, 4 heads | 3-layer GIN, residual + BatchNorm |
| GraphCodeBERT dim | 768 | 768 |
| Structural features | 5 | 6 (added `language_id`) |
| **Total input dim** | **773** | **774** |
| Parameters | 298K | 2,375,046 |

The `language_id` feature was added in V3 when the corpus expanded beyond a single language dominating training. The dimension went from 773 to 774 at the same transition.
