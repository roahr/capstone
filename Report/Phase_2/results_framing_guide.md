# Results Framing Guide — Sec-C Thesis

How to present different types of results honestly while maximizing research value.

---

## Pattern 1: Strong Result — Confident statement with measured scope

**Template:** "[System/component] achieved [metric] on [dataset/scenario], [comparison to baseline]. This [supports/confirms] [research question/hypothesis]."

**Example:**
> The SAST pre-screener resolved 75% of findings at Stage 1, reducing downstream analysis by an estimated 3x compared to processing all findings through the full cascade. This supports RQ1: uncertainty scoring enables cost-effective triage without sacrificing recall.

**Rules:** Always scope the claim (dataset, conditions). Always tie back to an RQ. Use "suggests" or "supports" not "proves."

---

## Pattern 2: Weak Result — Pivot to research insight

The weak result IS the contribution. The insight matters more than the number.

**Template:** "[Component] achieved [metric] on [realistic dataset], compared with [higher metric] on [synthetic dataset]. This [gap/difference] reveals [insight about the problem domain]. [How the system design accounts for this]."

**Sec-C specific applications:**

### GNN F1=0.57 on multi-source data vs. 0.9999 on Juliet
> The V2 model's F1 of 0.57 on the multi-source dataset — comprising CVEfixes, DiverseVul, and Devign samples — stands in contrast to the 0.9999 achieved on Juliet's synthetic patterns. This gap is consistent with Ding et al.'s PrimeVul findings, where models achieving 90%+ on curated benchmarks collapsed to 3.09% on realistic data. The result validates our cascade hypothesis: no single model reliably classifies real-world vulnerabilities, and the GNN serves as a probabilistic filter rather than a standalone classifier. Within the cascade, even moderate GNN performance reduces the LLM workload by routing clear cases.

### 100% conformal prediction ambiguity
> Conformal prediction produced prediction sets containing both classes for all test samples, triggering full LLM escalation. This indicates the GNN's softmax outputs lack the calibration required for APS to distinguish confident from uncertain predictions — consistent with Guo et al.'s demonstration that modern neural networks are systematically overconfident. The cascade absorbs this gracefully: Stage 3 provides the verdict when Stage 2 cannot. The conformal layer functions as designed — it correctly identified that the GNN's predictions were unreliable, preventing false confidence from propagating downstream.

### Focal Loss + class weights double-correction
> Combining Focal Loss with class-weight sampling degraded V2 performance compared to using either mechanism alone. Both techniques address class imbalance, and their joint application over-suppressed the majority class gradient signal. This practical finding — that imbalance-handling mechanisms should not be stacked — provides a concrete training guideline for GNN-based vulnerability detection on imbalanced security datasets.

---

## Pattern 3: Negative Result — Scope delimiter

The system boundary itself is useful knowledge.

**Template:** "[Approach/component] did not achieve [expected outcome] under [conditions]. This delimits the conditions under which [approach] is effective: [specific boundary]. [Implication for practitioners/researchers]."

**Example:**
> Cross-language evaluation was limited to Python for end-to-end cascade testing, as the GNN was trained primarily on C/C++ and Python samples. The cascade architecture itself is language-agnostic — Tree-sitter and CodeQL support all five target languages — but the GNN component's performance on JavaScript, Java, and Go remains unvalidated. We identify cross-language GNN evaluation as a priority for Phase 3.

---

## Pattern 4: Unexpected Result — Research direction

Surprise findings are often the most publishable part of a thesis.

**Template:** "We did not anticipate [observation]. [Evidence for the observation]. This suggests [hypothesis for why], which [opens research direction / has practical implication]."

**Example:**
> We did not anticipate that the attacker and defender agents would agree on 85% of findings. We expected frequent disagreement to be the norm for adversarial analysis. The high agreement rate suggests that for well-characterized vulnerability patterns (SQL injection, XSS), both perspectives converge — the adversarial framing adds value primarily for ambiguous or novel vulnerability types where the attack surface is unclear.

---

## Pattern 5: Comparison Framing — Position honestly

When your system underperforms on some metrics but adds value elsewhere.

**Template:** "[Baseline] achieves [metric] on [narrow task]. Sec-C's cascade achieves [metric] on [broader scope]. The comparison is [not directly equivalent because...]. Sec-C's value lies in [unique capability: multi-stage, explainability, CVSS scoring, etc.]."

**Rules:**
- Never cherry-pick the metric where you win
- If a baseline beats you on precision, say so, then explain the recall/explainability trade-off
- Use multi-dimensional comparison tables, not single-metric claims
- Acknowledge when you're comparing different scopes

---

## Threats to Validity Templates (Ch4 Section 4.9)

### Construct Validity
"Our evaluation metrics (precision, recall, F1) measure classification accuracy but not real-world deployment utility. A security engineer's workflow involves triage time, context quality, and false-positive burden — metrics we do not directly measure."

### Internal Validity
"GNN training results may be affected by data leakage between training sources (CVEfixes and DiverseVul may share functions from the same projects). We did not perform deduplication across sources, which may inflate reported metrics."

### External Validity
"End-to-end evaluation was conducted on [N] test cases spanning [CWE types]. Results may not generalize to vulnerability types outside this set, proprietary codebases, or languages beyond Python."

### Reliability
"LLM-based validation depends on Gemini 2.5 Flash outputs, which are non-deterministic. Running the same finding through Stage 3 multiple times may produce different verdicts. We report single-run results; aggregated multi-run evaluation remains future work."
