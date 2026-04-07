"""Update all markdown cells in V4 notebook to reflect V4 changes."""
import json

NB = "D:/sec-c/notebooks/sec_c_gnn_training_v4.ipynb"
nb = json.load(open(NB, encoding="utf-8"))
md_cells = [(i, c) for i, c in enumerate(nb["cells"]) if c["cell_type"] == "markdown"]


def set_md(cell, text):
    cell["source"] = text.splitlines(keepends=True)


changes = 0

# ─── MD[0]: Main header ───────────────────────────────────────────────────────
_, c = md_cells[0]
set_md(c, """\
# SEC-C GNN V4 Training Notebook
## MiniGINv3 + APS Conformal Prediction for Vulnerability Detection

**Framework role:** Trains Module 2 (Graph stage) of the SEC-C 4-stage cascade.
The model produces `structural_risk_score` (β-weight = 30% in fusion) and APS
conformal prediction sets that gate escalation from Stage 2 → Stage 3 (LLM).

---

### V4 Fixes Over V3

| Problem (V3) | Fix (V4) |
|---|---|
| `max_per_language=3000` discarded 20K C/C++ samples | Raised to **20,000** — uses full ~23K available |
| 3,032 total samples → 0.6 min training | **~20,000 samples** → 35–50 min training |
| Conformal threshold=1.0, 99.7% ambiguous | More data → better generalisation → real threshold |
| CrossVul: all 3 HF IDs failed | **`hitoshura25/crossvul`** (9.3K multi-lang pairs, correct ID) |
| CVEfixes: only 11 Python vuln samples | **`DetectVul/CVEFixes`** (5.7K Python stmts, fixed ID) |
| Juliet C/C++: 150 samples (HF truncated) | **`LorenzH/juliet_test_suite_c_1_3`** (101K available) |
| No PrimeVul | **`starsofchance/PrimeVul`** (236K deduplicated, hardest benchmark) |
| No Python statement-level data | **`DetectVul/Vudenc`** (15.8K Python CVE stmts) |
| `alpha=0.2` (80% coverage) | **`alpha=0.1`** (90% coverage, aligned with framework config) |
| `patience=25` | **`patience=20`** |
| `dropout=0.4` | **`dropout=0.35`** (less regularisation with 8x more data) |

### V3 Fixes (inherited, kept in V4)

| Problem (V2) | Fix (retained) |
|---|---|
| Focal(gamma=2) + inverse weights → predict-all-vulnerable | Standard CE + label_smoothing=0.1 + mild class_weight=[1, 1.5] |
| LR=1e-3, best at epoch 3, 1.1 min training | LR=3e-4, 5-epoch warmup, cosine decay |
| Early stopping on val_loss (wrong metric) | Early stopping on **val F1** |
| Per-language class imbalance unchecked | Strict 1:1 per-language balancing |
| 2-layer GAT, 298K params, shallow | 3-layer GIN + residual + BatchNorm + dual pooling, 2.37M params |
| Regex-only code graphs | tree-sitter real AST + regex CFG/DDG fallback |

### Expected V4 Results

| Metric | V2 (actual) | V3 (actual) | V4 (target) |
|---|---|---|---|
| Training samples | ~3K (buggy) | 1,819 | **~13,800** |
| Test F1 | 0.57 (degenerate) | 0.652 | **0.68 – 0.74** |
| Test Precision | 0.40 | 0.544 | **0.63 – 0.72** |
| AUC-ROC | — | 0.623 | **0.70 – 0.76** |
| Conformal threshold | 1.0 | 1.0 | **0.78 – 0.92** |
| Conformal singleton rate | 0% | 0.2% | **20 – 40%** |
| Training time | 1.2 min | 0.6 min | **35 – 50 min** |

### Architecture: MiniGINv3

Graph Isomorphism Network (Xu et al., ICLR 2019) — maximally expressive classical
GNN, equivalent to the Weisfeiler-Lehman graph isomorphism test.

```
Input: 774-dim per node  (768 GraphCodeBERT mean-pool + 6 structural features)
  └─ Linear projection  774 → 384
  └─ 3x GINConv(MLP: 384→768→384) + BatchNorm + ReLU + Dropout(0.35) + Residual
  └─ Dual pooling: global_mean_pool + global_add_pool → concat → 768-dim
  └─ Classifier head: Linear(768 → 384 → 2)
  └─ Confidence head: Linear(768 → 1) + Sigmoid
  Total params: 2,375,046
```

**Novel contribution:** First application of APS conformal prediction to
vulnerability detection (Angelopoulos & Bates, ICLR 2024). Provides
distribution-free 90% coverage guarantee, replacing arbitrary thresholds
with principled uncertainty-driven escalation decisions.
""")
changes += 1
print("[MD 0] Header updated")

# ─── MD[2]: Configuration ─────────────────────────────────────────────────────
_, c = md_cells[2]
set_md(c, """\
## Cell 2: Configuration — V4

All hyperparameters in one place. V4 changes from V3:

- `max_per_language = 20000` — **critical fix** (was 3000; was silently discarding 20K real C/C++ samples)
- `alpha = 0.1` — 90% APS coverage guarantee (was 0.2, misaligned with framework `default.yaml`)
- `dropout = 0.35` — less regularisation needed with 8x more training data
- `patience = 20` — tighter early stopping (was 25)
- New per-source caps: `max_primevul=8000`, `max_juliet_c=6000`, `max_crossvul=6000`, `max_vudenc=3000`
""")
changes += 1
print("[MD 2] Config updated")

# ─── MD[3]: Dataset ───────────────────────────────────────────────────────────
_, c = md_cells[3]
set_md(c, """\
## Cell 3: Multi-Source Dataset Loading — V4

Eight sources with **verified** HuggingFace IDs (3 new, 2 corrected vs V3):

| # | Dataset | HF ID | Lang | Type | Samples |
|---|---------|-------|------|------|---------|
| 1 | BigVul | `bstee615/bigvul` | C/C++ | Real CVE | 217K (cap 10K) |
| 2 | DiverseVul | `claudios/DiverseVul` | C/C++ | Real CVE | 330K (cap 8K) |
| 3 | Devign | `google/code_x_glue_cc_defect_detection` | C/C++ | Real | 27K (cap 5K) |
| 4 | **PrimeVul** *(new)* | `starsofchance/PrimeVul` | C/C++ | Real CVE | 236K dedup (cap 8K) |
| 5 | **Juliet C/C++** *(fixed)* | `LorenzH/juliet_test_suite_c_1_3` | C/C++ | Synthetic NIST | 101K (cap 6K) |
| 6 | **CrossVul** *(fixed ID)* | `hitoshura25/crossvul` | Multi-lang | Real CVE | 9.3K pairs (cap 6K) |
| 7 | **VUDENC** *(new)* | `DetectVul/Vudenc` | Python | Real CVE | 15.8K stmts (cap 3K) |
| 8 | **CVEfixes** *(fixed ID)* | `DetectVul/CVEFixes` | Python | Real CVE | 5.7K stmts (cap 3K) |

All wrapped in `try/except` — any failed HF download is skipped gracefully.

**Column parsing notes:**
- BigVul: `func_before` (vuln) / `func_after` (safe), `vul` label, `CWE ID` column
- PrimeVul: `func` column, `vul` binary label, `CWE ID` column
- CrossVul: `vulnerable_code` → label=1, `fixed_code` → label=0, `cwe_id`, `language`
- Juliet: `bad` → label=1, `good` → label=0, `class` (CWE number as int)
- VUDENC / CVEfixes: `lines` code column, `label` (0/1); snippets < 30 chars filtered
""")
changes += 1
print("[MD 3] Dataset sources updated")

# ─── MD[4]: Balance ───────────────────────────────────────────────────────────
_, c = md_cells[4]
set_md(c, """\
## Cell 4: Strict 1:1 Per-Language Balancing — V4

**V4 key fix:** `max_per_language=20000` (was 3000) allows C/C++ to contribute its
full ~15K balanced samples. In V3 this cap threw away 20K samples, causing 0.6-min
training and model overfit on 1,819 samples.

Procedure:
1. **Dedup** by SHA-256 of code string — removes exact duplicates across sources
2. **Length filter** — drop samples shorter than 20 characters
3. **Per-language 1:1 balance** — subsample majority class to match minority
4. **Language gate** — skip languages with < `min_per_language=50` total samples

Expected V4 output: ~15,000 C/C++ + ~3,000 Python + ~300 Java = ~18,300 total
""")
changes += 1
print("[MD 4] Balance updated")

# ─── MD[10]: Training ─────────────────────────────────────────────────────────
_, c = md_cells[10]
set_md(c, """\
## Cell 10: Training — WeightedCE + LR Warmup + Early Stopping on val F1

Design choices (all corrected from V2, V4 adjustments noted):

| Component | Choice | Reason |
|---|---|---|
| Loss | `CrossEntropyLoss(weight=[1.0, 1.5], label_smoothing=0.1)` | No Focal Loss (caused collapse in V2) |
| Optimizer | AdamW, LR=3e-4, weight_decay=1e-3 | Stable with GCB embeddings |
| LR schedule | Linear warmup (5 ep) → cosine decay | Prevents cold-start instability |
| Early stopping | **val F1**, patience=20 *(V4: was 25)* | V2 used val_loss and stopped 15 ep early |
| Gradient clip | max_norm=0.5 | Prevents exploding gradients |
| Confidence head | BCE auxiliary loss (0.1 weight) | Calibrates sigmoid output for conformal |

With ~13,800 training graphs, expect best val F1 around epoch 25–40.
Training time: ~35–50 min on T4 GPU.
""")
changes += 1
print("[MD 10] Training updated")

# ─── MD[11]: Threshold ────────────────────────────────────────────────────────
_, c = md_cells[11]
set_md(c, """\
## Cell 11: F1-Optimal Decision Threshold Search

Grid search over 81 thresholds in [0.05, 0.95] on the **validation set** to find
the probability cutoff that maximises F1 score.

Why not argmax (threshold=0.50)?
- V3: threshold=0.41 gave val F1=0.679 vs 0.665 at 0.50 — +1.4 pp
- With imbalanced training data, the model's calibration shifts; optimal threshold
  compensates without retraining

V4 expectation: with better class balance and more data, threshold should be
closer to 0.45–0.50 (more calibrated model).

Saved to: `decision_threshold_v3.json` (loaded by `src/graph/gnn/graph_validator.py`)
""")
changes += 1
print("[MD 11] Threshold updated")

# ─── MD[12]: Test eval ────────────────────────────────────────────────────────
_, c = md_cells[12]
set_md(c, """\
## Cell 12: Test Set Evaluation

Evaluates on the held-out test set (10% of data, stratified, never seen during
training or conformal calibration).

Reports:
- **Overall:** Accuracy, Precision, Recall, F1, AUC-ROC
- **Per-language:** C/C++, Python, Java breakdowns
- **Per-CWE:** F1 for top-15 CWEs by sample count
- **Plots:** ROC curve, confusion matrix → `evaluation_plots_v3.png`

V4 targets: **F1 >= 0.68**, AUC-ROC >= 0.70, Precision >= 0.63.

C/C++ is the primary evaluation language (~95% of test samples).
Per-CWE results for known CWEs (CWE-119, CWE-20, CWE-125, etc.) should
exceed F1=0.80 based on V3 results (CWE-119: 0.941, CWE-20: 0.909).
""")
changes += 1
print("[MD 12] Test eval updated")

# ─── MD[13]: Conformal — CRITICAL alpha fix ────────────────────────────────────
_, c = md_cells[13]
set_md(c, """\
## Cell 13: Conformal Prediction — APS (alpha=0.1, 90% coverage guarantee)

**Adaptive Prediction Sets** (Angelopoulos & Bates, ICLR 2024).
First application to vulnerability detection — novel contribution of SEC-C.

**V4 fix:** `alpha=0.1` (was 0.2 in V3, which gave only 80% coverage).
Now aligned with framework `configs/default.yaml` (`conformal.alpha: 0.1`).

**Coverage guarantee:** P(true label in prediction_set) >= 1 - alpha = **0.90**,
distribution-free, holds for any data distribution without parametric assumptions.

### Algorithm

**Calibration phase** (on ~454 held-out cal samples):
1. Run model forward pass → softmax probabilities
2. Sort classes by descending probability
3. Compute cumulative sum; record value at position of true label = nonconformity score
4. Set threshold: `q_hat = quantile(scores, ceil((n+1)(1-alpha)) / n)`

**Inference phase** (per finding at runtime):
1. Sort classes by descending softmax probability
2. Include classes until cumulative sum >= q_hat
3. Return resulting set:
   - `{"safe"}` → confident SAFE, resolve at Stage 2 (no LLM)
   - `{"vulnerable"}` → confident VULNERABLE, resolve at Stage 2 as LIKELY
   - `{"safe", "vulnerable"}` → ambiguous, escalate to Stage 3 (LLM dual-agent)

### V3 vs V4 Conformal Expectations

| Metric | V3 (actual) | V4 (target) |
|---|---|---|
| Threshold | 1.0 (broken) | **0.78 – 0.92** |
| Singleton rate | 0.2% | **20 – 40%** |
| Ambiguous rate | 99.7% | **60 – 80%** |
| Empirical coverage | 1.0 (trivial) | **>= 0.90** (meaningful) |

V3 failure cause: 2.37M-param model overfit on 1,819 samples → uncertain on cal set
→ all scores pile at 1.0 → threshold must be 1.0. V4 fixes this via 8x more data.

Saved to: `conformal_calibration_v3.json`
""")
changes += 1
print("[MD 13] Conformal updated (alpha=0.1 fix + V4 targets)")

# ─── MD[14]: Export ───────────────────────────────────────────────────────────
_, c = md_cells[14]
set_md(c, """\
## Cell 14: Export Artifacts

Saves all framework-ready artifacts to `/kaggle/working/`:

| File | Size (approx) | Purpose |
|------|--------------|---------|
| `mini_gat_v3.pt` | ~9 MB | Model weights — copy to `data/models/mini_gat_v4.pt` |
| `mini_gat_v3_best.pt` | ~9 MB | Best val-F1 checkpoint |
| `decision_threshold_v3.json` | < 1 KB | F1-optimal threshold (0.41 in V3) |
| `conformal_calibration_v3.json` | < 5 KB | APS calibration + all test metrics |
| `graph_config_v3.json` | < 10 KB | Model config + node feature spec (framework wiring) |

**Legacy aliases also created** (`conformal_calibration.json`, `graph_config.json`,
`mini_gat.pt`) for backward compatibility with framework default paths.

**Post-download framework integration:**
```
mini_gat_v3.pt          → data/models/mini_gat_v4.pt
conformal_calibration_v3.json → data/models/conformal_calibration.json
graph_config_v3.json    → data/models/graph_config.json
```
Then update `configs/default.yaml`:
```yaml
gnn:
  input_dim: 774
  hidden_dim: 384
  num_gin_layers: 3
  model_path: "data/models/mini_gat_v4.pt"
```
""")
changes += 1
print("[MD 14] Export updated")

# ─── MD[15]: Summary ──────────────────────────────────────────────────────────
_, c = md_cells[15]
set_md(c, """\
## Cell 15: Run Summary Report

Prints a complete summary of the V4 training run:

- **Dataset:** per-source sample counts, per-language split, CWE coverage
- **Training:** best epoch, best val F1, train/val loss at convergence, total time
- **Test results:** F1, Precision, Recall, AUC-ROC, per-CWE top-5
- **Conformal:** threshold, singleton rate, ambiguous rate, empirical coverage
- **Framework instructions:** exact copy commands for artifact deployment

**PhD result framing printed at end:**
> MiniGINv3 trained on ~13,800 real C/C++ vulnerability samples achieves
> F1=X, Precision=Y, Recall=Z on deduplicated held-out test set (BigVul +
> DiverseVul + Devign + PrimeVul). APS conformal prediction (alpha=0.1)
> resolves W% of escalated findings at Stage 2 with guaranteed 90% coverage,
> reducing LLM API calls by W% vs a non-cascade baseline.
""")
changes += 1
print("[MD 15] Summary updated")

# ─── MD[16]: Zip ──────────────────────────────────────────────────────────────
_, c = md_cells[16]
set_md(c, """\
## Cell 16: Zip All Artifacts for Single-Click Download

Packages all essential outputs into **`sec_c_gnn_v4_artifacts.zip`** for
download from the Kaggle Output tab.

**Included in zip:**

| File | Description |
|------|-------------|
| `mini_gat_v3.pt` | Model weights (main) |
| `mini_gat_v3_best.pt` | Best val-F1 checkpoint |
| `decision_threshold_v3.json` | F1-optimal decision threshold |
| `conformal_calibration_v3.json` | APS calibration + all metrics |
| `graph_config_v3.json` | Model + graph config (framework wiring) |
| `training_curves_v3.png` | Loss and F1 training curves |
| `evaluation_plots_v3.png` | ROC curve, confusion matrix, per-CWE F1 |
| `conformal_diagnostics_v3.png` | APS score histogram, set sizes, coverage curve |
| `threshold_calibration_v3.png` | F1 vs threshold search plot |
| `eda_overview_v3.png` | Dataset EDA (language/CWE/label distribution) |
| `raw_samples_v3.json` | Balanced sample list (if < 50 MB) |
| `mini_gat_v3_epoch*.pt` | Last 2 periodic epoch checkpoints |

**Excluded:** `pyg_dataset_v3.pt` (large intermediate, not needed for inference).

After download, extract and follow the deployment steps in Cell 14.
""")
changes += 1
print("[MD 16] Zip updated")

# ─── Save ──────────────────────────────────────────────────────────────────────
json.dump(nb, open(NB, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print(f"\nTotal: {changes} markdown cells updated. Saved -> {NB}")
