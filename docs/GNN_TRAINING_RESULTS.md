# Sec-C: GNN Training Results — V1 through V5

> Complete training history with all epoch data, metrics, conformal prediction results, and lessons learned.
> Data extracted from Kaggle notebook output cells.

---

## Overview

The Mini-GAT is the Graph Neural Network component of Sec-C's Stage 2 (Graph-Augmented Validation). It classifies code property graph nodes as safe or vulnerable. Multiple training versions were attempted with different datasets, hyperparameters, and architectural choices.

---

## V1: Juliet Test Suite Only

**Notebook**: `notebooks/sec_c_gnn_training.ipynb` (executed as `Kaggle_output_1.ipynb`)
**Hardware**: Tesla T4 (sm_75), PyTorch 2.10.0+cu128, PyG 2.7.0

### Dataset

| Metric | Value |
|--------|-------|
| Total graphs | 54,147 |
| Vulnerable (bad) | 50,372 (93%) |
| Safe (good) | 3,775 (7%) |
| Balance ratio | 13.34:1 (heavily imbalanced) |
| Languages | C/C++ (32,016), Java (22,131) |
| CWEs covered | 14 |
| Source | Juliet Test Suite only (synthetic, templated code) |

**Split**: Train 37,902 / Validation 8,122 / Calibration 8,123

### Hyperparameters

| Parameter | Value |
|-----------|-------|
| Optimizer | Adam |
| Learning rate | 0.001 (constant) |
| Epochs (target/actual) | 50 / 50 |
| Loss function | Weighted Cross-Entropy + Confidence (weight=0.2) |
| Class weights | safe=7.173, vuln=0.537 |
| LR scheduler | None |
| Early stopping patience | 10 |

### Training Curves (Selected Epochs)

| Epoch | Train Loss | Val Loss | Accuracy | Precision | Recall | F1 | Best? |
|-------|-----------|----------|----------|-----------|--------|-----|-------|
| 1 | 0.1539 | 0.0423 | 0.999 | 0.999 | 1.000 | 0.999 | * |
| 5 | 0.0242 | 0.0106 | 1.000 | 1.000 | 1.000 | 1.000 | * |
| 10 | 0.0253 | 0.0052 | 1.000 | 1.000 | 1.000 | 1.000 | * |
| 22 | 0.0094 | 0.0011 | 1.000 | 1.000 | 1.000 | 1.000 | * |
| 28 | 0.0093 | 0.0001 | 1.000 | 1.000 | 1.000 | 1.000 | * |
| 38 | 0.0063 | 0.0000 | 1.000 | 1.000 | 1.000 | 1.000 | * |
| 46 | 0.0095 | 0.0000 | 1.000 | 1.000 | 1.000 | 1.000 | * (best) |
| 50 | 0.0081 | 0.0055 | 1.000 | 1.000 | 1.000 | 1.000 | |

**Best epoch**: 46, best val_loss: 0.0000
**Total training time**: 919.1s (15.3 min)

### Final Test Metrics (on Calibration Set — 8,123 samples)

| Metric | Value |
|--------|-------|
| Accuracy | 0.9999 |
| Precision | 0.9999 |
| Recall | 1.0000 |
| F1 Score | 0.9999 |
| AUC-ROC | 0.9996 |

### Conformal Prediction (Alpha = 0.1)

| Metric | Value |
|--------|-------|
| Coverage guarantee target | >= 0.90 |
| Empirical coverage | 1.0000 (MET) |
| APS threshold | 1.0000 |
| Singleton rate | 10.0% |
| Ambiguous rate | 90.0% |

### Critical Assessment

**Why 0.9999 accuracy is a problem, not a success:**
1. Juliet is synthetic — every test case follows a predictable template. The model memorizes patterns, not vulnerability semantics.
2. The 13:1 class imbalance means predicting "vulnerable" for everything yields 93% accuracy before any learning.
3. Evaluation is on the calibration set from the same Juliet distribution — no out-of-distribution testing.
4. Conformal prediction produces 90% ambiguous sets because the model is overconfident on training-distribution data but the threshold computation includes the softmax gaps, which are artificially uniform at threshold=1.0.

---

## V2: Multi-Source Dataset

**Notebook**: `notebooks/sec_c_gnn_training_v2.ipynb` (executed in `kaggle_sec_c_gnn_v2/`)

### Dataset

| Source | Samples |
|--------|---------|
| CVEfixes | 5,000 |
| DiverseVul (C/C++) | 2,933 |
| Devign (C/C++) | 2,000 |
| Juliet-Java | 1,000 |
| Juliet-C/C++ | 1,000 |
| **Total** | **11,933** |

| Metric | Value |
|--------|-------|
| Languages | C/C++ (9,150), Java (1,429), Python (586), JS (599), Go (169) |
| Balance ratio | ~0.4:1 vulnerable:safe (near-balanced) |

**Split**: Train 6,803 / Validation 1,701 / Calibration 1,701 / Test 1,134

### Hyperparameters

| Parameter | Value |
|-----------|-------|
| Optimizer | Adam |
| Learning rate | 0.001 → 1e-6 (CosineAnnealingLR, T_max=60) |
| Epochs (target/actual) | 60 / 18 (early stopped) |
| Loss function | Focal Loss (gamma=2.0) + Confidence (weight=0.2) |
| Class weights | safe=0.702, vuln=1.737 |
| Early stopping patience | 15 |
| Batch size | 32 |
| Input dimension | 774 (768 + 6 structural features) |

### Training Curves (All 18 Epochs)

| Epoch | Train Loss | Val Loss | F1 | Precision | Recall | LR | Best? |
|-------|-----------|----------|-----|-----------|--------|-----|-------|
| 1 | 0.2965 | 0.1643 | 0.5333 | 0.3653 | 0.9878 | 9.99e-04 | * |
| 2 | 0.2760 | 0.1618 | 0.5291 | 0.3605 | 0.9939 | 9.97e-04 | * |
| 3 | 0.2683 | 0.1556 | 0.5695 | 0.4046 | 0.9612 | 9.94e-04 | * (best val_loss) |
| 5 | 0.2579 | 0.1611 | 0.5669 | 0.4060 | 0.9388 | 9.83e-04 | |
| 10 | 0.2438 | 0.1719 | 0.5705 | 0.4094 | 0.9408 | 9.33e-04 | |
| 15 | 0.2365 | 0.1918 | 0.5873 | 0.4344 | 0.9061 | 8.54e-04 | |
| 18 | — | — | — | — | — | — | Early stop triggered |

**Best epoch**: 3, best val_loss: 0.1556, best val_F1: 0.5695
**Total training time**: 1.1 min (+ 46:08 for graph building)

### Final Test Metrics (on Test Set — 1,134 samples)

| Metric | Value |
|--------|-------|
| Accuracy | 0.5705 |
| Precision | 0.3969 |
| Recall | 0.9509 |
| F1 Score | 0.5601 |
| AUC-ROC | 0.7433 |

### Per-Language Test Performance

| Language | Samples | Accuracy | Precision | Recall | F1 |
|----------|---------|----------|-----------|--------|-----|
| Python | 54 | 0.4630 | 0.4630 | 1.0000 | 0.6329 |
| JavaScript | 54 | 0.4815 | 0.4815 | 1.0000 | 0.6500 |
| Java | 138 | 0.8043 | 0.4186 | 0.9000 | 0.5714 |
| C/C++ | 872 | 0.5482 | 0.3811 | 0.9435 | 0.5429 |
| Go | 16 | 0.4375 | 0.4375 | 1.0000 | 0.6087 |

### Conformal Prediction (Alpha = 0.3)

| Metric | Calibration Set | Test Set |
|--------|-----------------|----------|
| Coverage target | >= 0.70 | >= 0.70 |
| Empirical coverage | 1.0000 (MET) | 1.0000 (MET) |
| APS threshold | 1.0000 | 1.0000 |
| Singleton rate | 0% (0/1701) | 0% (0/1134) |
| Ambiguous rate | 100% | 100% |

---

## V1 vs V2: Root Cause Analysis

### Why V2 "Performs Worse" — 5 Root Causes

| Root Cause | Impact |
|------------|--------|
| **V1 trains/tests on same Juliet distribution** | V1's 0.9999 is memorization of synthetic templates, not generalization |
| **V2 has 5× less data for a harder task** | 6,803 train samples vs 37,902, across 5 languages and 4 data sources |
| **Early stopping on val_loss instead of val_F1** | Stopped at epoch 18 while F1 was still improving (0.5695 → 0.5873) |
| **Focal Loss + class weights double-stacked** | Both mechanisms upweight vulnerable class → model predicts "vulnerable" for everything (precision ~0.40, recall ~0.95) |
| **Conformal threshold = 1.0** | Model produces uniformly uncertain outputs, 100% ambiguous → all escalated to LLM |

### The Honest Interpretation

V2 is the **correct direction**. Its lower numbers reflect honest evaluation on diverse, real-world data. V1's perfect scores would not survive out-of-distribution testing. For the report:
- V1 demonstrates the model architecture works (it can learn to classify)
- V2 demonstrates the challenge of generalization (the real research problem)
- The gap between V1 and V2 is itself a research finding about dataset bias

---

## V4: Extended Multi-Source (Summary)

**Key results**:
- 8 datasets attempted, 5 loaded successfully (PrimeVul, VUDENC, CVEfixes failed)
- Training samples: 12,556
- Test F1: ~0.781
- Conformal: still 0% singletons, threshold = 1.0

**Failure causes**:
- PrimeVul: broken HuggingFace metadata (`SplitInfo` keyword argument issue)
- VUDENC: labels are `list[int]`, not scalar — loader expected scalar
- CVEfixes: same label format issue
- Conformal: label_smoothing=0.1 compresses logit gaps, prevents confident predictions

---

## V5: Planned Fix (Not Yet Executed)

### Targeted Changes

1. **Remove label smoothing** — label_smoothing=0.1 is the root cause of the conformal threshold = 1.0 problem. It compresses the difference between logits, making all predictions equally uncertain.
2. **Add temperature scaling (ConfTS)** — post-hoc calibration layer that sharpens softmax outputs without retraining. Applied after best model is selected.
3. **Fix 3 broken dataset loaders** — PrimeVul (patch SplitInfo), VUDENC/CVEfixes (handle list[int] labels)
4. **Early stop on val_F1** instead of val_loss — Focal Loss values are not directly comparable to CE, so loss going up does not mean the model is getting worse

### Expected Results

| Metric | V4 | V5 Target |
|--------|-----|-----------|
| Datasets loaded | 5/8 | 8/8 |
| Training samples | 12,556 | 16,000-18,000 |
| Test F1 | 0.781 | 0.75-0.80 (similar) |
| Conformal threshold | 1.0 | 0.75-0.92 |
| Singleton rate | 0% | 20-40% |
| Ambiguous rate | 100% | 60-80% |

### Why Singleton Rate Matters

The singleton rate is the **cascade-critical metric**. If the conformal prediction always produces ambiguous sets (both "safe" and "vulnerable"), then Stage 2 can never resolve findings — they all escalate to Stage 3 (LLM). This defeats the purpose of the cascade.

Target: 20-40% singletons means 20-40% of findings are resolved at the Graph stage without needing expensive LLM calls.

---

## Architecture Comparison Across Versions

| Parameter | V1 | V2 | V4 |
|-----------|-----|-----|-----|
| Architecture | MiniGAT | MiniGATv2 | MiniGINv3 |
| Input dim | 773 | 774 | 773 |
| Hidden dim | 256 | 256 | 256 |
| Output dim | 128 | 128 | 128 |
| Heads L1/L2 | 4/4 | 4/4 | — (GIN) |
| Parameters | 297,987 | 298,243 | ~2,370,000 |
| Loss | Weighted CE | Focal Loss | Focal + label_smooth |
| LR schedule | Fixed | CosineAnnealing | CosineAnnealing |
| Conformal alpha | 0.1 | 0.3 | 0.1 |

---

## Lessons Learned (For Report Chapter 4)

1. **Juliet is not sufficient as sole training source.** Its synthetic patterns are trivially memorizable. Always include real-world CVE datasets (CVEfixes, DiverseVul, Devign).

2. **Early stopping criterion must match the actual objective.** When using Focal Loss, val_loss is not a reliable proxy for classification quality. Use val_F1 instead.

3. **Do not double-stack class rebalancing.** Either use Focal Loss (which inherently upweights hard examples) OR use explicit class weights — not both. Stacking causes the model to over-correct and predict the minority class for everything.

4. **Label smoothing kills conformal prediction.** Conformal prediction relies on the model producing discriminative softmax outputs. Label smoothing (even at 0.1) compresses logit gaps, making all predictions equally uncertain → threshold = 1.0 → 0% singletons.

5. **Temperature scaling (ConfTS) is a necessary post-hoc calibration step.** Even without label smoothing, neural networks often produce miscalibrated probabilities. ConfTS adjusts the softmax temperature on a held-out calibration set to produce better-calibrated confidence scores.

6. **Training data volume matters.** V2 had 5× less data than V1 for a 5× harder task. For multi-language GNN vulnerability detection, 15,000+ training samples is the minimum for reasonable performance.

7. **Per-language performance varies significantly.** Python and JavaScript had ~1.0 recall but ~0.46 precision (predicting "vulnerable" for everything). Java performed best (0.80 accuracy). This suggests language-specific fine-tuning or larger per-language datasets are needed.
