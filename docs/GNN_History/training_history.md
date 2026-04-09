# GNN Training History: V1 through V5

## Version Summary

| Version | Date | Samples | Model | Test F1 | AUC-ROC | Singleton% | Key Change |
|---------|------|---------|-------|---------|---------|------------|------------|
| V1 | Mar 2026 | ~1,500 | Mini-GAT | ~0.72 | — | — | Synthetic-inflated, overfit |
| V2 | Mar 2026 | ~1,700 | Mini-GAT (298K) | 0.560 | 0.744 | 0% | Multi-language, honest eval |
| V3 | Apr 2026 | 3,032 | MiniGINv3 (2.4M) | 0.653 | 0.623 | 0.22% | GIN architecture, real datasets |
| V4 | Apr 2026 | 20,928 | MiniGINv3 (2.4M) | **0.781** | **0.826** | 0% | Data cap fix, 7x more data |
| V5 | Apr 2026 | 21,150 | MiniGINv3 + ConfTS | 0.750 | 0.781 | **69.1%** | Label smoothing fix, ConfTS |

---

## V1: Synthetic Baseline (Discarded)

- Used synthetically generated code samples
- Achieved ~0.72 F1 — inflated by overfitting to synthetic patterns
- **Lesson**: Synthetic-only training produces deceptively high metrics that don't generalize

---

## V2: Multi-Language GAT Baseline

**Architecture**: 2-layer Mini-GAT, 298K parameters, 773-dim input (768 GCB + 5 structural)

**Test Metrics**:
- F1: 0.560, Precision: 0.397, Recall: 0.951, AUC-ROC: 0.744
- Degenerate: predicts almost everything as vulnerable (high recall, low precision)

**Per-Language F1**: Python 0.633, JS 0.650, Java 0.571, C/C++ 0.543, Go 0.609

**Conformal**: alpha=0.3, threshold=1.0, singleton=0%, mean_set_size=2.0

**Issues**:
- GAT's weighted-mean aggregation is not injective (can conflate structurally distinct graphs)
- Small dataset (~1,700 calibration samples)
- Focal loss (gamma=2) caused threshold collapse

---

## V3: GIN Architecture Shift

**Key Changes from V2**:
- Architecture: GAT(2L, 298K) -> GIN(3L, 2.4M) with residual + BatchNorm
- Pooling: global_mean -> mean+add dual pooling (768-dim graph embedding)
- Embedding: CLS token -> mean pooling (fixes MISSING pooler warning)
- Loss: Focal loss -> CrossEntropy + label_smoothing=0.1
- LR: 1e-3 -> 3e-4 with 5-epoch linear warmup + cosine decay
- Balance: 2.0:1 -> strict 1.0:1 per-language
- Added 6th structural feature: language_id (was 5 features, now 6)

**Test Metrics**:
- F1: 0.653, Precision: 0.544, Recall: 0.815, AUC-ROC: 0.623
- Best epoch: 20/45, val F1: 0.665

**Dataset**: 3,032 total graphs (train: 1,819)
- **Root cause of small dataset**: `max_per_language=3000` capped 23,150 available C/C++ to 3,000
- CrossVul failed (wrong HF IDs), CVEfixes only 11 Python samples

**Conformal**: alpha=0.2, threshold=0.41, singleton=0.22%
- 1,819 training samples on 2.4M-param model -> massive overfit
- Conformal threshold near-degenerate (99.78% ambiguous)

**Lesson**: Data starvation was the bottleneck, not architecture

---

## V4: Dataset Expansion Breakthrough

**Key Changes from V3**:
- `max_per_language`: 3,000 -> 20,000 (the single most impactful fix)
- alpha: 0.2 -> 0.1 (aligned with framework's default.yaml)
- Dropout: 0.4 -> 0.35 (less regularization with more data)
- Patience: 25 -> 20
- Corrected HuggingFace dataset IDs for CrossVul, Juliet, CVEfixes
- Added PrimeVul as a new source (failed to load — metadata bug)
- Fixed SINK_PATTERNS scoping bug (was causing 100% graph build failures)

**Dataset**: 20,928 total graphs (7x increase!)
- C/C++: 20,000 (10K vuln + 10K safe)
- Python: 374, JS: 252, Java: 194, Go: 108
- Sources: BigVul (5,723), DiverseVul (4,944), Juliet-C (3,632), CrossVul (3,619), Devign (3,010)

**Test Metrics**:
- **F1: 0.781** — exceeded 0.72 stretch target
- Precision: 0.675, Recall: 0.926, **AUC-ROC: 0.826**
- C/C++ F1: 0.788
- Training: 41 epochs, best epoch 21, 4.8 min on T4

**Per-CWE Standouts**: CWE-476 (null ptr) 0.926, CWE-787 (OOB write) 0.895, CWE-416 (UAF) 0.872

**Conformal**: alpha=0.1, threshold=1.0, **singleton=0%**
- Despite 7x more data, conformal still completely broken
- Root cause identified: `label_smoothing=0.1` compresses logit gaps to ~2.6 nats
- Softmax outputs cluster in narrow band around 0.5-0.6
- With accuracy=74%, 26% of cal samples misranked -> APS score=1.0 for all misranked
- Since 26% > alpha=10%, the 90th-percentile quantile must be 1.0

**Lesson**: Classification performance and conformal prediction have different requirements. Good F1 needs correct binary decisions; conformal needs confident correct rankings.

---

## V5 (V4-Improved): ConfTS Breakthrough

**Key Changes from V4**:
- `label_smoothing`: 0.1 -> 0.0 (allow wider logit gaps, sharper softmax)
- **NEW**: ConfTS (Conformal Temperature Scaling, Dabah et al. 2024)
  - Post-hoc optimization of temperature parameter T
  - Grid search T in [0.05, 3.0] on validation set
  - Minimizes mean APS set size while maintaining coverage >= 90%
  - Best T = 0.100 (aggressive sharpening)
- Fixed VUDENC dataset loading (label is list, not scalar)
- Fixed CVEfixes dataset loading (same issue)
- PrimeVul fix attempted (JSONL direct load) — new error "Value is too big!"

**Dataset**: 21,150 total graphs
- C/C++: 20,000, Python: 596 (up from 374), JS: 252, Java: 194, Go: 108
- 7 of 8 planned sources loaded (PrimeVul still failing)
- VUDENC: 3,000 samples (2,916 safe, 84 vuln) — extreme class imbalance in source
- CVEfixes: 3,000 samples (2,964 safe, 36 vuln) — extreme class imbalance in source

**Test Metrics**:
- F1: 0.750 (slight drop from 0.781 due to no label smoothing regularization)
- Precision: 0.643, Recall: 0.899, AUC-ROC: 0.781
- **Python F1: 0.836** (up from 0.667 — major improvement from VUDENC/CVEfixes)
- Training: 61 epochs, best epoch 41, 7.0 min on T4
- Decision threshold: 0.32 (shifted from 0.53 due to bimodal P(vuln) distribution)

**Conformal — THE BREAKTHROUGH**:
- Temperature: T=0.100 (ConfTS optimized)
- **Singleton rate: 69.1% (cal) / 67.7% (test)**
- Ambiguous rate: 30.9% (cal) / 32.3% (test)
- Mean set size: 1.309 (down from 2.0)

**Coverage Issue**: Test coverage=84.3% — below the 90% target
- T=0.10 is too aggressive (val coverage was 92%, but didn't transfer to test)
- **Fix needed**: Use T=0.20 (val coverage 96.3%, expected test coverage ~93%)
- With T=0.20: expected singleton rate ~35-40%, coverage ~93-96%
- This is a config change, no retraining needed

**Training Behavior Without Label Smoothing**:
- Train loss drops to 0.16 (strong memorization)
- Val loss climbs to 1.94 (overfitting after epoch ~20)
- The model is less regularized but produces sharper logit gaps
- Score distribution becomes bimodal: safe near 0.0, vulnerable near 1.0

---

## Metrics Progression Table

### Classification
| Metric | V2 | V3 | V4 | V5 |
|--------|----|----|----|----|
| Test F1 | 0.560 | 0.653 | **0.781** | 0.750 |
| Test Precision | 0.397 | 0.544 | 0.675 | 0.643 |
| Test Recall | 0.951 | 0.815 | 0.926 | 0.899 |
| Test AUC-ROC | 0.744 | 0.623 | **0.826** | 0.781 |
| C/C++ F1 | 0.543 | 0.658 | **0.788** | 0.750 |
| Python F1 | 0.633 | 0.400 | 0.667 | **0.836** |

### Conformal Prediction
| Metric | V2 | V3 | V4 | V5 |
|--------|----|----|----|----|
| Alpha | 0.30 | 0.20 | 0.10 | 0.10 |
| Threshold | 1.0 | 0.41 | 1.0 | 1.0 |
| Singleton% | 0% | 0.22% | 0% | **69.1%** |
| Mean set size | 2.0 | 1.998 | 2.0 | **1.309** |
| Coverage | 100% | 100% | 100% | 84.3% |
| ConfTS Temp | — | — | — | 0.100 |

### Scale
| Metric | V2 | V3 | V4 | V5 |
|--------|----|----|----|----|
| Training samples | ~1,500 | 1,819 | 12,556 | 12,689 |
| Total graphs | ~1,700 | 3,032 | 20,928 | 21,150 |
| Training time | ~1 min | 0.6 min | 4.8 min | 7.0 min |
| Best epoch | — | 20 | 21 | 41 |
| Total epochs | — | 45 | 41 | 61 |
| Parameters | 298K | 2.4M | 2.4M | 2.4M |
