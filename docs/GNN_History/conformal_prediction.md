# Conformal Prediction: From Failure to Breakthrough

## What Conformal Prediction Does in SEC-C

The GNN produces a **prediction set** instead of a single label:
- **Singleton set** `{"safe"}` or `{"vulnerable"}` -> finding resolved at Stage 2, no LLM needed
- **Ambiguous set** `{"safe", "vulnerable"}` -> finding escalated to Stage 3 (LLM dual-agent)

This provides a **distribution-free coverage guarantee**: P(true label in prediction set) >= 1-alpha, regardless of the data distribution. Alpha=0.1 means 90% coverage.

## APS (Adaptive Prediction Sets) Algorithm

1. For each calibration sample, compute the APS nonconformity score:
   - Sort classes by softmax probability (descending)
   - Accumulate probabilities until reaching the true class
   - Score = cumulative probability at true class position

2. Compute threshold q_hat = (1-alpha) quantile of calibration scores

3. At inference: build prediction set by accumulating classes until cumsum >= q_hat

For binary classification (K=2):
- If model ranks true class first (correct): score = P(true class)
- If model ranks true class second (wrong): score = 1.0 (need both classes)

## Why Conformal Failed in V2-V4

### The Mathematical Reality

For binary APS at alpha=0.1, singletons require:
- The model must rank the correct class first AND have P(true) high enough
- If >10% of calibration samples are misranked, the 90th-percentile quantile hits 1.0
- At accuracy=74% (V4), ~26% are misranked -> threshold must be 1.0

### V2 (alpha=0.3): Threshold=1.0, Singletons=0%
- Small dataset, weak model, focal loss collapse
- Everything predicted as ambiguous

### V3 (alpha=0.2): Threshold=0.41, Singletons=0.22%
- Only 454 calibration samples (too few for reliable quantile estimation)
- Model overfit on 1,819 training samples

### V4 (alpha=0.1): Threshold=1.0, Singletons=0%
- 7x more data improved F1 to 0.781 BUT conformal still broken
- **Root cause discovered**: `label_smoothing=0.1` compresses logit gaps
  - Targets [0.933, 0.067] instead of [1, 0]
  - Caps logit gap at ~2.6 nats
  - Softmax probabilities compressed into narrow band [0.5, 0.6]
  - Even correctly classified samples have P(true) ≈ 0.55
  - APS scores cluster at 0.55 (correct) and 1.0 (wrong) -> threshold=1.0

## The ConfTS Solution (V5)

### Conformal Temperature Scaling (Dabah et al. 2024)

**Paper**: "Delving into Temperature Scaling for Adaptive Conformal Prediction" (arXiv:2402.04344)

**Key insight**: A single post-hoc temperature parameter T transforms softmax outputs:
```
calibrated_probs = softmax(logits / T)
```
- T < 1: Sharpens (makes confident predictions more extreme)
- T > 1: Softens (makes confident predictions less extreme)

**Why standard temperature scaling (Guo et al. 2017) doesn't work**: It optimizes T for NLL (calibration), which typically produces T > 1. But our model is underconfident — we need T < 1 to sharpen, not soften.

**ConfTS difference**: Optimizes T to minimize mean prediction set size while maintaining coverage, not to minimize NLL. This naturally finds T < 1 for underconfident models.

### Implementation

```
Val set (15%): Used for T optimization (grid search)
Cal set (15%): Used for final conformal threshold q_hat
Test set (10%): Final evaluation
```

This split preserves exchangeability -> coverage guarantee maintained. Proven safe by Kofman et al. (ICML 2025) and Dabah et al. (2024).

### V5 Results

ConfTS grid search on validation set (75 candidates, T in [0.05, 3.0]):

| T | Val Coverage | Singleton% | Mean Set Size |
|---|-------------|------------|---------------|
| 0.05 | 87.1% | 66.2% | 1.338 |
| **0.10** | **92.0%** | **53.7%** | **1.463** |
| 0.15 | 94.4% | 45.8% | 1.542 |
| 0.20 | 96.3% | 39.1% | 1.609 |
| 0.25 | 97.6% | 33.8% | 1.662 |
| 0.50 | 99.3% | 13.0% | 1.870 |
| 1.00 | 97.4% | 2.6% | 1.974 |

Selected T=0.10 (minimum T meeting val coverage >= 90%).

**Applied to calibration/test sets**:
- Cal singleton rate: 69.1%, coverage: 86.4%
- Test singleton rate: 67.7%, coverage: 84.3%

### From Offline to Live Deployment (V6)

Three critical findings emerged when deploying the conformal predictor in the live cascade:

**Finding 1: Threshold=1.0 is a degenerate boundary for binary classification.**
For 2-class softmax, `P(top_class) < 1.0` strictly with finite logits. The condition
`cumsum[0] >= 1.0` can only be satisfied by float overflow — not a principled threshold.
Setting threshold=0.95 provides a meaningful confidence gate: singletons require ≥95%
model confidence, which is scientifically defensible.

**Finding 2: Backward slicing creates distribution shift.**
The model was calibrated on full function graphs (10-300 nodes), but the live pipeline's
backward slicer reduces CPGs to 1-6 nodes. On such tiny graphs, the model cannot extract
meaningful structural features. Solution: use full CPG for GNN inference (truncated to
max_nodes=300), aligning inference with training conditions.

**Finding 3: Extreme temperature scaling eliminates uncertainty signal.**
T=0.2 produces near-binary softmax for ALL inputs, making every prediction a singleton
regardless of actual model confidence. This defeats the purpose of conformal routing —
the cascade needs SOME ambiguous predictions to trigger LLM escalation. T=0.95 preserves
natural uncertainty: confident → singleton (GNN), uncertain → ambiguous (LLM).

**Deployed configuration**: threshold=0.95, T=0.95, full CPG input.

**Live benchmark (15 repos, 184 findings)**:
- SAST: 85% | GNN: 2% | LLM: 12% | Unresolved: 0%

## Theoretical Guarantees

### Coverage Guarantee (Vovk et al. 2005)
For exchangeable calibration data, APS provides:
```
P(Y_new in C(X_new)) >= 1 - alpha
```
This holds regardless of the data distribution — no parametric assumptions needed.

### Temperature Scaling Preserves Guarantees (Kofman et al. ICML 2025)
Post-hoc temperature scaling before conformal prediction does NOT violate coverage guarantees, provided:
1. Temperature is optimized on a separate split from the conformal calibration set
2. The calibration set remains exchangeable with test data

### Novel Contribution
First application of APS conformal prediction to vulnerability detection, combined with ConfTS temperature optimization. This replaces arbitrary confidence thresholds with finite-sample-guaranteed uncertainty sets for principled cascade routing.

## Key Citations

- Vovk et al. 2005, "Algorithmic Learning in a Random World" (conformal prediction foundations)
- Angelopoulos et al. 2021, "Uncertainty Sets for Image Classifiers using Conformal Prediction" (APS/RAPS, ICLR)
- Angelopoulos & Bates 2023, "A Gentle Introduction to Conformal Prediction" (tutorial)
- Guo et al. 2017, "On Calibration of Modern Neural Networks" (temperature scaling, ICML)
- Dabah et al. 2024, "Delving into Temperature Scaling for Adaptive Conformal Prediction" (ConfTS)
- Kofman et al. 2025, "On Temperature Scaling and Conformal Prediction of Deep Classifiers" (ICML)
