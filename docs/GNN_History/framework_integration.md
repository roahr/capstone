# Framework Integration: GNN in the SEC-C Cascade

## Cascade Position

```
Source Code
  -> [Module 1: SAST] (tree-sitter + CodeQL)
       -> Uncertainty score U = 0.4*conf + 0.3*complex + 0.2*novelty + 0.1*conflict
       -> U < 0.5: resolve here (~75% of findings)
       -> U >= 0.5: escalate to Module 2

  -> [Module 2: GNN] (MiniGINv3 + APS conformal)
       -> structural_risk_score (0-1, feeds into fusion)
       -> conformal_prediction_set
       -> Singleton {"safe"} or {"vulnerable"}: resolve here (~35-69% of escalated)
       -> Ambiguous {"safe","vulnerable"}: escalate to Module 3

  -> [Module 3: LLM] (Gemini 2.5, dual-agent Attacker/Defender)
       -> CVSS v3.1 score
       -> Consensus verdict

  -> [Module 4: Report] (CWE-adaptive fusion + SARIF output)
       -> final_score = alpha*SAST + beta*GAT + gamma*LLM
       -> Classification: >=0.85 CONFIRMED, >=0.50 LIKELY, <0.50 POTENTIAL
```

## GNN Outputs Used by Framework

### 1. `structural_risk_score` (float, 0-1)
- Source: softmax probability of "vulnerable" class
- Used in: `src/orchestrator/fusion.py` line ~45: `gat_score = finding.graph_validation.structural_risk_score`
- Role: beta-term in CWE-adaptive fusion formula

### 2. `conformal_prediction_set` (list of class labels)
- Source: APS prediction set from conformal calibration
- Used in: `src/sast/router.py` for escalation decisions
- Singleton = resolve at Stage 2, Ambiguous = escalate to Stage 3

### 3. Confidence score (float, 0-1)
- Source: confidence head output (sigmoid)
- Used in: uncertainty scoring for downstream routing

## CWE-Adaptive Fusion Weights

From `configs/cwe_weights.yaml`:

| CWE Category | SAST (alpha) | GAT (beta) | LLM (gamma) |
|-------------|------|-----|-----|
| Injection (CWE-78,79,89,94) | 0.20 | 0.20 | **0.60** |
| Buffer (CWE-119,120,121,122) | 0.25 | **0.45** | 0.30 |
| Memory (CWE-125,416,476,787) | 0.20 | **0.60** | 0.20 |
| Crypto (CWE-326,327,328) | **0.50** | 0.30 | 0.20 |
| Default | 0.35 | **0.30** | 0.35 |

Memory and buffer CWEs weight the GNN heavily (45-60%) because graph structure captures pointer/memory patterns effectively.

## Framework Integration (Completed)

All integration changes have been applied and verified (287 tests pass).

### Files Created
- `src/graph/gnn/mini_gin_v3.py` — MiniGINv3 model class (2.375M params)

### Files Modified
- `src/graph/gnn/graph_validator.py` — Loads MiniGINv3, passes language to data builder,
  reads conformal_temperature from calibration JSON, uses **full CPG** (not backward-sliced)
  for GNN inference to match training distribution
- `src/graph/uncertainty/conformal.py` — Added `_temperature` field, applies
  `softmax(logits / T)` in both `calibrate()` and `predict()`, clamped threshold to 1.0 max
- `src/graph/gnn/data_builder.py` — `NODE_FEATURE_DIM: 5 → 6`, `TOTAL_DIM: 773 → 774`,
  passes `language` parameter to feature extractor
- `src/graph/features/node_features.py` — Added 6th feature (`language_id`), added
  `LANGUAGE_IDS` mapping (py=0.0, js=0.2, java=0.4, c/cpp=0.6, go=0.8)
- `configs/default.yaml` — `input_dim: 774`, `hidden_dim: 384`, `model_path: mini_gin_v3.pt`,
  added `conformal.temperature: 0.95`
- `src/cli/main.py`, `src/cli/interactive.py` — Updated model path references

### Deployed Artifacts
```
data/models/
  mini_gin_v3.pt                 (9.1 MB)  — V5 trained weights
  conformal_calibration.json               — T=0.95, threshold=0.95
  graph_config.json                        — Architecture + dataset info
```

## Graceful Degradation

The framework runs without the GNN model. If the model file is missing:
- `graph_validator.py` sets `self._model = None`
- Findings skip Stage 2 entirely
- All SAST-escalated findings go directly to Stage 3 (LLM)
- Fusion uses only SAST and LLM scores (beta=0)

This ensures the framework is functional during development and for users who don't train the GNN.
