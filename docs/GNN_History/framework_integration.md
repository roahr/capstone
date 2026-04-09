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

## Files Requiring Update for V5 Model

### 1. `src/graph/gnn/mini_gin.py` (CREATE)
Port MiniGINv3 from notebook. Must implement:
- `__init__(input_dim=774, hidden_dim=384, num_gin_layers=3, dropout=0.35)`
- `forward(x, edge_index, batch)` -> `(logits, confidence)`
- `predict(x, edge_index, batch)` -> `(pred_class, pred_prob, confidence)`
- `get_attention_weights()` -> `{}` (stub, GIN has no attention)

### 2. `src/graph/gnn/graph_validator.py` (UPDATE)
- Lines 156-166: Replace `MiniGAT` import with `MiniGINv3`
- Update `input_dim=773` to `774`
- Load `conformal_temperature` from calibration JSON
- Apply `softmax(logits / T)` before conformal prediction

### 3. `src/graph/gnn/data_builder.py` (UPDATE)
- `NODE_FEATURE_DIM: int = 5` -> `6`
- `TOTAL_DIM: int = 773` -> `774`
- Add `language_id` to feature extraction

### 4. `configs/default.yaml` (UPDATE)
```yaml
gnn:
  input_dim: 774        # was 773
  hidden_dim: 384
  num_gin_layers: 3
  dropout: 0.35
  num_classes: 2
  model_path: "data/models/mini_gat_v5.pt"
```

### 5. Artifact Deployment
```
notebooks/Kaggle_sec_c_gnn_v4_improved/mini_gat_v3.pt
  -> data/models/mini_gat_v5.pt

notebooks/Kaggle_sec_c_gnn_v4_improved/conformal_calibration_v3.json
  -> data/models/conformal_calibration.json

notebooks/Kaggle_sec_c_gnn_v4_improved/graph_config_v3.json
  -> data/models/graph_config.json
```

## Graceful Degradation

The framework runs without the GNN model. If the model file is missing:
- `graph_validator.py` sets `self._model = None`
- Findings skip Stage 2 entirely
- All SAST-escalated findings go directly to Stage 3 (LLM)
- Fusion uses only SAST and LLM scores (beta=0)

This ensures the framework is functional during development and for users who don't train the GNN.
