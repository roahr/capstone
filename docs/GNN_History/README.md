# SEC-C GNN Training History

Complete knowledge transfer documentation for Module 2 (Graph Neural Network) of the SEC-C vulnerability detection cascade.

## Document Index

| Document | Purpose |
|----------|---------|
| [training_history.md](training_history.md) | Full V1-V5 progression with all metrics, decisions, and lessons |
| [architecture.md](architecture.md) | Model architecture evolution: GAT to GIN, features, graph construction |
| [conformal_prediction.md](conformal_prediction.md) | APS conformal prediction journey and ConfTS breakthrough |
| [datasets.md](datasets.md) | Dataset sources, schemas, loading issues, and fixes |
| [framework_integration.md](framework_integration.md) | How GNN fits into the 4-stage cascade and what files need updating |
| [report.md](report.md) | Report-ready metrics, improvements, and talking points for publication |

## Quick Context

SEC-C is a 4-module cascade for vulnerability detection:
```
Source Code -> [SAST] -> uncertainty routing -> [GNN] -> conformal routing -> [LLM] -> [Report]
```

The GNN (Module 2) produces two outputs:
1. **`structural_risk_score`** — feeds into CWE-adaptive fusion (30% weight by default)
2. **`conformal_prediction_set`** — hard routing gate: singleton = resolve here, ambiguous = escalate to LLM

Five training iterations were conducted on Kaggle T4 GPUs between March-April 2026.

## Current Best Model (V6 Deployed)

- **Architecture**: MiniGINv3 (3-layer GIN, 2.375M params)
- **Test F1**: 0.750 (C/C++ primary), Python F1: 0.836
- **ConfTS**: T=0.95, threshold=0.95 (natural uncertainty routing)
- **Live cascade**: 85% SAST, 2% GNN, 12% LLM across 184 findings / 15 repos
- **Artifacts**: `data/models/mini_gin_v3.pt`, `data/models/conformal_calibration.json`

## Key Artifacts

```
notebooks/
  Kaggle_sec_c_gnn_v3/          # V3 outputs (3K samples, broken conformal)
  Kaggle_sec_c_gnn_v4/          # V4 outputs (21K samples, F1=0.78, 0% singletons)
  Kaggle_sec_c_gnn_v4_improved/ # V5 outputs (21K samples, F1=0.75, 69% singletons)
  sec_c_gnn_training_v4.ipynb   # Current notebook (V5 code)

src/graph/gnn/
  mini_gat.py                   # V2 model (legacy, still loaded by framework)
  graph_validator.py            # Module 2 orchestrator
  data_builder.py               # Feature extraction (needs 5->6 feature update)

configs/
  default.yaml                  # GNN config (needs input_dim 773->774)
  cwe_weights.yaml              # Per-CWE fusion weights
```
