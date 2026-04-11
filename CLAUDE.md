# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PhD research prototype: **Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection.** 4-module cascade (SAST → Graph → LLM → Reporting) with uncertainty-driven escalation. Findings are resolved at the cheapest stage possible; only ambiguous cases escalate.

## Build & Run

```bash
# Install (base + dev tools)
pip install -e ".[dev]"

# Install with GNN dependencies (PyTorch, PyG, transformers, torchcp)
pip install -e ".[gnn]"

# Run all tests
pytest -v

# Run specific test file or directory
pytest tests/unit/test_sast/test_uncertainty.py -v
pytest tests/unit/ -v
pytest tests/integration/ -v

# Coverage
pytest --cov=src

# Lint
ruff check src/
ruff format src/

# CLI commands
sec-c scan <path>                          # Full cascade scan
sec-c scan --dashboard                     # Open interactive HTML dashboard
sec-c scan --stage sast                    # SAST-only (fast)
sec-c scan --stage graph                   # Up to Graph stage
sec-c scan --languages py,js --dashboard    # Filter languages, open dashboard
sec-c report <sarif_file>                  # Display existing SARIF report
sec-c status                               # Show tool availability
sec-c                                      # Interactive REPL mode
```

## Environment Variables

Copy `.env.example` to `.env`. Required keys depend on which stages you run:
- `GEMINI_API_KEY` — Required for LLM stage (free tier: 15 RPM / 500 RPD for Flash)
- `GROQ_API_KEY` — Alternative LLM provider (set `LLM_PROVIDER=groq`)
- `GITHUB_TOKEN` — For CodeQL database downloads and GitHub repo scanning
- `NVD_API_KEY` — Faster NVD fetching (50 req/30s vs 5/30s without)

## Architecture

### Cascade Flow
```
Source Code → [Module 1: SAST] → route by uncertainty → [Module 2: Graph] → route by conformal → [Module 3: LLM] → [Module 4: Fusion + Report]
```

- **Module 1 (SAST)**: Tree-sitter pre-screening (24 patterns) + CodeQL taint analysis. Produces findings with 4-factor uncertainty scores. Findings with U < 0.5 are resolved here (~75%).
- **Module 2 (Graph)**: Joern CPG → backward slicing → GraphCodeBERT embeddings (768-dim) + 5 structural features → Mini-GAT (773→256→128, 4 heads) → conformal prediction (APS, α=0.1). Singleton prediction sets resolve here; ambiguous sets escalate.
- **Module 3 (LLM)**: Dual-agent consensus — Attacker (exploit analysis) + Defender (sanitizer analysis) via Gemini 2.5. RAG retrieval from 200K+ NVD entries + 900+ CWE entries (FAISS + BM25 hybrid). Produces CVSS v3.1 scores.
- **Module 4 (Report)**: CWE-adaptive score fusion (α·SAST + β·GAT + γ·LLM), SARIF 2.1.0 output, HTML dashboard, console tables.

### Uncertainty-Driven Escalation
```
U = 0.4·confidence + 0.3·complexity + 0.2·novelty + 0.1·conflict + severity_adj
Escalation threshold: U >= 0.5
```

### Score Fusion
Weights are CWE-adaptive (from `configs/cwe_weights.yaml`):
- Injection CWEs: LLM-heavy (0.2, 0.2, 0.6)
- Crypto CWEs: SAST-heavy (0.5, 0.3, 0.2)
- Memory CWEs: Graph-heavy (0.2, 0.6, 0.2)

Classification: ≥0.85 CONFIRMED, ≥0.50 LIKELY, <0.50 POTENTIAL.

### Graceful Degradation
The framework runs without CodeQL, Joern, GNN model, or LLM API keys. Missing tools skip their stage; findings escalate to the next available stage or remain UNRESOLVED.

## Conventions

- All data models in `src/sast/sarif/schema.py` use Pydantic v2
- Async where possible (google-genai SDK, httpx for API calls)
- Type hints required on all public functions
- Tests in `tests/` mirror `src/` structure
- SARIF 2.1.0 with custom `sec-c/*` properties
- Ruff: Python 3.11 target, 100-char line length, rules E/F/I/N/W
- LLM prompts use Jinja2 templates in `src/llm/prompts/templates/` organized by CWE category

## Key Files

- `src/sast/sarif/schema.py` — Core Pydantic models: Finding, TaintFlow, UncertaintyScore, GraphValidation, LLMValidation, AttackerVerdict, DefenderVerdict, ScanResult
- `src/sast/uncertainty/scorer.py` — 4-factor uncertainty scoring with severity adjustments
- `src/sast/router.py` — Escalation routing (SAST → Graph → LLM)
- `src/orchestrator/pipeline.py` — Async cascade coordinator (PipelineOrchestrator, CascadeStats)
- `src/orchestrator/fusion.py` — CWE-adaptive score fusion engine
- `src/graph/gnn/mini_gat.py` — 2-layer GAT architecture (classification + confidence heads)
- `src/graph/uncertainty/conformal.py` — APS conformal prediction layer
- `src/llm/consensus/engine.py` — Attacker/Defender consensus protocol (4 decision rules)
- `src/llm/consensus/cvss.py` — CVSS v3.1 base score calculator
- `src/llm/rag/knowledge_base.py` — Hybrid FAISS + BM25 retrieval with Reciprocal Rank Fusion
- `src/cli/main.py` — Typer CLI entry point
- `configs/default.yaml` — All thresholds, weights, model paths, rate limits
- `configs/cwe_weights.yaml` — Per-CWE fusion weight calibration
