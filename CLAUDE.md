# SEC-C: Multi-Stage Code Security Framework

## Project Overview
PhD-level research prototype for adaptive vulnerability triage and detection.
4-module cascade: SAST → Graph → LLM → Reporting with uncertainty-driven escalation.

## Architecture
- **Module 1 (SAST)**: CodeQL + Tree-sitter, 5 languages (Python, JS/TS, Java, C/C++, Go)
- **Module 2 (Graph)**: Joern CPG + Mini-GAT + TorchCP conformal prediction
- **Module 3 (LLM)**: Gemini 2.5 dual-agent (attacker/defender) + NVD RAG
- **Module 4 (Report)**: SARIF 2.1.0 + console output + CLI

## Tech Stack
- Python 3.11+, Pydantic for data models
- CodeQL CLI for taint analysis
- Joern v4.0 for CPG generation
- PyTorch + PyTorch Geometric for Mini-GAT
- GraphCodeBERT for code embeddings
- TorchCP for conformal prediction
- Gemini 2.5 API (free tier) for LLM validation
- FAISS + BM25 for RAG
- Typer + Rich for CLI

## Conventions
- All data models in `src/sast/sarif/schema.py` use Pydantic v2
- Async where possible (aiohttp for API calls)
- Type hints required on all public functions
- Tests in `tests/` mirror `src/` structure
- SARIF 2.1.0 with custom `sec-c/*` properties

## Running
```bash
# Install
pip install -e ".[dev]"

# Test
pytest -v

# Scan local code
sec-c scan <path>

# Scan GitHub repo
sec-c scan --github <owner/repo>
```

## Key Files
- `src/sast/sarif/schema.py` — Core data models (Finding, TaintFlow, etc.)
- `src/sast/uncertainty/scorer.py` — 4-factor uncertainty scoring
- `src/orchestrator/pipeline.py` — Cascade coordinator
- `src/orchestrator/fusion.py` — Score fusion (α·SAST + β·GAT + γ·LLM)
- `configs/default.yaml` — Framework configuration
