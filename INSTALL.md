# SEC-C Installation & Running Manual

> Complete step-by-step guide to install, configure, and run SEC-C.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Step-by-Step Installation](#2-step-by-step-installation)
3. [External Tools Setup](#3-external-tools-setup)
4. [Dataset & Model Setup](#4-dataset--model-setup)
5. [Configuration](#5-configuration)
6. [Running SEC-C](#6-running-sec-c)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. System Requirements

### Minimum

| Component | Requirement |
|-----------|------------|
| **OS** | Windows 10/11, Linux (Ubuntu 20.04+), macOS 12+ |
| **Python** | 3.11 or higher |
| **RAM** | 8 GB |
| **Disk** | 5 GB free (for tools + data) |
| **Network** | Required for initial setup |

### Recommended

| Component | Requirement |
|-----------|------------|
| **RAM** | 16 GB |
| **GPU** | NVIDIA with 8GB+ VRAM (for faster GNN training) |
| **Disk** | 20 GB free (for full NVD database) |

### Check Your System

```bash
python --version    # Need 3.11+
java -version       # Need 11+ (for Joern)
git --version       # Need 2.30+
```

---

## 2. Step-by-Step Installation

### Step 2.1: Clone and Setup Environment

```bash
# Clone the repository
git clone https://github.com/your-org/sec-c.git
cd sec-c

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Linux/macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Windows (Git Bash):
source .venv/Scripts/activate
```

### Step 2.2: Install Python Dependencies

```bash
# Install SEC-C with all dependencies
pip install -e ".[dev]"
```

**If you encounter PyTorch installation issues:**

```bash
# CPU-only PyTorch (smaller download, works everywhere)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install torch-geometric

# GPU PyTorch (CUDA 12.1)
pip install torch --index-url https://download.pytorch.org/whl/cu121
pip install torch-geometric
```

**If you encounter torch-geometric installation issues:**

```bash
# Install PyG dependencies first
pip install torch-scatter torch-sparse -f https://data.pyg.org/whl/torch-2.0.0+cpu.html
pip install torch-geometric
```

### Step 2.3: Verify Installation

```bash
# Check that sec-c is installed
sec-c status

# Run tests
pytest tests/ -v --tb=short
```

---

## 3. External Tools Setup

### 3.1 CodeQL CLI (Required for Stage 1)

CodeQL is the backbone of the SAST engine. It provides deep taint tracking across 5 languages.

**Automated:**
```bash
bash scripts/setup_codeql.sh
```

**Manual (Windows):**

1. Go to: https://github.com/github/codeql-cli-binaries/releases
2. Download `codeql-win64.zip` (latest release)
3. Extract to `C:\codeql\` (or `%USERPROFILE%\.sec-c\codeql\`)
4. Add to PATH:
   ```powershell
   # PowerShell (temporary)
   $env:PATH += ";C:\codeql"

   # Permanent: System → Environment Variables → PATH → add C:\codeql
   ```
5. Download query packs:
   ```bash
   codeql pack download codeql/python-queries
   codeql pack download codeql/javascript-queries
   codeql pack download codeql/java-queries
   codeql pack download codeql/cpp-queries
   codeql pack download codeql/go-queries
   ```
6. Verify: `codeql --version`

**Manual (Linux/macOS):**

```bash
# Download latest
CODEQL_VERSION=$(curl -s https://api.github.com/repos/github/codeql-cli-binaries/releases/latest | grep tag_name | cut -d'"' -f4)
wget "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip"

# Extract
mkdir -p ~/.sec-c/codeql
unzip codeql-linux64.zip -d ~/.sec-c/

# Add to PATH
echo 'export PATH="$HOME/.sec-c/codeql:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Download query packs
codeql pack download codeql/python-queries
codeql pack download codeql/javascript-queries
codeql pack download codeql/java-queries
codeql pack download codeql/cpp-queries
codeql pack download codeql/go-queries

# Verify
codeql --version
```

### 3.2 Joern (Optional — for Stage 2 Graph Analysis)

Joern generates Code Property Graphs for the Mini-GAT validator. If not installed, Stage 2 will use a simplified graph fallback.

**Automated:**
```bash
bash scripts/setup_joern.sh
```

**Manual:**

```bash
# Requires Java 11+
java -version

# Install Joern (Linux/macOS)
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" | bash

# Windows: Download from https://github.com/joernio/joern/releases
# Extract and add to PATH

# Verify
joern --version
```

### 3.3 Gemini API Key (Optional — for Stage 3 LLM Analysis)

The LLM dual-agent requires a Gemini API key. The **free tier** is sufficient.

1. Go to: https://aistudio.google.com/apikey
2. Sign in with Google account
3. Click "Create API Key"
4. Copy the key (starts with `AIza...`)

```bash
# Set the API key
# Linux/macOS:
export GEMINI_API_KEY="AIza..."

# Windows PowerShell:
$env:GEMINI_API_KEY="AIza..."

# Windows CMD:
set GEMINI_API_KEY=AIza...

# Permanent: add to your shell profile (.bashrc, .zshrc) or Windows Environment Variables
```

**Free Tier Limits:**
| Model | Requests/Minute | Requests/Day |
|-------|----------------|-------------|
| Gemini 2.5 Pro | 5 | 100 |
| Gemini 2.5 Flash | 10 | 250 |

### 3.4 GitHub Token (Optional — for GitHub Repo Scanning)

```bash
# Generate at: https://github.com/settings/tokens
# Needs: repo (read) scope
export GITHUB_TOKEN="ghp_..."
```

---

## 4. Dataset & Model Setup

### 4.1 Build RAG Knowledge Base

The RAG system indexes CVE/CWE data for LLM grounding. This reduces hallucinations and improves accuracy.

```bash
# Full build (CWE + NVD CVEs from 2022-2026)
# Takes: ~2-3 hours, downloads ~2GB
python scripts/build_rag.py --years 2022-2026

# Quick build (CWE catalog only)
# Takes: ~2 minutes
python scripts/build_rag.py --cwe-only

# What gets created:
#   data/cwe/          - 900+ CWE descriptions
#   data/rag/nvd/      - NVD CVE entries
#   data/rag/faiss_index   - FAISS vector index
#   data/rag/bm25_index    - BM25 keyword index
```

**To update later:**
```bash
python scripts/update_nvd.py  # Fetches only new CVEs
```

### 4.2 Download Juliet Test Suite (For GNN Training)

```bash
# Downloads NIST Juliet Test Suite
# Takes: ~5-10 minutes
python scripts/download_juliet.py

# What gets created:
#   data/juliet/python/    - Python test cases
#   data/juliet/java/      - Java test cases
#   data/juliet/labels.json - Ground truth labels
```

### 4.3 Train Mini-GAT Model

```bash
# Train on Juliet (CPU, ~4 hours)
python scripts/train_gat.py --epochs 50 --device cpu

# Train on GPU (~1 hour)
python scripts/train_gat.py --epochs 50 --device cuda

# Custom settings
python scripts/train_gat.py \
    --epochs 100 \
    --batch-size 64 \
    --lr 0.0005 \
    --device cuda \
    --output data/models/mini_gat.pt

# What gets created:
#   data/models/mini_gat.pt - Trained model weights
```

---

## 5. Configuration

### Main Configuration: `configs/default.yaml`

Key settings to customize:

```yaml
# Adjust escalation sensitivity (lower = more escalation)
sast:
  uncertainty:
    escalation_threshold: 0.5   # Default: 0.5

# Use GPU for embeddings
graph:
  embeddings:
    device: "cuda"              # Default: "cpu"

# Conformal prediction coverage
graph:
  conformal:
    alpha: 0.1                  # 90% coverage (lower alpha = more conservative)

# Score fusion weights
orchestrator:
  fusion:
    sast_weight: 0.3
    gat_weight: 0.3
    llm_weight: 0.4
```

### CWE-Specific Weights: `configs/cwe_weights.yaml`

Different CWE categories perform best with different stage weights. These are pre-configured based on research findings.

---

## 6. Running SEC-C

### Quick Start: Scan Your Code

```bash
# Simplest: SAST-only scan (no external tools needed beyond CodeQL)
sec-c scan ./your-project --stage sast

# Full cascade with HTML report
sec-c scan ./your-project --html

# Interactive mode
sec-c
```

### Running Modes

#### Mode 1: SAST Only (Fastest, Minimal Setup)

**Requires:** CodeQL CLI only

```bash
sec-c scan ./your-project --stage sast
```

This runs:
- Tree-sitter pre-screening (< 100ms)
- CodeQL taint analysis (seconds to minutes depending on project size)
- 4-factor uncertainty scoring
- Console report with findings

#### Mode 2: SAST + Graph (Moderate)

**Requires:** CodeQL + Joern + trained Mini-GAT model

```bash
sec-c scan ./your-project --stage graph
```

This adds:
- Joern CPG generation
- GraphCodeBERT embeddings
- Mini-GAT structural validation
- Conformal prediction calibrated sets

#### Mode 3: Full Cascade (Most Accurate)

**Requires:** CodeQL + Joern + Mini-GAT + Gemini API

```bash
sec-c scan ./your-project --stage llm --html
```

This adds:
- Gemini 2.5 attacker agent (exploit construction)
- Gemini 2.5 defender agent (sanitization analysis)
- Adversarial consensus protocol
- RAG-grounded reasoning with CVE/CWE knowledge
- HTML dashboard with detailed analysis

#### Mode 4: GitHub Repo Scanning

**Requires:** CodeQL + GitHub token

```bash
sec-c scan --github django/django --stage sast
sec-c scan --github expressjs/express --html
```

### Output Options

```bash
# Console only (default)
sec-c scan ./project

# Save SARIF report
sec-c scan ./project --output results.sarif

# Open HTML dashboard in browser
sec-c scan ./project --html

# Both SARIF and HTML
sec-c scan ./project --output results.sarif --html

# View existing SARIF as HTML
sec-c report results.sarif --html
```

---

## 7. Troubleshooting

### Common Issues

#### "CodeQL not found"
```bash
# Check if CodeQL is in PATH
which codeql  # Linux/macOS
where codeql  # Windows

# If not, add it:
export PATH="$HOME/.sec-c/codeql:$PATH"
```

#### "Joern not found" (Stage 2 warning)
This is non-fatal. Stage 2 will use a simplified graph fallback. To fix:
```bash
bash scripts/setup_joern.sh
```

#### "GEMINI_API_KEY not set" (Stage 3 warning)
This is non-fatal. Stage 3 will be skipped. To fix:
```bash
export GEMINI_API_KEY="your-key"
```

#### PyTorch/torch-geometric import errors
```bash
# Reinstall PyTorch for your platform
pip uninstall torch torch-geometric torch-scatter torch-sparse
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install torch-geometric
```

#### "No module named 'tree_sitter_python'"
```bash
pip install tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-c tree-sitter-go
```

#### Rate limit errors (Gemini API)
The free tier is limited. SEC-C automatically:
- Queues requests with backoff
- Falls back between Pro and Flash models
- Shows remaining quota via `sec-c status`

#### Out of memory during GNN training
```bash
# Reduce batch size
python scripts/train_gat.py --batch-size 8 --device cpu
```

### Checking Status

```bash
# Shows all tool availability and API quotas
sec-c status
```

Example output:
```
◆ Sec-C v2.0.0

┌─────────────────────────────────────────┐
│ Component      │ Status     │ Details    │
├────────────────┼────────────┼────────────┤
│ CodeQL CLI     │ Available  │ v2.19.3    │
│ Joern          │ Available  │ v4.0.508   │
│ Gemini API     │ Configured │ ...xyz1    │
│ GitHub Token   │ Configured │ ...abc2    │
│ GPU (CUDA)     │ Available  │ RTX 4090   │
└─────────────────────────────────────────┘
```

---

## Summary: What You Need For Each Stage

| Stage | Required Tools | Optional | Setup Time |
|-------|---------------|----------|------------|
| **SAST only** | Python 3.11, CodeQL | — | 10 min |
| **+ Graph** | + Joern, trained model | GPU | 1-4 hours |
| **+ LLM** | + Gemini API key | RAG database | 2-3 hours |
| **Full setup** | All of the above | — | 4-6 hours |

**Minimum viable demo:** Just CodeQL + `sec-c scan --stage sast` works out of the box.
