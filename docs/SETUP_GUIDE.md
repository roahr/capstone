# SEC-C Setup Guide

> Complete setup from clone to working demo. Windows 11 first, then Linux/macOS.

**SEC-C v2.0.0** -- Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Level 1: Minimal Setup (5 minutes, SAST only)](#level-1-minimal-setup-5-minutes-sast-only)
3. [Level 2: Standard Setup (15 minutes, SAST + LLM)](#level-2-standard-setup-15-minutes-sast--llm)
4. [Level 3: Full Setup (includes Kaggle GNN training)](#level-3-full-setup-includes-kaggle-gnn-training)
5. [CodeQL Installation](#codeql-installation)
6. [Gemini API Key](#gemini-api-key)
7. [Groq API Key (Alternative)](#groq-api-key-alternative)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| **Python** | 3.11+ | Runtime for the entire framework. SEC-C uses `match` statements, `tomllib`, and type unions that require 3.11 minimum. |
| **Git** | 2.30+ | Cloning the repository and (optionally) scanning GitHub repos. |
| **pip** | Latest | Package installation. Comes with Python. |

### External Tools (by stage)

| Tool | Stage | What It Does | Required? |
|------|-------|-------------|-----------|
| **Tree-sitter** | SAST (Stage 1) | Parses source code into ASTs for fast pattern matching across 5 languages (Python, JavaScript, Java, C/C++, Go). Installed automatically via pip. | Auto-installed |
| **CodeQL CLI** | SAST (Stage 1) | GitHub's deep semantic code analysis engine. Performs interprocedural taint tracking to find data flows from untrusted sources to dangerous sinks. | Recommended |
| **Joern** | Graph (Stage 2) | Generates Code Property Graphs (CPGs) that combine AST, control flow, and data flow into a single queryable graph. Used as input for the Mini-GAT neural network. Requires Java 11+. | Optional |
| **PyTorch** | Graph (Stage 2) | Deep learning framework used to run the Mini-GAT (Graph Attention Network) model for structural vulnerability validation. | Optional |
| **Gemini API** | LLM (Stage 3) | Google's multimodal LLM. Powers the dual-agent (attacker/defender) adversarial validation system that constructs exploit proofs and analyzes sanitization. | Optional |
| **Groq API** | LLM (Stage 3) | Alternative LLM provider using Llama models. Faster inference, higher free-tier limits (1000 RPD), no credit card needed. | Optional (alternative to Gemini) |

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10/11, Linux (Ubuntu 20.04+), macOS 12+ | Windows 11, Ubuntu 22.04+ |
| RAM | 8 GB | 16 GB |
| Disk | 5 GB free | 20 GB free (for full NVD database) |
| GPU | Not required | NVIDIA with 8GB+ VRAM (for GNN training only) |
| Network | Required for initial setup | Required for LLM stage |

### Verify Prerequisites

```bash
python --version        # Need 3.11+
git --version           # Need 2.30+
pip --version           # Should come with Python
```

---

## Level 1: Minimal Setup (5 minutes, SAST only)

This gives you Tree-sitter pattern matching and CodeQL taint analysis with no API keys or model training required.

### Windows 11

```powershell
# Clone the repository
git clone https://github.com/your-org/sec-c.git
cd sec-c

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install SEC-C with dev dependencies
pip install -e ".[dev]"

# Verify installation
sec-c status

# Run your first scan (SAST only)
sec-c scan tests/fixtures/vulnerable_python.py --stage sast
```

### Linux / macOS

```bash
# Clone the repository
git clone https://github.com/your-org/sec-c.git
cd sec-c

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# Install SEC-C with dev dependencies
pip install -e ".[dev]"

# Verify installation
sec-c status

# Run your first scan (SAST only)
sec-c scan tests/fixtures/vulnerable_python.py --stage sast
```

### What You Get

- **Tree-sitter pre-screening**: Sub-100ms AST pattern matching across Python, JavaScript, Java, C/C++, Go
- **CodeQL taint analysis**: Interprocedural data flow tracking from sources to sinks (if CodeQL CLI is installed and in PATH)
- **4-factor uncertainty scoring**: Each finding gets a composite uncertainty score based on confidence, complexity, novelty, and conflict factors
- **Console output**: Color-coded findings table grouped by verdict (confirmed / likely / potential / safe)

### Core Dependencies Installed

From `pyproject.toml`, `pip install -e ".[dev]"` installs:

| Package | Purpose |
|---------|---------|
| tree-sitter, tree-sitter-{python,javascript,java,c,go} | AST parsing for 5 languages |
| sarif-om | SARIF schema support |
| networkx | Graph analysis |
| google-genai | Gemini LLM client (google-genai SDK) |
| faiss-cpu | Vector similarity search for RAG |
| rank-bm25 | BM25 keyword search for RAG |
| jinja2 | CWE-specific prompt templates |
| typer, rich, prompt-toolkit, pygments | CLI and terminal UI |
| pyyaml, pydantic | Configuration and data models |
| aiohttp, httpx | Async HTTP for API calls and GitHub scanning |
| pytest, pytest-cov, pytest-asyncio, ruff | Testing and linting (dev extras) |

---

## Level 2: Standard Setup (15 minutes, SAST + LLM)

This adds the dual-agent LLM validation stage. You need either a Gemini API key or a Groq API key.

### Step 1: Get an LLM API Key

**Option A -- Gemini (default, recommended for accuracy):**

1. Go to https://aistudio.google.com/apikey
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the key (starts with `AIza...`)

**Option B -- Groq (alternative, faster, higher free quota):**

1. Go to https://console.groq.com/keys
2. Create a free account (no credit card required)
3. Click "Create API Key"
4. Copy the key (starts with `gsk_...`)

### Step 2: Create Your .env File

```bash
# Copy the example
cp .env.example .env
```

Edit `.env` with your key:

**For Gemini:**
```
LLM_PROVIDER=gemini
GEMINI_API_KEY=AIza...your-actual-key
```

**For Groq:**
```
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_...your-actual-key
```

### Step 3: Build the CWE Knowledge Base

The RAG (Retrieval-Augmented Generation) system grounds LLM reasoning in real CWE/CVE data, reducing hallucinations.

```bash
# CWE catalog only (fast, ~2 minutes)
python scripts/setup_rag.py

# Full build with NVD CVE data (~2-3 hours)
python scripts/setup_rag.py --full

# Full build with NVD API key (10x faster download)
python scripts/setup_rag.py --full --nvd-key YOUR_NVD_KEY
```

This creates:
- `data/cwe/` -- 900+ MITRE CWE descriptions
- `data/rag/cwe_faiss.bin` -- FAISS vector index for semantic search
- `data/rag/cwe_bm25.pkl` -- BM25 keyword index
- `data/rag/nvd/` -- NVD CVE entries (if `--full`)

### Step 4: Test the LLM Stage

```bash
# Full cascade including LLM dual-agent validation
sec-c scan tests/fixtures/vulnerable_python.py --stage llm

# Or scan the entire fixtures directory
sec-c scan tests/fixtures/ --stage llm

# Check provider status
sec-c providers
```

### What You Get

Everything from Level 1, plus:

- **Dual-agent LLM validation**: An "attacker" agent constructs exploit proofs while a "defender" agent analyzes sanitization and access controls
- **Adversarial consensus**: Findings are adjudicated through structured debate between the two agents
- **RAG-grounded reasoning**: LLM prompts are enriched with relevant CWE descriptions and real-world CVE examples
- **CWE-specific prompt templates**: 15+ Jinja2 templates tuned for different vulnerability classes (injection, XSS, SSRF, etc.)
- **Three-tier classification**: Findings are classified as Confirmed (score >= 0.85), Likely (score >= 0.50), or Potential (score < 0.50)

---

## Level 3: Full Setup (includes Kaggle GNN training)

This adds the Graph stage with the Mini-GAT neural network for structural vulnerability validation with conformal prediction guarantees.

### Step 1: Install GNN Dependencies Locally

```bash
# CPU-only PyTorch (no GPU needed for inference)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install torch-geometric
pip install transformers
```

This installs:
- `torch` -- Deep learning framework (CPU inference only)
- `torch-geometric` -- Graph neural network library (GAT convolutions)
- `transformers` -- HuggingFace library (for GraphCodeBERT node embeddings)

### Step 2: Install Joern (Code Property Graph generator)

Joern converts source code into rich Code Property Graphs with AST, CFG, and data flow edges. Requires Java 11+.

**Windows (recommended -- install script + JDK):**
```bash
# Verify Java is available
java -version    # Need 11+

# Download and install Joern
bash scripts/setup_joern.sh

# Or download manually from https://github.com/joernio/joern/releases
# Download joern-cli.zip, extract to %USERPROFILE%\.sec-c\joern\
```

**Linux / macOS:**
```bash
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" | bash
```

**Verify Joern:**
```bash
sec-c status
# Should show: Joern | Available | <path>
```

SEC-C auto-detects Joern at:
- `~/.sec-c/joern/joern-cli/bin/` (install script default)
- System PATH
- On Windows, it uses `.bat` wrappers automatically

If Joern is not installed, Stage 2 uses a simplified graph fallback (line-level nodes with sequential edges). The GNN still runs but with less structural information.

### Step 3: Train the Mini-GAT Model on Kaggle

Training uses the NIST Juliet Test Suite (Java + C/C++) on Kaggle's free GPU. Your laptop never runs training.

1. Go to https://www.kaggle.com and create a free account
2. Click **New Notebook**
3. Upload `notebooks/sec_c_gnn_training.ipynb`
4. Under **Settings**, set **Accelerator** to **GPU P100** (or GPU T4 x2)
5. Click **Run All** -- takes 2-3 hours

The notebook:
- Downloads the NIST Juliet Test Suite (25K+ labeled test cases)
- Installs Joern on Kaggle (Java is pre-installed)
- Builds Code Property Graphs from each test case
- Generates 768-dim GraphCodeBERT node embeddings
- Trains a 2-layer GAT (4 attention heads, 773-dim input)
- Calibrates conformal prediction (APS, alpha=0.1)
- Produces 3 output files

### Step 4: Download and Place Model Artifacts

After Kaggle training completes, go to the **Output** tab and download:

| File | Purpose | Size |
|------|---------|------|
| `mini_gat.pt` | Trained GAT model weights | ~5-10 MB |
| `conformal_calibration.json` | APS calibration data (threshold, coverage) | ~1 KB |
| `graph_config.json` | Hyperparameters + normalization stats | ~2 KB |

Place them in your local project:

```bash
# Windows
mkdir data\models
move %USERPROFILE%\Downloads\mini_gat.pt data\models\
move %USERPROFILE%\Downloads\conformal_calibration.json data\models\
move %USERPROFILE%\Downloads\graph_config.json data\models\

# Linux/macOS
mkdir -p data/models
mv ~/Downloads/mini_gat.pt data/models/
mv ~/Downloads/conformal_calibration.json data/models/
mv ~/Downloads/graph_config.json data/models/
```

### Step 5: Verify Graph Stage

```bash
# Status should now show Mini-GAT as "Trained"
sec-c status

# Test Graph stage (SAST + Graph, no LLM)
sec-c scan tests/fixtures/vulnerable_python.py --stage graph

# Full 3-stage cascade with HTML dashboard
sec-c scan sample_testcases/python/ --stage llm --html

# Check all components
sec-c version
```

### What You Get

Everything from Levels 1 and 2, plus:

- **Joern CPG generation**: Real Code Property Graphs with AST, control flow, and data dependency edges (645+ nodes for a typical Java class)
- **Backward slicing**: 67-91% code reduction by extracting only vulnerability-relevant subgraphs
- **Mini-GAT structural validation**: A 2-layer Graph Attention Network (4 heads, 773-dim input = 768 GraphCodeBERT + 5 structural features) validates vulnerability patterns
- **5 per-node features**: in-degree, out-degree, is-sink, is-source, depth -- computed consistently between training (Kaggle) and inference (local)
- **Conformal prediction sets**: Calibrated with 90% coverage guarantee (alpha=0.1). Singleton sets resolve at Graph stage, ambiguous sets escalate to LLM
- **Three-stage cascade efficiency**: Proven 75% resolution at Stage 1 on real test cases (24 findings: 18 SAST, 6 LLM)

---

## CodeQL Installation

CodeQL is the backbone of Stage 1 SAST analysis. It provides deep interprocedural taint tracking.

### Windows

1. Go to https://github.com/github/codeql-cli-binaries/releases
2. Download `codeql-win64.zip` (latest release)
3. Extract to a permanent location (e.g., `C:\codeql\` or `%USERPROFILE%\.sec-c\codeql\`)
4. Add to PATH:

```powershell
# PowerShell (temporary, current session only)
$env:PATH += ";C:\codeql"

# Permanent:
# System Settings > System > About > Advanced system settings
#   > Environment Variables > PATH > Edit > New > C:\codeql
```

Or set `CODEQL_HOME` in your `.env`:
```
CODEQL_HOME=C:\codeql
```

5. Download query packs (required for analysis):
```bash
codeql pack download codeql/python-queries
codeql pack download codeql/javascript-queries
codeql pack download codeql/java-queries
codeql pack download codeql/cpp-queries
codeql pack download codeql/go-queries
```

6. Verify:
```bash
codeql --version
```

### Linux

```bash
# Get the latest version tag
CODEQL_VERSION=$(curl -s https://api.github.com/repos/github/codeql-cli-binaries/releases/latest | grep tag_name | cut -d'"' -f4)

# Download
wget "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip"

# Extract
mkdir -p ~/.sec-c/codeql
unzip codeql-linux64.zip -d ~/.sec-c/

# Add to PATH permanently
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

### macOS

**Option A: Homebrew**
```bash
brew install codeql
```

**Option B: Manual**
```bash
# Get the latest version tag
CODEQL_VERSION=$(curl -s https://api.github.com/repos/github/codeql-cli-binaries/releases/latest | grep tag_name | cut -d'"' -f4)

# Download (Apple Silicon or Intel)
# For Apple Silicon (M1/M2/M3):
wget "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-osx64.zip"

# Extract
mkdir -p ~/.sec-c/codeql
unzip codeql-osx64.zip -d ~/.sec-c/

# Add to PATH
echo 'export PATH="$HOME/.sec-c/codeql:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**Query packs (all platforms):**
```bash
codeql pack download codeql/python-queries
codeql pack download codeql/javascript-queries
codeql pack download codeql/java-queries
codeql pack download codeql/cpp-queries
codeql pack download codeql/go-queries
```

**Verification (all platforms):**
```bash
codeql --version
# Expected: CodeQL command-line toolchain release 2.x.x

codeql resolve packs
# Should list all 5 downloaded query packs
```

---

## Gemini API Key

### Step-by-Step

1. Open https://aistudio.google.com/apikey in your browser
2. Sign in with your Google account (any Google account works)
3. If prompted, accept the terms of service
4. Click **"Create API Key"**
5. Select a Google Cloud project (or create a new one -- no billing required for free tier)
6. The key appears on screen -- copy it immediately (it starts with `AIza`)
7. Add to your `.env` file:
   ```
   LLM_PROVIDER=gemini
   GEMINI_API_KEY=AIzaSy...your-full-key
   ```

### Free Tier Limits (as of March 2026)

| Model | Requests/Min (RPM) | Requests/Day (RPD) | Notes |
|-------|-------------------:|-------------------:|-------|
| Gemini 2.5 Flash | 10 | 250 | **Recommended.** Primary model for SEC-C. |
| Gemini 2.5 Flash-Lite | 15 | 1,000 | Lighter variant, higher quota, slightly lower quality. |
| Gemini 2.5 Pro | -- | -- | **Removed from free tier** (Dec 2025). Requires paid billing. |

### Multiple Keys for Rotation

Each API key gets independent rate limits. Using 3 keys gives you 3x throughput.

```bash
# In .env -- comma-separated, no spaces
GEMINI_API_KEYS=AIzaSy...key1,AIzaSy...key2,AIzaSy...key3
```

SEC-C automatically rotates between keys using round-robin. Set `GEMINI_API_KEYS` (plural) instead of `GEMINI_API_KEY` (singular). If both are set, the plural version takes priority for rotation, and the singular key is included in the pool.

### Tips

- Each Google account can create multiple API keys
- Free tier is per-key, not per-account
- Flash is the default model and is sufficient for all SEC-C use cases
- You can override the model with `LLM_MODEL=gemini-2.5-flash-lite` in `.env` for higher throughput

---

## Groq API Key (Alternative)

Groq is an alternative LLM provider offering faster inference and higher free-tier limits. Use Groq when:

- You want **1000 requests/day** free (vs Gemini's 250)
- You prefer **no credit card** requirement
- You need **faster inference** (Groq's LPU hardware is optimized for speed)
- You want to use **open-source models** (Llama, Qwen)

Use Gemini when:

- You want the **default, tested configuration**
- You need **multimodal capabilities** (Gemini can analyze code screenshots)
- You prefer **Google's safety filters** and content policies

### Step-by-Step

1. Open https://console.groq.com/keys in your browser
2. Create a free account (email or GitHub sign-in, no credit card)
3. Click **"Create API Key"**
4. Give it a name (e.g., "sec-c")
5. Copy the key (starts with `gsk_`)
6. Add to your `.env` file:
   ```
   LLM_PROVIDER=groq
   GROQ_API_KEY=gsk_...your-full-key
   ```

### Free Tier Limits

| Model | RPM | RPD | Notes |
|-------|----:|----:|-------|
| llama-3.3-70b-versatile | 30 | 1,000 | **Recommended.** Best quality on Groq. |
| llama-3.1-8b-instant | 30 | 14,400 | Fastest, lower quality. Good for large scans. |
| qwen/qwen3-32b | 30 | 1,000 | Strong reasoning capabilities. |
| meta-llama/llama-4-scout-17b-16e-instruct | 30 | 1,000 | Latest Llama 4 architecture. |

### Multiple Keys for Rotation

```bash
# In .env
GROQ_API_KEYS=gsk_...key1,gsk_...key2,gsk_...key3
```

Same round-robin rotation as Gemini.

---

## Troubleshooting

### Installation Errors

| # | Error | Cause | Fix |
|---|-------|-------|-----|
| 1 | `pip install -e ".[dev]"` fails with "build wheel" error | Missing C compiler for tree-sitter native extensions | **Windows:** Install Visual Studio Build Tools. **Linux:** `sudo apt install build-essential`. **macOS:** `xcode-select --install` |
| 2 | `pip install -e ".[dev]"` fails with "No module named setuptools" | Old pip/setuptools | `pip install --upgrade pip setuptools wheel` |
| 3 | `ERROR: Failed building wheel for faiss-cpu` | Platform compatibility issue with FAISS | `pip install faiss-cpu --no-cache-dir` or try `pip install faiss-cpu==1.7.4` |
| 4 | `ModuleNotFoundError: No module named 'src'` | SEC-C not installed in editable mode | Run `pip install -e ".[dev]"` from the project root |
| 5 | `ModuleNotFoundError: No module named 'tree_sitter_python'` | Tree-sitter language bindings missing | `pip install tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-c tree-sitter-go` |
| 6 | `sec-c: command not found` | Entry point not in PATH | Use `python -m src.cli.main` instead, or verify your venv is activated |
| 7 | `Python version 3.10 not supported` | Python too old | Install Python 3.11 or newer from https://python.org |
| 8 | `pip install` hangs on Windows | Antivirus blocking pip | Temporarily disable real-time protection, or add Python/pip to exclusion list |

### PyTorch & GNN Errors

| # | Error | Cause | Fix |
|---|-------|-------|-----|
| 9 | `ImportError: No module named 'torch'` | PyTorch not installed | `pip install torch --index-url https://download.pytorch.org/whl/cpu` |
| 10 | `RuntimeError: CUDA out of memory` | GPU memory exhausted during GNN inference | Set `SEC_C_DEVICE=cpu` in `.env`, or reduce `graph.gnn.max_nodes` in config |
| 11 | `ImportError: No module named 'torch_geometric'` | PyG not installed | `pip install torch-geometric` |
| 12 | `OSError: Failed to load model mini_gat.pt` | Model file not found at `data/models/mini_gat.pt` | Download from Kaggle or train locally. Check `graph.gnn.model_path` in config. |
| 13 | `torch-scatter` / `torch-sparse` build failures | C++ compilation issues with PyG extensions | `pip install torch-scatter torch-sparse -f https://data.pyg.org/whl/torch-2.0.0+cpu.html` |
| 14 | `torch.load` unpickling error | Model trained with different PyTorch version | Retrain with your current PyTorch version, or `pip install torch==<version used to train>` |
| 15 | `Out of memory during GNN training` | Batch size too large | `python scripts/train_gat.py --batch-size 8 --device cpu` |
| 16 | `ImportError: torchcp` | Conformal prediction library missing | `pip install torchcp>=0.2` |

### CodeQL Errors

| # | Error | Cause | Fix |
|---|-------|-------|-----|
| 17 | `FileNotFoundError: codeql not found` | CodeQL CLI not in PATH | See [CodeQL Installation](#codeql-installation). Or set `CODEQL_HOME` in `.env`. |
| 18 | `codeql: error: Could not find QL pack` | Query packs not downloaded | `codeql pack download codeql/python-queries` (repeat for each language) |
| 19 | `codeql database create` times out | Large project, default 300s timeout exceeded | Increase `sast.codeql.timeout_seconds` in `configs/default.yaml` |
| 20 | `codeql resolve packs` shows nothing | Packs downloaded but not found | Run `codeql pack download` again. Check `~/.codeql/packages/` exists. |
| 21 | `Error: no source files for language X` | CodeQL cannot find source files for the specified language | Check that `--languages` matches actual files in the target |
| 22 | CodeQL database creation fails on Windows with encoding error | Source files contain non-UTF-8 characters | Set `PYTHONUTF8=1` environment variable, or exclude binary files |

### API & LLM Errors

| # | Error | Cause | Fix |
|---|-------|-------|-----|
| 23 | `No LLM provider available -- LLM stage will be skipped` | No API key set or `LLM_PROVIDER` incorrect | Check `.env`: set `LLM_PROVIDER=gemini` and `GEMINI_API_KEY=AIza...` |
| 24 | `google.api_core.exceptions.ResourceExhausted: 429` | Gemini rate limit exceeded | Wait and retry. Use multiple keys: `GEMINI_API_KEYS=key1,key2,key3`. Or switch to Groq. |
| 25 | `GEMINI_API_KEY is invalid` | Malformed or revoked API key | Regenerate at https://aistudio.google.com/apikey |
| 26 | `groq.APIError: rate_limit_exceeded` | Groq rate limit exceeded | Wait 60 seconds. Use multiple keys: `GROQ_API_KEYS=key1,key2` |
| 27 | `Gemini Pro not available on free tier` | Pro model was removed from free tier Dec 2025 | Use Flash: `LLM_MODEL=gemini-2.5-flash` (this is the default) |
| 28 | `SSL: CERTIFICATE_VERIFY_FAILED` | Corporate proxy or firewall intercepting HTTPS | Install corporate CA cert, or set `REQUESTS_CA_BUNDLE` env var |
| 29 | `TimeoutError` during LLM calls | Slow network or API latency | Retry. Check internet connection. Consider using Groq for faster inference. |
| 30 | `LLM response parsing error` | Unexpected LLM output format | Run with `--verbose` to see raw responses. Usually a transient issue, retry. |

### RAG & Data Errors

| # | Error | Cause | Fix |
|---|-------|-------|-----|
| 31 | `RAG data directory not found` | Knowledge base not built | Run `python scripts/setup_rag.py` |
| 32 | `FAISS index load failed` | Corrupted or missing FAISS index | Delete `data/rag/` and rebuild: `python scripts/setup_rag.py` |
| 33 | `NVD API rate limited (5 req/30s)` | No NVD API key for full build | Get free key at https://nvd.nist.gov/developers/request-an-api-key, then `python scripts/setup_rag.py --full --nvd-key YOUR_KEY` |
| 34 | `sentence-transformers not installed` | Missing embedding model dependency | `pip install sentence-transformers` |

### Encoding & Platform Errors

| # | Error | Cause | Fix |
|---|-------|-------|-----|
| 35 | `UnicodeDecodeError` when scanning files | Source files with non-UTF-8 encoding | Set `PYTHONUTF8=1` environment variable. SEC-C defaults to UTF-8. |
| 36 | Box-drawing characters display as `?` on Windows CMD | CMD lacks Unicode font support | Use Windows Terminal, PowerShell 7, or Git Bash instead. SEC-C auto-detects Windows and uses ASCII-safe box drawing. |
| 37 | `PermissionError` on Windows | File locked by another process or antivirus | Close editors/IDEs accessing the file. Exclude project dir from antivirus. |
| 38 | `OSError: [WinError 206] filename or extension is too long` | Windows path length limit (260 chars) | Enable long paths: `git config --system core.longpaths true`. Or clone to a shorter path (e.g., `C:\sec-c`). |

### GitHub Scanning Errors

| # | Error | Cause | Fix |
|---|-------|-------|-----|
| 39 | `GitHub token not set` when using `--github` | `GITHUB_TOKEN` not configured | Generate at https://github.com/settings/tokens (needs `repo` read scope). Add to `.env`. |
| 40 | `403 Forbidden` from GitHub API | Token lacks required scope or repo is private | Regenerate token with `repo` scope. Verify repo access. |
| 41 | `Repository not found` | Typo in owner/repo format | Use exact format: `sec-c scan --github owner/repo` (e.g., `django/django`) |

### General Runtime Errors

| # | Error | Cause | Fix |
|---|-------|-------|-----|
| 42 | `sec-c scan` returns 0 findings | No vulnerable code patterns detected, or wrong language | Check `--languages` flag. Try `--verbose` for debug output. Verify target contains source files. |
| 43 | `KeyboardInterrupt` during scan | User pressed Ctrl+C | Normal. Partial results may be lost. |
| 44 | `MemoryError` during large scans | System RAM exhausted | Scan subdirectories individually. Reduce `graph.gnn.max_nodes` in config. Close other applications. |
| 45 | `Config file not found` | `configs/default.yaml` missing | Re-clone the repo or copy from `configs/default.yaml.example`. SEC-C uses built-in defaults if config is missing. |

### Quick Diagnostic Commands

```bash
# Check all tool availability and API status
sec-c status

# Check LLM provider details
sec-c providers

# Check available models
sec-c models

# Show current configuration
sec-c config

# Run with debug logging
sec-c scan ./project --verbose

# Run tests to verify installation
pytest tests/ -v --tb=short
```

---

## Summary: What You Need For Each Level

| Level | Required | Optional | Setup Time | What You Get |
|-------|----------|----------|------------|-------------|
| **Level 1** | Python 3.11, Git | CodeQL CLI | 5 min | Tree-sitter + CodeQL SAST scanning |
| **Level 2** | + Gemini or Groq API key | RAG knowledge base | 15 min | + Dual-agent LLM validation |
| **Level 3** | + PyTorch, trained Mini-GAT | Joern, GPU | 1-2 hours | Complete 3-stage cascade with conformal prediction |

**Minimum viable demo:** `pip install -e ".[dev]"` + `sec-c scan --stage sast` works with zero external tools.
