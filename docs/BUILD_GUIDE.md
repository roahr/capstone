# SEC-C Build Guide: From Zero to Full Demo

> A step-by-step walkthrough to get every component of SEC-C working with real data.
>
> **Target audience:** PhD student on Windows 11 with Python experience but no prior SAST tool experience.
>
> **Total time:** 4-8 hours for everything. You can stop after any Part and have a working subset.

---

## Quick Reference: What Each Part Gets You

| Part | Time | What you unlock |
|------|------|-----------------|
| Part 1: Environment Setup | 30 min | Python packages, imports verified |
| Part 2: CodeQL Setup | 20 min | SAST scanning (Stage 1) |
| Part 3: GNN Setup | 2-4 hrs | Graph-based validation (Stage 2) |
| Part 4: RAG Knowledge Base | 1-3 hrs | CVE/CWE-grounded LLM reasoning |
| Part 5: Gemini API Setup | 10 min | LLM dual-agent validation (Stage 3) |
| Part 6: First Full Demo | 15 min | End-to-end scan with HTML report |
| Part 7: Real Projects | varies | Scan open-source or your own code |
| Part 8: Running Tests | 5 min | Verify everything works |

**Minimum viable demo:** Parts 1 + 2 only. You can scan code with SAST-only mode in under an hour.

---

## Part 1: Environment Setup (30 minutes)

### Step 1.1: Verify Python 3.11+

Open **PowerShell** (not CMD) and run:

```powershell
python --version
```

You need `Python 3.11.x` or higher. If you see an older version or "not recognized":

1. Download Python 3.11+ from https://www.python.org/downloads/
2. During installation, **check "Add Python to PATH"** (this is critical)
3. Restart PowerShell after installing
4. Verify again: `python --version`

If you have multiple Python versions, you may need to use `py -3.11` instead of `python` in all commands below.

### Step 1.2: Create a Virtual Environment

```powershell
# Navigate to the SEC-C project root
cd D:\sec-c

# Create the virtual environment
python -m venv .venv
```

**Activate the virtual environment.** You must do this every time you open a new terminal.

In **PowerShell**:
```powershell
.venv\Scripts\Activate.ps1
```

If you get a "running scripts is disabled" error:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.venv\Scripts\Activate.ps1
```

In **Git Bash**:
```bash
source .venv/Scripts/activate
```

You should see `(.venv)` at the beginning of your prompt. All commands from here on assume the venv is active.

### Step 1.3: Install SEC-C and Dependencies

```powershell
pip install --upgrade pip setuptools wheel
pip install -e ".[dev]"
```

This installs SEC-C in editable mode along with ~30 dependencies. It will take 2-5 minutes.

**Common errors and fixes:**

| Error | Fix |
|-------|-----|
| `error: Microsoft Visual C++ 14.0 or greater is required` | Install "Build Tools for Visual Studio" from https://visualstudio.microsoft.com/visual-cpp-build-tools/ -- select "Desktop development with C++" workload |
| `pip` not recognized | Ensure your venv is activated. Try `python -m pip install ...` instead |
| Network timeout | Try again. If behind a proxy: `pip install --proxy http://proxy:port -e ".[dev]"` |

### Step 1.4: Install PyTorch

PyTorch often needs to be installed separately to get the right build for your system.

**CPU-only (recommended if you do not have an NVIDIA GPU):**
```powershell
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

**GPU with CUDA 12.1 (if you have an NVIDIA GPU with 8GB+ VRAM):**
```powershell
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

To check if CUDA is available after installing:
```powershell
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"
```

If CUDA shows `False` but you have an NVIDIA GPU, make sure you have the latest NVIDIA drivers from https://www.nvidia.com/Download/index.aspx and that the CUDA toolkit version matches. For most users, CPU-only works fine -- training is slower but everything else runs at the same speed.

### Step 1.5: Install torch-geometric

This is the trickiest dependency on Windows. Follow these steps exactly:

```powershell
# Step A: Check your PyTorch version
python -c "import torch; print(torch.__version__)"
```

Note the version (e.g., `2.5.1` or `2.6.0`). You need this for the next step.

```powershell
# Step B: Install PyG dependencies
# Replace TORCH_VERSION with your version (e.g., 2.5.0) and cpu or cu121
pip install torch-scatter torch-sparse -f https://data.pyg.org/whl/torch-2.5.0+cpu.html

# Step C: Install torch-geometric itself
pip install torch-geometric
```

**If Step B fails** (common on Windows), try installing without the prebuilt wheels:
```powershell
pip install torch-scatter torch-sparse
pip install torch-geometric
```

**If that also fails**, torch-geometric can often work without `torch-scatter` and `torch-sparse` for basic operations:
```powershell
pip install torch-geometric
```

SEC-C will still function -- the GNN training may be slower but will work.

### Step 1.6: Verify All Imports

Run this verification script to confirm everything installed correctly:

```powershell
python -c "
import sys
print(f'Python {sys.version}')
errors = []

# Core
for mod in ['yaml', 'pydantic', 'httpx', 'typer', 'rich']:
    try:
        __import__(mod)
        print(f'  [OK] {mod}')
    except ImportError as e:
        errors.append(f'{mod}: {e}')
        print(f'  [FAIL] {mod}: {e}')

# SAST
for mod in ['tree_sitter', 'tree_sitter_python', 'tree_sitter_javascript']:
    try:
        __import__(mod)
        print(f'  [OK] {mod}')
    except ImportError as e:
        errors.append(f'{mod}: {e}')
        print(f'  [FAIL] {mod}: {e}')

# Graph
for mod in ['torch', 'torch_geometric', 'transformers', 'networkx']:
    try:
        __import__(mod)
        print(f'  [OK] {mod}')
    except ImportError as e:
        errors.append(f'{mod}: {e}')
        print(f'  [FAIL] {mod}: {e}')

# LLM / RAG
for mod in ['google.generativeai', 'faiss', 'rank_bm25', 'jinja2']:
    try:
        __import__(mod)
        print(f'  [OK] {mod}')
    except ImportError as e:
        errors.append(f'{mod}: {e}')
        print(f'  [FAIL] {mod}: {e}')

print()
if errors:
    print(f'{len(errors)} module(s) failed. Fix them before proceeding.')
else:
    print('All imports OK!')
"
```

Every line should show `[OK]`. If any show `[FAIL]`, install the missing package with `pip install <package-name>`.

---

## Part 2: CodeQL Setup (20 minutes)

CodeQL is GitHub's static analysis engine. It is the backbone of SEC-C's Stage 1 (SAST). Without it, you cannot scan code.

### Step 2.1: Download CodeQL CLI

1. Go to https://github.com/github/codeql-cli-binaries/releases
2. Find the latest release (e.g., `v2.19.3`)
3. Download **`codeql-win64.zip`** (~450 MB)
4. Extract the zip. You will get a folder called `codeql` containing `codeql.exe`
5. Move or extract it to a permanent location, for example:
   ```
   C:\codeql\
   ```
   So that `C:\codeql\codeql.exe` exists.

### Step 2.2: Add CodeQL to PATH

**PowerShell (temporary, for this session only):**
```powershell
$env:PATH += ";C:\codeql"
```

**PowerShell (permanent):**
```powershell
# This adds C:\codeql to your user PATH permanently
[System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\codeql", "User")
```
Restart your terminal after running the permanent command.

**Git Bash:**
```bash
export PATH="$PATH:/c/codeql"
```

To make it permanent in Git Bash, add that line to `~/.bashrc`:
```bash
echo 'export PATH="$PATH:/c/codeql"' >> ~/.bashrc
```

### Step 2.3: Download Query Packs

CodeQL needs language-specific query packs to know what vulnerabilities to look for. Download all five:

```powershell
codeql pack download codeql/python-queries
codeql pack download codeql/javascript-queries
codeql pack download codeql/java-queries
codeql pack download codeql/cpp-queries
codeql pack download codeql/go-queries
```

Each pack is 10-50 MB. This takes 2-5 minutes total.

### Step 2.4: Verify CodeQL Works

```powershell
codeql --version
```

You should see output like:
```
CodeQL command-line toolchain release 2.19.3
```

### Step 2.5: Create a Test CodeQL Database

Let us create a CodeQL database from the included test fixtures to confirm everything works end-to-end.

```powershell
# Create a CodeQL database from the vulnerable Python test file
codeql database create D:\sec-c\test-db --language=python --source-root=D:\sec-c\tests\fixtures --overwrite
```

This takes 30-60 seconds. You should see output ending with:
```
Successfully created database at D:\sec-c\test-db
```

### Step 2.6: Run a Security Query and See SARIF Output

Now analyze the database using the `security-extended` query suite:

```powershell
codeql database analyze D:\sec-c\test-db codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest --output=D:\sec-c\test-results.sarif
```

This runs all security queries against your test database. It takes 1-3 minutes. The output is a SARIF file (Static Analysis Results Interchange Format) -- the industry standard for reporting static analysis findings.

To see a summary of what was found:

```powershell
python -c "
import json
with open(r'D:\sec-c\test-results.sarif') as f:
    sarif = json.load(f)
results = sarif['runs'][0]['results']
print(f'Findings: {len(results)}')
for r in results[:10]:
    rule = r['ruleId']
    msg = r['message']['text'][:80]
    print(f'  [{rule}] {msg}')
"
```

### Step 2.7: Understanding Query Suites

SEC-C uses the `security-extended` query suite by default (configured in `configs/default.yaml`). Here is what the options mean:

| Suite | What it covers | When to use |
|-------|---------------|-------------|
| `security-extended` | Security vulnerabilities + security-relevant quality issues | **Default.** Best balance of coverage and precision |
| `security-and-quality` | Everything in `security-extended` + code quality issues | Use for thorough audits. More findings but higher false positive rate |
| `security-experimental` | All of the above + experimental/preview queries | Use for research. Highest coverage but lowest precision |

To change the suite, edit `configs/default.yaml`:
```yaml
sast:
  codeql:
    query_suite: "security-extended"  # Change this
```

### Step 2.8: Clean Up Test Artifacts

```powershell
# Optional: remove the test database and results
Remove-Item -Recurse -Force D:\sec-c\test-db
Remove-Item D:\sec-c\test-results.sarif
```

You now have a working CodeQL installation. You can already scan code with `sec-c scan <path> --stage sast`.

---

## Part 3: Module 2 -- GNN Setup (2-4 hours)

The Graph Neural Network (GNN) module provides structural validation of findings from Stage 1. It builds Code Property Graphs (CPGs), embeds them with GraphCodeBERT, and classifies them with a 2-layer Graph Attention Network (Mini-GAT). This part is optional but significantly reduces false positives.

### 3a: Download Training Data

The Mini-GAT model needs labeled training data. SEC-C uses the NIST Juliet Test Suite -- a curated set of known-vulnerable and known-safe code samples across 40 CWE categories.

```powershell
cd D:\sec-c
python scripts/download_juliet.py
```

**What happens:**
1. Downloads the Juliet Java test suite (~400 MB) from NIST SAMATE
2. Downloads the Juliet C/C++ test suite (~500 MB) from NIST SAMATE
3. Organizes test cases by CWE into `data/juliet/java/` and `data/juliet/c_cpp/`
4. Generates synthetic Python test cases (6 CWEs, ~20 samples) since Juliet does not include Python
5. Creates `data/juliet/labels.json` with ground-truth labels

**Expected output:**
```
  Juliet Test Suite Summary
  ---------------------------------------------
  Total test cases:  5000+
  Vulnerable (bad):  2500+
  Safe (good):       2500+
  CWEs covered:      40
  Labels saved to:   data/juliet/labels.json
```

**Expected time:** 5-10 minutes (depends on network speed).

**Verify the download worked:**
```powershell
# Check that labels.json exists and has data
python -c "
import json
from pathlib import Path
labels = json.load(open('data/juliet/labels.json'))
print(f'Vulnerable samples: {len(labels[\"vulnerable\"])}')
print(f'Safe samples: {len(labels[\"safe\"])}')
print(f'CWEs covered: {len(labels[\"stats\"])}')
for cwe in sorted(labels['stats'].keys())[:5]:
    c = labels['stats'][cwe]
    print(f'  {cwe}: {c[\"vulnerable\"]} vuln, {c[\"safe\"]} safe')
print('  ...')
"
```

**If the NIST download fails** (site occasionally goes down), use the built-in synthetic Python cases:

```powershell
python scripts/download_juliet.py --python-only
```

This generates ~20 synthetic Python test cases covering CWE-22, CWE-78, CWE-79, CWE-89, CWE-95, and CWE-502. The resulting model will be less accurate but sufficient for a demo. You can re-run the full download later.

### 3b: Joern Setup (Optional)

Joern generates Code Property Graphs (CPGs) that combine AST, control flow, and data flow into a single graph structure. **If Joern is not installed, SEC-C will use a simplified graph fallback** that creates sequential graphs from code lines. Results are still useful but less structurally rich.

**Why Joern is optional:** The simplified fallback still captures basic code structure. Joern adds inter-procedural data flow edges and more precise control flow, which improves the GNN's accuracy by ~5-10% in benchmarks.

#### Option A: Docker (Recommended on Windows)

This is the easiest path on Windows. You need Docker Desktop installed.

```powershell
# Pull the Joern Docker image
docker pull ghcr.io/joernio/joern

# Test it: generate a CPG from the test fixtures
docker run --rm -v D:\sec-c\tests\fixtures:/code ghcr.io/joernio/joern joern-parse /code
```

If you see output about a CPG being generated, Joern is working.

#### Option B: WSL2 (Alternative)

If you have WSL2 set up:

```powershell
# From PowerShell, enter WSL
wsl

# Inside WSL: check Java
java -version   # Need 11+

# If Java is missing:
sudo apt update && sudo apt install -y openjdk-17-jdk

# Install Joern
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" | bash

# Verify
joern --version
```

#### Option C: Skip Joern

If you skip Joern entirely, SEC-C will print a warning during Stage 2 scans:
```
[WARN] Joern not available, using simplified graph analysis
```

This is non-fatal. The simplified graph fallback:
- Creates nodes from code lines/statements
- Creates sequential edges between consecutive lines
- Creates skip-connection edges (line i to line i+2)
- Still feeds into the Mini-GAT for structural classification

The main thing you lose is inter-procedural data flow tracking. For most Python/JavaScript vulnerability detection, the simplified approach works well.

#### Verify Joern (if installed)

```powershell
# Native installation
joern --version

# Docker
docker run --rm ghcr.io/joernio/joern joern --version
```

### 3c: Train Mini-GAT

Now train the 2-layer Graph Attention Network on the Juliet dataset.

**CPU training (no GPU required):**
```powershell
cd D:\sec-c
python scripts/train_gat.py --epochs 50 --device cpu
```

**GPU training (NVIDIA GPU with CUDA):**
```powershell
python scripts/train_gat.py --epochs 50 --device cuda
```

**Expected training time:**

| Setup | Time |
|-------|------|
| CPU only, full Juliet dataset | 2-4 hours |
| CPU only, Python-only dataset | 5-10 minutes |
| NVIDIA GPU (8GB+ VRAM) | 20-40 minutes |

**What you will see during training:**

```
  SEC-C Mini-GAT Training
  ---------------------------------------------
  Epochs:     50
  Batch size: 32
  LR:         0.001
  Device:     cpu

2025-03-24 10:15:00 [INFO] Found 5200 test cases (2600 vuln, 2600 safe)
2025-03-24 10:15:01 [INFO] Using simplified graph features
2025-03-24 10:15:01 [INFO] Created dataset with 5150 graphs
2025-03-24 10:15:01 [INFO] Split: 3605 train, 772 val, 773 test/calibration
2025-03-24 10:15:01 [INFO] Model parameters: 1,245,441
2025-03-24 10:15:01 [INFO] Starting training...
```

The model architecture:
- **Input:** 773-dimensional features (768 from GraphCodeBERT + 5 graph-structural features)
- **Hidden:** 256-dimensional, 4 attention heads
- **Output:** 128-dimensional graph embedding, binary classification
- **Parameters:** ~1.2 million (intentionally small -- "Mini"-GAT)

**Expected metrics after training:**

| Metric | Expected range |
|--------|---------------|
| Accuracy | 0.75 - 0.90 |
| F1 Score | 0.73 - 0.88 |
| Precision | 0.70 - 0.90 |
| Recall | 0.72 - 0.92 |

If metrics are significantly below these ranges, try:
- More epochs: `--epochs 100`
- Lower learning rate: `--lr 0.0005`
- Larger batch size: `--batch-size 64`

**If training fails -- common errors:**

| Error | Fix |
|-------|-----|
| `Labels file not found` | Run `python scripts/download_juliet.py` first |
| `Not enough data (X samples). Need at least 10.` | Run download script, or use `--python-only` flag |
| `CUDA out of memory` | Reduce batch size: `--batch-size 8` or switch to CPU: `--device cpu` |
| `ModuleNotFoundError: No module named 'torch_geometric'` | See Step 1.5 for torch-geometric installation |
| `ModuleNotFoundError: No module named 'src.graph.gnn.mini_gat'` | Make sure you ran `pip install -e ".[dev]"` from the project root |

**Verify the trained model exists:**
```powershell
python -c "
from pathlib import Path
model_path = Path('data/models/mini_gat.pt')
if model_path.exists():
    size_mb = model_path.stat().st_size / 1e6
    print(f'Model found: {model_path} ({size_mb:.1f} MB)')
else:
    print('ERROR: Model file not found. Training may have failed.')
"
```

The model file should be approximately 5-10 MB.

### 3d: Calibrate Conformal Prediction

Conformal prediction calibration **happens automatically** at the end of training. You do not need to run a separate command. The training script:

1. Holds out 15% of the dataset as a calibration set
2. Runs the trained model on the calibration set
3. Computes nonconformity scores
4. Saves calibration data to `data/models/conformal_calibration.json`

**Verify calibration file exists:**
```powershell
python -c "
import json
from pathlib import Path
cal_path = Path('data/models/conformal_calibration.json')
if cal_path.exists():
    cal = json.load(open(cal_path))
    for key, value in cal.items():
        if isinstance(value, float):
            print(f'  {key}: {value:.4f}')
        else:
            print(f'  {key}: {value}')
else:
    print('ERROR: Calibration file not found.')
"
```

**What the calibration numbers mean:**

- **alpha:** The target miscoverage rate. `alpha=0.1` means the conformal prediction sets aim for 90% coverage -- meaning at least 90% of the time, the true label is included in the prediction set.
- **calibration_size:** Number of samples used for calibration.
- **quantile / threshold:** The nonconformity score cutoff. Samples with scores above this threshold are "uncertain" and get escalated to Stage 3 (LLM validation).
- **average_set_size:** Average number of labels in each prediction set. Closer to 1.0 means the model is confident; closer to 2.0 means the model is uncertain about many samples.

In practice: when SEC-C scans real code, the conformal predictor wraps the Mini-GAT's output. Instead of a single "vulnerable" or "safe" label, it produces a **prediction set** like `{vulnerable}` (confident) or `{vulnerable, safe}` (uncertain). Uncertain findings get escalated to the LLM for a second opinion.

---

## Part 4: RAG Knowledge Base Setup (1-3 hours)

The RAG (Retrieval-Augmented Generation) system grounds the LLM's reasoning in real vulnerability data. When the LLM analyzes a finding, it retrieves relevant CWE descriptions and CVE reports to reduce hallucinations and improve accuracy.

### 4a: Quick Start -- CWE Only (2 minutes)

If you just want to get started quickly:

```powershell
cd D:\sec-c
python scripts/build_rag.py --cwe-only
```

**What this does:**
1. Downloads the MITRE CWE catalog (XML, ~15 MB)
2. Parses all 900+ CWE entries (descriptions, mitigations, examples)
3. Builds a FAISS vector index (semantic search) and BM25 index (keyword search)

**Expected output:**
```
  SEC-C RAG Builder
  ========================================
  Output directory : data/rag
  CWE catalog      : will download
  NVD CVE data     : skipped (--cwe-only)

  [1/3] Downloading CWE catalog ...
        930 CWE entries parsed
  [2/3] Skipping NVD download (--cwe-only)
  [3/3] Building FAISS + BM25 indexes ...
        Indexes built successfully

  ----------------------------------------
  Build complete!
  CWEs indexed     : 930
  CVEs indexed     : 0
  FAISS index size : 12.5 MB
  BM25 index size  : 3.2 MB
  Elapsed time     : 45.3s
```

**Verify:**
```powershell
python -c "
from pathlib import Path
rag_dir = Path('data/rag')
for f in sorted(rag_dir.iterdir()):
    size = f.stat().st_size
    if size > 1024*1024:
        print(f'  {f.name}: {size/1e6:.1f} MB')
    elif size > 1024:
        print(f'  {f.name}: {size/1024:.1f} KB')
    else:
        print(f'  {f.name}: {size} B')
"
```

You should see files like `faiss_index.bin`, `bm25_index.pkl`, `cwe_data.json`, and `last_update.txt`.

### 4b: Full NVD Database (2-3 hours)

For production-quality results, index real CVE vulnerability data from the National Vulnerability Database:

```powershell
python scripts/build_rag.py --years 2022-2026
```

**What this does:**
1. Downloads the CWE catalog (same as 4a)
2. Downloads CVE records from the NVD API for years 2022 through 2026
3. Indexes everything into FAISS + BM25

**NVD API rate limits:**
- **Without an API key:** 5 requests per 30-second rolling window
- **With an API key:** 50 requests per 30-second rolling window

At 5 req/30s, downloading 4 years of CVEs (~150,000+ records) takes 2-3 hours. With an API key, it takes 15-30 minutes.

**How to get an NVD API key (optional but recommended):**
1. Go to https://nvd.nist.gov/developers/request-an-api-key
2. Enter your email and organization
3. You will receive the key by email within minutes
4. Set it as an environment variable:

   **PowerShell:**
   ```powershell
   $env:NVD_API_KEY="your-key-here"
   ```

   **Git Bash:**
   ```bash
   export NVD_API_KEY="your-key-here"
   ```

   Then re-run the build script.

**Expected download size:** ~1-2 GB of raw JSON, compressed to ~200-400 MB in the indexes.

**If the download is interrupted,** you can resume by running the same command again. The script will pick up where it left off based on the NVD API's pagination.

**Verify CVE count:**
```powershell
python -c "
import json
from pathlib import Path
rag_dir = Path('data/rag')

# Check last_update.txt
ts = (rag_dir / 'last_update.txt').read_text().strip()
print(f'Last updated: {ts}')

# Check index sizes
faiss_path = rag_dir / 'faiss_index.bin'
bm25_path = rag_dir / 'bm25_index.pkl'
if faiss_path.exists():
    print(f'FAISS index: {faiss_path.stat().st_size/1e6:.1f} MB')
if bm25_path.exists():
    print(f'BM25 index:  {bm25_path.stat().st_size/1e6:.1f} MB')
"
```

### 4c: Integration Check

The RAG knowledge base is used during Stage 3 (LLM validation). When the dual-agent system analyzes a finding, it:

1. Takes the CWE ID and code context from the finding
2. Queries the knowledge base for relevant CWE descriptions and CVE examples
3. Includes the retrieved context in the LLM prompt
4. This grounds the LLM's reasoning in real-world vulnerability data

**Test that the knowledge base responds to queries:**
```powershell
python -c "
from src.llm.rag.knowledge_base import KnowledgeBase
from pathlib import Path

kb = KnowledgeBase(
    faiss_index_path=Path('data/rag/faiss_index.bin'),
    bm25_index_path=Path('data/rag/bm25_index.pkl'),
    cwe_data_path=Path('data/rag/cwe_data.json'),
)

# Test: query for SQL injection
results = kb.query('CWE-89 SQL injection user input')
print(f'Results for CWE-89 query: {len(results)} documents')
for i, r in enumerate(results[:3]):
    text_preview = str(r)[:120].replace(chr(10), ' ')
    print(f'  [{i+1}] {text_preview}...')
"
```

You should see 3-5 relevant results about SQL injection, CWE-89 descriptions, and (if you loaded NVD data) real CVE examples.

---

## Part 5: Gemini API Setup (10 minutes)

The LLM dual-agent system uses Google's Gemini models. The **free tier is sufficient** for SEC-C -- you do not need to pay anything.

### Step 5.1: Get a Free API Key

1. Go to https://aistudio.google.com/apikey
2. Sign in with any Google account
3. Click **"Create API Key"**
4. Select any Google Cloud project (or create a new one)
5. Copy the key -- it starts with `AIza...`

### Step 5.2: Set the API Key

**PowerShell (current session):**
```powershell
$env:GEMINI_API_KEY="AIzaSy..."
```

**PowerShell (permanent -- survives restarts):**
```powershell
[System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "AIzaSy...", "User")
```
Restart your terminal after setting it permanently.

**Git Bash (current session):**
```bash
export GEMINI_API_KEY="AIzaSy..."
```

**Git Bash (permanent):**
```bash
echo 'export GEMINI_API_KEY="AIzaSy..."' >> ~/.bashrc
source ~/.bashrc
```

### Step 5.3: Multiple Keys for Rate Limit Rotation (Optional)

If you are scanning large projects and hitting rate limits, you can provide multiple API keys. SEC-C will rotate between them:

**PowerShell:**
```powershell
$env:GEMINI_API_KEYS="AIzaSy...key1,AIzaSy...key2,AIzaSy...key3"
```

**Git Bash:**
```bash
export GEMINI_API_KEYS="AIzaSy...key1,AIzaSy...key2,AIzaSy...key3"
```

Each key gets its own rate limit quota, so 3 keys = 3x the throughput.

### Step 5.4: Verify API Access

```powershell
sec-c status
```

You should see output like:
```
  SEC-C v2.0.0

  Component       Status      Details
  ─────────────   ─────────   ─────────────
  CodeQL CLI      Available   v2.19.3
  Joern           Not found   (simplified graph fallback)
  Gemini API      Configured  ...xyz1
  GitHub Token    Not set     (optional)
  GPU (CUDA)      Not found   (using CPU)
```

The `Gemini API` row should show `Configured`. If it shows `Not set`, your environment variable is not being picked up -- check spelling and make sure you restarted your terminal.

### Step 5.5: Free Tier Limits and Planning

| Model | Requests/Minute | Requests/Day | Used for |
|-------|----------------|-------------|----------|
| Gemini 2.5 Pro | 5 | 100 | Complex findings (high uncertainty) |
| Gemini 2.5 Flash | 10 | 250 | Simpler findings (moderate uncertainty) |

**What this means for scanning:**
- Each finding that reaches Stage 3 uses 2 API calls (1 attacker agent + 1 defender agent)
- With Flash only: ~125 findings/day
- With Pro + Flash mixed: depends on complexity routing, roughly 100-175 findings/day
- The cascade design means most findings are resolved in Stages 1-2, so even large projects rarely exhaust the free tier

**Planning a large scan:**
- Small project (< 1000 LOC): 5-15 findings reach Stage 3 -- easily fits in free tier
- Medium project (1000-10000 LOC): 20-50 findings -- fits in free tier
- Large project (10000+ LOC): 50-200 findings -- may need multiple days or multiple keys

SEC-C automatically:
- Queues requests with exponential backoff when rate limited
- Routes simpler findings to Flash (cheaper quota) and complex findings to Pro
- Falls back from Pro to Flash if Pro quota is exhausted
- Reports remaining quota via `sec-c status`

---

## Part 6: First Full Demo Run

Now let us run SEC-C end-to-end. We will scan the included test fixtures at increasing cascade depths.

### Step 6.1: SAST Only (Stage 1)

```powershell
cd D:\sec-c
sec-c scan tests/fixtures/vulnerable_python.py --stage sast
```

**What happens:**
1. Tree-sitter pre-screening identifies suspicious patterns (< 100ms)
2. CodeQL creates a database and runs `security-extended` queries
3. 4-factor uncertainty scoring: each finding gets a confidence, complexity, novelty, and conflict score
4. Console report shows findings with severity and uncertainty

**What you should see:**
- 8-10 findings (SQL injection, command injection, path traversal, eval injection, deserialization, XSS, hardcoded credentials, weak crypto)
- Each finding shows: CWE ID, severity (critical/high/medium/low), confidence score, and the vulnerable code line
- Findings with high uncertainty are marked as candidates for escalation

### Step 6.2: SAST + Graph (Stage 2)

```powershell
sec-c scan tests/fixtures/vulnerable_python.py --stage graph
```

**What happens (in addition to Stage 1):**
1. Uncertain findings from Stage 1 get escalated
2. Joern (or simplified fallback) generates a Code Property Graph
3. GraphCodeBERT embeds each code node into a 768-dim vector
4. Mini-GAT classifies the graph structure
5. Conformal prediction produces calibrated prediction sets
6. Score fusion combines SAST score (weight 0.3) with GAT score (weight 0.3)

**What changes from Stage 1:**
- Some findings may be reclassified (e.g., "potential" upgraded to "likely" or downgraded)
- Uncertainty scores are updated based on structural analysis
- You may see fewer findings if the GNN confidently classifies some as false positives

### Step 6.3: Full Cascade with HTML Report (All 3 Stages)

```powershell
sec-c scan tests/fixtures/vulnerable_python.py --html
```

**What happens (in addition to Stages 1-2):**
1. Remaining uncertain findings get escalated to Stage 3
2. **Attacker agent** (Gemini) attempts to construct an exploit for the finding
3. **Defender agent** (Gemini) analyzes whether existing sanitization prevents the exploit
4. Adversarial consensus: if both agents agree it is vulnerable, confidence increases
5. RAG retrieves relevant CWE/CVE context to ground the LLM reasoning
6. Final score fusion (SAST 0.3 + GAT 0.3 + LLM 0.4) produces the final classification
7. An interactive HTML dashboard opens in your default browser

**The HTML report includes:**
- Summary donut chart: confirmed / likely / potential findings
- Sortable table of all findings
- Expandable detail view for each finding: code snippet, taint path, stage-by-stage scores
- Cascade flow visualization showing how each finding moved through stages
- Confidence breakdown: SAST score vs GAT score vs LLM score

### Step 6.4: Compare with Safe Code

For contrast, scan the safe test fixture:

```powershell
sec-c scan tests/fixtures/safe_python.py --stage sast
```

You should see zero or very few findings -- the safe fixture uses parameterized queries, subprocess with list args, path validation, JSON instead of pickle, HTML escaping, and `ast.literal_eval` instead of `eval`.

---

## Part 7: Scanning Real Projects

### Step 7.1: Scan a Known Vulnerable Repository

Scan OWASP WebGoat, a deliberately vulnerable application used for security training:

```powershell
sec-c scan --github OWASP/WebGoat --stage sast
```

This will:
1. Clone the repository to a temporary directory
2. Detect languages (Java, JavaScript)
3. Create CodeQL databases
4. Run the full scan cascade up to the specified stage

Note: scanning a large repo takes 5-30 minutes depending on size. Use `--stage sast` for faster results.

You need a GitHub token for private repos:
```powershell
$env:GITHUB_TOKEN="ghp_your_token_here"
```

Generate one at https://github.com/settings/tokens with `repo` (read) scope.

### Step 7.2: Scan Your Own Code

```powershell
# Scan a local directory
sec-c scan D:\path\to\your\project --html

# Scan a single file
sec-c scan D:\path\to\your\file.py --stage sast

# Scan specific languages only
sec-c scan D:\path\to\your\project --languages python,javascript --html

# Save SARIF output for CI/CD integration
sec-c scan D:\path\to\your\project --output results.sarif
```

### Step 7.3: Interpreting Results

SEC-C classifies findings into three tiers based on the fused confidence score:

| Classification | Score threshold | Meaning |
|---------------|----------------|---------|
| **Confirmed** | >= 0.85 | High confidence this is a real vulnerability. Multiple stages agree. Action required. |
| **Likely** | >= 0.50 and < 0.85 | Probable vulnerability but some uncertainty remains. Review recommended. |
| **Potential** | < 0.50 | Low confidence. May be a false positive. Investigate if in a sensitive context. |

These thresholds are configured in `configs/default.yaml` under `orchestrator.classification`.

### Step 7.4: Reading the HTML Dashboard

The HTML dashboard has several sections:

1. **Summary bar** at the top: total findings, counts by classification tier, languages scanned
2. **Donut chart**: visual breakdown of confirmed/likely/potential
3. **Findings table**: sortable by severity, CWE, confidence, classification
4. **Detail panel** (click any finding): shows the full code context, taint path (source to sink), stage-by-stage analysis, and the LLM agents' reasoning (if Stage 3 ran)
5. **Cascade statistics**: how many findings were resolved at each stage, average uncertainty reduction

---

## Part 8: Running Tests

SEC-C includes a test suite to verify all components work correctly.

### Step 8.1: Run All Tests

```powershell
cd D:\sec-c
pytest tests/ -v
```

**Expected output:**
```
tests/test_treesitter.py::test_python_patterns PASSED
tests/test_treesitter.py::test_javascript_patterns PASSED
tests/test_uncertainty.py::test_four_factor_scoring PASSED
tests/test_sarif.py::test_sarif_generation PASSED
tests/test_gnn.py::test_mini_gat_forward PASSED
tests/test_rag.py::test_knowledge_base_query PASSED
...

==================== X passed, Y skipped in Z.ZZs ====================
```

Some tests may be **skipped** if optional components are not installed (Joern, Gemini API key, trained model). This is expected. The key thing is that no tests **fail**.

### Step 8.2: Run Tests with Coverage

```powershell
pytest tests/ -v --cov=src --cov-report=term-missing
```

### Step 8.3: If Tests Fail -- Common Issues

| Failure | Fix |
|---------|-----|
| `ModuleNotFoundError` | Make sure your venv is activated and you ran `pip install -e ".[dev]"` |
| Tests related to CodeQL | Verify `codeql --version` works. CodeQL must be in PATH |
| Tests related to GNN | Verify `data/models/mini_gat.pt` exists. Run training first |
| Tests related to RAG | Verify `data/rag/` directory has index files. Run `build_rag.py` first |
| Tests related to Gemini | Set `GEMINI_API_KEY` environment variable |
| `asyncio` errors | Make sure `pytest-asyncio>=0.23` is installed |

---

## Part 9: Troubleshooting Reference

Quick-fix table for every common error:

### Installation Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `python: command not found` | Python not in PATH | Reinstall Python with "Add to PATH" checked, or use `py` instead |
| `pip: command not found` | pip not in PATH | Use `python -m pip` instead of `pip` |
| `error: Microsoft Visual C++ 14.0 or greater is required` | Missing C++ build tools | Install "Build Tools for Visual Studio" from https://visualstudio.microsoft.com/visual-cpp-build-tools/ |
| `ERROR: Could not build wheels for ...` | Package build failure | Try `pip install --upgrade pip setuptools wheel` first, then retry |
| `.venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell execution policy | Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `No matching distribution found for torch-geometric` | Wrong Python version or platform | Verify Python 3.11+ with `python --version`. Install PyTorch first, then torch-geometric |

### PyTorch / torch-geometric Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: No module named 'torch'` | PyTorch not installed | `pip install torch --index-url https://download.pytorch.org/whl/cpu` |
| `ModuleNotFoundError: No module named 'torch_geometric'` | PyG not installed | See Step 1.5 for detailed installation |
| `ModuleNotFoundError: No module named 'torch_scatter'` | Missing PyG dependency | `pip install torch-scatter -f https://data.pyg.org/whl/torch-2.5.0+cpu.html` (match your torch version) |
| `RuntimeError: CUDA out of memory` | GPU memory exhausted | Add `--device cpu` or reduce `--batch-size 8` |
| `AssertionError: Torch not compiled with CUDA enabled` | CPU-only PyTorch but requested CUDA | Reinstall with CUDA: `pip install torch --index-url https://download.pytorch.org/whl/cu121` |

### CodeQL Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `codeql: command not found` / `not recognized` | CodeQL not in PATH | Add `C:\codeql` to PATH (see Step 2.2) |
| `A fatal error occurred: Could not find a CodeQL query pack` | Query packs not downloaded | Run `codeql pack download codeql/python-queries` (and other languages) |
| `codeql database create` hangs | Large project or slow disk | Add `--threads=0` to use all cores, or scan a subdirectory |
| `No source code found` | Source root mismatch | Use `--source-root=<path>` pointing to the actual source directory |

### Joern Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Joern not found` warning | Joern not installed (non-fatal) | Install via Docker: `docker pull ghcr.io/joernio/joern` -- or ignore, SEC-C uses fallback |
| `java: command not found` | Java not installed | Install Java 17: download from https://adoptium.net/ |
| `Unsupported major.minor version` | Java version too old | Upgrade to Java 11+ |

### Gemini API Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `GEMINI_API_KEY not set` | Environment variable missing | Set it: `$env:GEMINI_API_KEY="AIzaSy..."` (PowerShell) |
| `403 Forbidden` | Invalid API key | Regenerate key at https://aistudio.google.com/apikey |
| `429 Resource exhausted` | Rate limit hit | Wait 30-60 seconds. SEC-C auto-retries with backoff. Or add more keys |
| `API key not valid. Please pass a valid API key.` | Wrong key format | Key must start with `AIza`. Check for trailing whitespace |

### RAG / NVD Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `NVD download failed: 403` | NVD API rate limited | Wait 30 seconds and retry. Or set `NVD_API_KEY` for higher limits |
| `CWE download failed` | Network issue | Check your internet. MITRE CWE site may be temporarily down -- retry later |
| `Index build failed` | Missing FAISS | `pip install faiss-cpu` |

### Runtime / Scanning Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `No module named 'tree_sitter_python'` | Missing tree-sitter grammar | `pip install tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-c tree-sitter-go` |
| `Labels file not found` | Juliet data not downloaded | `python scripts/download_juliet.py` |
| `Model file not found` | GNN not trained | `python scripts/train_gat.py --epochs 50 --device cpu` |
| Scan produces 0 findings on known-vulnerable code | CodeQL database creation failed silently | Check CodeQL is in PATH. Try creating the database manually (Step 2.5) |
| HTML report does not open | Default browser issue | The HTML file is saved to a temp directory. Check console output for the file path, then open it manually |

### General Debugging

If something is not working and the error is not listed above:

```powershell
# Check the status of all components
sec-c status

# Run a scan with verbose logging
sec-c scan tests/fixtures/vulnerable_python.py --stage sast --verbose

# Check Python environment
python -c "import sys; print(sys.executable); print(sys.version)"

# Check if you are in the right virtual environment
pip list | findstr sec-c
```

---

## Appendix: Configuration Reference

The main configuration file is `configs/default.yaml`. Here are the most important settings you may want to customize:

```yaml
# Escalation sensitivity (lower = more findings go to Stage 2/3)
sast:
  uncertainty:
    escalation_threshold: 0.5   # Range: 0.0 to 1.0

# GPU vs CPU for embeddings
graph:
  embeddings:
    device: "cpu"               # Change to "cuda" if you have a GPU

# Conformal prediction coverage guarantee
graph:
  conformal:
    alpha: 0.1                  # 0.1 = 90% coverage. Lower = more conservative

# Score fusion weights (must sum to 1.0)
orchestrator:
  fusion:
    sast_weight: 0.3            # How much to trust SAST findings
    gat_weight: 0.3             # How much to trust GNN findings
    llm_weight: 0.4             # How much to trust LLM findings

# Classification thresholds
orchestrator:
  classification:
    confirmed_threshold: 0.85   # Score >= 0.85 = "confirmed"
    likely_threshold: 0.50      # Score >= 0.50 = "likely"
                                # Score < 0.50  = "potential"
```

CWE-specific weight overrides are in `configs/cwe_weights.yaml`. For example, SQL injection (CWE-89) may weight SAST higher because CodeQL's taint tracking is particularly strong for that category.

---

## Appendix: File System Layout After Full Setup

After completing all parts, your `D:\sec-c` directory should contain:

```
D:\sec-c\
  configs/
    default.yaml              # Main configuration
    cwe_weights.yaml          # Per-CWE fusion weights
  data/
    juliet/                   # Part 3a
      java/                   # Juliet Java test cases by CWE
      c_cpp/                  # Juliet C/C++ test cases by CWE
      python/                 # Synthetic Python test cases
      labels.json             # Ground-truth labels
    models/                   # Part 3c
      mini_gat.pt             # Trained GNN model (~5-10 MB)
      conformal_calibration.json  # Part 3d
    rag/                      # Part 4
      cwe_raw/                # Raw CWE XML data
      nvd_raw/                # Raw NVD JSON data (if full build)
      faiss_index.bin         # Semantic search index
      bm25_index.pkl          # Keyword search index
      cwe_data.json           # Parsed CWE entries
      last_update.txt         # Timestamp of last build
  src/                        # Source code (installed via pip install -e)
  tests/
    fixtures/
      vulnerable_python.py    # Intentionally vulnerable test code
      safe_python.py          # Properly secured test code
  scripts/
    download_juliet.py        # Part 3a
    train_gat.py              # Part 3c
    build_rag.py              # Part 4
    setup_codeql.sh           # Part 2 (automated)
    setup_joern.sh            # Part 3b (automated)
```
