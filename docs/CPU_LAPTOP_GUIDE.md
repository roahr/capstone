# SEC-C: CPU Laptop Setup Guide

> Specific to your system: i5-1240P, 16GB RAM, Windows 11, no GPU.
> Train on Kaggle (free GPU), run everything else locally.

---

## Your System

| Component | Value | Status |
|-----------|-------|--------|
| CPU | Intel i5-1240P (12 cores) | Good for inference |
| RAM | 16 GB | Sufficient |
| Disk | 600+ GB free | Plenty |
| Python | 3.13.7 | ✓ |
| PyTorch | 2.10.0+cpu | ✓ |
| CodeQL | Installed at C:\codeql | ✓ |
| Java | JDK 21 (Corretto) | ✓ (for Joern) |
| Joern | Not installed | Need to install |
| GPU | None | Use Kaggle for training |

---

## What Runs Where

```
LOCAL (your laptop)                    KAGGLE (free P100 GPU)
═══════════════════                    ══════════════════════
✓ Module 1: SAST (CodeQL)             ✓ GNN Training (~30 min)
✓ Module 2: Joern CPG generation      ✓ GraphCodeBERT embeddings
✓ Module 2: GNN Inference (<10ms)     ✓ Conformal calibration
✓ Module 3: Gemini API calls
✓ Module 4: Reports + HTML
✓ RAG knowledge base
✓ Interactive CLI

Output from Kaggle:
  mini_gat.pt → D:/sec-c/data/models/
  conformal_calibration.json → D:/sec-c/data/models/
```

---

## Step 1: Install Joern (5 min)

You have Java 21 installed, so Joern will work.

```powershell
# Option A: Using the install script (Git Bash)
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh
bash joern-install.sh --install-dir="$HOME/.sec-c/joern"

# Add to PATH (PowerShell)
$env:PATH += ";$env:USERPROFILE\.sec-c\joern"

# Option B: Docker (if install script fails on Windows)
docker pull ghcr.io/joernio/joern
# Use via: docker run --rm -v D:/sec-c:/code ghcr.io/joernio/joern

# Verify
joern --version
```

**If Joern won't install**: That's OK. The framework has a simplified graph fallback. Module 2 will still work with reduced accuracy.

---

## Step 2: Train Mini-GAT on Kaggle (30 min)

### 2a: Upload to Kaggle

1. Go to [kaggle.com/kernels](https://www.kaggle.com/code) → **New Notebook**
2. Set **Accelerator** → **GPU P100** (under Settings → Accelerator)
3. Copy the entire content of `D:/sec-c/notebooks/kaggle_train_gat.py`
4. Paste into the notebook (or create cells from the `# Cell N` markers)
5. Click **Run All**

### 2b: What Happens

```
Cell 1:  Install torch-geometric + transformers      (~2 min)
Cell 2:  Detect GPU (should show P100)                (~5 sec)
Cell 3:  Generate 1000 training samples               (~10 sec)
Cell 4:  Build graph representations with             (~10 min)
         GraphCodeBERT embeddings (GPU-accelerated)
Cell 5:  Split into train/val/test                    (~1 sec)
Cell 6:  Create MiniGAT model                        (~1 sec)
Cell 7:  Train for 50 epochs                          (~10 min on GPU)
Cell 8:  Evaluate on test set                         (~30 sec)
Cell 9:  Calibrate conformal prediction               (~30 sec)
Cell 10: Save outputs                                 (~1 sec)
```

### 2c: Download Results

After training completes, you'll see:
```
DONE! Download these 2 files:
  1. mini_gat.pt
  2. conformal_calibration.json
```

1. Click the **Output** tab in Kaggle
2. Download both files
3. Place them in:
```
D:/sec-c/data/models/mini_gat.pt
D:/sec-c/data/models/conformal_calibration.json
```

### 2d: Expected Metrics

| Metric | Expected Range |
|--------|---------------|
| Accuracy | 0.75 - 0.90 |
| Precision | 0.70 - 0.85 |
| Recall | 0.75 - 0.90 |
| F1 | 0.72 - 0.87 |
| Empirical Coverage | ≥ 0.90 (guaranteed by conformal prediction) |
| Singleton Rate | 60-80% (resolved at graph stage) |

---

## Step 3: Build RAG Knowledge Base (2 min quick / 2-3 hours full)

### Quick Start (CWE only — recommended to start)

```powershell
cd D:\sec-c
python scripts/build_rag.py --cwe-only
```

This indexes 900+ CWE descriptions. Enough for the LLM to have context.

### Full NVD (do this overnight)

```powershell
python scripts/build_rag.py --years 2022-2026
```

Downloads 200K+ CVEs. Takes 2-3 hours due to NVD API rate limits.

---

## Step 4: Set Gemini API Key

```powershell
# PowerShell (temporary)
$env:GEMINI_API_KEY="AIza...your-key"

# Permanent (PowerShell)
[System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "AIza...your-key", "User")

# Multiple keys for 3x throughput
$env:GEMINI_API_KEYS="AIza...key1,AIza...key2,AIza...key3"
```

---

## Step 5: Verify Everything

```powershell
sec-c status
```

Expected output:
```
◆ Sec-C v2.0.0

Component        Status       Details
──────────────────────────────────────────
CodeQL CLI       Available    C:\codeql\codeql.EXE
Joern            Available    ~/.sec-c/joern/joern
Gemini API       Configured   ...xyz1
GPU (CUDA)       CPU Only     GNN runs on CPU (inference only)
```

---

## Step 6: First Demo Run

```powershell
# SAST only (instant, no model needed)
sec-c scan tests/fixtures/vulnerable_python.py --stage sast

# With Graph validation (needs trained model)
sec-c scan tests/fixtures/vulnerable_python.py --stage graph

# Full cascade with HTML dashboard
sec-c scan tests/fixtures/ --html

# Interactive mode
sec-c
```

---

## Performance on Your System

| Operation | Expected Time | Notes |
|-----------|--------------|-------|
| Tree-sitter pre-screen | < 50ms | Instant |
| CodeQL database creation | 10-60s | Depends on project size |
| CodeQL query execution | 5-30s | Per language |
| Joern CPG generation | 2-10s | Per file |
| GNN inference (Mini-GAT) | < 10ms | CPU is fine for inference |
| Gemini API call | 2-10s | Network dependent |
| Full cascade (small project) | 30s - 2min | Most time in CodeQL + Gemini |
| Full cascade (large project) | 2-10min | Depends on findings count |

### Memory Usage

| Component | RAM Usage |
|-----------|----------|
| CodeQL database | 200MB - 1GB |
| Joern CPG | 100MB - 500MB |
| Mini-GAT model | < 50MB |
| GraphCodeBERT (if loaded locally) | ~1.5GB |
| RAG index (CWE only) | < 100MB |
| RAG index (full NVD) | ~500MB |
| **Total peak** | **~3-4 GB** |

Your 16GB RAM is more than sufficient. You'll have plenty of headroom.

---

## FAQ

**Q: Can I skip Joern entirely?**
A: Yes. The framework detects Joern is missing and uses a simplified graph fallback. You lose some accuracy in Stage 2 but everything else works.

**Q: Do I need GraphCodeBERT locally?**
A: Not if you trained on Kaggle with real embeddings. For local inference, the saved model weights already contain the learned representations. GraphCodeBERT is only needed at training time (Kaggle handles this).

**Q: What if Kaggle is down or slow?**
A: You can train on CPU locally. It takes ~4 hours instead of ~30 min:
```powershell
python scripts/train_gat.py --epochs 50 --device cpu --batch-size 16
```

**Q: Can I use Google Colab instead of Kaggle?**
A: Yes, same notebook works. Just set Runtime → GPU.

**Q: How many Gemini API calls does a typical scan use?**
A: Only ~5% of findings reach the LLM stage. For a project with 20 findings:
- ~16 resolved at SAST (no API calls)
- ~3 resolved at Graph (no API calls)
- ~1 sent to LLM (2 API calls: attacker + defender)

Free tier (350 calls/day) is enough for ~175 findings reaching LLM stage.
