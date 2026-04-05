"""
patch_v4_notebook.py
====================
Produces notebooks/sec_c_gnn_training_v4.ipynb from V3 by applying:
  - CONFIG changes  (code cell [1])
  - Full dataset-loading rewrite  (code cell [2])
  - Zip cell update  (code cell [15])

Run:  python scripts/patch_v4_notebook.py
"""

import json
from pathlib import Path

SRC = Path("D:/sec-c/notebooks/sec_c_gnn_training_v3.ipynb")
DST = Path("D:/sec-c/notebooks/sec_c_gnn_training_v4.ipynb")

nb = json.load(open(SRC, encoding="utf-8"))
code_cells = [c for c in nb["cells"] if c["cell_type"] == "code"]


def set_src(cell, text: str):
    cell["source"] = text.splitlines(keepends=True)


def src(cell) -> str:
    return "".join(cell["source"])


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 1 — CONFIG cell  (code_cells[1])
# ─────────────────────────────────────────────────────────────────────────────
NEW_CONFIG = '''\
# ============================================================================
# Cell 2: Configuration — V4 (all hyperparameters in one place)
# ============================================================================
from pathlib import Path
import json, random
import numpy as np

SEED = 42
random.seed(SEED); np.random.seed(SEED)
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

CONFIG = {
    # ── Model architecture ──────────────────────────────────────────────────
    "embedding_model":     "microsoft/graphcodebert-base",
    "embedding_dim":       768,
    "node_feature_dim":    6,
    "input_dim":           774,     # 768 GCB mean-pool + 6 structural features
    "hidden_dim":          384,
    "num_gin_layers":      3,
    "dropout":             0.35,    # V4: 0.35 (less regularisation with more data)
    "num_classes":         2,

    # ── Graph construction ──────────────────────────────────────────────────
    "max_nodes":               300,
    "max_tokens_per_node":     128,
    "embedding_batch_size":    64,

    # ── Per-language data caps ──────────────────────────────────────────────
    "target_balance_ratio":    1.0,   # strict 1:1 vuln:safe per language
    "max_per_language":        20000, # V4 FIX: was 3000 (was discarding 20K C/C++ samples)
    "min_per_language":        50,

    # ── Per-source dataset caps ─────────────────────────────────────────────
    "max_bigvul":      10000,
    "max_diversevul":  8000,
    "max_devign":      5000,
    "max_primevul":    8000,   # NEW: starsofchance/PrimeVul
    "max_juliet_c":    6000,   # NEW: LorenzH/juliet_test_suite_c_1_3  (101K avail)
    "max_crossvul":    6000,   # NEW: hitoshura25/crossvul (was failing)
    "max_vudenc":      3000,   # NEW: DetectVul/Vudenc  (Python, 15.8K stmts)
    "max_cvefixes":    3000,   # DetectVul/CVEFixes  (Python stmts)

    # ── Training ────────────────────────────────────────────────────────────
    "batch_size":          64,
    "epochs":              100,
    "lr":                  3e-4,
    "lr_warmup_epochs":    5,
    "weight_decay":        1e-3,
    "patience":            20,    # V4: 20 (was 25)
    "label_smoothing":     0.1,
    "grad_clip":           0.5,
    "class_weight_vuln":   1.5,   # mild; no focal loss

    # ── Conformal prediction ────────────────────────────────────────────────
    "alpha":                   0.1,  # V4 FIX: 0.1 = 90% coverage (was 0.2, misaligned with framework)
    "threshold_search_steps":  81,

    # ── Dataset split ───────────────────────────────────────────────────────
    "train_ratio": 0.60,
    "val_ratio":   0.15,
    "cal_ratio":   0.15,
    "test_ratio":  0.10,

    # ── Language encoding ───────────────────────────────────────────────────
    "language_ids": {
        "python":     0.0,
        "javascript": 0.2,
        "java":       0.4,
        "c_cpp":      0.6,
        "go":         0.8,
    },
}

OUTPUT_DIR = Path("/kaggle/working")
OUTPUT_DIR.mkdir(exist_ok=True)

print("Configuration loaded.")
print(f"  Architecture: MiniGINv3, {CONFIG[\'num_gin_layers\']}-layer GIN, hidden={CONFIG[\'hidden_dim\']}")
print(f"  Training: LR={CONFIG[\'lr\']}, warmup={CONFIG[\'lr_warmup_epochs\']}ep, patience={CONFIG[\'patience\']}")
print(f"  Balance: {CONFIG[\'target_balance_ratio\']}:1 (strict per-language)")
print(f"  Loss: CE + label_smoothing={CONFIG[\'label_smoothing\']} (no focal loss)")
print(f"  Conformal: alpha={CONFIG[\'alpha\']} ({(1-CONFIG[\'alpha\'])*100:.0f}% coverage target)")
print(f"  Max per language: {CONFIG[\'max_per_language\']} (V4: uncapped for C/C++)")
'''

# ─────────────────────────────────────────────────────────────────────────────
# PATCH 2 — Dataset loading cell  (code_cells[2])
# ─────────────────────────────────────────────────────────────────────────────
NEW_DATASET = '''\
# ============================================================================
# Cell 3: Dataset Loading — V4 (verified HuggingFace IDs, corrected schemas)
#
# Sources:
#   C/C++ real:      bstee615/bigvul | claudios/DiverseVul | google/code_x_glue_cc_defect_detection
#   C/C++ quality:   starsofchance/PrimeVul  (deduplicated, hard benchmark)
#   C/C++ synthetic: LorenzH/juliet_test_suite_c_1_3  (101K avail, was 150)
#   Multi-lang:      hitoshura25/crossvul  (was failing with wrong IDs)
#   Python:          DetectVul/Vudenc | DetectVul/CVEFixes
# ============================================================================
import hashlib, re, time, os
from collections import Counter, defaultdict
from datasets import load_dataset

all_samples = []

# ── Helpers ─────────────────────────────────────────────────────────────────
def make_sample(code, label, cwe, lang, source):
    """Return a sample dict or None if code is unusable."""
    if not code or not isinstance(code, str):
        return None
    code = code.strip()
    if len(code) < 20:          # too short to build a meaningful graph
        return None
    return {
        "code":     code,
        "label":    int(label),
        "cwe":      str(cwe).strip() if cwe else "unknown",
        "language": lang,
        "source":   source,
    }

def collect(name, samples, max_count=None):
    """Apply cap, extend all_samples, print stats."""
    if not samples:
        print(f"  [{name}] 0 samples")
        return
    capped = samples[:max_count] if max_count and len(samples) > max_count else samples
    lc = Counter(s["label"] for s in capped)
    lnc = Counter(s["language"] for s in capped)
    all_samples.extend(capped)
    print(f"  [{name}] {len(capped)} samples — {dict(lc)} — langs={dict(lnc)}")

# ── 1. BigVul ────────────────────────────────────────────────────────────────
print("=" * 60)
print("  1. BigVul (C/C++, ~217K real CVE-labeled functions)")
try:
    _bv = load_dataset("bstee615/bigvul", split="train", trust_remote_code=True)
    _bv_s = []
    for row in _bv:
        code  = row.get("func_before") or row.get("func_after") or ""
        label = int(row.get("vul", 0))
        cwe   = str(row.get("CWE ID", "unknown") or "unknown")
        _bv_s.append(make_sample(code, label, cwe, "c_cpp", "BigVul"))
    collect("BigVul", [s for s in _bv_s if s], CONFIG["max_bigvul"])
except Exception as _e:
    print(f"  BigVul FAILED: {_e}")

# ── 2. DiverseVul ────────────────────────────────────────────────────────────
print("=" * 60)
print("  2. DiverseVul (C/C++, 330K real CVE-labeled)")
try:
    _dv = load_dataset("claudios/DiverseVul", split="test", trust_remote_code=True)
    _dv_s = []
    for row in _dv:
        code  = row.get("func", "") or ""
        label = int(row.get("target", 0))
        cwe_r = row.get("cwe", [])
        cwe   = cwe_r[0] if isinstance(cwe_r, list) and cwe_r else str(cwe_r or "unknown")
        _dv_s.append(make_sample(code, label, cwe, "c_cpp", "DiverseVul"))
    collect("DiverseVul", [s for s in _dv_s if s], CONFIG["max_diversevul"])
except Exception as _e:
    print(f"  DiverseVul FAILED: {_e}")

# ── 3. Devign / CodeXGLUE ────────────────────────────────────────────────────
print("=" * 60)
print("  3. Devign/CodeXGLUE (C/C++, 27K real samples, all splits)")
try:
    _dg_s = []
    for _split in ["train", "validation", "test"]:
        try:
            _dg = load_dataset("google/code_x_glue_cc_defect_detection",
                               split=_split, trust_remote_code=True)
            for row in _dg:
                code  = row.get("func", "") or ""
                label = int(row.get("target", 0))
                _dg_s.append(make_sample(code, label, "unknown", "c_cpp", "Devign"))
        except Exception as _e2:
            print(f"    Devign split={_split}: {_e2}")
    collect("Devign", [s for s in _dg_s if s], CONFIG["max_devign"])
except Exception as _e:
    print(f"  Devign FAILED: {_e}")

# ── 4. PrimeVul — NEW ────────────────────────────────────────────────────────
print("=" * 60)
print("  4. PrimeVul (C/C++, 236K deduplicated, hardest benchmark)")
try:
    _pv_s = []
    for _split in ["train", "validation", "test"]:
        try:
            _pv = load_dataset("starsofchance/PrimeVul",
                               split=_split, trust_remote_code=True)
            for row in _pv:
                code  = row.get("func", "") or ""
                label = int(row.get("vul", 0))
                cwe   = str(row.get("CWE ID", "unknown") or "unknown")
                _pv_s.append(make_sample(code, label, cwe, "c_cpp", "PrimeVul"))
        except Exception as _e2:
            print(f"    PrimeVul split={_split}: {_e2}")
    collect("PrimeVul", [s for s in _pv_s if s], CONFIG["max_primevul"])
except Exception as _e:
    print(f"  PrimeVul FAILED: {_e}")

# ── 5. Juliet C/C++ — NEW large source ───────────────────────────────────────
print("=" * 60)
print("  5. Juliet C/C++ (LorenzH/juliet_test_suite_c_1_3, 101K avail)")
try:
    _jc_s = []
    for _split in ["train", "test"]:
        try:
            _jc = load_dataset("LorenzH/juliet_test_suite_c_1_3",
                               split=_split, trust_remote_code=True)
            for row in _jc:
                bad_code  = row.get("bad", "") or ""
                good_code = row.get("good", "") or ""
                cwe_num   = str(row.get("class", "") or "")
                cwe       = f"CWE-{cwe_num}" if cwe_num.isdigit() else cwe_num or "unknown"
                _jc_s.append(make_sample(bad_code,  1, cwe, "c_cpp", "Juliet-C"))
                _jc_s.append(make_sample(good_code, 0, cwe, "c_cpp", "Juliet-C"))
        except Exception as _e2:
            print(f"    Juliet-C split={_split}: {_e2}")
    collect("Juliet-C", [s for s in _jc_s if s], CONFIG["max_juliet_c"])
except Exception as _e:
    print(f"  Juliet-C FAILED: {_e}")

# ── 6. CrossVul — FIXED HF ID ────────────────────────────────────────────────
print("=" * 60)
print("  6. CrossVul multi-language (hitoshura25/crossvul, 9.3K pairs)")
try:
    _cv = load_dataset("hitoshura25/crossvul", split="train", trust_remote_code=True)
    _cv_s = []
    _lang_map = {
        "c": "c_cpp", "cpp": "c_cpp", "c++": "c_cpp", "c/c++": "c_cpp",
        "python": "python", "py": "python",
        "java": "java",
        "javascript": "javascript", "js": "javascript", "typescript": "javascript",
        "go": "go",
    }
    for row in _cv:
        vuln_code = row.get("vulnerable_code", "") or ""
        safe_code = row.get("fixed_code", "") or ""
        cwe       = str(row.get("cwe_id", "unknown") or "unknown")
        lang_raw  = str(row.get("language", "") or "").lower().strip()
        lang      = _lang_map.get(lang_raw)
        if lang is None:
            continue
        _cv_s.append(make_sample(vuln_code, 1, cwe, lang, "CrossVul"))
        _cv_s.append(make_sample(safe_code, 0, cwe, lang, "CrossVul"))
    collect("CrossVul", [s for s in _cv_s if s], CONFIG["max_crossvul"])
except Exception as _e:
    print(f"  CrossVul FAILED: {_e}")

# ── 7. VUDENC Python — NEW correct ID ────────────────────────────────────────
print("=" * 60)
print("  7. VUDENC Python (DetectVul/Vudenc, 15.8K statement-level CVE)")
try:
    _vu_s = []
    for _split in ["train", "test"]:
        try:
            _vu = load_dataset("DetectVul/Vudenc", split=_split, trust_remote_code=True)
            for row in _vu:
                code  = row.get("lines", "") or row.get("raw_lines", "") or ""
                label = int(row.get("label", 0))
                if len(code.strip()) < 30:   # too short — skip
                    continue
                _vu_s.append(make_sample(code, label, "unknown", "python", "VUDENC"))
        except Exception as _e2:
            print(f"    VUDENC split={_split}: {_e2}")
    collect("VUDENC", [s for s in _vu_s if s], CONFIG["max_vudenc"])
except Exception as _e:
    print(f"  VUDENC FAILED: {_e}")

# ── 8. CVEfixes Python — FIXED ID ────────────────────────────────────────────
print("=" * 60)
print("  8. CVEfixes Python (DetectVul/CVEFixes, 5.7K statement-level)")
try:
    _cf_s = []
    for _split in ["train", "test"]:
        try:
            _cf = load_dataset("DetectVul/CVEFixes", split=_split, trust_remote_code=True)
            for row in _cf:
                code  = row.get("lines", "") or row.get("raw_lines", "") or ""
                label = int(row.get("label", 0))
                if len(code.strip()) < 30:
                    continue
                _cf_s.append(make_sample(code, label, "unknown", "python", "CVEfixes-Py"))
        except Exception as _e2:
            print(f"    CVEFixes split={_split}: {_e2}")
    collect("CVEfixes-Py", [s for s in _cf_s if s], CONFIG["max_cvefixes"])
except Exception as _e:
    print(f"  CVEfixes-Py FAILED: {_e}")

# ── Summary ──────────────────────────────────────────────────────────────────
print(f"\\nRaw total: {len(all_samples)} samples")
_lbl_c = Counter(s["label"] for s in all_samples)
_lng_c = Counter(s["language"] for s in all_samples)
_cwe_k = sum(1 for s in all_samples if s["cwe"] != "unknown")
print(f"  Labels:    vuln={_lbl_c[1]}, safe={_lbl_c[0]}")
print(f"  CWE known: {_cwe_k}/{len(all_samples)} ({100*_cwe_k/max(len(all_samples),1):.1f}%)")
for _lang, _n in sorted(_lng_c.items()):
    _vn = sum(1 for s in all_samples if s["language"]==_lang and s["label"]==1)
    _sn = sum(1 for s in all_samples if s["language"]==_lang and s["label"]==0)
    print(f"  {_lang:<20s} {_n:5d} (v={_vn}, s={_sn})")

_src_c = Counter(s["source"] for s in all_samples)
print("\\nSource breakdown:")
for _src, _n in _src_c.most_common():
    print(f"  {_src:<25s} {_n:5d}")
'''

# ─────────────────────────────────────────────────────────────────────────────
# PATCH 3 — Zip cell  (code_cells[15])  — update filename + add raw_samples note
# ─────────────────────────────────────────────────────────────────────────────
NEW_ZIP = '''\
# ============================================================================
# Cell 16: Zip all artifacts for single-click download from Kaggle
# ============================================================================
import zipfile, time

_zip_path = OUTPUT_DIR / f"sec_c_gnn_v4_artifacts.zip"

# Files to include (essential artifacts only — large intermediates excluded)
_files = [
    ("mini_gat_v3.pt",                "model weights — load with MiniGINv3"),
    ("mini_gat_v3_best.pt",           "best val-F1 checkpoint"),
    ("decision_threshold_v3.json",    "F1-optimal decision threshold"),
    ("conformal_calibration_v3.json", "APS conformal calibration + all metrics"),
    ("graph_config_v3.json",          "model config + dataset info (framework wiring)"),
    ("eda_overview_v3.png",           "dataset EDA"),
    ("training_curves_v3.png",        "loss / F1 training curves"),
    ("threshold_calibration_v3.png",  "threshold search"),
    ("evaluation_plots_v3.png",       "ROC, confusion matrix, per-CWE F1"),
    ("conformal_diagnostics_v3.png",  "APS score histogram, set sizes, coverage"),
]

# Optionally include raw_samples if small enough (<50 MB)
_rs = OUTPUT_DIR / "raw_samples_v3.json"
if _rs.exists() and _rs.stat().st_size < 50 * 1024 * 1024:
    _files.append(("raw_samples_v3.json", "balanced sample list (for reproducibility)"))

# Include last 2 epoch checkpoints if present
_epoch_ckpts = sorted(OUTPUT_DIR.glob("mini_gat_v3_epoch*.pt"))[-2:]

print(f"Zipping artifacts -> {_zip_path.name}")
print(f"{'File':<42} {'Size':>8}  Description")
print("-" * 75)

with zipfile.ZipFile(str(_zip_path), "w", zipfile.ZIP_DEFLATED) as _zf:
    for _fname, _desc in _files:
        _fp = OUTPUT_DIR / _fname
        if _fp.exists():
            _sz = _fp.stat().st_size
            _zf.write(str(_fp), _fname)
            print(f"  {_fname:<40} {_sz/1024:>7.0f}K  {_desc}")
        else:
            print(f"  {_fname:<40} {'MISSING':>8}  {_desc}")
    for _ck in _epoch_ckpts:
        _zf.write(str(_ck), _ck.name)
        print(f"  {_ck.name:<40} {_ck.stat().st_size/1024:>7.0f}K  epoch checkpoint")

_total_mb = _zip_path.stat().st_size / 1024 / 1024
print(f"\\nZip: {_zip_path.name}  ({_total_mb:.1f} MB)")
print(f"Path: {_zip_path}")
print("\\nDownload: Kaggle Output tab -> sec_c_gnn_v4_artifacts.zip")
'''

# ─────────────────────────────────────────────────────────────────────────────
# Apply patches
# ─────────────────────────────────────────────────────────────────────────────
changes = 0

# Patch CONFIG (code cell 1)
assert "CONFIG = {" in src(code_cells[1]), "CONFIG cell not found at index 1"
set_src(code_cells[1], NEW_CONFIG)
print("[Patch 1] CONFIG cell updated")
changes += 1

# Patch dataset cell (code cell 2)
assert "BigVul" in src(code_cells[2]) and "load_dataset" in src(code_cells[2]), \
    "Dataset cell not found at index 2"
set_src(code_cells[2], NEW_DATASET)
print("[Patch 2] Dataset loading cell replaced")
changes += 1

# Patch zip cell (code cell 15)
assert "zipfile" in src(code_cells[15]), "Zip cell not found at index 15"
set_src(code_cells[15], NEW_ZIP)
print("[Patch 3] Zip cell updated")
changes += 1

# Clear all outputs so Kaggle starts fresh
for cell in nb["cells"]:
    if cell.get("outputs"):
        cell["outputs"] = []
    if "execution_count" in cell:
        cell["execution_count"] = None

print(f"\nTotal patches: {changes}")
json.dump(nb, open(DST, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print(f"Saved: {DST}")
