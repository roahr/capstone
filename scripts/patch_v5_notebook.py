"""
SEC-C GNN V5 Notebook Patcher
Applies all 7 changes to sec_c_gnn_training_v4.ipynb:
  1. CONFIG: label_smoothing 0.1 -> 0.0
  2. Dataset: Fix PrimeVul, remove trust_remote_code, fix newline join
  3. NEW ConfTS cell (insert between Eval and Conformal)
  4. Conformal: use T-scaled softmax
  5. Export: add conformal_temperature
  6. Summary: fix KeyError, add V5 info
  7. Zip: add ConfTS plot
"""

import json
import sys

NB_PATH = "D:/sec-c/notebooks/sec_c_gnn_training_v4.ipynb"

with open(NB_PATH, "r", encoding="utf-8") as f:
    nb = json.load(f)

cells = nb["cells"]
fixes = []


def get_src(cell):
    s = cell["source"]
    return "".join(s) if isinstance(s, list) else s


def set_src(cell, text):
    cell["source"] = text


# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 1: CONFIG — label_smoothing 0.1 → 0.0
# ═══════════════════════════════════════════════════════════════════════════
src = get_src(cells[4])
assert '"label_smoothing"' in src, "Wrong cell for CONFIG"
src = src.replace(
    '"label_smoothing":     0.1,',
    '"label_smoothing":     0.0,    # V5: was 0.1 (killed conformal singletons)',
)
src = src.replace("Configuration \u2014 V4", "Configuration \u2014 V5")
set_src(cells[4], src)
fixes.append("Change 1: label_smoothing 0.1 -> 0.0")

# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 2a: Fix PrimeVul — JSONL direct load
# ═══════════════════════════════════════════════════════════════════════════
src = get_src(cells[6])
assert "starsofchance/PrimeVul" in src, "Wrong cell for Dataset"

# Find the PrimeVul block boundaries
lines = src.split("\n")
pv_start = None
pv_end = None
for i, l in enumerate(lines):
    if "4. PrimeVul" in l and pv_start is None:
        pv_start = i
    if pv_start is not None and "5. Juliet" in l:
        pv_end = i
        break

if pv_start is not None and pv_end is not None:
    new_pv_lines = [
        "# \u2500\u2500 4. PrimeVul \u2014 V5 FIX: load JSONL directly (HF split metadata broken) \u2500\u2500\u2500\u2500",
        'print("=" * 60)',
        'print("  4. PrimeVul (C/C++, 236K deduplicated, hardest benchmark)")',
        "try:",
        "    _pv_s = []",
        "    _pv_files = {",
        '        "train": "hf://datasets/starsofchance/PrimeVul/primevul_train.jsonl",',
        '        "valid": "hf://datasets/starsofchance/PrimeVul/primevul_valid.jsonl",',
        '        "test":  "hf://datasets/starsofchance/PrimeVul/primevul_test.jsonl",',
        "    }",
        "    for _split_name, _pv_path in _pv_files.items():",
        "        try:",
        '            _pv = load_dataset("json", data_files=_pv_path, split="train")',
        "            for row in _pv:",
        '                code  = row.get("func", "") or ""',
        '                label = int(row.get("vul", 0))',
        '                cwe   = str(row.get("CWE ID", "unknown") or "unknown")',
        '                _pv_s.append(make_sample(code, label, cwe, "c_cpp", "PrimeVul"))',
        "        except Exception as _e2:",
        '            print(f"    PrimeVul {_split_name}: {_e2}")',
        '    collect("PrimeVul", [s for s in _pv_s if s], CONFIG["max_primevul"])',
        "except Exception as _e:",
        '    print(f"  PrimeVul FAILED: {_e}")',
        "",
    ]
    lines = lines[:pv_start] + new_pv_lines + lines[pv_end:]
    src = "\n".join(lines)
    fixes.append("Change 2a: PrimeVul -> JSONL direct load")
else:
    fixes.append("WARN 2a: Could not find PrimeVul section boundaries")

# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 2b: Remove trust_remote_code=True
# ═══════════════════════════════════════════════════════════════════════════
count_trc = src.count("trust_remote_code=True")
src = src.replace(", trust_remote_code=True", "")
src = src.replace(",trust_remote_code=True", "")
fixes.append(f"Change 2b: Removed trust_remote_code from {count_trc} calls")

# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 2c: Fix "\n".join(raw) encoding
# ═══════════════════════════════════════════════════════════════════════════
src = src.replace('code = "\n".join(raw)', "code = chr(10).join(raw)")
fixes.append("Change 2c: Fixed newline join encoding")

set_src(cells[6], src)

# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 3: Insert ConfTS cells
# ═══════════════════════════════════════════════════════════════════════════
confts_md = {
    "cell_type": "markdown",
    "id": "confts-md",
    "metadata": {},
    "source": (
        "## Cell 12b: Conformal Temperature Scaling (ConfTS)\n"
        "\n"
        "Post-hoc temperature optimization to minimize APS prediction set sizes "
        "(Dabah et al. 2024, arXiv:2402.04344).\n"
        "\n"
        "- Uses **val set** for T optimization, **cal set** for final conformal threshold\n"
        "- Preserves exchangeability \u2192 coverage guarantee maintained (Kofman et al. ICML 2025)\n"
        "- T < 1 sharpens softmax outputs, enabling singleton prediction sets"
    ),
}

confts_src_lines = [
    "# ============================================================================",
    "# Cell 12b: Conformal Temperature Scaling (ConfTS)",
    "# V5 NEW: Post-hoc temperature optimization to minimize APS set sizes",
    "# while maintaining coverage >= 1-alpha.",
    "#",
    "# Theory: ConfTS (Dabah et al. 2024, arXiv:2402.04344) optimizes a single",
    "# scalar T such that softmax(logits / T) produces smaller conformal",
    "# prediction sets. T < 1 sharpens confident predictions; T > 1 softens.",
    "# Using val set for T search and cal set for final threshold preserves",
    "# exchangeability -> coverage guarantee maintained.",
    "# ============================================================================",
    "import math",
    "import numpy as np",
    "import torch.nn.functional as F",
    "import matplotlib",
    "matplotlib.use('Agg')",
    "import matplotlib.pyplot as plt",
    "",
    "# -- APS helper functions (used here and in conformal cell) ------------------",
    "def aps_scores(sm_probs, true_labels):",
    '    """Compute APS nonconformity scores."""',
    "    n = len(true_labels)",
    "    scores = np.zeros(n, np.float64)",
    "    for i in range(n):",
    "        probs = sm_probs[i]",
    "        si = np.argsort(-probs)",
    "        cs = np.cumsum(probs[si])",
    "        rank = int(np.where(si == true_labels[i])[0][0])",
    "        scores[i] = cs[rank]",
    "    return scores",
    "",
    'CLASS_LABELS = ["safe", "vulnerable"]',
    "",
    "def build_pred_set(probs, threshold):",
    '    """Build a conformal prediction set from softmax probs and threshold."""',
    "    si = np.argsort(-probs)",
    "    cs = np.cumsum(probs[si])",
    "    ps = []",
    "    for j, idx in enumerate(si):",
    "        ps.append(CLASS_LABELS[int(idx)])",
    "        if cs[j] >= threshold: break",
    "    return ps or [CLASS_LABELS[int(si[0])]]",
    "",
    "# -- Collect raw logits from val set ----------------------------------------",
    'alpha = CONFIG["alpha"]',
    "model.eval()",
    "",
    "val_logits_list, val_labels_list = [], []",
    "with torch.no_grad():",
    "    for data in val_loader:",
    "        data = data.to(device)",
    "        logits, _ = model(data.x, data.edge_index, data.batch)",
    "        val_logits_list.append(logits.cpu().numpy())",
    "        val_labels_list.extend(data.y.cpu().tolist())",
    "",
    "val_logits_np = np.concatenate(val_logits_list, axis=0)",
    "val_labels_np = np.array(val_labels_list, dtype=np.int64)",
    "n_val = len(val_labels_np)",
    "",
    "# -- Grid search over temperature T -----------------------------------------",
    "T_candidates = np.concatenate([",
    "    np.arange(0.05, 0.5, 0.05),   # aggressive sharpening",
    "    np.arange(0.5, 1.5, 0.02),    # fine-grained around T=1",
    "    np.arange(1.5, 3.01, 0.1),    # softening",
    "])",
    "",
    "print(f\"{'='*60}\")",
    "print(f\"  ConfTS: Temperature Search ({len(T_candidates)} candidates)\")",
    "print(f\"  alpha={alpha}, val_n={n_val}\")",
    "print(f\"{'='*60}\")",
    "",
    "best_T, best_mean_size = 1.0, 2.0",
    "results_T = []",
    "",
    "for T in T_candidates:",
    "    # Tempered softmax on val set",
    "    scaled = val_logits_np / T",
    "    exp_s = np.exp(scaled - scaled.max(axis=1, keepdims=True))",
    "    val_sm = exp_s / exp_s.sum(axis=1, keepdims=True)",
    "",
    "    # APS scores on val set",
    "    scores_v = aps_scores(val_sm, val_labels_np)",
    "",
    "    # Quantile threshold",
    "    ql = min(math.ceil((n_val + 1) * (1. - alpha)) / n_val, 1.)",
    "    try:",
    '        thr_v = float(np.quantile(scores_v, ql, method="higher"))',
    "    except TypeError:",
    '        thr_v = float(np.quantile(scores_v, ql, interpolation="higher"))',
    "",
    "    # Coverage and set sizes on val set",
    "    covered, singleton, total_size = 0, 0, 0",
    "    for i in range(n_val):",
    "        ps = build_pred_set(val_sm[i], thr_v)",
    "        total_size += len(ps)",
    "        if CLASS_LABELS[val_labels_np[i]] in ps:",
    "            covered += 1",
    "        if len(ps) == 1:",
    "            singleton += 1",
    "",
    "    cov = covered / n_val",
    "    mean_sz = total_size / n_val",
    "    sing_rate = singleton / n_val",
    "",
    "    results_T.append({",
    '        "T": float(T), "coverage": cov, "mean_size": mean_sz,',
    '        "singleton_rate": sing_rate, "threshold": thr_v',
    "    })",
    "",
    "    # Select: must maintain coverage, minimize mean set size",
    "    if cov >= (1 - alpha) and mean_sz < best_mean_size:",
    "        best_T = float(T)",
    "        best_mean_size = mean_sz",
    "",
    "CONFORMAL_TEMPERATURE = best_T",
    'best_row = next(r for r in results_T if abs(r["T"] - best_T) < 0.001)',
    'baseline_row = min(results_T, key=lambda r: abs(r["T"] - 1.0))',
    "",
    'print(f"\\n  Best T = {CONFORMAL_TEMPERATURE:.3f}")',
    "print(f\"  Mean set size: {best_row['mean_size']:.4f}  (T=1.0 baseline: {baseline_row['mean_size']:.4f})\")",
    "print(f\"  Singleton rate: {best_row['singleton_rate']:.1%}  (T=1.0: {baseline_row['singleton_rate']:.1%})\")",
    'print(f"  Coverage: {best_row[\'coverage\']:.4f}  (target >= {1-alpha:.2f})")',
    "",
    "# Show top candidates",
    "print(f\"\\n  {'T':>6} {'Cov':>7} {'MeanSz':>8} {'Single%':>8} {'Thr':>8}\")",
    "print(f\"  {'-'*42}\")",
    'for r in sorted(results_T, key=lambda x: x["mean_size"])[:12]:',
    '    flag = " <--" if abs(r["T"] - CONFORMAL_TEMPERATURE) < 0.001 else ""',
    "    print(f\"  {r['T']:6.3f} {r['coverage']:7.4f} {r['mean_size']:8.4f} \"",
    "          f\"{r['singleton_rate']:7.1%} {r['threshold']:8.4f}{flag}\")",
    "",
    "# Plot",
    "fig, axes = plt.subplots(1, 2, figsize=(14, 5))",
    'Ts = [r["T"] for r in results_T]',
    'axes[0].plot(Ts, [r["mean_size"] for r in results_T], "b-", lw=2, label="Mean set size")',
    'axes[0].axvline(CONFORMAL_TEMPERATURE, color="green", ls="--", lw=2,',
    '                label=f"Best T={CONFORMAL_TEMPERATURE:.3f}")',
    'axes[0].axvline(1.0, color="gray", ls=":", label="T=1.0 (no scaling)")',
    'axes[0].set_xlabel("Temperature T"); axes[0].set_ylabel("Mean Set Size")',
    'axes[0].set_title("ConfTS: Temperature vs Set Size"); axes[0].legend(); axes[0].grid(True, alpha=.3)',
    "",
    'axes[1].plot(Ts, [r["singleton_rate"] for r in results_T], "purple", lw=2, label="Singleton rate")',
    'axes[1].plot(Ts, [r["coverage"] for r in results_T], "r--", lw=1.5, label="Coverage")',
    'axes[1].axhline(1-alpha, color="orange", ls=":", label=f"1-alpha={1-alpha:.2f}")',
    'axes[1].axvline(CONFORMAL_TEMPERATURE, color="green", ls="--", lw=2)',
    'axes[1].set_xlabel("Temperature T"); axes[1].set_title("ConfTS: Singleton Rate & Coverage")',
    'axes[1].legend(); axes[1].grid(True, alpha=.3)',
    'plt.suptitle("Conformal Temperature Scaling (ConfTS, Dabah et al. 2024)", fontsize=14, fontweight="bold")',
    "plt.tight_layout()",
    'plt.savefig(str(OUTPUT_DIR / "confts_temperature_v5.png"), dpi=150)',
    "plt.show()",
    'print(f"\\n  Saved confts_temperature_v5.png")',
]

confts_code = {
    "cell_type": "code",
    "execution_count": None,
    "id": "confts-code",
    "metadata": {},
    "outputs": [],
    "source": "\n".join(confts_src_lines),
}

cells.insert(25, confts_md)
cells.insert(26, confts_code)
fixes.append("Change 3: Inserted ConfTS markdown + code cells at [25-26]")

# After insertion: conformal=[28], export=[30], summary=[32], zip=[34]

# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 4: Conformal cell — use T-scaled softmax
# ═══════════════════════════════════════════════════════════════════════════
src = get_src(cells[28])
assert "Conformal Prediction" in src, f"Wrong cell at [28]"

# Remove duplicate function definitions (now in ConfTS cell)
src = src.replace(
    "def aps_scores(sm_probs, true_labels):\n"
    "    n = len(true_labels)\n"
    "    scores = np.zeros(n, np.float64)\n"
    "    for i in range(n):\n"
    "        probs = sm_probs[i]\n"
    "        si = np.argsort(-probs)\n"
    "        cs = np.cumsum(probs[si])\n"
    "        rank = int(np.where(si == true_labels[i])[0][0])\n"
    "        scores[i] = cs[rank]\n"
    "    return scores\n"
    "\n"
    "def build_pred_set(probs, threshold):\n"
    "    si = np.argsort(-probs)\n"
    "    cs = np.cumsum(probs[si])\n"
    "    ps = []\n"
    "    for j, idx in enumerate(si):\n"
    "        ps.append(CLASS_LABELS[int(idx)])\n"
    "        if cs[j] >= threshold: break\n"
    "    return ps or [CLASS_LABELS[int(si[0])]]",
    "# aps_scores, build_pred_set, CLASS_LABELS defined in ConfTS cell above",
)

# Update header comment
src = src.replace(
    "# V4: alpha=0.1 (90% coverage guarantee, aligned with framework default.yaml).",
    "# V5: alpha=0.1, uses ConfTS temperature scaling for smaller prediction sets.",
)

# Replace raw softmax with T-scaled softmax
src = src.replace(
    "cal_sm.append(F.softmax(logits, dim=-1).cpu().numpy())",
    "# V5: Apply conformal temperature scaling\n"
    "        cal_sm.append(F.softmax(logits / CONFORMAL_TEMPERATURE, dim=-1).cpu().numpy())",
)

# Replace test verification block to use T-scaled softmax
src = src.replace(
    "# Test verification\n"
    "tc, ts, tsz = 0, 0, []\n"
    "for i in range(len(test_labels)):\n"
    "    ps = build_pred_set(test_probs_np[i], conf_threshold)",
    "# Test verification (V5: use T-scaled softmax for test set too)\n"
    "test_sm_t = []\n"
    "with torch.no_grad():\n"
    "    for data in test_loader:\n"
    "        data = data.to(device)\n"
    "        logits, _ = model(data.x, data.edge_index, data.batch)\n"
    "        test_sm_t.append(F.softmax(logits / CONFORMAL_TEMPERATURE, dim=-1).cpu().numpy())\n"
    "test_sm_conformal = np.concatenate(test_sm_t, axis=0)\n"
    "\n"
    "tc, ts, tsz = 0, 0, []\n"
    "for i in range(len(test_labels)):\n"
    "    ps = build_pred_set(test_sm_conformal[i], conf_threshold)",
)

# Add temperature to threshold print
src = src.replace(
    'print(f"  Threshold:    {conf_threshold:.4f}  (V2 was 1.0',
    'print(f"  Temperature:  {CONFORMAL_TEMPERATURE:.4f}  (ConfTS optimized)")\n'
    'print(f"  Threshold:    {conf_threshold:.4f}  (V2 was 1.0',
)

set_src(cells[28], src)
fixes.append("Change 4: Conformal cell uses T-scaled softmax")

# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 5: Export cell — add conformal_temperature
# ═══════════════════════════════════════════════════════════════════════════
src = get_src(cells[30])
assert "Export All Artifacts" in src, f"Wrong cell at [30]"

src = src.replace(
    '"decision_threshold": DECISION_THRESHOLD,',
    '"decision_threshold": DECISION_THRESHOLD,\n    "conformal_temperature": CONFORMAL_TEMPERATURE,',
)
set_src(cells[30], src)
fixes.append("Change 5: Export adds conformal_temperature")

# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 6: Summary cell — fix KeyError + add V5 info
# ═══════════════════════════════════════════════════════════════════════════
src = get_src(cells[32])
assert "Final Summary Report" in src, f"Wrong cell at [32]"

# Fix KeyError
src = src.replace("CONFIG['max_juliet']", "CONFIG['max_juliet_c']")

# Add V5 info before the existing V2->V3 changelog
src = src.replace(
    '  V2 -> V3 changes:',
    '  CONFTS (V5 NEW):\\n"\n'
    '      f"    Temperature: {CONFORMAL_TEMPERATURE:.3f}\\n"\n'
    '      f"\\n"\n'
    '      f"  V4 -> V5 changes:\\n"\n'
    '      f"    Smoothing:  0.1 -> 0.0 (was compressing logit gaps)\\n"\n'
    '      f"    PrimeVul:   Fixed (JSONL direct load)\\n"\n'
    '      f"    VUDENC:     Fixed (list label handling)\\n"\n'
    '      f"    CVEfixes:   Fixed (list label handling)\\n"\n'
    '      f"    ConfTS:     NEW (post-hoc temperature for smaller pred sets)\\n"\n'
    '      f"\\n"\n'
    '      f"  V2 -> V3 changes:',
)

set_src(cells[32], src)
fixes.append("Change 6: Summary fixed KeyError + V5 info")

# ═══════════════════════════════════════════════════════════════════════════
# CHANGE 7: Zip cell — add ConfTS plot
# ═══════════════════════════════════════════════════════════════════════════
src = get_src(cells[34])
assert "zipfile" in src, f"Wrong cell at [34]"

src = src.replace(
    '("conformal_diagnostics_v3.png",',
    '("confts_temperature_v5.png",      "ConfTS temperature search (V5)"),\n    ("conformal_diagnostics_v3.png",',
)
set_src(cells[34], src)
fixes.append("Change 7: Zip includes ConfTS plot")

# ═══════════════════════════════════════════════════════════════════════════
# Clear all outputs
# ═══════════════════════════════════════════════════════════════════════════
for c in cells:
    if c["cell_type"] == "code":
        c["outputs"] = []
        c["execution_count"] = None

# ═══════════════════════════════════════════════════════════════════════════
# Save
# ═══════════════════════════════════════════════════════════════════════════
with open(NB_PATH, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f"Applied {len(fixes)} fixes:")
for fix in fixes:
    print(f"  {fix}")
print(f"\nTotal cells: {len(cells)}")
print("Notebook saved.")
