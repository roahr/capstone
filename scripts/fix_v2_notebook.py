"""Fix sec_c_gnn_training_v2.ipynb with 5 improvements."""
import json

NB = "D:/sec-c/notebooks/sec_c_gnn_training_v2.ipynb"
with open(NB, "r", encoding="utf-8") as f:
    nb = json.load(f)

cells = nb["cells"]


def src(cell):
    return "".join(cell["source"])


def set_src(cell, text):
    cell["source"] = text.splitlines(keepends=True)


# ─── FIX 1: total_mem → total_memory + try/except ─────────────────────────────
OLD_GPU = (
    "# GPU check\n"
    'print("\\n" + "="*60)\n'
    "if torch.cuda.is_available():\n"
    "    gpu_name = torch.cuda.get_device_name(0)\n"
    "    gpu_mem = torch.cuda.get_device_properties(0).total_mem / 1e9\n"
    '    print(f"  GPU: {gpu_name} ({gpu_mem:.1f} GB)")\n'
    "else:\n"
    '    print("  WARNING: No GPU detected! Training will be very slow.")\n'
    'print("="*60)\n'
    "\n"
    'device = torch.device("cuda" if torch.cuda.is_available() else "cpu")\n'
    'print(f"  Device: {device}")'
)

NEW_GPU = (
    "# GPU check\n"
    'print("\\n" + "="*60)\n'
    "try:\n"
    "    if torch.cuda.is_available():\n"
    "        gpu_name = torch.cuda.get_device_name(0)\n"
    "        props = torch.cuda.get_device_properties(0)\n"
    "        gpu_mem = props.total_memory / 1e9  # FIX: total_memory not total_mem\n"
    '        print(f"  GPU: {gpu_name} ({gpu_mem:.1f} GB)")\n'
    "    else:\n"
    '        print("  WARNING: No GPU detected! Training will be very slow.")\n'
    "except Exception as _gpu_err:\n"
    '    print(f"  GPU info unavailable: {_gpu_err}")\n'
    'print("="*60)\n'
    "\n"
    'device = torch.device("cuda" if torch.cuda.is_available() else "cpu")\n'
    'print(f"  Device: {device}")'
)

# ─── FIX 2: append raw-sample checkpoint save to Cell 6 (idx 12) ─────────────
CELL12_APPEND = r"""

# ── Checkpoint: save raw samples so Cell 7 (embedding) can resume ─────────────
import json as _json_ckpt
_raw_ckpt = OUTPUT_DIR / "raw_samples_v2.json"
try:
    with open(str(_raw_ckpt), "w", encoding="utf-8") as _f:
        _json_ckpt.dump(all_samples, _f)
    print(f"\n  [CKPT] Saved {len(all_samples)} raw samples -> {_raw_ckpt}")
except Exception as _e:
    print(f"  [CKPT] Could not save raw samples: {_e}")
"""

# ─── FIX 3a: replace PyG build loop with checkpoint-aware version ─────────────
OLD_BUILD = (
    "print(f\"\\nBuilding PyG dataset ({len(all_samples)} samples)...\")\n"
    "print(f\"  Features: {CONFIG['embedding_dim']} + {CONFIG['node_feature_dim']} = {CONFIG['input_dim']}\")\n"
    "\n"
    "pyg_dataset = []\n"
    "failed = 0\n"
    "for i, sample in enumerate(tqdm(all_samples, desc=\"Building graphs\")):\n"
    "    try:\n"
    "        data = build_pyg_data(sample, CONFIG[\"max_nodes\"])\n"
    "        if data is not None:\n"
    "            pyg_dataset.append(data)\n"
    "        else:\n"
    "            failed += 1\n"
    "    except Exception as e:\n"
    "        failed += 1\n"
    "        if i < 3:\n"
    "            print(f\"  Error {i}: {e}\")\n"
    "\n"
    "print(f\"\\n  Built {len(pyg_dataset)} graphs, {failed} failed\")"
)

NEW_BUILD = r"""# ── Load checkpoint if available (saves 3+ hours of re-embedding) ─────────────
_pyg_ckpt  = OUTPUT_DIR / "pyg_dataset_v2_partial.pt"
_pyg_done  = OUTPUT_DIR / "pyg_dataset_v2.pt"

if _pyg_done.exists():
    pyg_dataset = torch.load(str(_pyg_done), weights_only=False)
    print(f"[CKPT] Loaded complete PyG dataset: {len(pyg_dataset)} graphs from {_pyg_done}")
else:
    # Resume from partial checkpoint if it exists
    if _pyg_ckpt.exists():
        pyg_dataset = torch.load(str(_pyg_ckpt), weights_only=False)
        _start_idx = len(pyg_dataset)
        print(f"[CKPT] Resuming from {_start_idx} already-embedded graphs")
    else:
        pyg_dataset = []
        _start_idx = 0

    print(f"\nBuilding PyG dataset ({len(all_samples)} samples, starting at {_start_idx})...")
    print(f"  Features: {CONFIG['embedding_dim']} + {CONFIG['node_feature_dim']} = {CONFIG['input_dim']}")

    failed = 0
    _SAVE_EVERY = 500  # periodic partial checkpoint every 500 graphs
    for i, sample in enumerate(tqdm(all_samples[_start_idx:], desc="Building graphs",
                                    initial=_start_idx, total=len(all_samples))):
        try:
            data = build_pyg_data(sample, CONFIG["max_nodes"])
            if data is not None:
                pyg_dataset.append(data)
            else:
                failed += 1
        except Exception as e:
            failed += 1
            if i < 3:
                print(f"  Error {_start_idx+i}: {e}")

        # Periodic save so a crash doesn't lose everything
        if len(pyg_dataset) > 0 and len(pyg_dataset) % _SAVE_EVERY == 0:
            try:
                torch.save(pyg_dataset, str(_pyg_ckpt))
            except Exception:
                pass  # don't let a save failure abort embedding

    print(f"\n  Built {len(pyg_dataset)} graphs, {failed} failed")"""

# ─── FIX 3b: replace single-path dataset save with versioned + legacy ─────────
OLD_SAVE = (
    "torch.save(pyg_dataset, str(OUTPUT_DIR / \"juliet_graphs_v2.pt\"))\n"
    "print(f\"  Saved {len(pyg_dataset)} graphs\")"
)

NEW_SAVE = r"""# Save final dataset (versioned name + legacy alias)
for _ds_path in [OUTPUT_DIR / "pyg_dataset_v2.pt",
                 OUTPUT_DIR / "juliet_graphs_v2.pt"]:
    try:
        torch.save(pyg_dataset, str(_ds_path))
        print(f"  [CKPT] Saved {len(pyg_dataset)} graphs -> {_ds_path}")
    except Exception as _sv_err:
        print(f"  [CKPT] Save failed ({_ds_path}): {_sv_err}")
# Remove partial checkpoint now that the full dataset is safe
try:
    if _pyg_ckpt.exists():
        _pyg_ckpt.unlink()
        print(f"  [CKPT] Removed partial checkpoint")
except Exception:
    pass"""

# ─── FIX 4: per-epoch checkpoint during training ──────────────────────────────
OLD_EPOCH = (
    "    else:\n"
    "        patience_ctr += 1\n"
    "    lr = optimizer.param_groups[0]['lr']\n"
    "    if epoch % 5 == 0 or epoch <= 3 or improved:"
)

NEW_EPOCH = (
    "    else:\n"
    "        patience_ctr += 1\n"
    "    lr = optimizer.param_groups[0]['lr']\n"
    "    # Periodic checkpoint every 10 epochs + on best\n"
    "    if improved or epoch % 10 == 0:\n"
    "        try:\n"
    "            _ep_ckpt = OUTPUT_DIR / f\"mini_gat_v2_epoch{epoch:03d}.pt\"\n"
    "            torch.save(model.state_dict(), str(_ep_ckpt))\n"
    "            # Prune old periodic checkpoints (keep last 2)\n"
    "            if epoch % 10 == 0 and epoch > 20 and not improved:\n"
    "                _old_ep = OUTPUT_DIR / f\"mini_gat_v2_epoch{epoch-20:03d}.pt\"\n"
    "                if _old_ep.exists():\n"
    "                    _old_ep.unlink()\n"
    "        except Exception:\n"
    "            pass  # never let checkpoint failure abort training\n"
    "    if epoch % 5 == 0 or epoch <= 3 or improved:"
)

# ─── FIX 5: v2 suffix on export files ────────────────────────────────────────
OLD_CAL = 'cal_path = OUTPUT_DIR / "conformal_calibration.json"'
NEW_CAL = 'cal_path = OUTPUT_DIR / "conformal_calibration_v2.json"'

OLD_CFG_BLOCK = (
    'config_path = OUTPUT_DIR / "graph_config.json"\n'
    "with open(str(config_path), \"w\") as f:\n"
    "    json.dump(graph_config, f, indent=2)\n"
    'print(f"3. Config:      {config_path}")'
)
NEW_CFG_BLOCK = (
    'config_path = OUTPUT_DIR / "graph_config_v2.json"\n'
    "with open(str(config_path), \"w\") as f:\n"
    "    json.dump(graph_config, f, indent=2)\n"
    'print(f"3. Config:      {config_path}")\n'
    "# Legacy aliases for backward compatibility\n"
    "import shutil as _shutil\n"
    "for _alias in [\"conformal_calibration.json\", \"graph_config.json\"]:\n"
    "    _alias_src = OUTPUT_DIR / _alias.replace(\".json\", \"_v2.json\")\n"
    "    _alias_dst = OUTPUT_DIR / _alias\n"
    "    if _alias_src.exists() and not _alias_dst.exists():\n"
    "        try: _shutil.copy(str(_alias_src), str(_alias_dst))\n"
    "        except Exception: pass"
)

# ─── Apply all fixes ──────────────────────────────────────────────────────────
changes = 0
for idx, cell in enumerate(cells):
    if cell["cell_type"] != "code":
        continue
    s = src(cell)

    if OLD_GPU in s:
        s = s.replace(OLD_GPU, NEW_GPU)
        print(f"[Fix 1] Cell {idx}: total_mem -> total_memory + try/except")
        changes += 1

    if idx == 12 and "build_code_graph" in s and "raw_samples_v2.json" not in s:
        s = s + CELL12_APPEND
        print(f"[Fix 2] Cell {idx}: appended raw-sample checkpoint save")
        changes += 1

    if OLD_BUILD in s:
        s = s.replace(OLD_BUILD, NEW_BUILD)
        print(f"[Fix 3a] Cell {idx}: checkpoint-aware PyG build loop")
        changes += 1

    if OLD_SAVE in s:
        s = s.replace(OLD_SAVE, NEW_SAVE)
        print(f"[Fix 3b] Cell {idx}: versioned dataset save")
        changes += 1

    if OLD_EPOCH in s:
        s = s.replace(OLD_EPOCH, NEW_EPOCH)
        print(f"[Fix 4] Cell {idx}: per-epoch checkpoint")
        changes += 1

    if OLD_CAL in s:
        s = s.replace(OLD_CAL, NEW_CAL)
        print(f"[Fix 5a] Cell {idx}: conformal_calibration.json -> _v2")
        changes += 1

    if OLD_CFG_BLOCK in s:
        s = s.replace(OLD_CFG_BLOCK, NEW_CFG_BLOCK)
        print(f"[Fix 5b] Cell {idx}: graph_config.json -> _v2")
        changes += 1

    set_src(cell, s)

print(f"\nTotal changes: {changes}")

with open(NB, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print("Notebook written.")
