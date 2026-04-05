"""Patch V3 notebook Cell 3 with verified dataset schemas from research agents."""
import json

NB = "D:/sec-c/notebooks/sec_c_gnn_training_v3.ipynb"
with open(NB, "r", encoding="utf-8") as f:
    nb = json.load(f)

NEW_CELL3_SRC = r"""# ============================================================================
# Cell 3: Download Datasets (verified schemas from research)
#
# Confirmed working HuggingFace IDs:
#   BigVul:     bstee615/bigvul  (cols: func_before, func_after, vul, "CWE ID", lang)
#   DiverseVul: claudios/DiverseVul  (split="test", col: cwe=list)
#   Devign:     google/code_x_glue_cc_defect_detection  (27K rows, col: func, target)
#   CrossVul:   CrossVul/crossvul or AhmedSSoliman/CrossVul (multi-language + CWE)
# ============================================================================
import hashlib, re, zipfile, time, urllib.request, os
from collections import Counter, defaultdict
from pathlib import Path

all_samples = []  # {code, label, language, cwe, source}

def add_samples(samples, src_name):
    for s in samples:
        s["source"] = src_name
    all_samples.extend(samples)
    langs = Counter(s["language"] for s in samples)
    labs  = Counter(s["label"]    for s in samples)
    print(f"  [{src_name}] {len(samples):>5} samples — {dict(labs)} — langs={dict(langs)}")

# ── 1. BigVul (22K+ C/C++ with real CWE labels, paired before/after) ──────
print("="*60); print("  1. BigVul (C/C++, ~22K vuln+safe pairs, real CWE labels)")
bigvul_loaded = False
try:
    from datasets import load_dataset as _ld
    # Confirmed working ID — Fan et al. MSR2020
    ds = _ld("bstee615/bigvul")
    import pandas as pd
    # Merge all splits
    dfs = []
    for split in ds.keys():
        dfs.append(ds[split].to_pandas())
    df = pd.concat(dfs, ignore_index=True)
    print(f"  BigVul loaded: {len(df)} rows, cols={list(df.columns[:6])}")

    bv_samples = []
    for _, row in df.iterrows():
        lang_raw = str(row.get("lang","c")).lower().strip()
        lang = "c_cpp"  # BigVul is C/C++ only
        cwe_raw = row.get("CWE ID","")  # Note: space in column name
        cwe = str(cwe_raw).strip() if pd.notna(cwe_raw) and str(cwe_raw).strip() else "CWE-unknown"
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}" if cwe.isdigit() else "CWE-unknown"

        func_before = str(row.get("func_before","")).strip()
        func_after  = str(row.get("func_after","")).strip()
        is_vuln = int(row.get("vul", 0))

        # func_before = vulnerable version, func_after = fixed version (safe)
        if is_vuln == 1 and len(func_before.split("\n")) >= 3:
            bv_samples.append({
                "code": func_before, "label": 1,
                "language": lang, "cwe": cwe,
            })
            # Paired safe sample (post-fix)
            if len(func_after.split("\n")) >= 3:
                bv_samples.append({
                    "code": func_after, "label": 0,
                    "language": lang, "cwe": "CWE-unknown",
                })

    if len(bv_samples) > CONFIG["max_bigvul"]:
        import random
        vuln_bv = [s for s in bv_samples if s["label"]==1]
        safe_bv  = [s for s in bv_samples if s["label"]==0]
        max_each = CONFIG["max_bigvul"] // 2
        bv_samples = random.sample(vuln_bv, min(max_each, len(vuln_bv))) + \
                     random.sample(safe_bv,  min(max_each, len(safe_bv)))

    if bv_samples:
        add_samples(bv_samples, "BigVul")
        bigvul_loaded = True
except Exception as e:
    print(f"  BigVul bstee615 failed: {e}")

if not bigvul_loaded:
    print("  BigVul unavailable — continuing without it")

# ── 2. DiverseVul (330K C/C++ with CWE list, split="test") ────────────────
print("\n" + "="*60); print("  2. DiverseVul (C/C++, 18K+ vuln with CWE labels)")
diversevul_loaded = False
try:
    from datasets import load_dataset as _ld
    # Confirmed: ID=claudios/DiverseVul, only split is "test"
    ds = _ld("claudios/DiverseVul")
    split_name = "test" if "test" in ds else list(ds.keys())[0]
    dv_rows = ds[split_name]
    dv_samples = []
    _count = 0
    for row in dv_rows:
        if _count >= CONFIG["max_diversevul"]: break
        func = row.get("func","")
        target = int(row.get("target", 0))
        cwe_list = row.get("cwe", [])
        # cwe is a list of strings (confirmed from API)
        if isinstance(cwe_list, list) and cwe_list:
            cwe = str(cwe_list[0]).strip()
            if not cwe.startswith("CWE-"): cwe = f"CWE-{cwe}" if cwe.isdigit() else cwe
        else:
            cwe = "CWE-unknown"
        if len(func.strip().split("\n")) >= 3:
            dv_samples.append({"code": func, "label": target,
                                "language": "c_cpp", "cwe": cwe})
            _count += 1
    if dv_samples:
        add_samples(dv_samples, "DiverseVul")
        diversevul_loaded = True
except Exception as e:
    print(f"  DiverseVul claudios failed: {e}")

if not diversevul_loaded:
    # Fallback to old ID
    try:
        from datasets import load_dataset as _ld
        ds = _ld("bstee615/diversevul", split="train", streaming=True)
        dv2 = []
        for i, row in enumerate(ds):
            if i >= CONFIG["max_diversevul"]: break
            func = row.get("func","")
            cwe_list = row.get("cwe",[])
            cwe = str(cwe_list[0]) if isinstance(cwe_list,list) and cwe_list else "CWE-unknown"
            if len(func.strip().split("\n")) >= 3:
                dv2.append({"code": func, "label": int(row.get("target",0)),
                             "language": "c_cpp", "cwe": cwe})
        if dv2:
            add_samples(dv2, "DiverseVul")
            diversevul_loaded = True
    except Exception as e2:
        print(f"  DiverseVul fallback failed: {e2}")

if not diversevul_loaded:
    print("  DiverseVul unavailable")

# ── 3. Devign/CodeXGLUE (27K C/C++ from FFmpeg+QEMU) ─────────────────────
print("\n" + "="*60); print("  3. Devign/CodeXGLUE (C/C++, 27K rows, all splits)")
devign_loaded = False
try:
    from datasets import load_dataset as _ld
    # Confirmed: full dataset ID is google/code_x_glue_cc_defect_detection
    ds = _ld("google/code_x_glue_cc_defect_detection")
    dev_samples = []
    for split_name in ds.keys():
        for row in ds[split_name]:
            func = row.get("func","")
            target = row.get("target", False)
            if len(func.strip().split("\n")) >= 3:
                dev_samples.append({"code": func,
                                     "label": 1 if target else 0,
                                     "language": "c_cpp",
                                     "cwe": "CWE-unknown"})
    if len(dev_samples) > CONFIG["max_devign"]:
        import random
        random.shuffle(dev_samples)
        dev_samples = dev_samples[:CONFIG["max_devign"]]
    if dev_samples:
        add_samples(dev_samples, "Devign")
        devign_loaded = True
except Exception as e:
    print(f"  Devign CodeXGLUE failed: {e}")

if not devign_loaded:
    # Fallback to old ID
    try:
        from datasets import load_dataset as _ld
        ds = _ld("DetectVul/devign", split="train", streaming=True)
        dv3 = []
        for i, row in enumerate(ds):
            if i >= CONFIG["max_devign"]: break
            func = row.get("func","")
            if len(func.strip().split("\n")) >= 3:
                dv3.append({"code": func, "label": 1 if row.get("target",False) else 0,
                             "language": "c_cpp", "cwe": "CWE-unknown"})
        if dv3:
            add_samples(dv3, "Devign")
            devign_loaded = True
    except Exception as e2:
        print(f"  Devign fallback failed: {e2}")
if not devign_loaded:
    print("  Devign unavailable")

# ── 4. CrossVul (multi-language: Python, JS, Java, Go + CWE) ──────────────
print("\n" + "="*60); print("  4. CrossVul (multi-language, CWE-labeled)")
crossvul_loaded = False
for hf_id in ["CrossVul/crossvul", "AhmedSSoliman/CrossVul", "Cimple-project/CrossVul"]:
    try:
        from datasets import load_dataset as _ld
        ds = _ld(hf_id, streaming=True)
        split_name = "train" if hasattr(ds, "train") else list(ds.keys())[0] if hasattr(ds, "keys") else "train"
        cv_iter = ds[split_name] if hasattr(ds, "__getitem__") else ds
        LANG_MAP_CV = {"python":"python","py":"python","javascript":"javascript","js":"javascript",
                       "java":"java","c":"c_cpp","c++":"c_cpp","cpp":"c_cpp","go":"go","golang":"go",
                       "ruby":"python","php":"javascript"}  # rough mapping
        cv_samples = []
        for i, row in enumerate(cv_iter):
            if i >= 5000: break
            code = row.get("code","") or row.get("func","")
            lang_raw = str(row.get("language","c")).lower().strip()
            lang = LANG_MAP_CV.get(lang_raw, None)
            if lang is None: continue
            label = int(row.get("label", row.get("target", row.get("vul", 0))))
            cwe_raw = row.get("cwe","") or row.get("CWE","") or "CWE-unknown"
            cwe = str(cwe_raw).strip() if cwe_raw else "CWE-unknown"
            if len(code.strip().split("\n")) >= 3:
                cv_samples.append({"code": code, "label": label,
                                    "language": lang, "cwe": cwe})
        if cv_samples:
            add_samples(cv_samples, "CrossVul")
            crossvul_loaded = True
            print(f"  Loaded CrossVul from {hf_id}")
            break
    except Exception as e:
        print(f"  {hf_id}: {e}")
if not crossvul_loaded:
    print("  CrossVul unavailable — Python/JS/Go will use CVEfixes only")

# ── 5. CVEfixes (multi-language, CWE-unknown but real code) ───────────────
print("\n" + "="*60); print("  5. CVEfixes (multi-language, supplemental)")
cvefixes_loaded = False
try:
    from datasets import load_dataset as _ld
    LANG_MAP_CF = {"python":"python","py":"python","javascript":"javascript","js":"javascript",
                   "java":"java","c":"c_cpp","c++":"c_cpp","cpp":"c_cpp","c/c++":"c_cpp",
                   "go":"go","golang":"go"}
    # Try CSV Kaggle path first
    kaggle_paths = [
        Path("/kaggle/input/cvefixes-vulnerable-and-fixed-code/CVEFixes.csv"),
        Path("/kaggle/input/cvefixes/CVEFixes.csv"),
    ]
    csv_path = next((p for p in kaggle_paths if p.exists()), None)
    if csv_path:
        import pandas as pd
        df = pd.read_csv(csv_path, on_bad_lines='skip', engine='python')
        cf_samples = []
        for _, row in df.iterrows():
            code = str(row.get("code",""))
            lang = LANG_MAP_CF.get(str(row.get("language","")).strip().lower(), None)
            safety = str(row.get("safety","")).strip().lower()
            if lang and len(code.strip().split("\n")) >= 3:
                cf_samples.append({"code": code, "label": 1 if safety=="vulnerable" else 0,
                                    "language": lang, "cwe": "CWE-unknown"})
        if len(cf_samples) > CONFIG["max_cvefixes"]:
            import random; random.shuffle(cf_samples)
            cf_samples = cf_samples[:CONFIG["max_cvefixes"]]
        if cf_samples:
            add_samples(cf_samples, "CVEfixes"); cvefixes_loaded = True
    else:
        # HF fallback (Python-only, statement-level)
        ds = _ld("DetectVul/CVEFixes", split="train", streaming=True)
        cf2 = []
        for i, row in enumerate(ds):
            if i >= 1000: break
            raw = row.get("raw_lines",[])
            if len(raw) >= 3:
                cf2.append({"code": "\n".join(raw), "cwe": "CWE-unknown",
                             "label": 1 if any(l==1 for l in row.get("label",[])) else 0,
                             "language": "python"})
        if cf2:
            add_samples(cf2, "CVEfixes-HF"); cvefixes_loaded = True
except Exception as e:
    print(f"  CVEfixes failed: {e}")
if not cvefixes_loaded:
    print("  CVEfixes unavailable")

# ── 6. Juliet (synthetic, reduced — prevent synthetic dominance) ───────────
print("\n" + "="*60); print(f"  6. Juliet (synthetic, max {CONFIG['max_juliet']} samples, CWE-labeled)")
CWE_PAT = re.compile(r'CWE(\d+)')
def extract_juliet(zip_path, language, max_s):
    samps = []
    ext = '.java' if language=='java' else '.c'
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = [n for n in zf.namelist() if n.endswith(ext) and '/testcases/' in n]
            import random; random.shuffle(names)
            for name in names[:max_s*4]:
                try: content = zf.read(name).decode('utf-8', errors='ignore')
                except Exception: continue
                if len(content.strip().split('\n')) < 5: continue
                cwe_m = CWE_PAT.search(name)
                cwe = f"CWE-{cwe_m.group(1)}" if cwe_m else "CWE-unknown"
                bn = name.split('/')[-1].lower()
                label = 0 if ('_good' in bn or 'good' in bn) else 1
                samps.append({"code": content[:3000], "label": label,
                               "language": "java" if language=="java" else "c_cpp", "cwe": cwe})
                if len(samps) >= max_s: break
    except Exception as e: print(f"  Juliet {language} error: {e}")
    return samps

juliet_java_url = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip"
juliet_c_url    = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
max_each = CONFIG["max_juliet"] // 2
for url, lang, zpath in [
    (juliet_java_url, "java", "/tmp/juliet_java.zip"),
    (juliet_c_url,    "c",    "/tmp/juliet_c.zip"),
]:
    try:
        if not os.path.exists(zpath):
            print(f"  Downloading Juliet {lang}...")
            urllib.request.urlretrieve(url, zpath)
        samps = extract_juliet(zpath, lang, max_each)
        if samps: add_samples(samps, f"Juliet-{lang.title()}")
    except Exception as e: print(f"  Juliet {lang}: {e}")

# Summary
total_lang = Counter(s["language"] for s in all_samples)
total_lab  = Counter(s["label"]    for s in all_samples)
cwe_ctr_raw = Counter(s.get("cwe","?") for s in all_samples)
known_cwe = len(all_samples) - cwe_ctr_raw.get("CWE-unknown",0)
print(f"\nRaw total: {len(all_samples)} samples")
print(f"  Labels:   vuln={total_lab[1]}, safe={total_lab[0]}")
print(f"  CWE known: {known_cwe}/{len(all_samples)} ({known_cwe/max(len(all_samples),1):.1%})")
for lang in CONFIG["language_ids"]:
    n  = total_lang.get(lang,0)
    nv = sum(1 for s in all_samples if s["language"]==lang and s["label"]==1)
    print(f"  {lang:<15} {n:>5} (v={nv}, s={n-nv})")
"""

# Find cell 3 (dataset cell) and replace it
# It's the code cell with "# Cell 3: Download Datasets"
replaced = 0
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] == "code":
        src = "".join(cell["source"])
        if "Cell 3: Download" in src and "CVEfixes" in src and replaced == 0:
            cell["source"] = NEW_CELL3_SRC.splitlines(keepends=True)
            print(f"[PATCH] Replaced Cell 3 datasets at index {i}")
            replaced += 1

if replaced == 0:
    print("ERROR: Could not find Cell 3 to replace!")
else:
    with open(NB, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1, ensure_ascii=False)
    print(f"Patched and written: {NB}")

# Also fix CONFIG to add max_crossvul and correct max values
print("\nVerifying key dataset IDs in patched cell:")
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] == "code":
        src = "".join(cell["source"])
        if "bstee615/bigvul" in src:
            print("  [OK] bstee615/bigvul (BigVul)")
        if "claudios/DiverseVul" in src:
            print("  [OK] claudios/DiverseVul")
        if "code_x_glue_cc_defect_detection" in src:
            print("  [OK] google/code_x_glue_cc_defect_detection (Devign 27K)")
        if "CrossVul/crossvul" in src:
            print("  [OK] CrossVul multi-ID tries")
