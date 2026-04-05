"""Generate sec_c_gnn_training_v3.ipynb with all V2 shortcomings fixed."""
import json

def cell(source: str, cell_type: str = "code") -> dict:
    base = {"cell_type": cell_type, "metadata": {}, "source": source.lstrip("\n")}
    if cell_type == "code":
        base["outputs"] = []
        base["execution_count"] = None
    return base

def md(source: str) -> dict:
    return cell(source, "markdown")

cells = []

# ─── HEADER ────────────────────────────────────────────────────────────────
cells.append(md("""# SEC-C Mini-GAT V3 GNN Training Notebook

**Root-cause fixes over V2:**

| Problem (V2) | Fix (V3) |
|---|---|
| Focal(γ=2) → predict-all-vulnerable | Standard CE + label smoothing + F1-optimal threshold |
| Best epoch=3, training 1.1 min | LR=3e-4, 5-epoch warmup, patience=25 |
| Java 5.9:1 / C++ 2.5:1 imbalance | Strict per-language 1:1 balance |
| Conformal threshold=1.0 (100% ambiguous) | F1-threshold calibration → then conformal APS |
| 2-layer GAT, 298K params, shallow | 3-layer GIN + residual + BN, 1.5M params |
| Regex-only graphs (noisy) | tree-sitter real AST + regex fallback |
| 61% CWE-unknown labels | + BigVul (11K C/C++ with CWE IDs) |

**Architecture:** MiniGINv3 — Graph Isomorphism Network (Xu et al. 2019), 3 layers, batch-norm, residual, dual pooling
"""))

# ─── CELL 1: SETUP ─────────────────────────────────────────────────────────
cells.append(md("## Cell 1: Setup & Install"))
cells.append(cell(r"""# ============================================================================
# Cell 1: Setup & Install
# ============================================================================
import subprocess, sys, os

def run_cmd(cmd, label=""):
    print(f"$ {label or cmd[:80]}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.stdout.strip():
        print(r.stdout.strip()[-400:])
    if r.returncode != 0 and r.stderr.strip():
        print(f"  WARN: {r.stderr.strip()[-200:]}")
    return r.returncode

import torch
tv = torch.__version__.split('+')[0]
ctag = torch.version.cuda.replace('.', '') if torch.cuda.is_available() else 'cpu'
print(f"PyTorch: {tv}, CUDA: {ctag}")

# PyG
pyg_url = f"https://data.pyg.org/whl/torch-{tv}+cu{ctag}.html"
run_cmd(f"{sys.executable} -m pip install -q torch-scatter torch-sparse torch-cluster -f {pyg_url}", "install pyg deps")
run_cmd(f"{sys.executable} -m pip install -q torch-geometric", "install torch-geometric")
run_cmd(f"{sys.executable} -m pip install -q transformers datasets scikit-learn matplotlib networkx tqdm", "install utils")

# tree-sitter (real AST parsing)
try:
    run_cmd(f"{sys.executable} -m pip install -q 'tree-sitter>=0.22' tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-c tree-sitter-go", "install tree-sitter")
    import tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_c, tree_sitter_go
    from tree_sitter import Language, Parser
    _TS_LANGS = {
        "python":     Language(tree_sitter_python.language()),
        "javascript": Language(tree_sitter_javascript.language()),
        "java":       Language(tree_sitter_java.language()),
        "c_cpp":      Language(tree_sitter_c.language()),
        "go":         Language(tree_sitter_go.language()),
    }
    USE_TREE_SITTER = True
    print("  tree-sitter: OK")
except Exception as _ts_err:
    USE_TREE_SITTER = False
    _TS_LANGS = {}
    print(f"  tree-sitter: unavailable ({_ts_err}) — using regex fallback")

# GPU check
print("\n" + "="*60)
try:
    if torch.cuda.is_available():
        props = torch.cuda.get_device_properties(0)
        gpu_mem = props.total_memory / 1e9
        print(f"  GPU: {torch.cuda.get_device_name(0)} ({gpu_mem:.1f} GB)")
    else:
        print("  WARNING: No GPU — training will be very slow.")
except Exception as e:
    print(f"  GPU info unavailable: {e}")
print("="*60)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"  Device: {device}")
"""))

# ─── CELL 2: CONFIG ────────────────────────────────────────────────────────
cells.append(md("## Cell 2: Configuration"))
cells.append(cell(r"""# ============================================================================
# Cell 2: Configuration — all hyperparameters in one place
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
    # Model
    "embedding_model": "microsoft/graphcodebert-base",
    "embedding_dim": 768,
    "node_feature_dim": 6,
    "input_dim": 774,           # 768 + 6
    "hidden_dim": 384,          # V3: 384 (was 256)
    "num_gin_layers": 3,        # V3: GIN not GAT
    "dropout": 0.4,             # V3: 0.4 (was 0.3)
    "num_classes": 2,

    # Data
    "max_nodes": 300,
    "max_tokens_per_node": 128,
    "embedding_batch_size": 64,
    "target_balance_ratio": 1.0,    # V3: STRICT 1:1 (was 2.0)
    "max_per_language": 2000,        # cap per language
    "min_per_language": 200,         # minimum per language
    "max_bigvul": 4000,              # limit BigVul C/C++ samples
    "max_diversevul": 3000,
    "max_devign": 2000,
    "max_cvefixes": 5000,
    "max_juliet": 300,               # V3: reduced from 1000 (prevent synthetic dominance)

    # Training
    "batch_size": 64,               # V3: 64 (was 32)
    "epochs": 100,                  # V3: 100 (was 60)
    "lr": 3e-4,                     # V3: 3e-4 (was 1e-3)
    "lr_warmup_epochs": 5,          # V3: linear warmup
    "weight_decay": 1e-3,           # V3: 1e-3 (was 1e-4)
    "patience": 25,                 # V3: 25 (was 15)
    "label_smoothing": 0.1,         # V3: smoothing to prevent overconfidence
    "grad_clip": 1.0,
    "class_weight_vuln": 1.5,       # V3: mild vuln weight (not inverse freq)
    # NO focal loss in V3 — it caused predict-all-vulnerable collapse in V2

    # Conformal
    "alpha": 0.2,                   # V3: tighter (was 0.3)
    "threshold_search_steps": 81,   # V3: F1-optimal threshold search

    # Splits
    "train_ratio": 0.60,
    "val_ratio": 0.15,
    "cal_ratio": 0.15,
    "test_ratio": 0.10,

    # Language ids (feature value for language_id node feature)
    "language_ids": {
        "python": 0.0, "javascript": 0.2, "java": 0.4,
        "c_cpp": 0.6, "go": 0.8,
    },
}

# Sink/source patterns (same as V2)
SINK_PATTERNS = [
    "execute","exec","system","popen","runtime","processbuilder",
    "sendredirect","forward","include","write","print","println",
    "printf","sprintf","fprintf","strcpy","strcat","memcpy",
    "gets","scanf","fscanf","sscanf","fread","recv",
    "malloc","calloc","realloc","free",
    "fopen","open","connect","bind","listen","accept",
    "eval","innerhtml","document.write","setattribute",
    "preparestatement","createquery","executequery","executeupdate",
    "subprocess","os.system","os.popen","pickle.loads","yaml.load",
    "cursor.execute","render_template_string",
    "child_process","vm.runinnewcontext","res.send","res.write",
    "exec.command","db.query","db.exec","fmt.fprintf",
]
SOURCE_PATTERNS = [
    "request","getparameter","getquerystring","getheader",
    "getinputstream","getreader","getcookies","getpathinfo",
    "input","argv","stdin","environ","getenv",
    "args","fgets","fread","recv","recvfrom",
    "read","readline","readlines","scanner",
    "bufferedreader","fileinputstream","socket",
    "urlconnection","httpservletrequest",
    "flask.request","django.request","sys.argv","os.environ",
    "req.body","req.params","req.query","process.env","process.argv",
    "r.formvalue","r.url.query","os.args","r.body",
]

OUTPUT_DIR = Path("/kaggle/working")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
print("Configuration loaded.")
print(f"  Architecture: MiniGINv3, {CONFIG['num_gin_layers']}-layer GIN, hidden={CONFIG['hidden_dim']}")
print(f"  Training: LR={CONFIG['lr']}, warmup={CONFIG['lr_warmup_epochs']}ep, patience={CONFIG['patience']}")
print(f"  Balance: {CONFIG['target_balance_ratio']}:1 (strict per-language)")
print(f"  Loss: CE + label_smoothing={CONFIG['label_smoothing']} (no focal loss)")
"""))

# ─── CELL 3: DATASETS ──────────────────────────────────────────────────────
cells.append(md("## Cell 3: Download Multi-Language Datasets"))
cells.append(cell(r"""# ============================================================================
# Cell 3: Download Datasets (CVEfixes + DiverseVul + Devign + BigVul + Juliet)
# ============================================================================
import hashlib, re, zipfile, time, urllib.request
from collections import Counter, defaultdict

all_samples = []  # {code, label, language, cwe, source}

def add_samples(samples, src_name):
    for s in samples:
        s["source"] = src_name
    all_samples.extend(samples)
    langs = Counter(s["language"] for s in samples)
    labs = Counter(s["label"] for s in samples)
    print(f"  [{src_name}] {len(samples)} samples — {dict(labs)} — langs={dict(langs)}")

# ── 1. CVEfixes ────────────────────────────────────────────────────────────
print("="*60); print("  1. CVEfixes (multi-language)")
cvefixes_loaded = False
try:
    import pandas as pd
    kaggle_paths = [
        Path("/kaggle/input/cvefixes-vulnerable-and-fixed-code/CVEFixes.csv"),
        Path("/kaggle/input/cvefixes/CVEFixes.csv"),
    ]
    csv_path = next((p for p in kaggle_paths if p.exists()), None)
    if csv_path is None:
        from datasets import load_dataset as _ld
        print("  Trying HuggingFace DetectVul/CVEFixes...")
        ds = _ld("DetectVul/CVEFixes", split="train", streaming=True)
        hf_s = []
        for i, row in enumerate(ds):
            if i >= CONFIG["max_cvefixes"]: break
            raw = row.get("raw_lines", [])
            if len(raw) >= 3:
                hf_s.append({"code": "\n".join(raw), "label": 1 if any(l==1 for l in row.get("label",[])) else 0,
                              "language": "python", "cwe": "CWE-unknown"})
        if hf_s:
            add_samples(hf_s, "CVEfixes-HF"); cvefixes_loaded = True
    else:
        lang_map = {"python":"python","py":"python","javascript":"javascript","js":"javascript",
                    "java":"java","c":"c_cpp","c++":"c_cpp","cpp":"c_cpp","c/c++":"c_cpp","go":"go","golang":"go"}
        df = pd.read_csv(csv_path, on_bad_lines='skip', engine='python')
        samps = []
        for _, row in df.iterrows():
            code = str(row.get("code",""))
            lang = lang_map.get(str(row.get("language","")).strip().lower(), None)
            safety = str(row.get("safety","")).strip().lower()
            if lang and len(code.strip().split("\n")) >= 3:
                samps.append({"code": code, "label": 1 if safety=="vulnerable" else 0,
                               "language": lang, "cwe": "CWE-unknown"})
        if len(samps) > CONFIG["max_cvefixes"]:
            random.shuffle(samps); samps = samps[:CONFIG["max_cvefixes"]]
        if samps:
            add_samples(samps, "CVEfixes"); cvefixes_loaded = True
except Exception as e:
    print(f"  CVEfixes failed: {e}")
if not cvefixes_loaded:
    print("  CVEfixes unavailable")

# ── 2. DiverseVul ──────────────────────────────────────────────────────────
print("\n" + "="*60); print("  2. DiverseVul (C/C++, has CWE labels)")
diversevul_loaded = False
try:
    from datasets import load_dataset as _ld
    ds = _ld("bstee615/diversevul", split="train", streaming=True)
    dv = []
    for i, row in enumerate(ds):
        if i >= CONFIG["max_diversevul"]: break
        func = row.get("func","")
        cwe_list = row.get("cwe",[])
        cwe = str(cwe_list[0]) if cwe_list else "CWE-unknown"
        if len(func.strip().split("\n")) >= 3:
            dv.append({"code": func, "label": int(row.get("target",0)),
                       "language": "c_cpp", "cwe": cwe})
    if dv:
        add_samples(dv, "DiverseVul"); diversevul_loaded = True
except Exception as e:
    print(f"  DiverseVul HF failed: {e}")
if not diversevul_loaded:
    print("  DiverseVul unavailable")

# ── 3. Devign ──────────────────────────────────────────────────────────────
print("\n" + "="*60); print("  3. Devign (C/C++)")
try:
    from datasets import load_dataset as _ld
    ds = _ld("DetectVul/devign", split="train", streaming=True)
    dev = []
    for i, row in enumerate(ds):
        if i >= CONFIG["max_devign"]: break
        func = row.get("func","")
        if len(func.strip().split("\n")) >= 3:
            dev.append({"code": func, "label": 1 if row.get("target",False) else 0,
                        "language": "c_cpp", "cwe": "CWE-unknown"})
    if dev:
        add_samples(dev, "Devign")
except Exception as e:
    print(f"  Devign failed: {e}")

# ── 4. BigVul (NEW in V3 — has CWE labels for C/C++) ──────────────────────
print("\n" + "="*60); print("  4. BigVul (C/C++ + Java, CWE labels)")
bigvul_loaded = False
try:
    from datasets import load_dataset as _ld
    # Try multiple known HuggingFace identifiers
    for hf_id in ["CGCL-CODES/BigVul", "liuyedong/BigVul", "VulnCode/BigVul"]:
        try:
            ds = _ld(hf_id, split="train", streaming=True)
            bv = []
            for i, row in enumerate(ds):
                if i >= CONFIG["max_bigvul"]: break
                code = row.get("func","") or row.get("code","")
                cwe_raw = row.get("CWE ID","") or row.get("cwe","CWE-unknown")
                cwe = str(cwe_raw).strip() if cwe_raw else "CWE-unknown"
                if not cwe.startswith("CWE-"):
                    cwe = f"CWE-{cwe}" if cwe.isdigit() else "CWE-unknown"
                label = int(row.get("vul",row.get("target",row.get("label",0))))
                lang_raw = str(row.get("lang","c")).lower()
                lang = "java" if "java" in lang_raw else "c_cpp"
                if len(code.strip().split("\n")) >= 3:
                    bv.append({"code": code, "label": label, "language": lang, "cwe": cwe})
            if bv:
                add_samples(bv, "BigVul"); bigvul_loaded = True
                break
        except Exception:
            continue
    if not bigvul_loaded:
        raise RuntimeError("No BigVul variant found on HuggingFace")
except Exception as e:
    print(f"  BigVul unavailable: {e}")

# ── 5. Juliet (reduced to prevent synthetic dominance) ─────────────────────
print("\n" + "="*60); print("  5. Juliet (Java + C/C++, REDUCED to avoid synthetic bias)")
CWE_PAT = re.compile(r'CWE(\d+)')
def extract_juliet(zip_path, language, max_s=150):
    samps = []
    ext = '.java' if language=='java' else '.c'
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = [n for n in zf.namelist() if n.endswith(ext) and '/testcases/' in n]
            random.shuffle(names)
            for name in names[:max_s*4]:
                try:
                    content = zf.read(name).decode('utf-8', errors='ignore')
                except Exception:
                    continue
                if len(content.strip().split('\n')) < 5: continue
                cwe_m = CWE_PAT.search(name)
                cwe = f"CWE-{cwe_m.group(1)}" if cwe_m else "CWE-unknown"
                bn = name.split('/')[-1].lower()
                label = 0 if '_good' in bn or 'good' in bn else 1
                lang_tag = "java" if language=="java" else "c_cpp"
                samps.append({"code": content[:3000], "label": label,
                               "language": lang_tag, "cwe": cwe})
                if len(samps) >= max_s: break
    except Exception as e:
        print(f"  Juliet extract error ({language}): {e}")
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
        if samps:
            add_samples(samps, f"Juliet-{lang.title()}")
    except Exception as e:
        print(f"  Juliet {lang} failed: {e}")

# Summary
total_lang = Counter(s["language"] for s in all_samples)
total_lab  = Counter(s["label"]    for s in all_samples)
print(f"\nRaw total: {len(all_samples)} samples")
print(f"  Labels: vuln={total_lab[1]}, safe={total_lab[0]}")
for lang in CONFIG["language_ids"]:
    n = total_lang[lang]
    nv = sum(1 for s in all_samples if s["language"]==lang and s["label"]==1)
    ns = n - nv
    print(f"  {lang:<15} {n:>5} (v={nv}, s={ns})")
"""))

# ─── CELL 4: STRICT BALANCE ────────────────────────────────────────────────
cells.append(md("## Cell 4: Strict 1:1 Per-Language Balance (V3 key fix)"))
cells.append(cell(r"""# ============================================================================
# Cell 4: Strict Per-Language 1:1 Balance
# V2 bug: Java was 5.9:1 safe:vuln; balancer only capped over-representation.
# V3 fix: oversample minority to achieve strict 1:1 within each language.
# ============================================================================
import hashlib
from collections import defaultdict

print("="*60)
print("  V3 Strict 1:1 Per-Language Balancing")
print("="*60)

# 1. Deduplicate by content hash
seen_hashes = set()
deduped = []
for s in all_samples:
    h = hashlib.md5(s["code"].encode("utf-8", errors="ignore")).hexdigest()
    if h not in seen_hashes:
        seen_hashes.add(h)
        deduped.append(s)
print(f"\n1. Dedup: {len(all_samples)} -> {len(deduped)}")
all_samples = deduped

# 2. Filter too-short samples
all_samples = [s for s in all_samples if len(s["code"].strip().split("\n")) >= 3]
print(f"2. Length filter: {len(all_samples)} samples remain")

# 3. Strict 1:1 balance per language
by_lang_label = defaultdict(list)
for s in all_samples:
    by_lang_label[(s["language"], s["label"])].append(s)

balanced = []
print("\n3. Per-language 1:1 balance:")
print(f"   {'Lang':<15} {'Vuln':>6} {'Safe':>6} {'Total':>6}  Action")
print(f"   {'-'*55}")

for lang in CONFIG["language_ids"]:
    vuln_s = by_lang_label[(lang, 1)][:]
    safe_s = by_lang_label[(lang, 0)][:]

    if not vuln_s and not safe_s:
        print(f"   {lang:<15} {'N/A':>6}  -- skipped")
        continue

    max_each = min(
        max(len(vuln_s), len(safe_s)),  # don't shrink more than necessary
        CONFIG["max_per_language"] // 2,
    )
    # Ensure minimum
    if max_each < CONFIG["min_per_language"] // 2:
        max_each = CONFIG["min_per_language"] // 2

    # Actual target: min of available in each class (1:1 strict)
    target = min(max_each, max(len(vuln_s), 1), max(len(safe_s), 1))
    # Ensure both sides have at least min
    target = max(target, min(CONFIG["min_per_language"] // 2, len(vuln_s), len(safe_s)) if (vuln_s and safe_s) else 0)

    if not vuln_s or not safe_s:
        # One side completely missing — skip
        print(f"   {lang:<15} {len(vuln_s):>6} {len(safe_s):>6}  -- one class missing, skip")
        continue

    # Oversample minority / undersample majority
    target = min(target, CONFIG["max_per_language"] // 2)

    if len(vuln_s) < target:
        vuln_bal = random.choices(vuln_s, k=target)   # oversample with replacement
        action_v = f"over({len(vuln_s)}->{target})"
    else:
        vuln_bal = random.sample(vuln_s, target)
        action_v = f"under({len(vuln_s)}->{target})" if len(vuln_s) > target else "ok"

    if len(safe_s) < target:
        safe_bal = random.choices(safe_s, k=target)
        action_s = f"over({len(safe_s)}->{target})"
    else:
        safe_bal = random.sample(safe_s, target)
        action_s = f"under({len(safe_s)}->{target})" if len(safe_s) > target else "ok"

    balanced.extend(vuln_bal + safe_bal)
    print(f"   {lang:<15} {target:>6} {target:>6} {target*2:>6}  v:{action_v} s:{action_s}")

random.shuffle(balanced)
all_samples = balanced

total_v = sum(1 for s in all_samples if s["label"]==1)
total_s = sum(1 for s in all_samples if s["label"]==0)
print(f"\n   Final: {len(all_samples)} samples — vuln={total_v}, safe={total_s}, ratio={total_v/max(total_s,1):.2f}:1")

# CWE coverage after balance
cwe_ctr = Counter(s.get("cwe","?") for s in all_samples)
known = len(all_samples) - cwe_ctr.get("CWE-unknown", 0)
print(f"   CWE labels known: {known}/{len(all_samples)} ({known/max(len(all_samples),1):.1%})")

# Save balanced raw samples checkpoint
import json as _j
_raw_ckpt = OUTPUT_DIR / "raw_samples_v3.json"
try:
    with open(str(_raw_ckpt), "w", encoding="utf-8") as _f:
        _j.dump(all_samples, _f)
    print(f"\n   [CKPT] raw_samples_v3.json saved ({len(all_samples)} samples)")
except Exception as _e:
    print(f"   [CKPT] save failed: {_e}")
"""))

# ─── CELL 5: EDA ───────────────────────────────────────────────────────────
cells.append(md("## Cell 5: Exploratory Data Analysis"))
cells.append(cell(r"""# ============================================================================
# Cell 5: Exploratory Data Analysis
# ============================================================================
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from collections import Counter

print("="*70)
print(f"  {'Language':<15} {'Total':>7} {'Vuln':>7} {'Safe':>7} {'Ratio':>8}")
print("  " + "-"*55)
lang_stats = {}
for lang in CONFIG["language_ids"]:
    subs = [s for s in all_samples if s["language"]==lang]
    nv = sum(1 for s in subs if s["label"]==1)
    ns = len(subs) - nv
    ratio = nv/max(ns,1)
    lang_stats[lang] = {"total": len(subs), "vuln": nv, "safe": ns, "ratio": ratio}
    print(f"  {lang:<15} {len(subs):>7} {nv:>7} {ns:>7} {ratio:>7.2f}:1")
print("  " + "-"*55)
tot = len(all_samples)
tv_ = sum(1 for s in all_samples if s["label"]==1)
ts_ = tot - tv_
print(f"  {'TOTAL':<15} {tot:>7} {tv_:>7} {ts_:>7} {tv_/max(ts_,1):>7.2f}:1")
print("="*70)

src_ctr = Counter(s.get("source","?") for s in all_samples)
print("\nSource distribution:")
for src, n in src_ctr.most_common():
    print(f"  {src:<25} {n:>5}")

cwe_ctr2 = Counter(s.get("cwe","?") for s in all_samples)
print(f"\nTop 10 CWEs:")
for cwe, n in cwe_ctr2.most_common(10):
    print(f"  {cwe:<20} {n:>5}")

fig, axes = plt.subplots(1, 3, figsize=(18, 5))
langs_ = [l for l in CONFIG["language_ids"] if lang_stats.get(l,{}).get("total",0)>0]
v_counts = [lang_stats[l]["vuln"] for l in langs_]
s_counts = [lang_stats[l]["safe"] for l in langs_]
x_ = range(len(langs_))
axes[0].bar(x_, v_counts, label="Vulnerable", color="#e74c3c", alpha=.8)
axes[0].bar(x_, s_counts, bottom=v_counts, label="Safe", color="#2ecc71", alpha=.8)
axes[0].set_xticks(list(x_)); axes[0].set_xticklabels(langs_, rotation=20)
axes[0].set_title("Per-Language Balance"); axes[0].legend()
axes[1].bar([c for c,_ in cwe_ctr2.most_common(12)], [n for _,n in cwe_ctr2.most_common(12)], color="#3498db")
axes[1].set_xticklabels([c for c,_ in cwe_ctr2.most_common(12)], rotation=45, ha='right')
axes[1].set_title("Top-12 CWEs")
lens = [len(s["code"].split("\n")) for s in all_samples]
axes[2].hist(lens, bins=40, color="#9b59b6", alpha=.7, edgecolor="black")
axes[2].set_title("Code Length Distribution (lines)"); axes[2].set_xlabel("Lines")
plt.suptitle("V3 Dataset Overview", fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(str(OUTPUT_DIR / "eda_overview_v3.png"), dpi=150)
plt.show()
print("EDA complete.")
"""))

# ─── CELL 6: GRAPH BUILD ───────────────────────────────────────────────────
cells.append(md("## Cell 6: Build Code Graphs (tree-sitter AST + regex CFG/DDG fallback)"))
cells.append(cell(r"""# ============================================================================
# Cell 6: Build Code Graphs
# V3: tree-sitter for real AST node extraction, regex for CFG/DDG edges.
# Falls back to pure regex if tree-sitter unavailable.
# ============================================================================
import networkx as nx, re
from collections import Counter

BRANCH_KW = {
    "python":     re.compile(r'^\s*(if|elif|else|for|while|try|except|finally|with|def|class|async)\b'),
    "javascript": re.compile(r'^\s*(if|else|for|while|do|switch|case|try|catch|finally|function|async|class)\b'),
    "java":       re.compile(r'^\s*(if|else|for|while|do|switch|case|try|catch|finally|class|public|private|protected)\b'),
    "c_cpp":      re.compile(r'^\s*(if|else|for|while|do|switch|case|goto|struct|typedef)\b'),
    "go":         re.compile(r'^\s*(if|else|for|switch|case|select|func|go|defer|type)\b'),
}
RETURN_KW = re.compile(r'^\s*(return|raise|throw|panic|break|continue|goto)\b')
VAR_DEF   = re.compile(r'(\b[a-zA-Z_]\w*)\s*(?:=|:=|<-)')
SKIP_VARS = {'if','for','while','return','else','self','this','true','false',
             'nil','null','None','var','let','const','int','string','bool'}

def get_indent(line):
    s = line.lstrip()
    return len(line) - len(s) if s else 0

def _extract_ts_nodes(code: str, language: str):
    # Use tree-sitter to get meaningful AST nodes (statements, expressions).
    if not USE_TREE_SITTER or language not in _TS_LANGS:
        return None
    try:
        parser = Parser(_TS_LANGS[language])
        tree = parser.parse(bytes(code, "utf-8"))
        INTERESTING = {
            "function_definition","function_declaration","method_declaration",
            "if_statement","for_statement","while_statement","return_statement",
            "expression_statement","assignment","call_expression","call",
            "variable_declaration","local_variable_declaration",
            "try_statement","catch_clause","block",
        }
        nodes_text = []
        def walk(node):
            if node.type in INTERESTING:
                text = code[node.start_byte:node.end_byte][:200].replace("\n"," ").strip()
                if text:
                    nodes_text.append(text)
            for child in node.children:
                walk(child)
        walk(tree.root_node)
        return nodes_text[:CONFIG["max_nodes"]] if nodes_text else None
    except Exception:
        return None

def build_code_graph(code: str, language: str) -> nx.DiGraph:
    G = nx.DiGraph()
    # Try tree-sitter first
    ts_nodes = _extract_ts_nodes(code, language)
    if ts_nodes:
        for i, text in enumerate(ts_nodes):
            G.add_node(i, text=text, indent=0)
        # Sequential AST edges + skip connections
        for i in range(len(ts_nodes)-1):
            G.add_edge(i, i+1, type="ast")
        for i in range(len(ts_nodes)-2):
            G.add_edge(i, i+2, type="ast_skip")
        # DDG: simple variable def-use within window
        VAR_DEF2 = re.compile(r'\b([a-zA-Z_]\w*)\s*(?:=|:=)')
        def_sites = {}
        for i, text in enumerate(ts_nodes):
            for var in VAR_DEF2.findall(text):
                if var not in SKIP_VARS:
                    def_sites[var] = i
            for var, def_i in def_sites.items():
                if var in text and def_i != i and abs(i-def_i) <= 5:
                    G.add_edge(def_i, i, type="ddg")
        return G

    # Regex fallback (same as V2)
    lines = code.split('\n')
    non_empty = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith(('#','//','/*','*','*/')):
            non_empty.append((i, line, stripped))
    if not non_empty:
        G.add_node(0, text="empty", indent=0)
        return G
    for idx, (_, line, stripped) in enumerate(non_empty):
        G.add_node(idx, text=stripped, indent=get_indent(line))
    # AST edges
    indent_stack = []
    for idx, (_, line, _) in enumerate(non_empty):
        indent = get_indent(line)
        while indent_stack and indent_stack[-1][1] >= indent:
            indent_stack.pop()
        if indent_stack:
            G.add_edge(indent_stack[-1][0], idx, type="ast")
        indent_stack.append((idx, indent))
    # CFG
    branch_re = BRANCH_KW.get(language, BRANCH_KW["python"])
    for idx in range(len(non_empty)-1):
        stripped = non_empty[idx][2]
        if branch_re.match(stripped) or RETURN_KW.match(stripped):
            G.add_edge(idx, idx+1, type="cfg_branch" if branch_re.match(stripped) else "cfg_return")
        else:
            G.add_edge(idx, idx+1, type="cfg")
    # DDG
    def_sites = {}
    for idx, (_, _, stripped) in enumerate(non_empty):
        for var in VAR_DEF.findall(stripped):
            if var not in SKIP_VARS:
                def_sites[var] = idx
        for var, def_i in def_sites.items():
            if var in stripped and def_i != idx and abs(idx-def_i) <= 8:
                G.add_edge(def_i, idx, type="ddg")
    return G

# Quick test
_test_code = "def foo(x):\n    y = x + 1\n    if y > 0:\n        return y\n    return 0"
_g = build_code_graph(_test_code, "python")
print(f"Graph builder OK: {_g.number_of_nodes()} nodes, {_g.number_of_edges()} edges")
print(f"  Using: {'tree-sitter' if USE_TREE_SITTER else 'regex'} mode")
print(f"  Edge types: {Counter(d.get('type','?') for _,_,d in _g.edges(data=True))}")
"""))

# ─── CELL 7: PyG DATASET ───────────────────────────────────────────────────
cells.append(md("## Cell 7: Build PyG Dataset (GraphCodeBERT + structural features, with checkpoint)"))
cells.append(cell(r"""# ============================================================================
# Cell 7: Build PyG Dataset with GraphCodeBERT + structural features
# Checkpoint: saves partial progress every 500 graphs.
# ============================================================================
import torch, torch.nn.functional as F
import numpy as np
from tqdm import tqdm
from transformers import AutoTokenizer, AutoModel
from torch_geometric.data import Data
import gc

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print("Loading GraphCodeBERT...")
tokenizer = AutoTokenizer.from_pretrained(CONFIG["embedding_model"])
gcb_model  = AutoModel.from_pretrained(CONFIG["embedding_model"]).to(device)
gcb_model.eval()
print(f"  Loaded on {device}")

def is_sink(text):   return any(p in text.lower() for p in SINK_PATTERNS)
def is_source(text): return any(p in text.lower() for p in SOURCE_PATTERNS)

def embed_batch(texts, bs=64):
    embs = []
    for i in range(0, len(texts), bs):
        batch = texts[i:i+bs]
        toks = tokenizer(batch, padding=True, truncation=True,
                         max_length=CONFIG["max_tokens_per_node"],
                         return_tensors="pt").to(device)
        with torch.no_grad():
            out = gcb_model(**toks)
            # mean pooling (better than CLS for code; avoids missing pooler issue)
            mask = toks["attention_mask"].unsqueeze(-1).float()
            mean_emb = (out.last_hidden_state * mask).sum(1) / mask.sum(1).clamp(min=1)
            embs.append(mean_emb.cpu())
    return torch.cat(embs, dim=0) if embs else torch.empty(0, 768)

def build_pyg(sample, max_nodes=300):
    G = build_code_graph(sample["code"], sample["language"])
    nodes = list(G.nodes(data=True))[:max_nodes]
    if not nodes: return None
    keep = set(n[0] for n in nodes)
    G = G.subgraph(keep).copy()
    mapping = {old: new for new, old in enumerate(sorted(G.nodes()))}
    G = nx.relabel_nodes(G, mapping)
    nodes = list(G.nodes(data=True))
    n = len(nodes)
    texts = [d.get("text","empty") for _, d in nodes]
    gcb_emb = embed_batch(texts, CONFIG["embedding_batch_size"])
    if gcb_emb.shape[0] == 0: return None
    # Structural features
    in_deg  = np.array([G.in_degree(i)  for i in range(n)], dtype=np.float32)
    out_deg = np.array([G.out_degree(i) for i in range(n)], dtype=np.float32)
    in_n  = in_deg  / max(in_deg.max(),  1.)
    out_n = out_deg / max(out_deg.max(), 1.)
    sink_f   = np.array([float(is_sink(texts[i]))   for i in range(n)], dtype=np.float32)
    source_f = np.array([float(is_source(texts[i])) for i in range(n)], dtype=np.float32)
    try:
        lengths = nx.single_source_shortest_path_length(G, 0) if n > 0 else {}
        depth = np.array([lengths.get(i, 0) for i in range(n)], dtype=np.float32)
    except Exception:
        depth = np.zeros(n, dtype=np.float32)
    depth_n = depth / max(depth.max(), 1.)
    lang_id = CONFIG["language_ids"].get(sample["language"], 0.5)
    lang_f  = np.full(n, lang_id, dtype=np.float32)
    struct  = np.stack([in_n, out_n, sink_f, source_f, depth_n, lang_f], axis=1)
    x = torch.cat([gcb_emb, torch.tensor(struct, dtype=torch.float32)], dim=1)
    assert x.shape[1] == CONFIG["input_dim"], f"dim mismatch {x.shape[1]} != {CONFIG['input_dim']}"
    edges = list(G.edges())
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous() if edges else torch.tensor([[0],[0]], dtype=torch.long)
    data = Data(x=x, edge_index=edge_index, y=torch.tensor(sample["label"], dtype=torch.long))
    data.language   = sample["language"]
    data.cwe        = sample.get("cwe", "unknown")
    data.source_ds  = sample.get("source", "unknown")
    return data

# ── Checkpoint-aware build ─────────────────────────────────────────────────
_pyg_done    = OUTPUT_DIR / "pyg_dataset_v3.pt"
_pyg_partial = OUTPUT_DIR / "pyg_dataset_v3_partial.pt"

if _pyg_done.exists():
    pyg_dataset = torch.load(str(_pyg_done), weights_only=False)
    print(f"[CKPT] Loaded complete v3 dataset: {len(pyg_dataset)} graphs")
else:
    if _pyg_partial.exists():
        pyg_dataset = torch.load(str(_pyg_partial), weights_only=False)
        _start = len(pyg_dataset)
        print(f"[CKPT] Resuming from {_start} graphs")
    else:
        pyg_dataset, _start = [], 0

    print(f"\nBuilding PyG dataset ({len(all_samples)} samples, start={_start})...")
    _SAVE_EVERY = 500
    failed = 0
    for i, sample in enumerate(tqdm(all_samples[_start:], desc="Embedding",
                                    initial=_start, total=len(all_samples))):
        try:
            d = build_pyg(sample, CONFIG["max_nodes"])
            if d is not None: pyg_dataset.append(d)
            else: failed += 1
        except Exception as e:
            failed += 1
            if i < 5: print(f"  Error [{_start+i}]: {e}")
        if len(pyg_dataset) > 0 and len(pyg_dataset) % _SAVE_EVERY == 0:
            try: torch.save(pyg_dataset, str(_pyg_partial))
            except Exception: pass

    print(f"\n  Built {len(pyg_dataset)} graphs, {failed} failed")

    # Save final
    for p in [_pyg_done, OUTPUT_DIR / "pyg_dataset_v3_backup.pt"]:
        try:
            torch.save(pyg_dataset, str(p))
            print(f"  [CKPT] Saved -> {p}")
        except Exception as e:
            print(f"  [CKPT] Save failed ({p}): {e}")
    if _pyg_partial.exists():
        try: _pyg_partial.unlink()
        except Exception: pass

# Free GPU memory
del gcb_model, tokenizer
gc.collect()
if torch.cuda.is_available(): torch.cuda.empty_cache()
print("  GraphCodeBERT freed from GPU")

if pyg_dataset:
    s0 = pyg_dataset[0]
    print(f"\n  Sample: {s0.x.shape[0]} nodes, {s0.edge_index.shape[1]} edges, dim={s0.x.shape[1]}")
    assert s0.x.shape[1] == CONFIG["input_dim"], f"Input dim mismatch!"
    print(f"  Total graphs: {len(pyg_dataset)}")
"""))

# ─── CELL 8: SPLIT ─────────────────────────────────────────────────────────
cells.append(md("## Cell 8: Stratified Split"))
cells.append(cell(r"""# ============================================================================
# Cell 8: Stratified Split (by label + language)
# ============================================================================
from torch_geometric.loader import DataLoader
from sklearn.model_selection import train_test_split

strat_keys = [f"{d.y.item()}_{getattr(d,'language','unk')}" for d in pyg_dataset]
indices = list(range(len(pyg_dataset)))
cal_test_ratio = CONFIG["cal_ratio"] + CONFIG["test_ratio"]

def stratified_split(idx, test_size, keys):
    try:
        return train_test_split(idx, test_size=test_size, stratify=[keys[i] for i in idx], random_state=SEED)
    except ValueError:
        return train_test_split(idx, test_size=test_size, random_state=SEED)

train_val_idx, cal_test_idx = stratified_split(indices, cal_test_ratio, strat_keys)
val_frac  = CONFIG["val_ratio"] / (CONFIG["train_ratio"] + CONFIG["val_ratio"])
test_frac = CONFIG["test_ratio"] / (CONFIG["cal_ratio"]  + CONFIG["test_ratio"])
train_idx, val_idx   = stratified_split(train_val_idx, val_frac,  strat_keys)
cal_idx,   test_idx  = stratified_split(cal_test_idx,  test_frac, strat_keys)

train_data = [pyg_dataset[i] for i in train_idx]
val_data   = [pyg_dataset[i] for i in val_idx]
cal_data   = [pyg_dataset[i] for i in cal_idx]
test_data  = [pyg_dataset[i] for i in test_idx]

print("Split summary:")
for name, split in [("Train", train_data), ("Val", val_data), ("Cal", cal_data), ("Test", test_data)]:
    labels = [d.y.item() for d in split]
    nv_ = sum(labels); ns_ = len(labels) - nv_
    print(f"  {name:<6} {len(split):>5}  vuln={nv_}  safe={ns_}  ratio={nv_/max(ns_,1):.2f}:1")

BS = CONFIG["batch_size"]
train_loader = DataLoader(train_data, batch_size=BS, shuffle=True,  drop_last=True)
val_loader   = DataLoader(val_data,   batch_size=BS, shuffle=False)
cal_loader   = DataLoader(cal_data,   batch_size=BS, shuffle=False)
test_loader  = DataLoader(test_data,  batch_size=BS, shuffle=False)
print(f"\nDataLoaders ready (batch_size={BS})")
"""))

# ─── CELL 9: MODEL ─────────────────────────────────────────────────────────
cells.append(md("## Cell 9: MiniGINv3 — 3-layer GIN with Residual + BatchNorm"))
cells.append(cell(r"""# ============================================================================
# Cell 9: MiniGINv3 Model
# Architecture: GIN (Xu et al. 2019) — provably more expressive than GCN/GAT
# 3 layers, hidden=384, residual connections, batch norm, dual pooling.
# V2 used 2-layer GAT (less expressive, 298K params).
# V3 uses 3-layer GIN (1.5M params, residual, batch norm).
# ============================================================================
import torch, torch.nn as nn, torch.nn.functional as F
from torch_geometric.nn import GINConv, global_mean_pool, global_add_pool

class MiniGINv3(nn.Module):
    # SEC-C Mini-GIN V3.
    # Input: 774-dim (768 GCB mean-pool + 6 structural)
    # Arch:  Lin(774->H) -> GINx3(H->H, residual, BN) -> MeanPool+AddPool -> Clf(2H->out)
    def __init__(self, input_dim=774, hidden_dim=384, dropout=0.4, num_classes=2):
        super().__init__()
        H = hidden_dim
        self.input_proj = nn.Linear(input_dim, H)
        self.bn_in      = nn.BatchNorm1d(H)

        # 3 GIN layers with MLP (2-layer MLP per GIN)
        self.gins = nn.ModuleList()
        self.bns  = nn.ModuleList()
        for _ in range(3):
            mlp = nn.Sequential(
                nn.Linear(H, H * 2),
                nn.BatchNorm1d(H * 2),
                nn.ReLU(),
                nn.Dropout(dropout / 2),
                nn.Linear(H * 2, H),
            )
            self.gins.append(GINConv(mlp, train_eps=True))
            self.bns.append(nn.BatchNorm1d(H))

        self.dropout = nn.Dropout(dropout)

        # Dual pooling: mean + add → 2H-dim graph embedding
        pool_dim = H * 2

        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(pool_dim, H),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(H, num_classes),
        )
        # Confidence estimation head
        self.confidence_head = nn.Sequential(
            nn.Linear(pool_dim, 1),
            nn.Sigmoid(),
        )

    def forward(self, x, edge_index, batch):
        h = F.relu(self.bn_in(self.input_proj(x)))

        # 3 GIN layers with residual
        prev = h
        for gin, bn in zip(self.gins, self.bns):
            h_new = bn(gin(h, edge_index))
            h_new = F.relu(h_new)
            h_new = self.dropout(h_new)
            h = h_new + prev        # residual
            prev = h

        # Dual pooling (mean + add)
        mean_pool = global_mean_pool(h, batch)
        add_pool  = global_add_pool(h, batch)
        graph_emb = torch.cat([mean_pool, add_pool], dim=-1)

        logits     = self.classifier(graph_emb)
        confidence = self.confidence_head(graph_emb)
        return logits, confidence


model = MiniGINv3(
    input_dim=CONFIG["input_dim"],
    hidden_dim=CONFIG["hidden_dim"],
    dropout=CONFIG["dropout"],
    num_classes=CONFIG["num_classes"],
).to(device)

pc = {"total": sum(p.numel() for p in model.parameters()),
      "trainable": sum(p.numel() for p in model.parameters() if p.requires_grad)}
print(f"MiniGINv3 on {device}")
print(f"  Params: {pc['trainable']:,} (V2 was 298K)")
print(f"  Arch:   {CONFIG['input_dim']} -> {CONFIG['hidden_dim']}*3 -> {CONFIG['hidden_dim']*2} -> 2")
"""))

# ─── CELL 10: TRAINING ─────────────────────────────────────────────────────
cells.append(md("## Cell 10: Training — WeightedCE + Warmup + Early Stopping"))
cells.append(cell(r"""# ============================================================================
# Cell 10: Training
# V3 key changes:
#   - Standard CrossEntropy with mild class weight (NOT focal loss)
#   - LR=3e-4 with 5-epoch linear warmup + cosine decay (NOT raw cosine from ep1)
#   - batch_size=64 (smoother gradients)
#   - patience=25 (give model time to learn)
#   - label_smoothing=0.1 (prevents overconfidence)
# ============================================================================
import copy, time
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import AdamW

# ── Loss: WeightedCE + label smoothing ────────────────────────────────────
# Mild vuln weight (1.5) instead of inverse frequency (1.74).
# Focal loss caused threshold collapse in V2 — do not use.
class_weights = torch.tensor([1.0, CONFIG["class_weight_vuln"]], dtype=torch.float32).to(device)
criterion = nn.CrossEntropyLoss(
    weight=class_weights,
    label_smoothing=CONFIG["label_smoothing"],
)
print(f"Loss: CrossEntropyLoss(weight=[1.0, {CONFIG['class_weight_vuln']}], smoothing={CONFIG['label_smoothing']})")

# ── Optimizer: AdamW ───────────────────────────────────────────────────────
optimizer = AdamW(model.parameters(), lr=CONFIG["lr"], weight_decay=CONFIG["weight_decay"])

# ── LR schedule: linear warmup → cosine decay ─────────────────────────────
def get_lr(epoch):
    warmup = CONFIG["lr_warmup_epochs"]
    total  = CONFIG["epochs"]
    if epoch <= warmup:
        return epoch / max(warmup, 1)     # linear ramp
    progress = (epoch - warmup) / max(total - warmup, 1)
    return 0.5 * (1 + np.cos(np.pi * progress))  # cosine

import math as _math
scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda=get_lr)

# ── Metrics helper ────────────────────────────────────────────────────────
def compute_metrics(preds, labels):
    if not preds: return {"accuracy":0,"precision":0,"recall":0,"f1":0}
    tp = sum(1 for p,l in zip(preds,labels) if p==1 and l==1)
    fp = sum(1 for p,l in zip(preds,labels) if p==1 and l==0)
    fn = sum(1 for p,l in zip(preds,labels) if p==0 and l==1)
    acc  = sum(1 for p,l in zip(preds,labels) if p==l) / len(preds)
    prec = tp / (tp+fp) if (tp+fp) > 0 else 0.
    rec  = tp / (tp+fn) if (tp+fn) > 0 else 0.
    f1   = 2*prec*rec / (prec+rec) if (prec+rec) > 0 else 0.
    return {"accuracy":acc,"precision":prec,"recall":rec,"f1":f1}

def train_one_epoch():
    model.train()
    total_loss, nb = 0., 0
    for data in train_loader:
        data = data.to(device)
        optimizer.zero_grad()
        logits, confidence = model(data.x, data.edge_index, data.batch)
        loss = criterion(logits, data.y)
        with torch.no_grad():
            correct = (logits.argmax(-1) == data.y).float()
        loss += 0.1 * F.binary_cross_entropy(confidence, correct)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), CONFIG["grad_clip"])
        optimizer.step()
        total_loss += loss.item(); nb += 1
    return total_loss / max(nb, 1)

@torch.no_grad()
def validate(loader):
    model.eval()
    total_loss, nb = 0., 0
    all_preds, all_labels = [], []
    for data in loader:
        data = data.to(device)
        logits, _ = model(data.x, data.edge_index, data.batch)
        total_loss += criterion(logits, data.y).item(); nb += 1
        all_preds.extend(logits.argmax(-1).cpu().tolist())
        all_labels.extend(data.y.cpu().tolist())
    return total_loss / max(nb, 1), compute_metrics(all_preds, all_labels)

# ── Training loop ─────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print(f"  Training MiniGINv3 ({CONFIG['epochs']} epochs, patience={CONFIG['patience']})")
print(f"  LR={CONFIG['lr']}, warmup={CONFIG['lr_warmup_epochs']}ep, batch={CONFIG['batch_size']}")
print(f"{'='*70}\n")

history = {k: [] for k in ["train_loss","val_loss","val_acc","val_f1","val_precision","val_recall"]}
best_val_f1, best_val_loss, best_epoch = 0., float('inf'), 0
patience_ctr = 0
best_state   = None
t0 = time.time()

for epoch in range(1, CONFIG["epochs"] + 1):
    train_loss = train_one_epoch()
    scheduler.step()
    val_loss, vm = validate(val_loader)
    for k in ["accuracy","f1","precision","recall"]:
        history[f"val_{k}"].append(vm[k])
    history["train_loss"].append(train_loss)
    history["val_loss"].append(val_loss)

    improved = ""
    if vm["f1"] > best_val_f1:
        best_val_f1 = vm["f1"]
        best_val_loss = val_loss
        best_epoch = epoch
        best_state = copy.deepcopy(model.state_dict())
        patience_ctr = 0
        improved = " *"
        # Save best checkpoint
        try:
            torch.save(best_state, str(OUTPUT_DIR / "mini_gat_v3_best.pt"))
        except Exception: pass
    else:
        patience_ctr += 1

    # Periodic checkpoint every 10 epochs
    if epoch % 10 == 0:
        try:
            torch.save(model.state_dict(), str(OUTPUT_DIR / f"mini_gat_v3_epoch{epoch:03d}.pt"))
            # Prune old periodic checkpoints
            old = OUTPUT_DIR / f"mini_gat_v3_epoch{epoch-20:03d}.pt"
            if old.exists() and not improved: old.unlink()
        except Exception: pass

    lr = optimizer.param_groups[0]['lr']
    if epoch % 5 == 0 or epoch <= 5 or improved:
        print(f"  Epoch {epoch:3d}/{CONFIG['epochs']}  "
              f"tl={train_loss:.4f} vl={val_loss:.4f} "
              f"F1={vm['f1']:.4f} P={vm['precision']:.4f} R={vm['recall']:.4f} "
              f"lr={lr:.2e}{improved}")

    if patience_ctr >= CONFIG["patience"]:
        print(f"\n  Early stopping at epoch {epoch} (patience={CONFIG['patience']})")
        break

elapsed = time.time() - t0
print(f"\n  Done in {elapsed/60:.1f} min. Best epoch {best_epoch} (F1={best_val_f1:.4f})")
if best_state:
    model.load_state_dict(best_state)
    print("  Restored best weights")

# Plot training curves
import matplotlib.pyplot as plt
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
epochs_x = range(1, len(history["train_loss"]) + 1)
axes[0].plot(epochs_x, history["train_loss"], label="Train"); axes[0].plot(epochs_x, history["val_loss"], label="Val")
axes[0].axvline(best_epoch, color='g', ls='--', alpha=.5, label=f'Best(ep{best_epoch})')
axes[0].set_title("Loss"); axes[0].legend(); axes[0].grid(True, alpha=.3)
axes[1].plot(epochs_x, history["val_f1"], label="F1", color='purple')
axes[1].plot(epochs_x, history["val_precision"], label="Precision", alpha=.7)
axes[1].plot(epochs_x, history["val_recall"], label="Recall", alpha=.7)
axes[1].set_title("Validation Metrics"); axes[1].legend(); axes[1].grid(True, alpha=.3)
axes[2].plot(epochs_x, history["val_acc"], label="Accuracy", color='teal')
axes[2].set_title("Validation Accuracy"); axes[2].legend(); axes[2].grid(True, alpha=.3)
plt.suptitle("MiniGINv3 Training Curves", fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(str(OUTPUT_DIR / "training_curves_v3.png"), dpi=150)
plt.show()
"""))

# ─── CELL 11: THRESHOLD CALIBRATION (NEW) ──────────────────────────────────
cells.append(md("## Cell 11: F1-Optimal Decision Threshold (New in V3)"))
cells.append(cell(r"""# ============================================================================
# Cell 11: F1-Optimal Decision Threshold Calibration (V3 key fix)
#
# V2 bug: always used argmax (equivalent to threshold=0.5), which caused
# high recall / low precision ("predict everything as vulnerable").
#
# V3 fix: search validation set for the threshold T* that maximises F1.
# All downstream predictions (test evaluation, conformal) use T*.
# ============================================================================
import numpy as np
import torch.nn.functional as F

model.eval()
val_probs_all, val_true_all = [], []
with torch.no_grad():
    for data in val_loader:
        data = data.to(device)
        logits, _ = model(data.x, data.edge_index, data.batch)
        probs = F.softmax(logits, dim=-1)[:, 1].cpu().numpy()   # P(vulnerable)
        val_probs_all.extend(probs.tolist())
        val_true_all.extend(data.y.cpu().tolist())

val_probs_arr = np.array(val_probs_all)
val_true_arr  = np.array(val_true_all)

thresholds = np.linspace(0.05, 0.95, CONFIG["threshold_search_steps"])
results = []
for thr in thresholds:
    preds = (val_probs_arr >= thr).astype(int)
    tp = int(((preds==1) & (val_true_arr==1)).sum())
    fp = int(((preds==1) & (val_true_arr==0)).sum())
    fn = int(((preds==0) & (val_true_arr==1)).sum())
    prec = tp / (tp + fp + 1e-9)
    rec  = tp / (tp + fn + 1e-9)
    f1   = 2 * prec * rec / (prec + rec + 1e-9)
    results.append({"thr": float(thr), "f1": f1, "prec": prec, "rec": rec, "tp": tp, "fp": fp, "fn": fn})

best_thr_row = max(results, key=lambda r: r["f1"])
DECISION_THRESHOLD = best_thr_row["thr"]

print(f"{'='*60}")
print(f"  F1-Optimal Threshold Search (val set, {len(val_true_arr)} samples)")
print(f"{'='*60}")
print(f"  Best threshold: {DECISION_THRESHOLD:.2f}")
print(f"  Val F1:         {best_thr_row['f1']:.4f}")
print(f"  Val Precision:  {best_thr_row['prec']:.4f}")
print(f"  Val Recall:     {best_thr_row['rec']:.4f}")
print(f"\n  Comparison (V2 used argmax = 0.5):")
row_05 = next(r for r in results if abs(r["thr"] - 0.50) < 0.01)
print(f"  threshold=0.50: F1={row_05['f1']:.4f} P={row_05['prec']:.4f} R={row_05['rec']:.4f}")
print(f"  threshold={DECISION_THRESHOLD:.2f}: F1={best_thr_row['f1']:.4f} P={best_thr_row['prec']:.4f} R={best_thr_row['rec']:.4f}")

# Plot threshold curve
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
thrs  = [r["thr"]  for r in results]
f1s   = [r["f1"]   for r in results]
precs = [r["prec"] for r in results]
recs  = [r["rec"]  for r in results]
axes[0].plot(thrs, f1s,   label="F1",        color="purple", lw=2)
axes[0].plot(thrs, precs, label="Precision",  color="blue",   alpha=.7)
axes[0].plot(thrs, recs,  label="Recall",     color="red",    alpha=.7)
axes[0].axvline(DECISION_THRESHOLD, color="green", ls="--", lw=2, label=f"Best T={DECISION_THRESHOLD:.2f}")
axes[0].axvline(0.50, color="gray", ls=":", label="V2 (0.5)")
axes[0].set_title("Threshold vs Metrics (Val Set)"); axes[0].legend(); axes[0].grid(True, alpha=.3)
axes[1].hist(val_probs_arr[val_true_arr==0], bins=30, alpha=.6, color="green", label="safe")
axes[1].hist(val_probs_arr[val_true_arr==1], bins=30, alpha=.6, color="red",   label="vulnerable")
axes[1].axvline(DECISION_THRESHOLD, color="black", ls="--", lw=2, label=f"T={DECISION_THRESHOLD:.2f}")
axes[1].set_title("Predicted P(vuln) Distribution"); axes[1].legend()
plt.suptitle("Decision Threshold Calibration", fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig(str(OUTPUT_DIR / "threshold_calibration_v3.png"), dpi=150)
plt.show()
"""))

# ─── CELL 12: EVALUATION ───────────────────────────────────────────────────
cells.append(md("## Cell 12: Test Set Evaluation (with F1-optimal threshold)"))
cells.append(cell(r"""# ============================================================================
# Cell 12: Comprehensive Evaluation using DECISION_THRESHOLD (not argmax)
# ============================================================================
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from collections import Counter

CLASS_LABELS = ["safe", "vulnerable"]
model.eval()
test_preds, test_labels = [], []
test_probs, test_langs, test_cwes = [], [], []

with torch.no_grad():
    for data in test_loader:
        data = data.to(device)
        logits, _ = model(data.x, data.edge_index, data.batch)
        sm_probs = F.softmax(logits, dim=-1).cpu().numpy()
        vuln_probs = sm_probs[:, 1]
        # Use F1-optimal threshold (not argmax/0.5)
        preds = (vuln_probs >= DECISION_THRESHOLD).astype(int).tolist()
        test_preds.extend(preds)
        test_labels.extend(data.y.cpu().tolist())
        test_probs.append(sm_probs)
        # Per-graph language extraction (from last feature dim)
        batch_np = data.batch.cpu().numpy()
        for b in range(logits.shape[0]):
            mask = batch_np == b
            nidx = np.where(mask)[0]
            if len(nidx) > 0:
                lf = data.x[nidx[0], -1].item()
                ln = min(CONFIG["language_ids"], key=lambda k: abs(CONFIG["language_ids"][k]-lf))
            else:
                ln = "unknown"
            test_langs.append(ln)
        # CWE: PyG batches string attrs as list (one per graph)
        _batch_cwes = data.cwe if hasattr(data, "cwe") else None
        if _batch_cwes is None:
            test_cwes.extend(["unknown"] * logits.shape[0])
        elif isinstance(_batch_cwes, list):
            test_cwes.extend([str(c) if c else "unknown" for c in _batch_cwes])
        else:
            test_cwes.extend([str(_batch_cwes)] * logits.shape[0])

test_probs_np = np.concatenate(test_probs, axis=0)
test_metrics  = compute_metrics(test_preds, test_labels)

print("="*70)
print(f"  TEST SET EVALUATION (threshold={DECISION_THRESHOLD:.2f}, N={len(test_labels)})")
print("="*70)
print(f"  Accuracy:  {test_metrics['accuracy']:.4f}")
print(f"  Precision: {test_metrics['precision']:.4f}")
print(f"  Recall:    {test_metrics['recall']:.4f}")
print(f"  F1:        {test_metrics['f1']:.4f}")
try:
    auc_roc = roc_auc_score(test_labels, test_probs_np[:, 1])
    print(f"  AUC-ROC:   {auc_roc:.4f}")
except Exception:
    auc_roc = 0.
    print("  AUC-ROC:   N/A")

print(f"\n{classification_report(test_labels, test_preds, target_names=CLASS_LABELS)}")

# Per-language
print(f"\n  Per-Language:")
print(f"  {'Lang':<15} {'N':>5} {'Acc':>7} {'P':>7} {'R':>7} {'F1':>7}")
print(f"  {'-'*50}")
lang_metrics = {}
for lang in CONFIG["language_ids"]:
    mi = [i for i,l in enumerate(test_langs) if l==lang]
    if not mi: continue
    m = compute_metrics([test_preds[i] for i in mi], [test_labels[i] for i in mi])
    lang_metrics[lang] = m
    print(f"  {lang:<15} {len(mi):>5} {m['accuracy']:>7.4f} {m['precision']:>7.4f} {m['recall']:>7.4f} {m['f1']:>7.4f}")

# Per-CWE
print(f"\n  Per-CWE (top 15):")
cwe_ctr = Counter(str(c) for c in test_cwes)
print(f"  {'CWE':<22} {'N':>5} {'F1':>7}")
print(f"  {'-'*37}")
for cwe, _ in cwe_ctr.most_common(15):
    ci = [i for i,c in enumerate(test_cwes) if str(c)==cwe]
    if len(ci) < 3: continue
    m = compute_metrics([test_preds[i] for i in ci], [test_labels[i] for i in ci])
    print(f"  {cwe:<22} {len(ci):>5} {m['f1']:>7.4f}")

# Plots
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
cm = confusion_matrix(test_labels, test_preds)
im = axes[0].imshow(cm, cmap='Blues')
axes[0].set_title(f"Confusion Matrix (T={DECISION_THRESHOLD:.2f})")
axes[0].set_xticks([0,1]); axes[0].set_yticks([0,1])
axes[0].set_xticklabels(CLASS_LABELS); axes[0].set_yticklabels(CLASS_LABELS)
for ii in range(2):
    for jj in range(2):
        axes[0].text(jj,ii,str(cm[ii,jj]),ha='center',va='center',
                     color='white' if cm[ii,jj]>cm.max()/2 else 'black',fontsize=14)
plt.colorbar(im, ax=axes[0])
try:
    fpr, tpr, _ = roc_curve(test_labels, test_probs_np[:,1])
    axes[1].plot(fpr, tpr, 'b-', lw=2, label=f'AUC={auc_roc:.4f}')
    axes[1].plot([0,1],[0,1],'r--',alpha=.5); axes[1].set_title("ROC"); axes[1].legend()
except Exception:
    axes[1].text(.5,.5,"N/A",ha='center')
axes[2].hist(test_probs_np[np.array(test_labels)==0,1], bins=30, alpha=.6, color='green', label='safe')
axes[2].hist(test_probs_np[np.array(test_labels)==1,1], bins=30, alpha=.6, color='red',   label='vulnerable')
axes[2].axvline(DECISION_THRESHOLD, color='black', ls='--', lw=2, label=f'T={DECISION_THRESHOLD:.2f}')
axes[2].set_title("Score Distribution"); axes[2].legend()
plt.suptitle("MiniGINv3 Test Evaluation", fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(str(OUTPUT_DIR / "evaluation_plots_v3.png"), dpi=150)
plt.show()
"""))

# ─── CELL 13: CONFORMAL ────────────────────────────────────────────────────
cells.append(md("## Cell 13: Conformal Prediction (APS, alpha=0.2)"))
cells.append(cell(r"""# ============================================================================
# Cell 13: Conformal Prediction — APS calibration
# V3: alpha=0.2 (tighter than V2's 0.3).
# NOTE: conformal uses softmax probs (not threshold), so even if classification
# threshold is calibrated, conformal adds a set-valued guarantee.
# ============================================================================
import math

def aps_scores(sm_probs, true_labels):
    n = len(true_labels)
    scores = np.zeros(n, np.float64)
    for i in range(n):
        probs = sm_probs[i]
        si = np.argsort(-probs)
        cs = np.cumsum(probs[si])
        rank = int(np.where(si == true_labels[i])[0][0])
        scores[i] = cs[rank]
    return scores

def build_pred_set(probs, threshold):
    si = np.argsort(-probs)
    cs = np.cumsum(probs[si])
    ps = []
    for j, idx in enumerate(si):
        ps.append(CLASS_LABELS[int(idx)])
        if cs[j] >= threshold: break
    return ps or [CLASS_LABELS[int(si[0])]]

# Collect cal probabilities
alpha = CONFIG["alpha"]
print(f"{'='*60}")
print(f"  Conformal Prediction (APS, alpha={alpha})")
print(f"{'='*60}")

model.eval()
cal_sm, cal_lb = [], []
with torch.no_grad():
    for data in cal_loader:
        data = data.to(device)
        logits, _ = model(data.x, data.edge_index, data.batch)
        cal_sm.append(F.softmax(logits, dim=-1).cpu().numpy())
        cal_lb.extend(data.y.cpu().tolist())

cal_sm   = np.concatenate(cal_sm, axis=0)
cal_lb_np = np.array(cal_lb, dtype=np.int64)
n_cal    = len(cal_lb_np)

scores = aps_scores(cal_sm, cal_lb_np)
ql = min(math.ceil((n_cal + 1) * (1. - alpha)) / n_cal, 1.)
try:
    conf_threshold = float(np.quantile(scores, ql, method="higher"))
except TypeError:
    conf_threshold = float(np.quantile(scores, ql, interpolation="higher"))

print(f"\n  Cal samples:  {n_cal}")
print(f"  Threshold:    {conf_threshold:.4f}  (V2 was 1.0 — broken)")
print(f"  Score mean:   {scores.mean():.4f}")
print(f"  Score std:    {scores.std():.4f}")

# Calibration coverage
covered, single, sizes = 0, 0, []
for i in range(n_cal):
    ps = build_pred_set(cal_sm[i], conf_threshold)
    sizes.append(len(ps))
    if CLASS_LABELS[cal_lb_np[i]] in ps: covered += 1
    if len(ps) == 1: single += 1

empirical_coverage = covered / n_cal
singleton_rate     = single / n_cal
ambig_rate         = 1 - singleton_rate
print(f"\n  [Calibration]")
print(f"  Coverage:     {empirical_coverage:.4f}  (target>={1-alpha:.2f})")
print(f"  Singleton:    {single}/{n_cal} ({singleton_rate:.1%})")
print(f"  Ambiguous:    {n_cal-single}/{n_cal} ({ambig_rate:.1%})")

# Test verification
tc, ts, tsz = 0, 0, []
for i in range(len(test_labels)):
    ps = build_pred_set(test_probs_np[i], conf_threshold)
    tsz.append(len(ps))
    if CLASS_LABELS[test_labels[i]] in ps: tc += 1
    if len(ps) == 1: ts += 1
n_test_c      = len(test_labels)
test_coverage = tc / n_test_c
test_singleton_rate = ts / n_test_c
test_ambig_rate     = 1 - test_singleton_rate
coverage_ok   = test_coverage >= (1 - alpha)
print(f"\n  [Test Verification]")
print(f"  Coverage:     {test_coverage:.4f}  ({'MET' if coverage_ok else 'NOT MET'})")
print(f"  Singleton:    {ts}/{n_test_c} ({test_singleton_rate:.1%})")
print(f"  Ambiguous:    {n_test_c-ts}/{n_test_c} ({test_ambig_rate:.1%})")

# Plots
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
axes[0].hist(scores, bins=30, color="#4dabf7", alpha=.7, edgecolor="black")
axes[0].axvline(conf_threshold, color="red", ls="--", lw=2, label=f"Thr={conf_threshold:.3f}")
axes[0].set_title("APS Scores (Cal Set)"); axes[0].legend()
sc2 = Counter(sizes)
su2 = sorted(sc2.keys())
axes[1].bar(su2, [sc2[s] for s in su2], color=["#51cf66","#ffa94d","#ff6b6b"][:len(su2)])
axes[1].set_title("Prediction Set Sizes")
alphas_t = np.linspace(0.01, 0.5, 50)
covs2 = []
for a2 in alphas_t:
    q2 = min(math.ceil((n_cal+1)*(1.-a2))/n_cal, 1.)
    try: t2 = float(np.quantile(scores, q2, method="higher"))
    except TypeError: t2 = float(np.quantile(scores, q2, interpolation="higher"))
    c2 = sum(1 for i in range(n_cal) if CLASS_LABELS[cal_lb_np[i]] in build_pred_set(cal_sm[i], t2))
    covs2.append(c2 / n_cal)
axes[2].plot(alphas_t, covs2, "b-", lw=2, label="Empirical")
axes[2].plot(alphas_t, 1-alphas_t, "r--", alpha=.7, label="1-alpha")
axes[2].axvline(alpha, color="green", ls=":", label=f"alpha={alpha}")
axes[2].set_title("Calibration Curve"); axes[2].legend(); axes[2].grid(True, alpha=.3)
plt.suptitle("Conformal Prediction Diagnostics (V3)", fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(str(OUTPUT_DIR / "conformal_diagnostics_v3.png"), dpi=150)
plt.show()
"""))

# ─── CELL 14: EXPORT ───────────────────────────────────────────────────────
cells.append(md("## Cell 14: Export Artifacts"))
cells.append(cell(r"""# ============================================================================
# Cell 14: Export All Artifacts
# ============================================================================
import json, torch_geometric, shutil

# 1. Model
model_path = OUTPUT_DIR / "mini_gat_v3.pt"
torch.save(model.cpu().state_dict(), str(model_path))
model.to(device)
print(f"1. Model:      {model_path}  ({model_path.stat().st_size/1024:.0f} KB)")

# 2. Decision threshold (NEW in V3)
thr_export = {
    "decision_threshold": DECISION_THRESHOLD,
    "val_f1_at_threshold": best_thr_row["f1"],
    "val_precision":       best_thr_row["prec"],
    "val_recall":          best_thr_row["rec"],
    "version": "v3",
    "note": "F1-optimal threshold found by grid search on val set. Use this instead of argmax.",
}
thr_path = OUTPUT_DIR / "decision_threshold_v3.json"
with open(str(thr_path), "w") as f:
    json.dump(thr_export, f, indent=2)
print(f"2. Threshold:  {thr_path}")

# 3. Conformal calibration
cal_export = {
    "alpha": CONFIG["alpha"],
    "threshold": float(conf_threshold),
    "decision_threshold": DECISION_THRESHOLD,
    "n_calibration": int(n_cal),
    "empirical_coverage": float(empirical_coverage),
    "test_coverage": float(test_coverage),
    "class_names": CLASS_LABELS,
    "singleton_rate": float(singleton_rate),
    "ambiguous_rate": float(ambig_rate),
    "test_singleton_rate": float(test_singleton_rate),
    "test_ambiguous_rate": float(test_ambig_rate),
    "mean_set_size": float(np.mean(sizes)),
    "score_stats": {
        "mean": float(scores.mean()), "std": float(scores.std()),
        "median": float(np.median(scores)), "min": float(scores.min()), "max": float(scores.max()),
    },
    "test_metrics": {
        "accuracy": float(test_metrics["accuracy"]),
        "precision": float(test_metrics["precision"]),
        "recall": float(test_metrics["recall"]),
        "f1": float(test_metrics["f1"]),
        "auc_roc": float(auc_roc),
    },
    "per_language_metrics": {l: {k: float(v) for k,v in m.items()} for l,m in lang_metrics.items()},
    "training_history": {
        "total_epochs": len(history["train_loss"]),
        "best_epoch": int(best_epoch),
        "best_val_f1": float(best_val_f1),
        "best_val_loss": float(best_val_loss),
    },
    "version": "v3",
}
cal_path = OUTPUT_DIR / "conformal_calibration_v3.json"
with open(str(cal_path), "w") as f:
    json.dump(cal_export, f, indent=2)
print(f"3. Calibration:{cal_path}")

# 4. Graph config
gc_export = {
    "model_class": "MiniGINv3",
    "model_config": {
        "input_dim": CONFIG["input_dim"], "hidden_dim": CONFIG["hidden_dim"],
        "num_gin_layers": CONFIG["num_gin_layers"], "dropout": CONFIG["dropout"],
        "num_classes": CONFIG["num_classes"], "embedding_model": CONFIG["embedding_model"],
        "embedding_mode": "mean_pooling",
    },
    "node_features": ["in_degree_norm","out_degree_norm","is_sink","is_source","depth_norm","language_id"],
    "language_ids": CONFIG["language_ids"],
    "sink_patterns": SINK_PATTERNS,
    "source_patterns": SOURCE_PATTERNS,
    "max_nodes": CONFIG["max_nodes"],
    "graph_builder": "tree_sitter+regex" if USE_TREE_SITTER else "regex",
    "torch_version": torch.__version__,
    "torch_geometric_version": torch_geometric.__version__,
    "dataset_info": {
        "total_graphs": len(pyg_dataset),
        "train": len(train_data), "val": len(val_data),
        "cal": len(cal_data), "test": len(test_data),
        "languages": list(CONFIG["language_ids"].keys()),
    },
    "version": "v3",
}
cfg_path = OUTPUT_DIR / "graph_config_v3.json"
with open(str(cfg_path), "w") as f:
    json.dump(gc_export, f, indent=2)
print(f"4. Config:     {cfg_path}")

# Legacy copies
for alias_src, alias_dst in [
    ("conformal_calibration_v3.json", "conformal_calibration.json"),
    ("graph_config_v3.json",          "graph_config.json"),
    ("mini_gat_v3.pt",                "mini_gat.pt"),
]:
    try:
        shutil.copy(str(OUTPUT_DIR / alias_src), str(OUTPUT_DIR / alias_dst))
    except Exception:
        pass

print(f"\nAll artifacts in {OUTPUT_DIR}")
"""))

# ─── CELL 15: SUMMARY ──────────────────────────────────────────────────────
cells.append(md("## Cell 15: Summary Report"))
cells.append(cell(r"""# ============================================================================
# Cell 15: Final Summary Report
# ============================================================================
print("="*70)
print("  SEC-C MiniGINv3 — Training Report")
print("="*70)
print(f"\n  MODEL:   MiniGINv3 (3-layer GIN), {pc['trainable']:,} params")
print(f"  INPUT:   {CONFIG['input_dim']} (768 GCB mean-pool + 6 structural)")
print(f"  ARCH:    GIN×3 hidden={CONFIG['hidden_dim']}, residual, BN, dual-pool")
total_v_ds  = sum(1 for s in all_samples if s["label"]==1)
total_s_ds  = len(all_samples) - total_v_ds
print(f"\n  DATA:    {len(pyg_dataset)} graphs ({total_v_ds} vuln, {total_s_ds} safe)")
srcs_used = sorted(set(s.get("source","?") for s in all_samples))
print(f"  SRCS:    {', '.join(srcs_used)}")
print(f"  SPLIT:   {len(train_data)}/{len(val_data)}/{len(cal_data)}/{len(test_data)}")
print(f"\n  TRAIN:   WeightedCE(vuln×{CONFIG['class_weight_vuln']}), smoothing={CONFIG['label_smoothing']}")
print(f"           LR={CONFIG['lr']}, warmup={CONFIG['lr_warmup_epochs']}ep, patience={CONFIG['patience']}")
print(f"  BEST:    epoch {best_epoch}, val_F1={best_val_f1:.4f}")
print(f"\n  THRESHOLD: {DECISION_THRESHOLD:.2f} (F1-optimal on val set, V2 used 0.5)")
print(f"\n  TEST METRICS (threshold={DECISION_THRESHOLD:.2f}):")
print(f"    Accuracy:  {test_metrics['accuracy']:.4f}")
print(f"    Precision: {test_metrics['precision']:.4f}")
print(f"    Recall:    {test_metrics['recall']:.4f}")
print(f"    F1:        {test_metrics['f1']:.4f}")
print(f"    AUC-ROC:   {auc_roc:.4f}")
print(f"\n  PER-LANGUAGE F1:")
for lang, m in lang_metrics.items():
    print(f"    {lang:<15} {m['f1']:.4f}")
print(f"\n  CONFORMAL (alpha={CONFIG['alpha']}):")
print(f"    APS Threshold: {conf_threshold:.4f}")
print(f"    Coverage:      {test_coverage:.4f} (>={1-CONFIG['alpha']:.2f}: {'YES' if coverage_ok else 'NO'})")
print(f"    Singleton:     {test_singleton_rate:.1%}  Ambiguous: {test_ambig_rate:.1%}")
print(f"\n  V2 -> V3 changes:")
print(f"    Loss:       FocalLoss(γ=2) -> CE+smooth(0.1)")
print(f"    LR:         1e-3 -> 3e-4 + warmup")
print(f"    Balance:    2.0:1 -> 1.0:1 strict per-language")
print(f"    Arch:       GAT(2L,298K) -> GIN(3L,{pc['trainable']//1000}K) + residual + BN")
print(f"    Pooling:    global_mean -> mean+add concat")
print(f"    Embedding:  CLS -> mean_pool (fixes MISSING pooler warning)")
print(f"    Threshold:  argmax(0.5) -> F1-optimal({DECISION_THRESHOLD:.2f})")
print(f"    Datasets:   +BigVul (CWE-labeled C/C++)")
print(f"    Juliet:     1000 -> {CONFIG['max_juliet']} (reduce synthetic bias)")
print(f"="*70)
"""))

# ─── CELL 16: ZIP ──────────────────────────────────────────────────────────
cells.append(md("## Cell 16: Zip All Downloadable Artifacts"))
cells.append(cell(r"""# ============================================================================
# Cell 16: Zip all artifacts for single-click download from Kaggle
# ============================================================================
import zipfile

zip_path = OUTPUT_DIR / "sec_c_gnn_v3_artifacts.zip"
files_to_zip = [
    ("mini_gat_v3.pt",                 "model weights (main)"),
    ("mini_gat_v3_best.pt",            "best checkpoint"),
    ("decision_threshold_v3.json",     "F1-optimal threshold"),
    ("conformal_calibration_v3.json",  "conformal calibration + metrics"),
    ("graph_config_v3.json",           "graph builder + model config"),
    ("raw_samples_v3.json",            "balanced dataset samples"),
    ("eda_overview_v3.png",            "dataset EDA plots"),
    ("training_curves_v3.png",         "training loss/F1 curves"),
    ("threshold_calibration_v3.png",   "threshold search plots"),
    ("evaluation_plots_v3.png",        "test evaluation (ROC, CM)"),
    ("conformal_diagnostics_v3.png",   "conformal prediction plots"),
]

print(f"Zipping artifacts -> {zip_path.name}")
print(f"{'File':<40} {'Size':>8}  Description")
print("-"*70)

with zipfile.ZipFile(str(zip_path), 'w', zipfile.ZIP_DEFLATED) as zf:
    for fname, desc in files_to_zip:
        fpath = OUTPUT_DIR / fname
        if fpath.exists():
            sz = fpath.stat().st_size
            zf.write(str(fpath), fname)
            print(f"  {fname:<38} {sz/1024:>7.0f}K  {desc}")
        else:
            print(f"  {fname:<38} {'MISSING':>8}  {desc}")

total_kb = zip_path.stat().st_size / 1024
print(f"\nZip total: {zip_path.name}  ({total_kb:.0f} KB = {total_kb/1024:.2f} MB)")
print(f"Location:  {zip_path}")
print("\nDownload from Kaggle: Output tab -> sec_c_gnn_v3_artifacts.zip")
"""))

# ─── Build notebook ─────────────────────────────────────────────────────────
nb = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11.0"},
    },
    "cells": cells,
}

out = "D:/sec-c/notebooks/sec_c_gnn_training_v3.ipynb"
with open(out, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f"Written: {out}")
print(f"Cells:   {len(cells)} ({sum(1 for c in cells if c['cell_type']=='code')} code, {sum(1 for c in cells if c['cell_type']=='markdown')} markdown)")
