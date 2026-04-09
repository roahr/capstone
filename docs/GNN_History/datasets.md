# Dataset Sources and History

## Active Sources (V5)

| # | Dataset | HuggingFace ID | Language | Samples | Schema |
|---|---------|---------------|----------|---------|--------|
| 1 | BigVul | `bstee615/bigvul` | C/C++ | 10,000 | `func_before`/`func_after`, `vul`, `CWE ID` |
| 2 | DiverseVul | `claudios/DiverseVul` | C/C++ | 8,000 | `func`, `target`, `cwe` (list) |
| 3 | Devign | `google/code_x_glue_cc_defect_detection` | C/C++ | 5,000 | `func`, `target` |
| 4 | Juliet C | `LorenzH/juliet_test_suite_c_1_3` | C/C++ | 6,000 | `bad`/`good` (pair), `class` (CWE#) |
| 5 | CrossVul | `hitoshura25/crossvul` | Multi | 6,000 | `vulnerable_code`/`fixed_code`, `cwe_id`, `language` |
| 6 | VUDENC | `DetectVul/Vudenc` | Python | 3,000 | `raw_lines` (list), `label` (list) |
| 7 | CVEfixes | `DetectVul/CVEFixes` | Python | 3,000 | `raw_lines` (list), `label` (list) |

## Failed Source

| Dataset | HuggingFace ID | Error | Status |
|---------|---------------|-------|--------|
| PrimeVul | `starsofchance/PrimeVul` | V4: `SplitInfo` metadata bug; V5: "Value is too big!" | Unresolved |

PrimeVul (236K C/C++ deduplicated samples) would add ~8,000 high-quality samples. The dataset has broken HF metadata that prevents standard loading. JSONL direct load via `hf://` URLs was attempted but the files may exceed Kaggle's parsing limits.

## Dataset Loading Issues and Fixes

### VUDENC and CVEfixes (Fixed in V5)

**Problem**: Both datasets store data at statement level with parallel lists:
```json
{
  "raw_lines": ["line1", "line2", "line3"],
  "label": [0, 0, 1],
  "type": ["Assign'", "Call'", "Return'"]
}
```

V4 code treated `label` as a scalar: `int(row.get("label", 0))` -> crashed with `TypeError`.

**Fix**: Derive function-level label from statement-level labels:
```python
raw = row.get("raw_lines", []) or row.get("lines", []) or []
labels = row.get("label", []) or []
code = chr(10).join(raw)
label = 1 if any(l == 1 for l in labels) else 0
```

### CrossVul (Fixed in V4)

**Problem**: V3 tried wrong HF IDs (`CrossVul/crossvul`, `CrossVul/Cross_Vul`, etc.)
**Fix**: Correct ID is `hitoshura25/crossvul`. Uses pair-based schema: `vulnerable_code` (label=1) and `fixed_code` (label=0).

### trust_remote_code Deprecation

All `load_dataset` calls used `trust_remote_code=True` which was deprecated in HF datasets 4.0.0. Removed in V5 — datasets load fine without it on current Kaggle environments.

## Per-Language Distribution After Balancing (V5)

| Language | Vulnerable | Safe | Total | Ratio |
|----------|-----------|------|-------|-------|
| C/C++ | 10,000 | 10,000 | 20,000 | 1.00:1 |
| Python | 298 | 298 | 596 | 1.00:1 |
| JavaScript | 126 | 126 | 252 | 1.00:1 |
| Java | 97 | 97 | 194 | 1.00:1 |
| Go | 54 | 54 | 108 | 1.00:1 |
| **Total** | **10,575** | **10,575** | **21,150** | **1.00:1** |

## Data Pipeline

```
Raw HF datasets (41K samples)
  -> Dedup by MD5 hash (39,674)
  -> Length filter (>= 3 lines, >= 20 chars) (39,462)
  -> Per-language 1:1 balance (oversample minority, undersample majority)
  -> Shuffle
  -> Final: 21,150 balanced samples
  -> Stratified split: 60% train / 15% val / 15% cal / 10% test
```

## Source Contribution After Balancing (V5)

| Source | Samples | % of Total |
|--------|---------|------------|
| BigVul | 5,777 | 27.3% |
| DiverseVul | 4,935 | 23.3% |
| Juliet-C | 3,611 | 17.1% |
| CrossVul | 3,428 | 16.2% |
| Devign | 3,002 | 14.2% |
| VUDENC | 222 | 1.1% |
| CVEfixes-Py | 175 | 0.8% |

Note: VUDENC and CVEfixes have extreme class imbalance (84/2916 and 36/2964 vuln/safe). After 1:1 per-language balancing, only ~84-36 pairs survive, contributing modestly to the total. Despite this, Python F1 improved from 0.667 to 0.836.

## Top CWEs in Dataset (V5)

| CWE | Count | Description |
|-----|-------|-------------|
| unknown | 5,450 | No CWE label available |
| CWE-119 | 2,178 | Buffer overflow |
| CWE-20 | 1,805 | Improper input validation |
| CWE-125 | 1,064 | Out-of-bounds read |
| CWE-264 | 857 | Permissions/privileges |
| CWE-200 | 841 | Information exposure |
| CWE-399 | 601 | Resource management |
| CWE-189 | 495 | Numeric errors |
| CWE-416 | 476 | Use after free |
| CWE-190 | 459 | Integer overflow |
