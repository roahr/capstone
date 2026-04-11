# SEC-C Live Demo — Complete Feature Walkthrough

Step-by-step guide for demonstrating the SEC-C framework during review.
Every CLI command, output format, and feature is covered.

---

## Part A: Framework Overview

### A1. Version
```bash
sec-c version
```
Shows: SEC-C v2.0.0

### A2. Configuration
```bash
sec-c config
```
Shows: Loaded YAML configuration (cascade thresholds, GNN params, LLM settings)

### A3. Framework Status
```bash
sec-c status
```
Expected output:
- Stage 1: CodeQL (Available), Tree-sitter (5 languages)
- Stage 2: Joern (Available), MiniGINv3 Model (Trained, 9326 KB)
- Stage 3: Gemini (Ready, 3 keys)
- RAG: CWE catalog (969 entries), NVD CVEs (106K), Templates (12)

### A4. LLM Provider Details
```bash
sec-c providers
sec-c models
```
Shows: Available LLM providers (Gemini/Groq) and models per provider.

---

## Part B: Cascade Demo (5 Scans)

### B1. Stage 1 — SAST Resolution (Fast, Simple Vulns)
```bash
sec-c scan Vulnerable_Repos/09_chatbridge/ --stage sast
```
Expected:
- 3-4 findings (XSS, SQL injection, eval injection)
- 100% resolved at Stage 1
- Demonstrates: Tree-sitter pattern matching + CodeQL taint analysis
- Scan time: ~10 seconds

**Talking point**: "Clear vulnerability patterns are resolved at the cheapest stage. No GNN or LLM resources wasted."

### B2. Stage 2 — GNN Escalation (Complex Taint Flows)
```bash
sec-c scan Vulnerable_Repos/01_taskflow/ --stage graph
```
Expected:
- 8-10 findings total
- ~70% resolved at SAST, some escalated to GNN
- GNN builds code property graph, runs MiniGINv3 inference
- Conformal prediction produces singleton or ambiguous sets

**Talking point**: "Multi-hop taint flows trigger escalation. The GNN analyzes the code graph structure and conformal prediction provides statistical routing guarantees."

### B3. Stage 3 — Full Cascade (LLM Dual-Agent)
```bash
sec-c scan Vulnerable_Repos/04_docvault/
```
Expected:
- Findings flow through all 3 stages
- SAST catches clear patterns (path traversal, hardcoded key)
- GNN processes complex SQL injection through auth chain
- LLM dual-agent analyzes subtle info exposure (CWE-209)
- Attacker/Defender verdicts and CVSS scores visible

**Talking point**: "Ambiguous findings reach the LLM for dual-agent consensus. The Attacker agent constructs exploit scenarios while the Defender identifies mitigations."

### B4. C/C++ Memory Safety (GNN Strength)
```bash
sec-c scan Vulnerable_Repos/12_sysmon/
```
Expected:
- Buffer overflow, format string, use-after-free detected
- GNN trained on 20K C/C++ samples — strongest language
- Conformal prediction sets show model confidence

**Talking point**: "Memory safety vulnerabilities are the GNN's strongest category. CWE-476 achieves F1=0.93, CWE-787 achieves F1=0.90 in our evaluation."

### B5. Go Language Support
```bash
sec-c scan Vulnerable_Repos/14_configsvc/
```
Expected:
- SQL injection, command injection, path traversal in Go
- Demonstrates multi-language cascade capability

**Talking point**: "The framework supports 5 languages. Tree-sitter provides AST analysis, CodeQL provides taint tracking, and GraphCodeBERT embeddings are language-agnostic."

---

## Part C: Output Formats

### C1. Console Table (Default)
```bash
sec-c scan Vulnerable_Repos/03_mailbridge/
```
Shows: Cascade breakdown table, findings with CWE/severity/verdict columns.

### C2. SARIF Output (Machine-Readable)
```bash
sec-c scan Vulnerable_Repos/06_dataflow/ --output results.sarif
```
Shows: SARIF 2.1.0 file generated. Open in VS Code SARIF Viewer or text editor to show:
- `runs[].results[]` with rule IDs, locations, severity
- Custom `sec-c/*` properties (uncertainty scores, conformal sets, cascade stage)

### C3. HTML Interactive Dashboard
```bash
sec-c scan Vulnerable_Repos/07_shopfront/ --dashboard
```
Shows: Browser opens with interactive dashboard. Features:
- Findings table with sorting/filtering
- Cascade breakdown chart
- Per-CWE distribution
- Finding details with code snippets

### C4. Display Existing Report
```bash
sec-c report results.sarif
sec-c report results.sarif --dashboard
```
Shows: Re-display or re-render a previously saved SARIF report.

---

## Part D: Advanced Features

### D1. Language Filtering
```bash
sec-c scan Vulnerable_Repos/ --languages py
```
Shows: Only Python files analyzed across all repos.

### D2. Stage Comparison (Same Repo, Different Depth)
```bash
sec-c scan Vulnerable_Repos/01_taskflow/ --stage sast
sec-c scan Vulnerable_Repos/01_taskflow/ --stage graph
sec-c scan Vulnerable_Repos/01_taskflow/
```
Shows: Progressive analysis depth — more findings resolved at deeper stages.

### D3. Verbose Mode (Debug Output)
```bash
sec-c scan Vulnerable_Repos/05_authkit/ --verbose
```
Shows: Detailed output including:
- Uncertainty score breakdown (confidence, complexity, novelty, conflict factors)
- Taint path details
- Conformal prediction internals (APS scores, temperature, threshold)
- GNN inference timing

---

## Part E: Interactive REPL

### E1. Launch
```bash
sec-c
```
Shows: Interactive prompt with tab-autocomplete for commands and file paths.

### E2. REPL Session Demo
```
SEC-C> /status
SEC-C> /scan Vulnerable_Repos/02_pymetrics/
SEC-C> /scan Vulnerable_Repos/10_inventoryapi/ --stage graph --verbose
SEC-C> /report results.sarif
SEC-C> /history
SEC-C> /config
SEC-C> /help
SEC-C> /clear
SEC-C> exit
```

---

## Part F: Saved Scan Results & Artifacts

### F1. Benchmark SARIF Files (all 15 repos)

All benchmark scans are saved as SARIF 2.1.0 files:

```
data/
  _benchmark_01_taskflow.sarif
  _benchmark_02_pymetrics.sarif
  _benchmark_03_mailbridge.sarif
  _benchmark_04_docvault.sarif
  _benchmark_05_authkit.sarif
  _benchmark_06_dataflow.sarif
  _benchmark_07_shopfront.sarif
  _benchmark_08_logstream.sarif
  _benchmark_09_chatbridge.sarif
  _benchmark_10_inventoryapi.sarif
  _benchmark_11_reportgen.sarif
  _benchmark_12_sysmon.sarif
  _benchmark_13_netprobe.sarif
  _benchmark_14_configsvc.sarif
  _benchmark_15_filesync.sarif
```

**View any saved result:**
```bash
sec-c report data/_benchmark_04_docvault.sarif           # Console table
sec-c report data/_benchmark_04_docvault.sarif --dashboard    # HTML dashboard
sec-c report data/_benchmark_02_pymetrics.sarif --dashboard   # Another repo
```

### F2. Generating New Reports During Demo
```bash
# Scan + save SARIF + open HTML in one command
sec-c scan Vulnerable_Repos/04_docvault/ --output data/demo_docvault.sarif --dashboard

# Later, re-display the saved result
sec-c report data/demo_docvault.sarif
sec-c report data/demo_docvault.sarif --dashboard
```

### F3. Benchmark Metrics Files
```
docs/Test_Check/
  benchmark_results.md       # Summary table (auto-generated)
  per_repo_results.json      # Raw JSON with all finding details
  cascade_analysis.md        # Per-stage breakdown
  final_demo.md              # Ranked demo order + minute-by-minute script
```

### F4. Key Metrics to Highlight
- **Total repos tested**: 15 (6 Python, 3 JS, 2 Java, 2 C/C++, 2 Go)
- **Total findings**: 184 across all repos
- **Cascade**: 85% SAST, 2% GNN, 12% LLM, 0% unresolved
- **LLM savings**: 87% fewer API calls vs non-cascaded approach
- **GNN model**: MiniGINv3, F1=0.75, AUC=0.78, trained on 21K graphs
- **Conformal**: APS with ConfTS (T=0.95, threshold=0.95, alpha=0.1)
- **Novel**: First APS conformal prediction for vulnerability detection

---

## Recommended Demo Order (15 minutes)

| Time | Action | Purpose |
|------|--------|---------|
| 0:00 | `sec-c status` | Show all components available |
| 0:30 | `sec-c scan Vulnerable_Repos/12_sysmon/ --stage sast` | Stage 1 resolution (C, fast, 16s) |
| 1:30 | `sec-c scan Vulnerable_Repos/04_docvault/` | Full 3-stage cascade (~58s) |
| 4:00 | `sec-c scan Vulnerable_Repos/02_pymetrics/ --verbose` | GNN conformal detail (~95s) |
| 7:00 | `sec-c scan Vulnerable_Repos/14_configsvc/` | Multi-language Go (~85s) |
| 9:00 | `sec-c report data/_benchmark_07_shopfront.sarif --dashboard` | HTML dashboard (instant, pre-saved) |
| 10:00 | `sec-c scan Vulnerable_Repos/06_dataflow/ --output demo.sarif` | SARIF output |
| 11:00 | `sec-c report demo.sarif` | Re-display saved report |
| 12:00 | Show `docs/Test_Check/benchmark_results.md` | Pre-computed metrics table |
| 13:00 | `sec-c` → `/status` → `/scan Vulnerable_Repos/09_chatbridge/` → `/help` → `exit` | REPL |
| 14:30 | `sec-c version` / `sec-c config` | Framework info |

**Tip**: Use pre-saved SARIFs (`sec-c report data/_benchmark_*.sarif --dashboard`) for
instant HTML dashboards without waiting for live scans.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| CodeQL slow (>60s) | Normal for first scan — database creation. Say "first scan creates analysis database" |
| "MiniGINv3 Not Trained" | Run: `cp notebooks/Kaggle_sec_c_gnn_v4_improved/mini_gat_v3.pt data/models/mini_gin_v3.pt` |
| "No LLM provider" | Set `GEMINI_API_KEY` in `.env` file |
| "Joern not found" | Optional — framework degrades gracefully. Stage 2 still runs GNN. |
| Stage 2 shows 0 GNN resolved | Expected for simple vulns. Use 04_docvault or 02_pymetrics for GNN demo. |
| LLM timeout | Gemini rate limit — wait 10s, or use pre-saved: `sec-c report data/_benchmark_*.sarif` |
| Want instant HTML | Use pre-saved: `sec-c report data/_benchmark_04_docvault.sarif --dashboard` (no scan needed) |
