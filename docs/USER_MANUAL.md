# SEC-C User Manual

> Every command, flag, and feature documented.

**SEC-C v2.0.0** -- Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection.

---

## Table of Contents

1. [Quick Reference Card](#quick-reference-card)
2. [Direct CLI Mode](#direct-cli-mode)
   - [sec-c scan](#sec-c-scan)
   - [sec-c report](#sec-c-report)
   - [sec-c status](#sec-c-status)
   - [sec-c providers](#sec-c-providers)
   - [sec-c models](#sec-c-models)
   - [sec-c version](#sec-c-version)
   - [sec-c config](#sec-c-config)
3. [Interactive REPL Mode](#interactive-repl-mode)
   - [Launching the REPL](#launching-the-repl)
   - [REPL Commands](#repl-commands)
   - [Tab Autocomplete](#tab-autocomplete)
   - [Command History](#command-history)
   - [File Path Completion](#file-path-completion)
4. [Output Formats](#output-formats)
   - [Console Output](#console-output)
   - [SARIF 2.1.0](#sarif-210)
   - [HTML Dashboard](#html-dashboard)
5. [Environment Variables Reference](#environment-variables-reference)
6. [Configuration File Reference](#configuration-file-reference)

---

## Quick Reference Card

### Direct CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `sec-c` | Launch interactive REPL | `sec-c` |
| `sec-c scan <path>` | Scan local code | `sec-c scan ./src` |
| `sec-c scan -g <owner/repo>` | Scan GitHub repo | `sec-c scan -g django/django` |
| `sec-c scan --stage sast` | SAST only (fastest) | `sec-c scan ./src -s sast` |
| `sec-c scan --stage graph` | SAST + Graph | `sec-c scan ./src -s graph` |
| `sec-c scan --stage llm` | Full cascade (default) | `sec-c scan ./src -s llm` |
| `sec-c scan --dashboard` | Generate HTML dashboard | `sec-c scan ./src --dashboard` |
| `sec-c scan -o file.sarif` | Save SARIF report | `sec-c scan ./src -o results.sarif` |
| `sec-c report <file.sarif>` | Display SARIF report | `sec-c report results.sarif` |
| `sec-c report --dashboard` | SARIF to HTML | `sec-c report results.sarif --dashboard` |
| `sec-c status` | Tool availability | `sec-c status` |
| `sec-c providers` | LLM provider details | `sec-c providers` |
| `sec-c models` | List available models | `sec-c models` |
| `sec-c version` | Version and build info | `sec-c version` |
| `sec-c config` | Show configuration | `sec-c config` |

### Interactive REPL Commands

| Command | Description |
|---------|-------------|
| `/scan <path>` | Scan local code |
| `/scan --github <owner/repo>` | Scan GitHub repo |
| `/report <file.sarif>` | Display SARIF report |
| `/status` | Framework status |
| `/providers` | LLM provider details |
| `/models` | List available models |
| `/config` | Show configuration |
| `/history` | Recent command history |
| `/version` | Version and build info |
| `/help` | Show help |
| `/clear` | Clear the screen |
| `exit` / `quit` / Ctrl+D | Exit SEC-C |

### Key Flags Summary

| Flag | Short | Values | Default | Description |
|------|-------|--------|---------|-------------|
| `--stage` | `-s` | `sast`, `graph`, `llm` | `llm` | Maximum cascade stage to execute |
| `--github` | `-g` | `owner/repo` | -- | Scan a GitHub repository instead of local path |
| `--languages` | `-l` | `python,javascript,java,cpp,go` | auto-detect | Comma-separated list of languages to scan |
| `--output` | `-o` | file path | -- | Save SARIF report to file |
| `--dashboard` | -- | flag | `false` | Generate interactive HTML dashboard |
| `--verbose` | `-v` | flag | `false` | Enable debug-level logging |
| `--config` | `-c` | file path | `configs/default.yaml` | Custom configuration file |

---

## Direct CLI Mode

Direct CLI mode executes a single command and exits. All commands are invoked as `sec-c <command> [arguments] [options]`.

---

### sec-c scan

Run a SEC-C security scan with uncertainty-driven cascade.

**Syntax:**
```
sec-c scan [TARGET] [OPTIONS]
```

**Arguments:**

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `TARGET` | `TEXT` | No (but see note) | Path to a local code directory or individual file. Either `TARGET` or `--github` must be provided. |

**Options:**

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--github` | `-g` | `TEXT` | -- | GitHub repository in `owner/repo` format. SEC-C clones and scans it. Requires `GITHUB_TOKEN` for private repos. |
| `--stage` | `-s` | `TEXT` | `llm` | Maximum cascade stage to execute. `sast` runs only Stage 1 (Tree-sitter + CodeQL). `graph` runs Stages 1-2 (adds Mini-GAT validation). `llm` runs all three stages (adds dual-agent LLM consensus). |
| `--languages` | `-l` | `TEXT` | auto-detect | Comma-separated list of languages to scan. Valid values: `python`, `javascript`, `java`, `cpp`, `go`. If omitted, SEC-C auto-detects languages from file extensions in the target. |
| `--output` | `-o` | `TEXT` | -- | File path for SARIF 2.1.0 output. Parent directories are created automatically. |
| `--dashboard` | -- | `BOOL` | `False` | Generate a self-contained interactive HTML dashboard and open it in the default browser. |
| `--verbose` | `-v` | `BOOL` | `False` | Enable debug-level logging. Shows stage timing, API calls, uncertainty scores, and internal pipeline details. |
| `--config` | `-c` | `TEXT` | `configs/default.yaml` | Path to a custom YAML configuration file. Overrides the default configuration. |

**Examples:**

```bash
# Scan a local directory with full cascade (default --stage llm)
sec-c scan ./my-project

# Scan a single file with SAST only
sec-c scan ./my-project/app.py --stage sast

# Scan with HTML dashboard output
sec-c scan ./my-project --stage sast --dashboard

# Scan a GitHub repository (Python only)
sec-c scan --github django/django --languages python

# Full scan with SARIF output and verbose logging
sec-c scan ./src --output results.sarif --verbose

# Scan specific languages with all outputs
sec-c scan ./project --languages python,javascript --output report.sarif --dashboard

# Scan with a custom config file
sec-c scan ./src --config configs/strict.yaml

# Graph stage only (SAST + GNN, no LLM)
sec-c scan ./project --stage graph
```

**Expected Output:**

1. **Scan header**: Shows target, detected languages, and active pipeline stages
2. **Stage progress**: Real-time progress for each active stage (SAST, Graph, LLM)
3. **Findings table**: Color-coded table grouped by verdict tier (Confirmed, Likely, Potential, Safe)
4. **Cascade statistics**: Bar chart showing how many findings were resolved at each stage
5. **Summary panel**: Total findings count by verdict tier with cascade efficiency percentage

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully (regardless of findings) |
| 1 | Invalid arguments (no target or `--github` provided, unknown language) |

**Notes:**
- Either `TARGET` or `--github` must be provided; specifying neither produces an error.
- Unknown languages in `--languages` are skipped with a warning (the scan continues).
- If `--dashboard` is not specified but findings are found, SEC-C prints a tip suggesting the `--dashboard` flag.
- The scan target can be a single file or a directory. Directories are scanned recursively.

---

### sec-c report

Display a formatted report from an existing SARIF file.

**Syntax:**
```
sec-c report <SARIF_FILE> [OPTIONS]
```

**Arguments:**

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `SARIF_FILE` | `TEXT` | Yes | Path to a SARIF 2.1.0 JSON file to display. |

**Options:**

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--dashboard` | -- | `BOOL` | `False` | Generate an interactive HTML dashboard from the SARIF file and open it in the browser. |
| `--verbose` | `-v` | `BOOL` | `False` | Enable debug logging. |

**Examples:**

```bash
# Display SARIF report in the console
sec-c report results.sarif

# Convert SARIF to interactive HTML dashboard
sec-c report results.sarif --dashboard

# Verbose console display
sec-c report results.sarif --verbose
```

**Expected Output:**

Without `--dashboard`: A console report identical in format to `sec-c scan` output, showing the findings table, verdict tiers, and summary.

With `--dashboard`: Opens a self-contained HTML dashboard in the default browser and prints the file path.

---

### sec-c status

Show SEC-C tool availability and API configuration status.

**Syntax:**
```
sec-c status
```

**Arguments:** None.

**Options:** None.

**Examples:**

```bash
sec-c status
```

**Expected Output:**

A table with the following sections:

| Section | Components Shown |
|---------|-----------------|
| **Stage 1: SAST** | CodeQL CLI (path or "Not Found"), Tree-sitter (always available, shows 5 languages) |
| **Stage 2: Graph** | Joern (path or "Not Installed"), Mini-GAT Model (file size or "Not Trained") |
| **Stage 3: LLM** | Gemini (key count, active marker), Groq (key count, active marker), Active Provider (name + model override) |
| **RAG Knowledge** | CWE Catalog (entry count), NVD CVE Data (CVE count), CWE Templates (template count) |
| **Infrastructure** | GitHub Token (set/not set), Compute (GPU name or "CPU only") |

Each component shows one of: `Available`, `Ready`, `Set` (green), `Not Found`, `Not Installed`, `Not Trained`, `No Key`, `Not Set` (red/dim), or specific values.

---

### sec-c providers

Show LLM provider details and available models.

**Syntax:**
```
sec-c providers
```

**Arguments:** None.

**Options:** None.

**Examples:**

```bash
sec-c providers
```

**Expected Output:**

A table with columns: Provider, Status, API Key (preview), Default Model, Free Tier.

- The active provider is marked with `[*]`
- Shows whether each provider is configured (has API key) or not
- Displays the default model for each provider
- Shows free tier rate limits
- Below the table: active provider name, any model override from `LLM_MODEL`, and instructions to change

---

### sec-c models

List available models per LLM provider.

**Syntax:**
```
sec-c models
```

**Arguments:** None.

**Options:** None.

**Examples:**

```bash
sec-c models
```

**Expected Output:**

A table with columns: Provider, Model, Free RPD, Notes.

**Gemini models listed:**

| Model | Free RPD | Notes |
|-------|----------|-------|
| `gemini-2.5-flash` | 250 | Primary (recommended) |
| `gemini-2.5-flash-lite` | 1,000 | Lighter, higher quota |
| `gemini-2.5-pro` | 0 | Removed from free tier |

**Groq models listed:**

| Model | Free RPD | Notes |
|-------|----------|-------|
| `llama-3.3-70b-versatile` | 1,000 | Best quality (recommended) |
| `llama-3.1-8b-instant` | 14,400 | Fastest, lower quality |
| `qwen/qwen3-32b` | 1,000 | Strong reasoning |
| `meta-llama/llama-4-scout-17b-16e-instruct` | 1,000 | Latest Llama 4 |

Below the table: instructions to set model via `LLM_MODEL` in `.env`.

---

### sec-c version

Show SEC-C version and build information.

**Syntax:**
```
sec-c version
```

**Arguments:** None.

**Options:** None.

**Examples:**

```bash
sec-c version
```

**Expected Output:**

```
  Sec-C v2.0.0
  Multi-Stage Code Security Framework

  Python:     3.11.x
  Platform:   win32
  Source:     XX files
  Tests:      XX files
  Templates:  XX CWE-specific prompts
```

Shows the framework version, Python version, platform, and counts of source files, test files, and CWE-specific Jinja2 prompt templates.

---

### sec-c config

Show current SEC-C configuration.

**Syntax:**
```
sec-c config [OPTIONS]
```

**Options:**

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--config` | `-c` | `TEXT` | `configs/default.yaml` | Path to a custom config file to display. |

**Examples:**

```bash
# Show default configuration
sec-c config

# Show a custom config
sec-c config --config configs/strict.yaml
```

**Expected Output:**

The full configuration YAML rendered as formatted JSON in the terminal. Shows all sections: framework, languages, sast, graph, llm, orchestrator, and reporting.

---

## Interactive REPL Mode

### Launching the REPL

Run `sec-c` with no arguments to launch the interactive Read-Eval-Print Loop:

```bash
sec-c
```

The REPL displays the full SEC-C ASCII art banner inside a bordered panel, then presents a prompt:

```
sec-c > C:\Users\you\project >
```

The prompt shows `sec-c` followed by the current working directory (truncated to 40 characters if longer, with `~` replacing the home directory path).

### REPL Commands

Commands can be entered with or without a leading `/`. Both `scan` and `/scan` work identically.

---

#### /scan

Scan a local directory or file for vulnerabilities.

**Syntax:**
```
/scan <path> [--github <owner/repo>] [--stage <sast|graph|llm>] [--languages <langs>] [--output <file>] [--verbose]
```

All flags work identically to the direct CLI `sec-c scan` command, except `--dashboard` is not available in REPL mode (use `/report --dashboard` on the saved SARIF file instead).

**Example interaction:**
```
sec-c > ~/projects > /scan ./my-app --stage sast

  >> Target    ./my-app
  >> Languages auto-detect
  >> Pipeline  [>] SAST

  [scanning progress bars...]

  Findings table and summary displayed inline.
```

In REPL mode, the scan shows animated progress bars for each stage before displaying results inline.

---

#### /report

Display a SARIF report file.

**Syntax:**
```
/report <file.sarif>
```

**Example interaction:**
```
sec-c > ~/projects > /report results.sarif

  [Findings table displayed inline]
```

If no file is specified, prints a usage message: `Usage: report <file.sarif>`.

The REPL report command always uses verbose mode (shows detailed finding information including code snippets, explanations, and remediation).

---

#### /status

Show framework status and tool availability.

**Syntax:**
```
/status
```

Displays the same status table as `sec-c status` (see [sec-c status](#sec-c-status)).

---

#### /providers

Show LLM provider details.

**Syntax:**
```
/providers
```

Displays the same provider table as `sec-c providers`.

---

#### /models

List available models per provider.

**Syntax:**
```
/models
```

Displays the same models table as `sec-c models`.

---

#### /config

Show current configuration.

**Syntax:**
```
/config
```

Loads configuration from `configs/default.yaml` and displays it as formatted JSON.

---

#### /history

Show recent command history.

**Syntax:**
```
/history
```

Displays the last 15 commands from the REPL history file.

**Example interaction:**
```
sec-c > ~/projects > /history
    > /scan ./my-app --stage sast
    > /status
    > /scan ./other-project --stage llm
    > /providers
```

---

#### /version

Show SEC-C version and build information.

**Syntax:**
```
/version
```

Displays the same version info as `sec-c version`.

---

#### /help

Show the help table listing all available commands.

**Syntax:**
```
/help
```

**Expected Output:**

A bordered table with two columns (Command, Description) listing all available commands:

| Command | Description |
|---------|-------------|
| `/scan <path>` | Scan local code (full cascade) |
| `/scan --github <owner/repo>` | Scan a GitHub repository |
| `/scan --stage <sast\|graph\|llm>` | Run up to a specific stage |
| `/scan --languages <py,js,java>` | Scan specific languages only |
| `/scan --output <file.sarif>` | Save SARIF report to file |
| `/scan --dashboard` | Generate interactive HTML dashboard |
| `/report <file.sarif>` | Display a SARIF report |
| `/status` | Framework status + tool availability |
| `/providers` | LLM provider details + API usage stats |
| `/models` | List available models per provider |
| `/config` | Show current configuration |
| `/history` | Show recent command history |
| `/version` | Show SEC-C version and build info |
| `/clear` | Clear the screen |
| `/help` | Show this help |
| `exit / quit / Ctrl+D` | Exit SEC-C |

Below the table: `Tip: Use Tab for autocomplete, Up/Down for command history`

---

#### /clear

Clear the terminal screen and redisplay the mini banner.

**Syntax:**
```
/clear
```

After clearing, the compact one-line banner (`Sec-C v2.0.0`) is shown.

---

#### exit / quit / Ctrl+D

Exit the interactive REPL.

Any of `exit`, `quit`, or pressing Ctrl+D ends the session with a `Goodbye!` message.

---

### Tab Autocomplete

The REPL provides intelligent tab completion powered by `prompt_toolkit`.

**How it works:**

1. **Command completion**: When the cursor is at the start of a line or on the first word, pressing Tab shows all available commands with descriptions:
   - `/scan` -- "Scan a local directory or file for vulnerabilities"
   - `/scan --github` -- "Scan a GitHub repository"
   - `/scan --stage sast` -- "Run SAST stage only"
   - `/scan --stage graph` -- "Run up to Graph stage"
   - `/scan --stage llm` -- "Run full pipeline"
   - `/scan --languages` -- "Specify languages to scan"
   - `/report` -- "Display a SARIF report file"
   - `/status` -- "Framework status + tool availability"
   - `/providers` -- "LLM provider details + usage stats"
   - `/models` -- "List available models per provider"
   - `/config` -- "Show current configuration"
   - `/history` -- "Show recent command history"
   - `/version` -- "Show SEC-C version and build info"
   - `/help` -- "Show available commands"
   - `/clear` -- "Clear the screen"
   - `exit` -- "Exit SEC-C"
   - `quit` -- "Exit SEC-C"
   - Commands also work without the `/` prefix: `scan`, `status`, `providers`, `models`, `help`

2. **Flag completion**: After `/scan` or `/report`, pressing Tab on a `--` prefix shows available flags:
   - `--github`, `--stage`, `--languages`, `--output`, `--verbose`

3. **File path completion**: After `/scan` or `/report`, pressing Tab on non-flag text triggers file system path completion. The completer filters to show only:
   - Directories
   - Source code files: `.py`, `.js`, `.ts`, `.java`, `.c`, `.cpp`, `.go`, `.h`

4. **Fuzzy matching**: Partial command input is fuzzy-matched against all completions.

5. **Auto-suggest from history**: As you type, the REPL shows a dim suggestion from your command history that you can accept with the right arrow key.

### Command History

- **Storage location**: `~/.sec-c/history` (the `~/.sec-c/` directory is created automatically on first REPL launch)
- **Persistence**: History persists across REPL sessions
- **Navigation**: Use Up/Down arrow keys to navigate through previous commands
- **Auto-suggest**: Previously entered commands appear as dim suggestions while typing; press Right Arrow to accept
- **View recent**: Use `/history` to display the last 15 entries

### File Path Completion

When entering a path argument after `/scan` or `/report`:

- Tab completes directory and file names from the file system
- Supports `~` expansion for home directory
- Filters to show only directories and recognized source code files (`.py`, `.js`, `.ts`, `.java`, `.c`, `.cpp`, `.go`, `.h`)
- Works on Windows (backslash paths), Linux, and macOS

---

## Output Formats

SEC-C produces three output formats: console (default), SARIF 2.1.0, and HTML dashboard.

### Console Output

Console output is the default and is always displayed (unless output is redirected).

#### Findings Table

Findings are grouped by verdict tier and displayed in separate tables. Each table has these columns:

| Column | Width | Description |
|--------|-------|-------------|
| **Severity** | 10 | Vulnerability severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| **CWE** | 10 | Common Weakness Enumeration ID (e.g., `CWE-89`) |
| **Location** | 35 | File path and line number (e.g., `src/app.py:42`) |
| **Message** | 45 | SAST finding description (truncated to 45 characters) |
| **Score** | 8 | Fused confidence score from 0.00 to 1.00 |
| **Stage** | 8 | Which cascade stage resolved this finding: `sast`, `graph`, or `llm` |

Tables are displayed in verdict priority order:
1. **Confirmed** findings first (highest risk)
2. **Likely** findings
3. **Potential** findings
4. **Safe** findings last (false positives filtered by the cascade)

#### Cascade Statistics

When `show_cascade_stats` is enabled (default: true), a statistics table shows how many findings were resolved at each stage:

| Column | Description |
|--------|-------------|
| **Stage** | Stage name: "SAST (Stage 1)", "Graph (Stage 2)", "LLM (Stage 3)", "Unresolved" |
| **Resolved** | Number of findings resolved at this stage |
| **Percentage** | Percentage of total findings |
| **Bar** | Visual bar chart using `#` (filled) and `-` (empty), 25 characters wide |

Bar colors: Stage 1 = green, Stage 2 = cyan, Stage 3 = yellow, Unresolved = red.

#### Severity Colors

| Severity | Console Color |
|----------|--------------|
| CRITICAL | **Bold red** |
| HIGH | Red |
| MEDIUM | Yellow |
| LOW | Cyan |
| INFO | Dim (gray) |

#### Verdict Icons (from `banner.py`)

These ASCII-safe icons appear in console output and stage markers:

**Stage icons:**

| Stage | Icon | Color |
|-------|------|-------|
| SAST | `[>]` | Bold green |
| Graph | `[*]` | Bold cyan |
| LLM | `[@]` | Bold yellow |
| Report | `[#]` | Bold magenta |

**Severity icons:**

| Severity | Icon | Color |
|----------|------|-------|
| Critical | `[!!]` | Bold red |
| High | `[!]` | Red |
| Medium | `[~]` | Yellow |
| Low | `[-]` | Cyan |
| Info | `[.]` | Dim |

**Verdict icons:**

| Verdict | Icon | Color |
|---------|------|-------|
| Confirmed | `[X]` | Bold red |
| Likely | `[?]` | Yellow |
| Potential | `[~]` | Cyan |
| Safe | `[OK]` | Green |
| Unknown | `[--]` | Dim |

#### Verbose Mode

With `--verbose` (`-v`), additional detail is printed for each Confirmed and Likely finding:

- Full CWE name and ID
- File location and rule ID
- Fused confidence score (3 decimal places)
- Code snippet (if available)
- Natural language explanation (from LLM stage, if available)
- Remediation suggestion (if available)

#### Summary Panel

A bordered panel at the end shows:

- Total findings count
- Count by verdict: Confirmed (red), Likely (yellow), Potential (cyan), Safe (green)
- Cascade efficiency: percentage of findings resolved at Stage 1

---

### SARIF 2.1.0

SARIF (Static Analysis Results Interchange Format) version 2.1.0 is the standardized output format. Generate it with `--output <file.sarif>`.

#### Standard SARIF Fields

The SARIF output follows the [OASIS SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and is compatible with:

- GitHub Code Scanning (Security tab)
- VS Code SARIF Viewer extension
- Azure DevOps
- Any SARIF 2.1.0 consumer

**Structure:**

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "sec-c",
        "version": "2.0.0",
        "rules": [...]
      }
    },
    "results": [...],
    "invocations": [...]
  }]
}
```

Each result includes:

| Field | Type | Description |
|-------|------|-------------|
| `ruleId` | string | Unique rule identifier |
| `level` | string | SARIF severity: `error` (critical/high), `warning` (medium), `note` (low/info) |
| `kind` | string | SARIF kind: `fail` (confirmed/likely), `review` (potential), `pass` (safe), `open` (unknown) |
| `message.text` | string | SAST finding description |
| `locations` | array | File path, line numbers, column numbers, code snippet |
| `codeFlows` | array | Taint flow steps from source to sink (when available) |
| `properties` | object | SEC-C custom properties (see below) |

#### SEC-C Custom Properties

All custom properties are namespaced under `sec-c/` and included when `reporting.sarif.include_custom_properties` is `true` (the default).

| Property | Type | Stage | Description |
|----------|------|-------|-------------|
| `sec-c/verdict` | string | All | Final three-tier classification: `confirmed`, `likely`, `potential`, `safe`, or `unknown`. Based on fused score thresholds: confirmed >= 0.85, likely >= 0.50, potential < 0.50. |
| `sec-c/fused_confidence` | float | All | Final fused confidence score (0.0 to 1.0). Weighted combination of SAST (0.3), Graph (0.3), and LLM (0.4) scores. Higher = more likely a true vulnerability. |
| `sec-c/stage_resolved` | string | All | Which cascade stage resolved this finding: `sast`, `graph`, or `llm`. Findings with low uncertainty are resolved early; high-uncertainty findings escalate to later stages. |
| `sec-c/uncertainty_score` | float | Stage 1+ | Composite uncertainty score from the SAST stage (0.0 to 1.0). Computed from 4 weighted factors: confidence (0.4), complexity (0.3), novelty (0.2), conflict (0.1). Findings above the escalation threshold (default 0.5) are escalated to the next stage. |
| `sec-c/structural_risk` | float | Stage 2+ | Graph-based structural risk score from the Mini-GAT model (0.0 to 1.0). Measures vulnerability patterns in Code Property Graph structure. Only present when Stage 2 runs. |
| `sec-c/conformal_prediction_set` | array | Stage 2+ | Calibrated prediction set from conformal prediction (APS method). Contains one or more labels from `["vulnerable", "safe"]` with a 90% coverage guarantee (alpha=0.1). A set of `["vulnerable", "safe"]` indicates high uncertainty. Only present when Stage 2 runs. |
| `sec-c/conformal_coverage` | float | Stage 2+ | Empirical coverage of the conformal prediction calibration set (0.0 to 1.0). Should be close to `1 - alpha` (0.9). Only present when Stage 2 runs. |
| `sec-c/attacker_verdict` | object | Stage 3 | Red team analysis from the attacker LLM agent. Contains `exploitable` (boolean: whether an exploit could be constructed) and `confidence` (float: agent's confidence in its assessment). Only present when Stage 3 runs. |
| `sec-c/defender_verdict` | object | Stage 3 | Blue team analysis from the defender LLM agent. Contains `defense_coverage_score` (float: how well existing defenses mitigate the vulnerability) and `path_feasible` (boolean: whether the taint path is actually reachable). Only present when Stage 3 runs. |
| `sec-c/nl_explanation` | string | Stage 3 | Natural language explanation of the vulnerability and its analysis (up to 2000 characters). Generated by the LLM consensus engine. Only present when Stage 3 runs. |
| `sec-c/model_used` | string | Stage 3 | The LLM model that analyzed this finding (e.g., `gemini-2.5-flash`, `llama-3.3-70b-versatile`). Only present when Stage 3 runs. |
| `sec-c/remediation` | string | Stage 3 | Suggested fix or mitigation for the vulnerability. Only present when the LLM provides a remediation suggestion. |

#### Invocation Properties

The SARIF `invocations` section includes cascade statistics:

```json
{
  "properties": {
    "sec-c/cascade_stats": {
      "total_findings": 42,
      "resolved_at_sast": 28,
      "resolved_at_graph": 8,
      "resolved_at_llm": 4,
      "unresolved": 2,
      "cascade_efficiency": "66.7%",
      "scan_duration_ms": 15234
    }
  }
}
```

---

### HTML Dashboard

Generate with `--dashboard` flag on either `sec-c scan` or `sec-c report`.

#### What It Shows

The HTML dashboard is a single self-contained file with no external dependencies (all CSS, JavaScript, and SVG icons are inlined).

**Sections:**

1. **Executive Summary Header**: Scan target, timestamp, framework version, and scan duration

2. **Metric Cards** (top row):
   - Total Findings count
   - Confirmed Vulnerabilities count (red)
   - Cascade Efficiency percentage
   - Scan Duration

3. **Cascade Pipeline Visualization**: Visual representation of the 3-stage pipeline showing:
   - Stage icons (SAST > Graph > LLM)
   - Number of findings entering and resolved at each stage
   - Flow arrows between stages

4. **Severity Distribution Chart**: Bar chart showing finding counts per severity level (Critical, High, Medium, Low, Info)

5. **Verdict Distribution Chart**: Visual breakdown of findings by verdict (Confirmed, Likely, Potential, Safe)

6. **Findings Table**: Sortable, filterable table with columns:
   - Severity (color-coded badge)
   - CWE ID
   - Location (file:line)
   - Message
   - Verdict (color-coded badge)
   - Fused Score
   - Stage Resolved

7. **Finding Detail Modals**: Clicking a finding row opens a detail panel showing:
   - Full SAST message
   - Code snippet
   - Uncertainty breakdown (confidence, complexity, novelty, conflict)
   - Graph validation results (structural risk, conformal prediction set)
   - LLM attacker/defender verdicts
   - Natural language explanation
   - Remediation suggestion

#### How to Open

```bash
# During scan -- opens automatically in default browser
sec-c scan ./project --dashboard

# From existing SARIF file
sec-c report results.sarif --dashboard
```

The HTML file is saved to a temporary directory and opened automatically via `webbrowser.open()`. The file path is printed to the console.

#### Characteristics

- **Self-contained**: Single `.html` file with all CSS, JS, and SVG inlined. No CDN dependencies, no internet required to view.
- **Interactive**: Tables are sortable and filterable. Finding rows are clickable for detail views.
- **Print-friendly**: Includes a print stylesheet for PDF export via browser print (Ctrl+P).
- **Professional styling**: Dark theme with color-coded severity badges and verdict indicators. Designed for presentation to security stakeholders.

---

## Environment Variables Reference

All environment variables are loaded from the `.env` file in the project root. SEC-C uses a built-in `.env` loader (no `python-dotenv` dependency needed). Variables already set in the shell environment take precedence over `.env` file values.

Copy `.env.example` to `.env` to get started:
```bash
cp .env.example .env
```

### Complete Variable Reference

| Variable | Default | Required | Purpose | Example |
|----------|---------|----------|---------|---------|
| `LLM_PROVIDER` | `gemini` | No | Selects which LLM provider to use for Stage 3 dual-agent validation. Valid values: `gemini`, `groq`. | `LLM_PROVIDER=groq` |
| `LLM_MODEL` | (provider default) | No | Overrides the default model for the active provider. Applies to both attacker and defender agents. See `sec-c models` for valid values. | `LLM_MODEL=gemini-2.5-flash-lite` |
| `GEMINI_API_KEY` | -- | For Gemini | Single Gemini API key. Obtain from https://aistudio.google.com/apikey. Starts with `AIza`. | `GEMINI_API_KEY=AIzaSy...` |
| `GEMINI_API_KEYS` | -- | No | Multiple Gemini API keys for round-robin rotation (comma-separated, no spaces). Each key gets independent rate limits. Takes priority over singular `GEMINI_API_KEY`. | `GEMINI_API_KEYS=AIza...1,AIza...2,AIza...3` |
| `GROQ_API_KEY` | -- | For Groq | Single Groq API key. Obtain from https://console.groq.com/keys. Starts with `gsk_`. No credit card required. | `GROQ_API_KEY=gsk_...` |
| `GROQ_API_KEYS` | -- | No | Multiple Groq API keys for round-robin rotation (comma-separated). Same pattern as Gemini. | `GROQ_API_KEYS=gsk_...1,gsk_...2` |
| `GITHUB_TOKEN` | -- | For `--github` | GitHub personal access token for scanning GitHub repositories. Required scope: `repo` (read). Generate at https://github.com/settings/tokens. Also used for downloading pre-built CodeQL databases. | `GITHUB_TOKEN=ghp_...` |
| `NVD_API_KEY` | -- | No | NVD (National Vulnerability Database) API key for faster CVE downloads during RAG knowledge base building. Without key: 5 req/30s. With key: 50 req/30s (10x faster). Obtain from https://nvd.nist.gov/developers/request-an-api-key. | `NVD_API_KEY=abc123...` |
| `CODEQL_HOME` | -- | No | Override path to CodeQL CLI installation directory. Use when CodeQL is not in system PATH. SEC-C checks this before falling back to PATH lookup. | `CODEQL_HOME=C:\codeql` or `CODEQL_HOME=~/.sec-c/codeql` |
| `JOERN_HOME` | -- | No | Override path to Joern installation directory. Use when Joern is not in system PATH. | `JOERN_HOME=~/.sec-c/joern` |
| `SEC_C_DEVICE` | (auto) | No | Force computation device. Set to `cpu` to disable CUDA even if a GPU is available. Useful for debugging or when GPU memory is limited. | `SEC_C_DEVICE=cpu` |
| `CUDA_VISIBLE_DEVICES` | (all) | No | Select which CUDA GPU device(s) to use when multiple GPUs are available. Standard PyTorch/CUDA variable. | `CUDA_VISIBLE_DEVICES=0` |
| `SEC_C_LOG_LEVEL` | `INFO` | No | Set the default logging level. Valid values: `DEBUG`, `INFO`, `WARNING`, `ERROR`. The `--verbose` flag overrides this to `DEBUG`. | `SEC_C_LOG_LEVEL=DEBUG` |

### Loading `.env` on Different Platforms

```bash
# Linux/macOS (bash/zsh) -- SEC-C auto-loads .env, but for shell use:
export $(cat .env | xargs)

# Or:
set -a; source .env; set +a

# Windows PowerShell:
Get-Content .env | ForEach-Object { if ($_ -match '^([^#].+?)=(.*)$') { [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2]) } }

# Windows Git Bash:
set -a; source .env; set +a
```

**Note:** SEC-C automatically loads `.env` on startup from either the current working directory or the project root. You do not need to manually export variables when running `sec-c` commands.

---

## Configuration File Reference

The main configuration file is `configs/default.yaml`. Override it with `--config <path>` on any command that accepts it.

### Loading Order

1. SEC-C checks `configs/default.yaml` in the current working directory
2. Falls back to `configs/default.yaml` relative to the installed package location
3. If no config file is found, built-in defaults are used
4. The `--config` flag overrides all of the above

### Complete Configuration Reference

#### framework

Top-level framework metadata.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `framework.name` | string | `"sec-c"` | Framework name. Used in SARIF output and reports. |
| `framework.version` | string | `"2.0.0"` | Framework version. Used in SARIF output and reports. |

#### languages

List of supported languages for scanning.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `languages` | list[string] | `["python", "javascript", "java", "cpp", "go"]` | Languages SEC-C can analyze. Each has Tree-sitter grammar support and CodeQL query packs. |

#### sast

Stage 1: SAST Engine configuration.

##### sast.codeql

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sast.codeql.cli_path` | string | `"codeql"` | Path to the CodeQL CLI binary. Set to a full path if CodeQL is not in system PATH. |
| `sast.codeql.query_suite` | string | `"security-extended"` | CodeQL query suite to run. `security-extended` includes more rules than the default `security` suite. |
| `sast.codeql.timeout_seconds` | int | `300` | Maximum time (in seconds) for CodeQL database creation and analysis per language. Increase for large projects. |
| `sast.codeql.database_cache_dir` | string | `"~/.sec-c/codeql-dbs"` | Directory to cache CodeQL databases. Reusing cached databases speeds up repeated scans. |
| `sast.codeql.github_token_env` | string | `"GITHUB_TOKEN"` | Name of the environment variable holding the GitHub token. Used for downloading pre-built CodeQL databases for GitHub repos. |

##### sast.treesitter

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sast.treesitter.enabled` | bool | `true` | Enable Tree-sitter pre-screening. Tree-sitter performs fast AST pattern matching before CodeQL's deeper analysis. |
| `sast.treesitter.prescreen_timeout_ms` | int | `100` | Maximum time (in milliseconds) for Tree-sitter pre-screening per file. Files that exceed this timeout are passed through without filtering. |

##### sast.uncertainty

4-factor uncertainty quantification that drives cascade escalation.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sast.uncertainty.confidence_weight` | float | `0.4` | Weight of the SAST confidence factor in the composite uncertainty score. Higher values make SAST confidence more influential in escalation decisions. |
| `sast.uncertainty.complexity_weight` | float | `0.3` | Weight of the code complexity factor. Complex code (deep nesting, many branches) increases uncertainty. |
| `sast.uncertainty.novelty_weight` | float | `0.2` | Weight of the novelty factor. Unusual or rarely-seen code patterns increase uncertainty. |
| `sast.uncertainty.conflict_weight` | float | `0.1` | Weight of the conflict factor. Conflicting signals between different SAST tools increase uncertainty. |
| `sast.uncertainty.escalation_threshold` | float | `0.5` | Uncertainty score threshold for escalation to the next stage. Findings with uncertainty >= this value are sent to Stage 2 (Graph). Lower = more aggressive escalation (more findings go to later stages). Higher = more conservative (more findings resolved at Stage 1). |
| `sast.uncertainty.severity_adjustments.critical` | float | `0.15` | Adjustment added to uncertainty score for Critical severity findings, making them more likely to escalate. |
| `sast.uncertainty.severity_adjustments.high` | float | `0.10` | Adjustment added for High severity findings. |
| `sast.uncertainty.severity_adjustments.medium` | float | `0.00` | Adjustment added for Medium severity findings (no change). |
| `sast.uncertainty.severity_adjustments.low` | float | `-0.05` | Adjustment for Low severity findings (reduces uncertainty, less likely to escalate). |
| `sast.uncertainty.max_taint_path_before_escalation` | int | `3` | Maximum number of taint flow steps before a finding is considered complex enough to warrant automatic escalation regardless of uncertainty score. |

#### graph

Stage 2: Graph-Augmented Validation configuration.

##### graph.joern

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `graph.joern.binary_path` | string | `"joern"` | Path to the Joern binary. Set to a full path if Joern is not in system PATH. |
| `graph.joern.timeout_seconds` | int | `120` | Maximum time (in seconds) for Joern CPG generation per file/module. |
| `graph.joern.export_format` | string | `"graphml"` | Graph export format from Joern. `graphml` is the standard XML-based graph format. |

##### graph.embeddings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `graph.embeddings.model` | string | `"microsoft/graphcodebert-base"` | Pre-trained model for generating code embeddings. GraphCodeBERT is specifically trained on code structure. |
| `graph.embeddings.embedding_dim` | int | `768` | Dimension of the embedding vectors from GraphCodeBERT. Do not change unless using a different embedding model. |
| `graph.embeddings.batch_size` | int | `32` | Batch size for embedding generation. Reduce if running out of memory. |
| `graph.embeddings.device` | string | `"cpu"` | Computation device for embedding generation. Set to `"cuda"` for GPU acceleration. |

##### graph.gnn

Mini-GAT (Graph Attention Network) architecture configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `graph.gnn.input_dim` | int | `773` | Input dimension for the GNN. Computed as 768 (GraphCodeBERT embedding) + 5 (graph structural features). Do not change unless modifying the feature pipeline. |
| `graph.gnn.hidden_dim` | int | `256` | Hidden layer dimension in the GAT. Larger values increase model capacity but require more memory. |
| `graph.gnn.output_dim` | int | `128` | Output dimension of the final GAT layer before classification. |
| `graph.gnn.num_heads_l1` | int | `4` | Number of attention heads in the first GAT layer. Multi-head attention allows the model to attend to different structural patterns. |
| `graph.gnn.num_heads_l2` | int | `4` | Number of attention heads in the second GAT layer. |
| `graph.gnn.dropout` | float | `0.3` | Dropout rate for regularization during training and inference. |
| `graph.gnn.num_classes` | int | `2` | Number of output classes: `vulnerable` and `safe`. |
| `graph.gnn.max_nodes` | int | `200` | Maximum number of nodes in a CPG subgraph. Graphs larger than this are truncated. Reduce to save memory. |
| `graph.gnn.model_path` | string | `"data/models/mini_gat.pt"` | Path to the trained Mini-GAT model weights file. |

##### graph.conformal

Conformal prediction configuration for calibrated uncertainty.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `graph.conformal.alpha` | float | `0.1` | Significance level for conformal prediction. `0.1` provides 90% coverage guarantee. Lower alpha = higher coverage = more conservative (larger prediction sets). |
| `graph.conformal.calibration_size` | float | `0.2` | Fraction of calibration data held out for conformal calibration. |
| `graph.conformal.method` | string | `"aps"` | Conformal prediction method. `aps` = Adaptive Prediction Sets, which produces variable-size prediction sets based on model uncertainty. |

#### llm

Stage 3: LLM Dual-Agent Validation configuration.

##### llm.gemini

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `llm.gemini.model_pro` | string | `"gemini-2.5-pro"` | Gemini Pro model identifier. Note: Pro has been removed from the free tier as of Dec 2025. |
| `llm.gemini.model_flash` | string | `"gemini-2.5-flash"` | Gemini Flash model identifier. This is the primary model used by SEC-C. |
| `llm.gemini.primary_model` | string | `"gemini-2.5-flash"` | Which model to use as the primary for dual-agent analysis. Flash is recommended for its higher free-tier quota. |
| `llm.gemini.fallback_model` | string | `"gemini-2.5-pro"` | Fallback model for complex cases that exceed the complexity threshold. Only used if Pro is available (requires paid tier). |
| `llm.gemini.api_key_env` | string | `"GEMINI_API_KEY"` | Name of the environment variable holding the Gemini API key. |
| `llm.gemini.pro_rpm` | int | `2` | Rate limit: requests per minute for Pro model. |
| `llm.gemini.pro_rpd` | int | `25` | Rate limit: requests per day for Pro model. |
| `llm.gemini.flash_rpm` | int | `15` | Rate limit: requests per minute for Flash model. |
| `llm.gemini.flash_rpd` | int | `500` | Rate limit: requests per day for Flash model. |
| `llm.gemini.temperature` | float | `0.1` | LLM temperature for generation. Low temperature (0.1) produces more deterministic, focused analysis. |
| `llm.gemini.max_output_tokens` | int | `4096` | Maximum output tokens per LLM response. |
| `llm.gemini.max_batch_size` | int | `5` | Maximum number of findings batched into a single LLM prompt. Batching reduces API calls but increases prompt size. |
| `llm.gemini.prompt_tier_thresholds.minimal` | float | `0.3` | Uncertainty scores below this use a minimal (shorter) prompt, saving tokens and API quota. |
| `llm.gemini.prompt_tier_thresholds.standard` | float | `0.6` | Uncertainty scores between minimal and this threshold use a standard prompt. Scores above this get the full detailed prompt. |

##### llm.consensus

Dual-agent consensus protocol thresholds.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `llm.consensus.confirmed_defense_threshold` | float | `0.5` | If the defender's defense coverage score is below this threshold, the finding is more likely to be confirmed as a true vulnerability. |
| `llm.consensus.safe_defense_threshold` | float | `0.7` | If the defender's defense coverage score exceeds this threshold, the finding is more likely to be classified as safe (false positive). |
| `llm.consensus.infeasible_confidence` | float | `0.8` | Minimum confidence required for the defender to declare a taint path infeasible. Below this, the attacker's verdict takes priority. |

##### llm.rag

RAG (Retrieval-Augmented Generation) configuration for CWE/CVE knowledge grounding.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `llm.rag.faiss_index_path` | string | `"data/rag/faiss_index"` | Path to the FAISS vector index for semantic similarity search. |
| `llm.rag.bm25_index_path` | string | `"data/rag/bm25_index"` | Path to the BM25 keyword index for lexical search. |
| `llm.rag.nvd_data_path` | string | `"data/rag/nvd"` | Path to downloaded NVD CVE data. |
| `llm.rag.cwe_data_path` | string | `"data/cwe"` | Path to the MITRE CWE catalog data. |
| `llm.rag.top_k` | int | `5` | Number of top results to retrieve from the knowledge base per query. Higher values provide more context but increase prompt size. |
| `llm.rag.hybrid_weight_semantic` | float | `0.6` | Weight for semantic (FAISS) search in hybrid retrieval. |
| `llm.rag.hybrid_weight_keyword` | float | `0.4` | Weight for keyword (BM25) search in hybrid retrieval. The two weights should sum to 1.0. |

##### llm.agents

Agent routing configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `llm.agents.complexity_threshold` | float | `0.7` | Findings with complexity above this threshold are routed to the Pro model (if available). Below this threshold, Flash handles the analysis. |
| `llm.agents.max_retries` | int | `2` | Maximum number of retries for failed LLM API calls before giving up on a finding. |

#### orchestrator

Score fusion and classification configuration.

##### orchestrator.fusion

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `orchestrator.fusion.sast_weight` | float | `0.3` | Weight of SAST confidence in the final fused score. |
| `orchestrator.fusion.gat_weight` | float | `0.3` | Weight of Graph (Mini-GAT) structural risk in the final fused score. |
| `orchestrator.fusion.llm_weight` | float | `0.4` | Weight of LLM consensus in the final fused score. The three weights should sum to 1.0. |

##### orchestrator.classification

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `orchestrator.classification.confirmed_threshold` | float | `0.85` | Minimum fused score for a finding to be classified as "Confirmed". |
| `orchestrator.classification.likely_threshold` | float | `0.50` | Minimum fused score for "Likely". Scores below this become "Potential". |

#### reporting

Output and display configuration.

##### reporting.sarif

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `reporting.sarif.schema_version` | string | `"2.1.0"` | SARIF schema version. Do not change. |
| `reporting.sarif.tool_name` | string | `"sec-c"` | Tool name in SARIF output. |
| `reporting.sarif.tool_version` | string | `"2.0.0"` | Tool version in SARIF output. |
| `reporting.sarif.include_custom_properties` | bool | `true` | Whether to include `sec-c/*` custom properties in SARIF results. Set to `false` for maximum compatibility with strict SARIF consumers. |

##### reporting.console

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `reporting.console.color` | bool | `true` | Enable color output in the console. Disable for piping to files or non-color terminals. |
| `reporting.console.verbose` | bool | `false` | Default verbose mode for console output. Overridden by `--verbose` flag. |
| `reporting.console.show_cascade_stats` | bool | `true` | Show cascade statistics table after findings. Displays how many findings were resolved at each stage. |
