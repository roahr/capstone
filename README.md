# SEC-C

```
    ____                ____
   / ___|  ___  ___    / ___|
   \___ \ / _ \/ __|  | |
    ___) |  __/ (__   | |___
   |____/ \___|\___|   \____|

   Multi-Stage Code Security Framework
   Adaptive Vulnerability Triage & Detection
   v2.0.0
```

> Uncertainty-driven cascading pipeline that combines SAST, Graph Neural Networks, and LLM dual-agent validation to reduce false positives by 60-70% compared to traditional static analysis tools.

## What is SEC-C?

SAST tools flag too many false positives (68-95% on OWASP Benchmark), causing alert fatigue and ignored warnings. SEC-C solves this with a three-stage cascade: fast SAST resolves 80% of findings in under 100ms, a GNN with conformal prediction handles 15%, and an adversarial attacker/defender LLM protocol validates the remaining 5%. The result is 85% fewer expensive LLM calls and principled, explainable verdicts for every finding.

## Architecture

```
Source Code (Python | JS/TS | Java | C/C++ | Go)
       |
       v
+------------------------------------------+
| STAGE 1: SAST ENGINE (< 100ms)          |  80% resolved here
|  Tree-sitter pre-screen + CodeQL taint   |
|  4-factor uncertainty scoring            |
+----------------+-------------------------+
                 | U_score >= 0.5
                 v
+------------------------------------------+
| STAGE 2: GRAPH VALIDATION (~1-3s)       |  15% resolved here
|  Joern CPG + Mini-GAT (GNN)             |
|  Conformal Prediction (90% coverage)     |
+----------------+-------------------------+
                 | prediction set = {safe, vuln}
                 v
+------------------------------------------+
| STAGE 3: LLM DUAL-AGENT (~5-15s)       |  5% resolved here
|  Attacker + Defender (Gemini / Groq)     |
|  RAG with 200K+ CVEs + 900 CWEs         |
+----------------+-------------------------+
                 v
+------------------------------------------+
| STAGE 4: UNIFIED REPORTING              |
|  CWE-adaptive score fusion              |
|  SARIF 2.1.0 + Console + HTML Dashboard |
+------------------------------------------+
```

## Quick Start

```bash
git clone https://github.com/your-org/sec-c.git && cd sec-c
pip install -e .
sec-c scan tests/fixtures/vulnerable_python.py --stage sast
```

See [Setup Guide](docs/BUILD_GUIDE.md) for full installation including CodeQL, Joern, and API keys.

## Documentation

| Document | Description |
|----------|-------------|
| [Setup Guide](docs/BUILD_GUIDE.md) | From clone to working demo |
| [Data Pipeline](docs/DATA_PIPELINE.md) | End-to-end technical flow |
| [Research Brief](docs/RESEARCH_BRIEF.md) | Novel contributions and comparison with prior work |
| [Upgrade Analysis](docs/UPGRADE_ANALYSIS.md) | Component upgrade roadmap |
| [CPU/Laptop Guide](docs/CPU_LAPTOP_GUIDE.md) | Running SEC-C without GPU |

## Key Features

- **Uncertainty-driven cascade** -- mathematically principled escalation, not heuristic routing
- **Conformal prediction** -- first application to vulnerability detection, with 90% coverage guarantee
- **Adversarial dual-agent triage** -- attacker/defender LLM protocol eliminates confirmation bias
- **CWE-adaptive score fusion** -- per-vulnerability-class weights (injection: LLM-heavy; crypto: SAST-heavy)
- **Multi-language pipeline** -- single configuration for Python, JS/TS, Java, C/C++, Go
- **SARIF 2.1.0 + HTML dashboard** -- GitHub Security tab compatible, interactive web reports
- **85% fewer LLM calls** -- cascade resolves most findings locally before invoking APIs

## Supported Languages

Python, JavaScript/TypeScript, Java, C/C++, Go

## LLM Providers

Gemini 2.5 Flash, Gemini 2.5 Pro, Groq Llama 3.3 70B (round-robin key rotation)

## License

MIT License. See [LICENSE](LICENSE) for details.

## Citation

```bibtex
@inproceedings{secc2026,
  title     = {{SEC-C}: A Multi-Stage Framework with Uncertainty-Driven
               Escalation and Conformal Prediction for Reducing False
               Positives in Static Application Security Testing},
  author    = {{[Author Name]}},
  year      = {2026},
  note      = {Under preparation}
}
```
