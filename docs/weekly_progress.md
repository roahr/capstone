# Sec-C — Semester 2 Weekly Progress Sheet (January - March 2026)

**Project:** Multi-Stage Code Security Framework for Adaptive Vulnerability Triage and Detection

*Continuation from Semester 1: Static analysis pre-screening and benchmark dataset preparation completed.*

---

| Week | Planned Task for the Week | Suggestions Given by Mentor | Overall Status |
|------|--------------------------|---------------------------|----------------|
| Jan 1-7 | Revisited Sem-1 module, fixed pattern matching edge cases. Started literature survey on LLM-based triage. | Survey recent AI-assisted SAST triage papers. | Sem-1 handoff done |
| Jan 8-14 | Studied multi-agent LLM and conformal prediction methods. Compared existing tools' false positive rates. | Conformal prediction for code security is novel — formalize the gap. | Survey in progress |
| Jan 15-21 | Drafted research questions. Proposed 3-stage cascade (SAST → Graph → LLM) with uncertainty-driven escalation. | Formalize the uncertainty model with weighted factors. | Architecture proposed |
| Jan 22-28 | Redesigned GNN as graph attention network with pre-trained code embeddings and structural features. | Keep model lightweight. Add confidence head for conformal calibration. | GNN redesign done |
| Feb 1-7 | Integrated deep taint analysis with pre-screener. Built data models and CWE-to-OWASP mapping. | Consider per-CWE weight calibration for score fusion. | SAST extended |
| Feb 8-14 | Designed score fusion with per-CWE adaptive weights. Coursework deadlines — limited progress. | Start drafting problem statement section for the paper. | Slow week |
| Feb 15-21 | Built CPG construction, conformal prediction layer, and GNN training notebook. | Reviewed Claude Code security approach — consider building similar interactive tool. | Training pipeline ready |
| Feb 22-28 | Inspired by agentic security tooling, pivoted to build as a full interactive tool. Started LLM client with key rotation. | Strong direction — working tool strengthens PhD contribution. Use dual-agent approach. | Tool vision defined |
| Mar 1-7 | Implemented attacker-defender dual-agent consensus protocol with CWE-specific prompts. | Add knowledge retrieval with real CVE/CWE data for prompt enrichment. | Dual-agent working |
| Mar 8-14 | Built hybrid knowledge retrieval (semantic + keyword search) over CWE and CVE databases. Rate limit issues resolved. | Build output layer — CLI, reports. Think about cascade visualization. | Knowledge base ready |
| Mar 15-21 | Built interactive CLI with scan commands. Implemented web dashboard and standardized report output. Coursework — reduced progress. | Prepare sample codebases for validation demo. | Reporting complete |
| Mar 22-28 | Added CVSS severity estimation and explainability features. Initial integration testing of full pipeline. | Plan benchmark evaluation. Start documenting methodology for paper. | Integration testing |

---

### Pending for Next Review

- Benchmark evaluation on standard datasets
- GNN training and model integration
- Cross-language testing
- Paper draft — methodology and evaluation

---
