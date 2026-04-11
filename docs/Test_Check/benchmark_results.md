# SEC-C Benchmark Results

Generated: 2026-04-11 14:14

## Summary Table

| # | Repo | Language | Findings | SAST | GNN | LLM | Unresolved | Time |
|---|------|----------|----------|------|-----|-----|------------|------|
| 1 | 01_taskflow | Python | 10 | 9 | 0 | 1 | 0 | 101.5s |
| 2 | 02_pymetrics | Python | 11 | 8 | 2 | 1 | 0 | 95.4s |
| 3 | 03_mailbridge | Python | 11 | 8 | 0 | 3 | 0 | 42.6s |
| 4 | 04_docvault | Python | 22 | 18 | 1 | 3 | 0 | 57.5s |
| 5 | 05_authkit | Python | 5 | 5 | 0 | 0 | 0 | 48.2s |
| 6 | 06_dataflow | Python | 13 | 13 | 0 | 0 | 0 | 29.3s |
| 7 | 07_shopfront | JavaScript | 15 | 10 | 0 | 5 | 0 | 272.4s |
| 8 | 08_logstream | JavaScript | 17 | 10 | 0 | 7 | 0 | 298.1s |
| 9 | 09_chatbridge | JavaScript | 4 | 3 | 0 | 1 | 0 | 74.2s |
| 10 | 10_inventoryapi | Java | 2 | 2 | 0 | 0 | 0 | 12.0s |
| 11 | 11_reportgen | Java | 9 | 9 | 0 | 0 | 0 | 15.0s |
| 12 | 12_sysmon | C | 22 | 22 | 0 | 0 | 0 | 15.8s |
| 13 | 13_netprobe | C | 23 | 23 | 0 | 0 | 0 | 14.4s |
| 14 | 14_configsvc | Go | 13 | 10 | 1 | 2 | 0 | 84.5s |
| 15 | 15_filesync | Go | 7 | 7 | 0 | 0 | 0 | 17.1s |
| | **TOTAL** | **Mixed** | **184** | **157** (85%) | **4** (2%) | **23** (12%) | **0** | 1178s |

## Cascade Efficiency

- **Stage 1 (SAST)**: 157/184 (85%) resolved at cheapest stage
- **Stage 2 (GNN)**: 4/184 (2%) resolved with graph + conformal
- **Stage 3 (LLM)**: 23/184 (12%) resolved with dual-agent consensus
- **Unresolved**: 0/184
- **Total scan time**: 1178s across 15 repos

## Per-Language Breakdown

| Language | Repos | Findings | SAST% | GNN% | LLM% |
|----------|-------|----------|-------|------|------|
| C | 2 | 45 | 100% | 0% | 0% |
| Go | 2 | 20 | 85% | 5% | 10% |
| Java | 2 | 11 | 100% | 0% | 0% |
| JavaScript | 3 | 36 | 63% | 0% | 36% |
| Python | 6 | 72 | 84% | 4% | 11% |
