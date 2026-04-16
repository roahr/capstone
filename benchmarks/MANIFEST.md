# Benchmarks

External vulnerable apps and real-CVE repos cloned for scanner evaluation.
Contents are git-ignored; regenerate with `bash scripts/fetch_benchmarks.sh` (TODO).

| Dir | Source | Commit/Tag | CWE focus |
|---|---|---|---|
| vulpy | github.com/fportantier/vulpy | master | 89, 79, 502, 287, 327 |
| vampi | github.com/erev0s/VAmPI | master | 89, 798, 862/863, 287 |
| nodegoat | github.com/OWASP/NodeGoat | master | NoSQLi, 918, 79, 327, 798 |
| dvna | github.com/appsecco/dvna | master | 89, 78, 918, 798, 327, 502 |
| webgoat | github.com/WebGoat/WebGoat | main | 89, 78, 611, 502, 22, 287 |
| juice-shop | github.com/juice-shop/juice-shop | master | full OWASP Top 10 |
| axios-cve-2025-27152 | github.com/axios/axios | v1.7.9 (pre-fix) | 918 (SSRF in buildFullPath) |

Results JSON/SARIF land in `results/<repo>/`.
