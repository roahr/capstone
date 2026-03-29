 Demo Playbook

  Phase 1: Enter Interactive Mode (the "Claude-like" experience)

  sec-c

  This drops you into the REPL with autocomplete, history, and the styled prompt.

  Phase 2: Show Framework Readiness

  /status
  Shows all 3 stages, RAG knowledge base (969 CWEs, CVE data), LLM providers, GPU status — proves the system is production-ready.

  /providers
  Shows Gemini + Groq with API keys, free tier limits, active provider.

  /models
  Lists all available LLM models with RPD quotas.

  Phase 3: Scan the Sample Test Cases (the main event)

  Quick SAST-only scan (fast, shows Stage 1):
  /scan D:\sec-c\sample_testcases\python --stage sast

  Full cascade on Python (shows all 3 stages resolving findings):
  /scan D:\sec-c\sample_testcases\python --html
  This auto-opens the HTML report in the browser — the cyber-themed dashboard with Orbitron font, pipeline visualization, and the floating methodology
  panel.

  Multi-language scan:
  /scan D:\sec-c\sample_testcases --languages python,javascript,java,c,go --html

  Scan with SARIF output + HTML:
  /scan D:\sec-c\sample_testcases --output D:\sec-c\results.sarif --html --verbose

  GitHub repo scan (public):
  /scan --github OWASP/WebGoat --languages java --stage graph --html

  Phase 4: Report Formats

  Console report from saved SARIF:
  /report D:\sec-c\results.sarif

  HTML dashboard from saved SARIF:
  /report D:\sec-c\results.sarif --html

  Print to PDF: In the HTML report, click the "Print Report" button in the nav bar (or Ctrl+P in browser) — it renders a clean A4 PDF with proper page
  breaks.

  Phase 5: Show Configuration

  /config
  Shows the full cascade configuration: fusion weights (alpha/beta/gamma), thresholds, conformal prediction alpha, etc.

  /version

  Phase 6: Show History

  /history
  Shows all commands you just ran — demonstrates the persistent session.

  exit

  ---
  Demo Order for Maximum Impact

  ┌──────┬──────────────────────────────────────────────────────┬──────────────────────────────────────────────────────────┐
  │ Step │                       Command                        │                    What the jury sees                    │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 1    │ sec-c                                                │ Claude-like interactive prompt with autocomplete         │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 2    │ /status                                              │ Full system health — 3 stages, RAG, LLM providers        │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 3    │ /scan sample_testcases/python --stage sast           │ Fast SAST scan with live progress                        │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 4    │ /scan sample_testcases/python --html                 │ Full cascade + HTML dashboard auto-opens                 │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 5    │ (in browser) Click findings, filter, sort            │ Interactive report with code snippets + analysis         │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 6    │ (in browser) Click floating ? button                 │ Methodology panel slides in — shows 3-stage architecture │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 7    │ (in browser) Click Print Report                      │ Clean PDF with A4 formatting                             │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 8    │ /scan sample_testcases --output results.sarif --html │ Multi-language full scan — 5 languages, 56 findings      │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 9    │ /scan --github OWASP/WebGoat --languages java --html │ Live GitHub repo scan                                    │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 10   │ /providers then /models                              │ Show LLM infrastructure                                  │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 11   │ /config                                              │ Show cascade parameters                                  │
  ├──────┼──────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
  │ 12   │ /history                                             │ Session history                                          │
  └──────┴──────────────────────────────────────────────────────┴──────────────────────────────────────────────────────────┘

  Key talking points for each step:
  - Step 3-4: "Watch the cascade — SAST resolves 80%, Graph catches contextual FPs, LLM validates the rest"
  - Step 5: "Click any finding to see the dual-agent attacker/defender analysis"
  - Step 6: "The methodology explains each stage for both experts and beginners"
  - Step 8: "56 findings across Python, JS, Java, C/C++, Go — 28 true positives, 28 false positives designed to test each cascade stage"
  - Step 9: "We can scan any public GitHub repository directly"