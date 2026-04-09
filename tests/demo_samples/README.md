# SEC-C Demo Samples

Test cases designed to demonstrate each stage of the SEC-C cascade.

## Usage

```bash
# Show framework status (all stages available)
sec-c status

# Demo 1: Stage 1 resolution (SAST catches clear vulnerabilities)
sec-c scan tests/demo_samples/stage1_resolve.py --stage sast

# Demo 2: Stage 2 escalation (GNN analyzes complex taint flows)
sec-c scan tests/demo_samples/stage2_escalate.py
sec-c scan tests/demo_samples/stage2_escalate.c

# Demo 3: Full cascade (ambiguous findings reach LLM dual-agent)
sec-c scan tests/demo_samples/stage3_llm.py

# Demo with HTML dashboard
sec-c scan tests/demo_samples/ --html
```

## Test Cases

| File | Stage | What It Demonstrates |
|------|-------|---------------------|
| `stage1_resolve.py` | Stage 1 (SAST) | Clear CWE-78/95/502 with 1-hop taint. Tree-sitter matches with high confidence, low uncertainty -> resolves cheaply at SAST. Shows cascade efficiency. |
| `stage2_escalate.py` | Stage 2 (GNN) | Multi-hop taint flows (4+ steps through helper functions). Taint path length > 3 triggers escalation. GNN produces conformal prediction sets for routing. |
| `stage2_escalate.c` | Stage 2 (GNN) | C/C++ memory vulns (CWE-120/416/190). GNN trained primarily on C/C++ (20K samples). Demonstrates graph-based vulnerability analysis. |
| `stage3_llm.py` | Stage 3 (LLM) | Subtle/ambiguous vulns (CSRF, weak crypto, partial SSRF mitigation). GNN may produce ambiguous conformal sets, triggering LLM dual-agent consensus. |
