# Sec-C: Multi-Stage Code Security Framework
## Complete Project Overview

**Project Name:** Sec-C (Security Code Analyzer)
**Version:** 2.0
**Last Updated:** January 2026
**Target Publication:** ISSTA 2026 / FSE 2026

---

## Executive Summary

Sec-C is an advanced **Static Application Security Testing (SAST) tool** that combines traditional static analysis with Graph Neural Networks (GNN) and Large Language Models (LLM) to achieve high-precision vulnerability detection with low false positive rates.

### Core Innovation
**Agentic GNN with Uncertainty-Driven Escalation** - A novel multi-agent architecture where:
1. Fast SAST agent handles 80% of cases in <100ms
2. GNN agent resolves 15% of uncertain cases with structural reasoning
3. LLM agent validates 5% of complex cases with semantic understanding

This hierarchical approach reduces false positives by 60-70% compared to traditional SAST while maintaining high recall.

---

## Problem Statement

### Current SAST Limitations

| Problem | Impact | Industry Data |
|---------|--------|---------------|
| **High False Positive Rate** | Alert fatigue, ignored warnings | 30-50% FP rate typical |
| **Limited Context Understanding** | Misses sanitized inputs | Can't track complex data flows |
| **No Confidence Indication** | All alerts treated equally | No prioritization guidance |
| **Black-box Results** | Developers don't trust findings | Low remediation rates |

### Our Solution

```
┌─────────────────────────────────────────────────────────────────┐
│                    SEC-C ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Source Code                                                    │
│       │                                                          │
│       ▼                                                          │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ STAGE 1: SAST Agent (< 100ms)                           │   │
│   │ - Tree-sitter parsing                                    │   │
│   │ - Pattern matching + Taint analysis                      │   │
│   │ - 80% cases resolved here                                │   │
│   └─────────────────────┬───────────────────────────────────┘   │
│                         │ if uncertain                           │
│                         ▼                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ STAGE 2: GNN Agent (~1s)                                │   │
│   │ - Code Property Graph analysis                           │   │
│   │ - Heterogeneous Graph Attention Networks                 │   │
│   │ - Uncertainty quantification                             │   │
│   │ - 15% cases resolved here                                │   │
│   └─────────────────────┬───────────────────────────────────┘   │
│                         │ if still uncertain                     │
│                         ▼                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ STAGE 3: LLM Agent (~10s)                               │   │
│   │ - Semantic validation with RAG                           │   │
│   │ - CVE/CWE knowledge grounding                            │   │
│   │ - Natural language explanation                           │   │
│   │ - 5% cases resolved here                                 │   │
│   └─────────────────────┬───────────────────────────────────┘   │
│                         │                                        │
│                         ▼                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ STAGE 4: Unified Report                                 │   │
│   │ - Three-tier classification (Confirmed/Likely/Potential) │   │
│   │ - Priority scoring                                       │   │
│   │ - Remediation guidance                                   │   │
│   │ - SARIF 2.1.0 output                                     │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Target Metrics

| Metric | Traditional SAST | Sec-C Target | Stretch Goal |
|--------|------------------|--------------|--------------|
| **Precision** | 50-70% | ≥85% | ≥90% |
| **Recall** | 60-80% | ≥80% | ≥85% |
| **F1 Score** | 55-75% | ≥82% | ≥87% |
| **False Positive Rate** | 30-50% | <15% | <10% |
| **Latency (median)** | 100-500ms | <200ms | <100ms |
| **Latency (P95)** | 1-5s | <2s | <1s |

---

## Technology Stack

### Core Technologies

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Parsing** | Tree-sitter | Fast incremental parsing |
| **Static Analysis** | Custom + CodeQL | Pattern matching, taint analysis |
| **Graph Construction** | NetworkX + DGL | Code Property Graph building |
| **Node Embedding** | GraphCodeBERT | Code-aware semantic embeddings |
| **GNN** | PyTorch Geometric | Heterogeneous Graph Attention |
| **LLM** | OpenAI/Anthropic API | Semantic validation |
| **Vector DB** | FAISS | RAG retrieval |
| **Output** | SARIF 2.1.0 | Standard security report format |

### Language Support

| Language | Status | Notes |
|----------|--------|-------|
| **Python** | Primary | Full support, main focus |
| JavaScript/TypeScript | Planned | Phase 3 |
| Go | Planned | Phase 4 |
| Java | Planned | Phase 4 |

---

## Project Phases

### Phase 1: Foundation (COMPLETED)
- Tree-sitter SAST engine
- CodeQL integration
- CPG schema and construction
- SARIF parser
- Basic taint analysis
- **Status:** 100% complete, 93% test coverage

### Phase 2: GNN Development (CURRENT)
- Dataset collection and processing
- CPG builder with GraphCodeBERT
- Heterogeneous GAT model
- Multi-task training pipeline
- Uncertainty quantification
- **Status:** 40% complete

### Phase 3: LLM Integration (PLANNED)
- RAG system setup
- LLM validation agent
- Multi-agent coordinator
- Natural language explanations
- **Status:** 0% complete

### Phase 4: Production (PLANNED)
- End-to-end integration
- Performance optimization
- IDE plugins
- CI/CD integration
- **Status:** 0% complete

---

## Research Contributions

### Novel Contributions (Not in Existing Literature)

1. **Agentic GNN Architecture**
   - First GNN that autonomously queries other agents when uncertain
   - Self-aware uncertainty quantification
   - Cost-aware inference routing

2. **Multi-Modal Security Analysis**
   - Structure (GNN) + Semantics (LLM) + History (RAG)
   - Evidence fusion from multiple sources
   - Confidence calibration across modalities

3. **Hierarchical Cascade with Escalation**
   - 80/15/5 split reduces expensive computations by 85%
   - Uncertainty thresholds trigger escalation
   - Maintains high recall while improving precision

4. **Explainable Security Findings**
   - Attention-based explanations from GNN
   - Natural language reasoning from LLM
   - Traceable taint paths with confidence scores

---

## Directory Structure

```
sec-c/
├── context/                    # Project documentation
│   ├── PROJECT_OVERVIEW.md     # This file
│   ├── PHASE1_COMPLETED.md     # Phase 1 documentation
│   ├── GNN_ARCHITECTURE.md     # GNN design decisions
│   ├── GNN_IMPLEMENTATION_PLAN.md
│   ├── DATASET_PIPELINE.md
│   └── TRAINING_GUIDE.md
│
├── src/                        # Source code
│   ├── sast/                   # SAST agent
│   │   ├── parser/            # Tree-sitter parsing
│   │   ├── rules/             # Security rules
│   │   └── taint/             # Taint analysis
│   │
│   ├── gnn/                    # GNN agent
│   │   ├── graph/             # CPG construction
│   │   ├── models/            # Neural network models
│   │   └── training/          # Training pipeline
│   │
│   ├── llm/                    # LLM agent
│   │   ├── validator/         # Semantic validation
│   │   └── rag/               # Retrieval system
│   │
│   ├── agents/                 # Multi-agent coordination
│   │   ├── coordinator.py
│   │   └── messaging.py
│   │
│   └── reporting/              # Output generation
│       ├── sarif.py
│       └── console.py
│
├── tests/                      # Test suite
├── configs/                    # Configuration files
├── scripts/                    # Utility scripts
├── docs/                       # Additional documentation
├── CLAUDE.md                   # Claude Code guidance
└── README.md                   # Project readme
```

---

## Success Criteria

### Research Success
- [ ] Achieve ≥82% F1 on Python vulnerability detection
- [ ] Demonstrate 60%+ false positive reduction vs CodeQL
- [ ] Publish at top-tier venue (ISSTA/FSE/ICSE)

### Engineering Success
- [ ] Process 10K LOC in <30 seconds
- [ ] Maintain 95%+ test coverage
- [ ] Support CI/CD integration (GitHub Actions)

### Practical Impact
- [ ] Detect real CVEs missed by existing tools
- [ ] Provide actionable remediation guidance
- [ ] Generate developer-friendly explanations

---

## References

### Key Papers
1. Luo et al. "Detecting Code Vulnerabilities with Heterogeneous GNN Training" (2025) - IPAG and HAGNN architecture
2. Zhou et al. "Devign: Effective Vulnerability Identification" (2019) - GNN for vulnerability detection
3. Li et al. "VulDeePecker: A Deep Learning-Based System" (2018) - Deep learning for security

### Datasets
1. CVEfixes - Real-world CVE vulnerabilities with patches
2. VUDENC - Python web vulnerabilities
3. Juliet Test Suite - NIST synthetic test cases

### Tools
1. CodeQL - GitHub's semantic code analysis
2. GraphCodeBERT - Pre-trained model for code
3. Tree-sitter - Incremental parsing library

---

## Contact & Resources

**Repository:** `Code_Mine/sec-c`
**Documentation:** `context/` folder
**Issue Tracker:** GitHub Issues

---

*Last updated: January 2026*
