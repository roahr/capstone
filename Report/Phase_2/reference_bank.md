# Reference Bank — Sec-C Phase 2 Report

Verified references for use in thesis chapters. Verify publication details before citing.
Use `\cite{key}` in text, add `\bibitem{key}` to bibliography.

---

## GNN for Vulnerability Detection

- **devign2019** — Zhou, Y. et al. (2019). Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks. *NeurIPS 32*. [63.69% accuracy on QEMU/FFmpeg dataset]
- **regvd2022** — Nguyen, V. et al. (2022). ReGVD: Revisiting Graph Neural Networks for Vulnerability Detection. *IEEE TSE*. [Regex + GNN hybrid]
- **linevul2022** — Fu, M. & Tantithamthavorn, C. (2022). LineVul: A Transformer-based Line-Level Vulnerability Prediction. *MSR 2022*. [Line-level granularity]
- **reveal2021** — Chakraborty, S. et al. (2021). Deep Learning based Vulnerability Detection: Are We There Yet? *IEEE TSE*. [CPGNN, showed dataset quality issues]
- **ivdetect2021** — Li, Y. et al. (2021). Vulnerability Detection with Fine-Grained Interpretations. *ESEC/FSE*. [Interpretable vulnerability detection]

## LLM for Code Security

- **llm4vuln2024** — Sun, Y. et al. (2024). LLM4Vuln: A Unified Evaluation Framework for Decoupling and Enhancing LLMs' Vulnerability Reasoning. *arXiv:2401.16185*.
- **primevul2024** — Ding, Y. et al. (2024). Vulnerability Detection with Code Language Models: How Far Are We? *ICSE 2025*. [3.09% F1 on realistic C/C++ data]
- **vulnhuntr2024** — Protectai (2024). VulnHuntr: Autonomous AI Vulnerability Discovery. *GitHub*.
- **thapa2022** — Thapa, C. et al. (2022). Transformer-based Language Models for Software Vulnerability Detection. *ACSAC*.
- **steenhoek2024** — Steenhoek, B. et al. (2024). A Comprehensive Study of the Capabilities of Large Language Models for Vulnerability Detection. *arXiv:2403.17218*.

## Conformal Prediction

- **angelopoulos2023** — Angelopoulos, A. N. & Bates, S. (2023). Conformal Prediction: A Gentle Introduction. *Foundations and Trends in Machine Learning*.
- **vovk2005** — Vovk, V., Gammerman, A., & Shafer, G. (2005). Algorithmic Learning in a Random World. *Springer*.
- **romano2020** — Romano, Y., Sesia, M., & Candes, E. (2020). Classification with Valid and Adaptive Coverage. *NeurIPS*.
- **barber2023** — Barber, R. F. et al. (2023). Conformal Prediction Beyond Exchangeability. *Annals of Statistics*.

## Code Representation

- **cpg2014** — Yamaguchi, F. et al. (2014). Modeling and Discovering Vulnerabilities with Code Property Graphs. *IEEE S&P*. [Cited in Phase 1]
- **codebert2020** — Feng, Z. et al. (2020). CodeBERT: A Pre-Trained Model for Programming and Natural Languages. *EMNLP*.
- **graphcodebert2021** — Guo, D. et al. (2021). GraphCodeBERT: Pre-training Code Representations with Data Flow. *ICLR*. [Dataflow-aware pre-training]

## Multi-Agent Systems

- **multiagentdebate2023** — Du, Y. et al. (2023). Improving Factuality and Reasoning in Language Models through Multiagent Debate. *arXiv:2305.14325*.
- **divergentthinking2023** — Liang, T. et al. (2023). Encouraging Divergent Thinking in Large Language Models through Multi-Agent Debate. *arXiv:2305.19118*.

## Tools and Datasets

- **semgrep2024** — Semgrep. (2024). Lightweight Static Analysis. *Semgrep Inc*.
- **codeql2024** — GitHub. (2024). CodeQL: Semantic Code Analysis Engine.
- **snyk2024** — Snyk. (2024). Developer Security Platform. *Snyk Ltd*.
- **nvd2023** — NIST. (2023). National Vulnerability Database. https://nvd.nist.gov.
- **juliet2017** — NSA/NIST. (2017). Juliet Test Suite for C/C++ and Java. *Software Assurance Reference Dataset*.
- **cvefixes2021** — Bhandari, G. et al. (2021). CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software. *PROMISE 2021*.
- **diversevul2023** — Chen, L. et al. (2023). DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection. *RAID*.
- **devigndataset2019** — Zhou, Y. et al. (2019). Devign Dataset. [Function-level C vulnerability dataset from QEMU/FFmpeg].

## Calibration & Uncertainty

- **guocalibration2017** — Guo, C. et al. (2017). On Calibration of Modern Neural Networks. *ICML*. [Modern NNs are poorly calibrated]
- **focalloss2017** — Lin, T. et al. (2017). Focal Loss for Dense Object Detection. *ICCV*. [Class imbalance handling]

## SAST & False Positives

- **johnson2013** — Johnson, B. et al. (2013). Why Don't Software Developers Use Static Analysis Tools to Find Bugs? *ICSE*. [30-50% FP rates, developer avoidance]
- **ghostsecurity2025** — Ghost Security. (2025). SAST Tool False Positive Analysis. [91% avg FP rate across 3,000 repos]

## CVSS

- **cvss31** — FIRST. (2019). Common Vulnerability Scoring System v3.1: Specification Document.
