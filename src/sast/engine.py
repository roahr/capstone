"""
SAST Engine: Combines Tree-sitter pre-screening with CodeQL analysis.

This is the Module 1 entry point that the Pipeline Orchestrator calls.
It runs Tree-sitter for fast pattern matching, optionally runs CodeQL
for deep taint analysis, merges findings, and computes uncertainty scores.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from src.sast.sarif.schema import Finding, Language
from src.sast.treesitter.prescreener import TreeSitterPreScreener
from src.sast.uncertainty.scorer import UncertaintyScorer

logger = logging.getLogger(__name__)


class SASTEngine:
    """
    Module 1: Combined SAST analysis engine.

    Runs Tree-sitter pre-screening on all files, optionally runs CodeQL
    for deeper taint analysis, merges results, and computes uncertainty
    scores for each finding.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.prescreener = TreeSitterPreScreener(
            timeout_ms=self.config.get("treesitter", {}).get("prescreen_timeout_ms", 100)
        )
        self.uncertainty_scorer = UncertaintyScorer(
            self.config.get("uncertainty", {})
        )
        self._codeql_available = shutil.which("codeql") is not None

    async def analyze(
        self,
        target: str,
        languages: list[Language] | None = None,
        github_repo: str | None = None,
    ) -> list[Finding]:
        """
        Run SAST analysis on a target.

        1. Tree-sitter pre-screening (fast, < 100ms per file)
        2. CodeQL analysis (if available, deeper taint tracking)
        3. Merge and deduplicate findings
        4. Compute uncertainty scores
        """
        all_findings: list[Finding] = []

        target_path = Path(target) if target else None

        # ── Step 1: Tree-sitter pre-screening ─────────────────────────────
        if target_path and target_path.exists():
            logger.info("Running Tree-sitter pre-screening on %s", target)
            ts_findings = self._run_treesitter(target_path)
            all_findings.extend(ts_findings)
            logger.info("Tree-sitter found %d potential findings", len(ts_findings))

        # ── Step 2: CodeQL analysis (optional) ────────────────────────────
        if self._codeql_available and target_path and target_path.exists():
            logger.info("Running CodeQL analysis...")
            codeql_findings = await self._run_codeql(target_path, languages)
            # Merge: add CodeQL findings that aren't duplicates of tree-sitter ones
            merged = self._merge_findings(all_findings, codeql_findings)
            all_findings = merged
            logger.info("After CodeQL merge: %d total findings", len(all_findings))
        elif not self._codeql_available:
            logger.info("CodeQL not available, using Tree-sitter findings only")

        # ── Step 3: Compute uncertainty scores ────────────────────────────
        for finding in all_findings:
            self.uncertainty_scorer.score(finding)

        logger.info(
            "SAST complete: %d findings (%d high-uncertainty)",
            len(all_findings),
            sum(1 for f in all_findings if f.uncertainty.should_escalate),
        )

        return all_findings

    def _run_treesitter(self, target_path: Path) -> list[Finding]:
        """Run tree-sitter pre-screening."""
        if target_path.is_file():
            result = self.prescreener.prescreen_file(str(target_path))
            logger.debug(
                "Pre-screened %s: %d findings in %.0fms",
                target_path.name, len(result.findings), result.scan_time_ms,
            )
            return result.findings
        elif target_path.is_dir():
            results = self.prescreener.prescreen_directory(str(target_path))
            all_findings = []
            for result in results:
                all_findings.extend(result.findings)
                if result.findings:
                    logger.debug(
                        "Pre-screened %s: %d findings",
                        result.file_path, len(result.findings),
                    )
            return all_findings
        return []

    # Extension-to-language mapping for single-file CodeQL detection
    _EXT_TO_LANGUAGE: dict[str, str] = {
        ".py": "python",
        ".pyw": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".java": "java",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".c": "cpp",
        ".h": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".go": "go",
    }

    async def _run_codeql(
        self,
        target_path: Path,
        languages: list[Language] | None,
    ) -> list[Finding]:
        """Run CodeQL analysis and parse SARIF output.

        Handles both single files and directories:
        - Single file: detect language from extension, use parent dir as
          project root, run CodeQL for that language only.
        - Directory: use ``run_all_languages()`` which auto-detects
          languages via ``os.walk()``.
        """
        try:
            from src.sast.codeql.query_executor import CodeQLQueryExecutor
            from src.sast.sarif.parser import SARIFParser

            executor = CodeQLQueryExecutor()
            parser = SARIFParser()
            findings: list[Finding] = []

            if target_path.is_file():
                # Single-file mode: detect language from extension and
                # use the file's parent directory as the CodeQL project root.
                ext = target_path.suffix.lower()
                language = self._EXT_TO_LANGUAGE.get(ext)
                if language is None:
                    logger.warning(
                        "CodeQL: unsupported file extension '%s', skipping", ext
                    )
                    return []

                project_root = target_path.parent
                logger.info(
                    "CodeQL single-file mode: language=%s, project_root=%s",
                    language,
                    project_root,
                )

                db_path = executor._db_manager.create_database(
                    project_root, language
                )
                sarif_path = executor.run_security_suite(
                    db_path, language
                )
                lang_findings = parser.parse_file(str(sarif_path))
                findings.extend(lang_findings)
                logger.info(
                    "CodeQL [%s]: %d findings from %s",
                    language, len(lang_findings), sarif_path,
                )
            else:
                # Directory mode: auto-detect languages and run all
                sarif_files = executor.run_all_languages(str(target_path))
                for lang, sarif_path in sarif_files.items():
                    lang_findings = parser.parse_file(str(sarif_path))
                    findings.extend(lang_findings)
                    logger.info(
                        "CodeQL [%s]: %d findings from %s",
                        lang, len(lang_findings), sarif_path,
                    )

            return findings

        except Exception as e:
            logger.warning("CodeQL analysis failed: %s", e)
            return []

    def _merge_findings(
        self,
        ts_findings: list[Finding],
        codeql_findings: list[Finding],
    ) -> list[Finding]:
        """
        Merge tree-sitter and CodeQL findings, deduplicating by location.

        When both tools find the same issue at the same location, prefer
        CodeQL's finding (higher confidence, better taint tracking) but
        boost its confidence if tree-sitter also flagged it.
        """
        # Index tree-sitter findings by (file, line, cwe)
        ts_index: dict[str, Finding] = {}
        for f in ts_findings:
            key = f"{f.location.file_path}:{f.location.start_line}:{f.cwe_id}"
            ts_index[key] = f

        merged: list[Finding] = []
        codeql_keys: set[str] = set()

        for f in codeql_findings:
            key = f"{f.location.file_path}:{f.location.start_line}:{f.cwe_id}"
            codeql_keys.add(key)

            if key in ts_index:
                # Both tools found it → boost confidence, mark corroborated
                f.sast_confidence = min(f.sast_confidence + 0.1, 1.0)
                f.tags.append("corroborated")
                f.properties["corroborating_tools"] = ["tree-sitter", "codeql"]
            merged.append(f)

        # Add tree-sitter findings not found by CodeQL
        for key, f in ts_index.items():
            if key not in codeql_keys:
                merged.append(f)

        return merged
