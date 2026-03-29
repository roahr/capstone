"""
CodeQL query execution engine for the SEC-C SAST module.

Runs CodeQL security query suites against databases and produces
SARIF output for downstream processing by the uncertainty scorer
and the rest of the SEC-C pipeline.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from src.sast.codeql.database_manager import CodeQLDatabaseManager

logger = logging.getLogger(__name__)


def _load_config() -> dict[str, Any]:
    """Load the framework configuration from configs/default.yaml.

    Returns:
        Parsed YAML configuration dictionary.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
    """
    config_path = Path(__file__).resolve().parents[3] / "configs" / "default.yaml"
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class CodeQLQueryExecutor:
    """Execute CodeQL queries against databases and collect SARIF results.

    Wraps the ``codeql database analyze`` command and handles query
    suite selection, SARIF output management, and multi-language
    orchestration.

    Example::

        executor = CodeQLQueryExecutor()
        sarif_path = executor.run_security_suite(db_path, "python")
        results   = executor.run_all_languages(Path("/src/myapp"))
    """

    def __init__(self) -> None:
        config = _load_config()
        codeql_cfg: dict[str, Any] = config.get("sast", {}).get("codeql", {})

        self.cli_path: str = codeql_cfg.get("cli_path", "codeql")
        self.query_suite: str = codeql_cfg.get("query_suite", "security-extended")
        self.timeout: int = int(codeql_cfg.get("timeout_seconds", 300))

        self._db_manager = CodeQLDatabaseManager()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_security_suite(
        self,
        database_path: Path | str,
        language: str,
        *,
        output_dir: Path | str | None = None,
    ) -> Path:
        """Run the security-extended query suite against a CodeQL database.

        Args:
            database_path: Path to an existing CodeQL database directory.
            language: Language of the database (e.g. ``"python"``).
                Used to select the correct query suite pack.
            output_dir: Directory to write the SARIF file into.  When
                ``None`` a temporary directory is created.

        Returns:
            Path to the SARIF results file.

        Raises:
            FileNotFoundError: If *database_path* does not exist.
            RuntimeError: If the CodeQL CLI exits with a non-zero status.
        """
        database_path = Path(database_path).resolve()
        if not database_path.exists():
            raise FileNotFoundError(
                f"CodeQL database not found: {database_path}"
            )

        language = language.lower()
        suite = f"{language}-{self.query_suite}.qls"

        if output_dir is not None:
            sarif_dir = Path(output_dir).resolve()
            sarif_dir.mkdir(parents=True, exist_ok=True)
        else:
            sarif_dir = Path(tempfile.mkdtemp(prefix="sec-c-sarif-"))

        sarif_path = sarif_dir / f"{language}-results.sarif"

        cmd = [
            self.cli_path,
            "database",
            "analyze",
            str(database_path),
            suite,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--sarif-add-query-help",
        ]

        logger.info(
            "Running security suite: language=%s, suite=%s, db=%s",
            language,
            suite,
            database_path,
        )
        self._run_cli(cmd)

        if not sarif_path.exists():
            raise RuntimeError(
                f"SARIF output file was not created at {sarif_path}. "
                "The CodeQL analysis may have produced no results."
            )

        logger.info("SARIF results written to %s", sarif_path)
        return sarif_path

    def run_custom_query(
        self,
        database_path: Path | str,
        query_path: Path | str,
        *,
        output_dir: Path | str | None = None,
    ) -> Path:
        """Run a single custom CodeQL query against a database.

        Args:
            database_path: Path to an existing CodeQL database directory.
            query_path: Path to a ``.ql`` query file.
            output_dir: Directory to write the SARIF file into.  When
                ``None`` a temporary directory is created.

        Returns:
            Path to the SARIF results file.

        Raises:
            FileNotFoundError: If either *database_path* or
                *query_path* does not exist.
            RuntimeError: If the CodeQL CLI exits with a non-zero status.
        """
        database_path = Path(database_path).resolve()
        query_path = Path(query_path).resolve()

        if not database_path.exists():
            raise FileNotFoundError(
                f"CodeQL database not found: {database_path}"
            )
        if not query_path.exists():
            raise FileNotFoundError(
                f"CodeQL query file not found: {query_path}"
            )

        if output_dir is not None:
            sarif_dir = Path(output_dir).resolve()
            sarif_dir.mkdir(parents=True, exist_ok=True)
        else:
            sarif_dir = Path(tempfile.mkdtemp(prefix="sec-c-sarif-"))

        sarif_path = sarif_dir / f"{query_path.stem}-results.sarif"

        cmd = [
            self.cli_path,
            "database",
            "analyze",
            str(database_path),
            str(query_path),
            "--format=sarif-latest",
            f"--output={sarif_path}",
        ]

        logger.info("Running custom query: %s against %s", query_path, database_path)
        self._run_cli(cmd)

        if not sarif_path.exists():
            raise RuntimeError(
                f"SARIF output file was not created at {sarif_path}. "
                "The custom query may have produced no results."
            )

        logger.info("SARIF results written to %s", sarif_path)
        return sarif_path

    def run_all_languages(
        self,
        project_path: Path | str,
        *,
        output_dir: Path | str | None = None,
    ) -> dict[str, Path]:
        """Detect languages, create databases, and run queries for each.

        This is the high-level convenience method that orchestrates the
        full SAST analysis for a project across all detected languages.

        Args:
            project_path: Root of the source tree to analyse.
            output_dir: Directory to write all SARIF files into.  When
                ``None`` a temporary directory is created.

        Returns:
            Mapping of language names to their SARIF result file paths.
            Languages that fail analysis are logged and skipped.

        Raises:
            FileNotFoundError: If *project_path* does not exist.
        """
        project_path = Path(project_path).resolve()
        if not project_path.exists():
            raise FileNotFoundError(
                f"Project path does not exist: {project_path}"
            )

        if output_dir is not None:
            sarif_dir = Path(output_dir).resolve()
            sarif_dir.mkdir(parents=True, exist_ok=True)
        else:
            sarif_dir = Path(tempfile.mkdtemp(prefix="sec-c-sarif-all-"))

        languages = self._db_manager.detect_languages(project_path)
        if not languages:
            logger.warning("No supported languages detected in %s", project_path)
            return {}

        logger.info(
            "Starting multi-language analysis for %s: %s",
            project_path,
            languages,
        )

        results: dict[str, Path] = {}

        for language in languages:
            try:
                # Reuse cached database when available
                db_path = self._db_manager.get_cached_database(project_path, language)
                if db_path is None:
                    logger.info("Creating database for %s", language)
                    db_path = self._db_manager.create_database(project_path, language)
                else:
                    logger.info("Using cached database for %s: %s", language, db_path)

                sarif_path = self.run_security_suite(
                    db_path,
                    language,
                    output_dir=sarif_dir,
                )
                results[language] = sarif_path
            except Exception:
                logger.exception(
                    "Analysis failed for language %s in %s — skipping",
                    language,
                    project_path,
                )

        logger.info(
            "Multi-language analysis complete: %d/%d languages succeeded",
            len(results),
            len(languages),
        )
        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_cli(
        self,
        cmd: list[str],
        *,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a CodeQL CLI command with timeout handling.

        Args:
            cmd: Full command list including the ``codeql`` binary.
            cwd: Working directory for the subprocess.

        Returns:
            The completed process object.

        Raises:
            RuntimeError: On non-zero exit code, timeout, or missing CLI.
        """
        logger.debug("Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=cwd,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"CodeQL CLI not found at {self.cli_path!r}. "
                "Ensure CodeQL is installed and available on PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"CodeQL command timed out after {self.timeout}s: {' '.join(cmd)}"
            ) from exc

        if result.returncode != 0:
            logger.error("CodeQL stderr:\n%s", result.stderr)
            raise RuntimeError(
                f"CodeQL command failed (exit {result.returncode}): "
                f"{' '.join(cmd)}\n{result.stderr.strip()}"
            )

        if result.stdout:
            logger.debug("CodeQL stdout:\n%s", result.stdout)
        return result
