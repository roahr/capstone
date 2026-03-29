"""
CodeQL database creation and management for the SEC-C SAST engine.

Handles creation of CodeQL databases from local projects, downloading
pre-built databases from GitHub, and caching databases for reuse.
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import httpx
import yaml

logger = logging.getLogger(__name__)

# Language → file extension mappings for auto-detection
_LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py", ".pyw"},
    "javascript": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    "java": {".java"},
    "cpp": {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx"},
    "go": {".go"},
}

_SUPPORTED_LANGUAGES: set[str] = set(_LANGUAGE_EXTENSIONS.keys())


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


def _project_hash(project_path: Path) -> str:
    """Compute a short deterministic hash for a project path.

    The hash is used as part of the cache key so that databases for
    different projects stored in the same cache directory do not collide.

    Args:
        project_path: Resolved absolute path to the project.

    Returns:
        8-character hex digest.
    """
    return hashlib.sha256(str(project_path).encode()).hexdigest()[:8]


class CodeQLDatabaseManager:
    """Manages CodeQL database lifecycle: creation, download, and caching.

    Uses the CodeQL CLI for local database creation and the GitHub
    code-scanning API for downloading pre-built databases.  All databases
    are cached under ``~/.sec-c/codeql-dbs/`` (configurable in
    ``configs/default.yaml``).

    Example::

        manager = CodeQLDatabaseManager()
        db_path = manager.create_database(Path("/src/myapp"), "python")
        cached  = manager.get_cached_database(Path("/src/myapp"), "python")
    """

    def __init__(self) -> None:
        config = _load_config()
        codeql_cfg: dict[str, Any] = config.get("sast", {}).get("codeql", {})

        self.cli_path: str = codeql_cfg.get("cli_path", "codeql")
        self.timeout: int = int(codeql_cfg.get("timeout_seconds", 300))
        self.github_token_env: str = codeql_cfg.get("github_token_env", "GITHUB_TOKEN")

        cache_dir_raw: str = codeql_cfg.get("database_cache_dir", "~/.sec-c/codeql-dbs")
        self.cache_dir: Path = Path(os.path.expanduser(cache_dir_raw)).resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._verify_codeql_installation()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_database(
        self,
        project_path: Path | str,
        language: str,
        output_dir: Path | str | None = None,
    ) -> Path:
        """Create a CodeQL database for the given project and language.

        If *output_dir* is ``None`` the database is placed in the
        framework cache directory so that subsequent calls to
        :meth:`get_cached_database` can find it.

        Args:
            project_path: Root of the source tree to analyse.
            language: One of the supported languages
                (``python``, ``javascript``, ``java``, ``cpp``, ``go``).
            output_dir: Optional explicit directory for the database.
                When omitted the cache directory is used.

        Returns:
            Path to the created CodeQL database directory.

        Raises:
            ValueError: If *language* is not supported.
            RuntimeError: If the CodeQL CLI exits with a non-zero status.
        """
        project_path = Path(project_path).resolve()
        language = language.lower()
        self._validate_language(language)

        if output_dir is not None:
            db_path = Path(output_dir).resolve()
        else:
            db_path = self._cache_path(project_path, language)

        # Remove stale database if it already exists (CodeQL refuses to
        # overwrite).
        if db_path.exists():
            logger.info("Removing existing database at %s", db_path)
            import shutil
            shutil.rmtree(db_path)

        cmd = [
            self.cli_path,
            "database",
            "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={project_path}",
            "--overwrite",
        ]

        logger.info(
            "Creating CodeQL database: language=%s, project=%s, output=%s",
            language,
            project_path,
            db_path,
        )
        self._run_cli(cmd, cwd=project_path)

        logger.info("Database created successfully at %s", db_path)
        return db_path

    def download_github_database(
        self,
        owner: str,
        repo: str,
        language: str,
    ) -> Path:
        """Download a pre-built CodeQL database from GitHub.

        Requires the ``GITHUB_TOKEN`` environment variable (or the
        variable named in the config) to be set with a token that has
        ``security_events`` read permission on the target repository.

        The database is downloaded as a zip archive and extracted into
        the cache directory.

        Args:
            owner: GitHub repository owner (user or organisation).
            repo: GitHub repository name.
            language: One of the supported languages.

        Returns:
            Path to the extracted CodeQL database directory.

        Raises:
            ValueError: If *language* is not supported.
            EnvironmentError: If the GitHub token is not set.
            RuntimeError: If the download fails.
        """
        language = language.lower()
        self._validate_language(language)

        token = os.environ.get(self.github_token_env)
        if not token:
            raise EnvironmentError(
                f"Environment variable {self.github_token_env!r} is not set. "
                "A GitHub personal access token is required to download "
                "pre-built CodeQL databases."
            )

        url = (
            f"https://api.github.com/repos/{owner}/{repo}"
            f"/code-scanning/codeql/databases/{language}"
        )

        db_dir = self.cache_dir / f"github_{owner}_{repo}_{language}"
        zip_path = db_dir.with_suffix(".zip")

        logger.info("Downloading CodeQL database from %s", url)

        headers = {
            "Accept": "application/zip",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()

                zip_path.parent.mkdir(parents=True, exist_ok=True)
                zip_path.write_bytes(response.content)
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"GitHub API returned {exc.response.status_code} for {url}. "
                "Ensure the repository has Code Scanning enabled and the "
                "token has the required permissions."
            ) from exc
        except httpx.RequestError as exc:
            raise RuntimeError(
                f"Network error while downloading CodeQL database: {exc}"
            ) from exc

        # Extract
        logger.info("Extracting database archive to %s", db_dir)
        if db_dir.exists():
            import shutil
            shutil.rmtree(db_dir)
        db_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(db_dir)
        except zipfile.BadZipFile as exc:
            raise RuntimeError(
                f"Downloaded file is not a valid zip archive: {exc}"
            ) from exc
        finally:
            zip_path.unlink(missing_ok=True)

        logger.info("GitHub database ready at %s", db_dir)
        return db_dir

    def get_cached_database(
        self,
        project_path: Path | str,
        language: str,
    ) -> Path | None:
        """Return the cached database path if it exists.

        Args:
            project_path: Root of the source tree.
            language: One of the supported languages.

        Returns:
            Path to the cached database directory, or ``None`` if no
            cache entry exists.
        """
        project_path = Path(project_path).resolve()
        language = language.lower()
        self._validate_language(language)

        db_path = self._cache_path(project_path, language)
        if db_path.exists() and db_path.is_dir():
            logger.debug("Cache hit for %s (%s): %s", project_path, language, db_path)
            return db_path

        logger.debug("Cache miss for %s (%s)", project_path, language)
        return None

    def detect_languages(self, project_path: Path | str) -> list[str]:
        """Auto-detect programming languages present in a project.

        Walks the source tree and maps file extensions to supported
        languages.  Returns languages sorted alphabetically.

        Args:
            project_path: Root of the source tree to inspect.

        Returns:
            Sorted list of detected language identifiers (e.g.
            ``["javascript", "python"]``).

        Raises:
            FileNotFoundError: If *project_path* does not exist.
        """
        project_path = Path(project_path).resolve()
        if not project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {project_path}")

        detected: set[str] = set()
        skip_dirs = {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            "vendor", "build", "dist", ".codeql",
        }

        for root, dirs, files in os.walk(project_path):
            # Prune directories we never want to scan
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for filename in files:
                ext = Path(filename).suffix.lower()
                for lang, extensions in _LANGUAGE_EXTENSIONS.items():
                    if ext in extensions:
                        detected.add(lang)

            # Short-circuit: every supported language already found
            if detected == _SUPPORTED_LANGUAGES:
                break

        languages = sorted(detected)
        logger.info("Detected languages in %s: %s", project_path, languages)
        return languages

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _verify_codeql_installation(self) -> None:
        """Check that the CodeQL CLI is reachable.

        Logs a warning (rather than raising) so that functionality that
        does not need the CLI (e.g. :meth:`detect_languages`) remains
        available.
        """
        try:
            result = subprocess.run(
                [self.cli_path, "version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                version = result.stdout.strip().splitlines()[0]
                logger.info("CodeQL CLI detected: %s", version)
            else:
                logger.warning(
                    "CodeQL CLI returned non-zero exit code %d. "
                    "Database creation will likely fail.",
                    result.returncode,
                )
        except FileNotFoundError:
            logger.warning(
                "CodeQL CLI not found at %r. "
                "Install CodeQL or set 'sast.codeql.cli_path' in the config.",
                self.cli_path,
            )
        except subprocess.TimeoutExpired:
            logger.warning("CodeQL CLI version check timed out.")

    def _validate_language(self, language: str) -> None:
        """Raise ``ValueError`` if *language* is not supported."""
        if language not in _SUPPORTED_LANGUAGES:
            raise ValueError(
                f"Unsupported language: {language!r}. "
                f"Supported: {sorted(_SUPPORTED_LANGUAGES)}"
            )

    def _cache_path(self, project_path: Path, language: str) -> Path:
        """Derive the deterministic cache path for a project+language pair."""
        slug = f"{project_path.name}_{_project_hash(project_path)}_{language}"
        return self.cache_dir / slug

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
            RuntimeError: On non-zero exit code or timeout.
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
