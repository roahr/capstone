"""
NVD CVE Database Indexer for the SEC-C RAG knowledge base.

Downloads CVE records from the NIST NVD API 2.0, parses them into
structured entries, and builds a FAISS vector index for semantic search
across vulnerability descriptions.  Supports incremental updates via
the ``lastModStartDate`` / ``lastModEndDate`` API parameters.

Rate limiting is enforced automatically:
- Without an API key: 5 requests per 30 seconds.
- With an API key:   50 requests per 30 seconds.

See https://nvd.nist.gov/developers/vulnerabilities for API documentation.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import numpy as np

logger = logging.getLogger(__name__)

# NVD API 2.0 endpoint.
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Maximum results per page (NVD hard limit).
NVD_PAGE_SIZE = 2000

# Rate limits (requests per 30-second window).
_RATE_LIMIT_NO_KEY = 5
_RATE_LIMIT_WITH_KEY = 50
_RATE_WINDOW_SECS = 30.0


class NVDIndexer:
    """Downloads, parses, and indexes NVD CVE data.

    Attributes:
        api_key: Optional NVD API key for elevated rate limits.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._rate_limit = (
            _RATE_LIMIT_WITH_KEY if self.api_key else _RATE_LIMIT_NO_KEY
        )
        self._request_timestamps: list[float] = []

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def download_nvd_data(
        self,
        output_dir: str | Path,
        year_start: int = 2020,
        year_end: int = 2026,
    ) -> Path:
        """Download CVE data from the NVD API 2.0.

        Fetches all CVEs published between *year_start*-01-01 and
        *year_end*-12-31, paging through the results automatically.
        Each page is saved as a separate JSON file in *output_dir*.

        Args:
            output_dir: Directory to write the raw JSON responses.
            year_start: First year to include (inclusive).
            year_end: Last year to include (inclusive).

        Returns:
            Path to *output_dir* containing the downloaded JSON files.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        total_cves = 0

        for year in range(year_start, year_end + 1):
            pub_start = f"{year}-01-01T00:00:00.000"
            pub_end = f"{year}-12-31T23:59:59.999"
            year_cves = self._download_year(output_dir, year, pub_start, pub_end)
            total_cves += year_cves
            logger.info("Year %d: downloaded %d CVEs", year, year_cves)

        logger.info(
            "Total CVEs downloaded: %d across years %d-%d",
            total_cves, year_start, year_end,
        )
        return output_dir

    def download_incremental(
        self,
        output_dir: str | Path,
        last_modified_start: str | None = None,
    ) -> tuple[Path, int]:
        """Download only CVEs modified since a given timestamp.

        This is used by the incremental update script to keep the local
        index in sync without re-downloading the entire NVD dataset.

        Args:
            output_dir: Directory for the JSON responses.
            last_modified_start: ISO-8601 timestamp.  If ``None``, fetches
                CVEs modified in the last 24 hours.

        Returns:
            Tuple of (output_dir, number of CVEs fetched).
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if last_modified_start is None:
            # Default: last 24 hours
            from datetime import timedelta
            start_dt = datetime.now(timezone.utc) - timedelta(days=1)
            last_modified_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

        end_dt = datetime.now(timezone.utc)
        last_modified_end = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

        params: dict[str, Any] = {
            "lastModStartDate": last_modified_start,
            "lastModEndDate": last_modified_end,
            "resultsPerPage": NVD_PAGE_SIZE,
            "startIndex": 0,
        }

        total_fetched = 0
        page = 0

        while True:
            params["startIndex"] = page * NVD_PAGE_SIZE
            data = self._api_request(params)
            if data is None:
                break

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            out_file = output_dir / f"nvd_incremental_{page:04d}.json"
            with open(out_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)

            total_fetched += len(vulnerabilities)
            logger.info(
                "Incremental page %d: %d CVEs (total so far: %d/%d)",
                page, len(vulnerabilities), total_fetched, total_results,
            )

            if total_fetched >= total_results:
                break
            page += 1

        return output_dir, total_fetched

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_cve_entry(cve_json: dict[str, Any]) -> dict[str, Any]:
        """Parse a single CVE JSON object into a structured dict.

        Extracts the fields most relevant for security analysis:

        - ``id``: CVE identifier (e.g. ``"CVE-2023-12345"``).
        - ``description``: English description text.
        - ``cwe_ids``: List of associated CWE identifiers.
        - ``cvss_v31_score``: CVSS v3.1 base score (0.0--10.0), or ``None``.
        - ``cvss_v31_severity``: CVSS severity string, or ``None``.
        - ``references``: List of reference URLs.
        - ``published``: ISO publication timestamp.
        - ``last_modified``: ISO last-modified timestamp.

        Args:
            cve_json: A single ``vulnerabilities[i]`` object from the
                NVD API response.

        Returns:
            Structured dict with the extracted fields.
        """
        cve = cve_json.get("cve", cve_json)

        cve_id = cve.get("id", "")

        # Description (prefer English)
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CWE IDs
        cwe_ids: list[str] = []
        weaknesses = cve.get("weaknesses", [])
        for weakness in weaknesses:
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # CVSS v3.1
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        cvss_score: float | None = None
        cvss_severity: str | None = None
        if cvss_v31:
            primary = cvss_v31[0].get("cvssData", {})
            cvss_score = primary.get("baseScore")
            cvss_severity = primary.get("baseSeverity")

        # If v3.1 not available, try v3.0
        if cvss_score is None:
            cvss_v30 = metrics.get("cvssMetricV30", [])
            if cvss_v30:
                primary = cvss_v30[0].get("cvssData", {})
                cvss_score = primary.get("baseScore")
                cvss_severity = primary.get("baseSeverity")

        # References
        references: list[str] = []
        for ref in cve.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        return {
            "id": cve_id,
            "description": description,
            "cwe_ids": cwe_ids,
            "cvss_v31_score": cvss_score,
            "cvss_v31_severity": cvss_severity,
            "references": references,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        }

    # ------------------------------------------------------------------
    # Index building
    # ------------------------------------------------------------------

    def build_index(
        self, nvd_dir: str | Path
    ) -> tuple[Any, list[dict[str, Any]]]:
        """Build a FAISS index from downloaded NVD JSON files.

        Reads all JSON files in *nvd_dir*, parses every CVE entry, generates
        sentence-transformer embeddings from CVE descriptions, and builds a
        FAISS inner-product index (cosine similarity on L2-normalised
        vectors).

        Args:
            nvd_dir: Directory containing JSON files from
                :meth:`download_nvd_data`.

        Returns:
            Tuple ``(faiss_index, metadata_list)`` where ``metadata_list[i]``
            is the parsed CVE dict corresponding to row ``i`` of the FAISS
            index.
        """
        nvd_dir = Path(nvd_dir)
        json_files = sorted(nvd_dir.glob("*.json"))
        if not json_files:
            raise FileNotFoundError(
                f"No JSON files found in {nvd_dir}. Run download_nvd_data() first."
            )

        all_entries: list[dict[str, Any]] = []

        for json_file in json_files:
            with open(json_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                entry = self.parse_cve_entry(vuln)
                if entry["description"]:
                    all_entries.append(entry)

        logger.info("Parsed %d CVE entries from %d files", len(all_entries), len(json_files))

        if not all_entries:
            raise ValueError("No CVE entries with descriptions found")

        # Build texts for embedding
        texts = []
        for entry in all_entries:
            cwes = ", ".join(entry["cwe_ids"]) if entry["cwe_ids"] else "N/A"
            score = entry["cvss_v31_score"] if entry["cvss_v31_score"] else "N/A"
            text = f"{entry['id']} ({cwes}, CVSS: {score}): {entry['description']}"
            texts.append(text)

        embeddings = self._embed_texts(texts)

        # Build FAISS index
        try:
            import faiss  # type: ignore[import-untyped]

            dim = embeddings.shape[1]
            index = faiss.IndexFlatIP(dim)
            faiss.normalize_L2(embeddings)
            index.add(embeddings)

            logger.info(
                "Built FAISS index with %d CVE entries (dim=%d)",
                index.ntotal, dim,
            )
            return index, all_entries

        except ImportError:
            logger.warning(
                "FAISS not available; returning raw embeddings array. "
                "Install faiss-cpu for proper vector search."
            )
            return embeddings, all_entries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _download_year(
        self,
        output_dir: Path,
        year: int,
        pub_start: str,
        pub_end: str,
    ) -> int:
        """Download all CVEs for a single year, handling pagination."""
        params: dict[str, Any] = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": NVD_PAGE_SIZE,
            "startIndex": 0,
        }

        total_fetched = 0
        page = 0

        while True:
            params["startIndex"] = page * NVD_PAGE_SIZE
            data = self._api_request(params)
            if data is None:
                logger.error("API request failed for year %d page %d", year, page)
                break

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            out_file = output_dir / f"nvd_{year}_{page:04d}.json"
            with open(out_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)

            total_fetched += len(vulnerabilities)
            logger.info(
                "Year %d page %d: %d CVEs (total: %d/%d)",
                year, page, len(vulnerabilities), total_fetched, total_results,
            )

            if total_fetched >= total_results:
                break
            page += 1

        return total_fetched

    def _api_request(self, params: dict[str, Any]) -> dict[str, Any] | None:
        """Make a rate-limited request to the NVD API.

        Automatically waits if the rate limit would be exceeded.

        Args:
            params: Query parameters for the NVD API.

        Returns:
            Parsed JSON response dict, or ``None`` on failure.
        """
        self._enforce_rate_limit()

        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            with httpx.Client(timeout=60, follow_redirects=True) as client:
                resp = client.get(NVD_API_BASE, params=params, headers=headers)
                self._request_timestamps.append(time.monotonic())
                resp.raise_for_status()
                return resp.json()

        except httpx.HTTPStatusError as e:
            logger.error("NVD API HTTP error: %s", e)
            if e.response.status_code == 403:
                logger.warning(
                    "Rate-limited by NVD. Sleeping 30s before retry..."
                )
                time.sleep(30)
                return self._api_request(params)
            return None
        except httpx.RequestError as e:
            logger.error("NVD API request error: %s", e)
            return None

    def _enforce_rate_limit(self) -> None:
        """Block until we are within the NVD rate-limit window."""
        now = time.monotonic()

        # Prune timestamps older than the rate window.
        cutoff = now - _RATE_WINDOW_SECS
        self._request_timestamps = [
            t for t in self._request_timestamps if t > cutoff
        ]

        if len(self._request_timestamps) >= self._rate_limit:
            oldest = self._request_timestamps[0]
            sleep_time = _RATE_WINDOW_SECS - (now - oldest) + 0.5
            if sleep_time > 0:
                logger.info(
                    "Rate limit reached (%d/%d). Sleeping %.1fs...",
                    len(self._request_timestamps),
                    self._rate_limit,
                    sleep_time,
                )
                time.sleep(sleep_time)

    @staticmethod
    def _embed_texts(texts: list[str]) -> np.ndarray:
        """Encode texts using sentence-transformers all-MiniLM-L6-v2.

        Falls back to random vectors if sentence-transformers is not
        installed (for development/testing only).

        Args:
            texts: Strings to embed.

        Returns:
            Float32 array of shape ``(len(texts), 384)``.
        """
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]

            model = SentenceTransformer("all-MiniLM-L6-v2")
            embeddings = model.encode(
                texts,
                show_progress_bar=True,
                convert_to_numpy=True,
                batch_size=64,
            )
            return embeddings.astype(np.float32)

        except ImportError:
            logger.warning(
                "sentence-transformers not installed. "
                "Using random embeddings as fallback."
            )
            return np.random.randn(len(texts), 384).astype(np.float32)
