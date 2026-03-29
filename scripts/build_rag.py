#!/usr/bin/env python3
"""
Build the SEC-C RAG knowledge base from CWE and NVD data sources.

Downloads the MITRE CWE catalog and NVD CVE records, then builds
FAISS (dense semantic) and BM25 (sparse keyword) indexes for the
dual-agent LLM validation pipeline.

Usage:
    python scripts/build_rag.py
    python scripts/build_rag.py --years 2023-2026
    python scripts/build_rag.py --cwe-only
    python scripts/build_rag.py --output data/rag
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path so ``src.*`` imports resolve when
# the script is executed directly (e.g. ``python scripts/build_rag.py``).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _parse_year_range(value: str) -> tuple[int, int]:
    """Parse a ``YYYY-YYYY`` string into (start, end) integers."""
    parts = value.split("-")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(
            f"Invalid year range '{value}'. Expected format: YYYY-YYYY"
        )
    try:
        start, end = int(parts[0]), int(parts[1])
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid year range '{value}'. Years must be integers."
        )
    if start > end:
        raise argparse.ArgumentTypeError(
            f"Start year ({start}) must be <= end year ({end})."
        )
    return start, end


def _fmt_size(path: Path) -> str:
    """Return a human-readable file size string."""
    if not path.exists():
        return "N/A"
    size = path.stat().st_size
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the SEC-C RAG knowledge base.",
    )
    parser.add_argument(
        "--years",
        type=str,
        default="2022-2026",
        help="Year range for NVD CVE download (default: 2022-2026).",
    )
    parser.add_argument(
        "--cwe-only",
        action="store_true",
        help="Only download the CWE catalog; skip NVD CVE data.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/rag",
        help="Output directory for indexes and data (default: data/rag).",
    )
    args = parser.parse_args()

    year_start, year_end = _parse_year_range(args.years)
    output_dir = Path(args.output)

    # Sub-directories for raw downloads.
    cwe_dir = output_dir / "cwe_raw"
    nvd_dir = output_dir / "nvd_raw"

    print()
    print("  ◆ SEC-C RAG Builder")
    print("  ════════════════════════════════════════")
    print(f"  Output directory : {output_dir}")
    print(f"  CWE catalog      : will download")
    if args.cwe_only:
        print("  NVD CVE data     : skipped (--cwe-only)")
    else:
        print(f"  NVD CVE data     : {year_start}–{year_end}")
    print()

    t0 = time.time()

    # ------------------------------------------------------------------
    # Step 1: Download CWE catalog
    # ------------------------------------------------------------------
    print("  [1/3] Downloading CWE catalog ...")
    cwe_count = 0
    try:
        from src.llm.rag.cwe_indexer import CWEIndexer

        cwe_indexer = CWEIndexer()
        xml_path = cwe_indexer.download_cwe_catalog(cwe_dir)
        cwe_entries = cwe_indexer.parse_cwe_xml(xml_path)
        cwe_count = len(cwe_entries)
        print(f"        ✓ {cwe_count} CWE entries parsed")
    except Exception as exc:
        print(f"        ✗ CWE download failed: {exc}")
        logger.exception("CWE download failed")
        if args.cwe_only:
            print("\n  Build aborted — CWE download is required in --cwe-only mode.")
            sys.exit(1)

    # ------------------------------------------------------------------
    # Step 2: Download NVD CVE data
    # ------------------------------------------------------------------
    cve_count = 0
    if args.cwe_only:
        print("  [2/3] Skipping NVD download (--cwe-only)")
    else:
        print(f"  [2/3] Downloading NVD CVEs ({year_start}–{year_end}) ...")
        try:
            from src.llm.rag.nvd_indexer import NVDIndexer

            nvd_indexer = NVDIndexer()
            nvd_indexer.download_nvd_data(
                output_dir=nvd_dir,
                year_start=year_start,
                year_end=year_end,
            )

            # Count CVEs that were downloaded.
            import json

            for jf in sorted(nvd_dir.glob("*.json")):
                with open(jf, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                for vuln in data.get("vulnerabilities", []):
                    entry = NVDIndexer.parse_cve_entry(vuln)
                    if entry["description"]:
                        cve_count += 1

            print(f"        ✓ {cve_count} CVE entries downloaded")
        except Exception as exc:
            print(f"        ✗ NVD download failed: {exc}")
            logger.exception("NVD download failed")

    # ------------------------------------------------------------------
    # Step 3: Build FAISS + BM25 indexes
    # ------------------------------------------------------------------
    print("  [3/3] Building FAISS + BM25 indexes ...")
    try:
        from src.llm.rag.knowledge_base import KnowledgeBase

        # Configure index output paths within the chosen output directory.
        faiss_path = output_dir / "faiss_index.bin"
        bm25_path = output_dir / "bm25_index.pkl"
        cwe_data_path = output_dir / "cwe_data.json"

        kb = KnowledgeBase(
            faiss_index_path=faiss_path,
            bm25_index_path=bm25_path,
            cwe_data_path=cwe_data_path,
        )

        # build_from_data expects directories with raw CWE XML / NVD JSON.
        # If nvd_dir doesn't exist (--cwe-only), create it empty so the
        # builder simply finds zero JSON files.
        if not nvd_dir.exists():
            nvd_dir.mkdir(parents=True, exist_ok=True)

        kb.build_from_data(cwe_dir=cwe_dir, nvd_dir=nvd_dir)
        print("        ✓ Indexes built successfully")
    except Exception as exc:
        print(f"        ✗ Index build failed: {exc}")
        logger.exception("Index build failed")
        sys.exit(1)

    elapsed = time.time() - t0

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    faiss_path = output_dir / "faiss_index.bin"
    bm25_path = output_dir / "bm25_index.pkl"

    print()
    print("  ────────────────────────────────────────")
    print("  Build complete!")
    print(f"  CWEs indexed     : {cwe_count}")
    print(f"  CVEs indexed     : {cve_count}")
    print(f"  FAISS index size : {_fmt_size(faiss_path)}")
    print(f"  BM25 index size  : {_fmt_size(bm25_path)}")
    print(f"  Elapsed time     : {elapsed:.1f}s")
    print()

    # Save a timestamp for incremental updates.
    from datetime import datetime, timezone

    ts_path = output_dir / "last_update.txt"
    ts_path.parent.mkdir(parents=True, exist_ok=True)
    ts_path.write_text(
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
