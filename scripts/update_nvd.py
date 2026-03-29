#!/usr/bin/env python3
"""
Incremental NVD CVE update for the SEC-C RAG knowledge base.

Fetches only new or modified CVEs since the last update (tracked in
``data/rag/last_update.txt``), merges them into the existing indexes,
and writes a new timestamp.

Usage:
    python scripts/update_nvd.py
    python scripts/update_nvd.py --data-dir data/rag
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on sys.path so ``src.*`` imports resolve when
# the script is executed directly.
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

def _read_last_update(ts_path: Path) -> str | None:
    """Read the ISO-8601 timestamp from *ts_path*, or return ``None``."""
    if not ts_path.exists():
        return None
    text = ts_path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    return text


def _count_existing_cves(cve_data_path: Path) -> int:
    """Return the number of CVEs already in the knowledge base."""
    if not cve_data_path.exists():
        return 0
    try:
        with open(cve_data_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return len(data) if isinstance(data, list) else 0
    except Exception:
        return 0


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Incremental NVD CVE update for the SEC-C RAG knowledge base.",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/rag",
        help="RAG data directory (default: data/rag).",
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    ts_path = data_dir / "last_update.txt"
    nvd_dir = data_dir / "nvd_raw"
    incr_dir = data_dir / "nvd_incremental"
    cve_data_path = data_dir / "cve_data.json"

    print()
    print("  ◆ SEC-C NVD Incremental Update")
    print("  ════════════════════════════════════════")

    # ------------------------------------------------------------------
    # Step 1: Determine time window
    # ------------------------------------------------------------------
    last_update = _read_last_update(ts_path)
    if last_update:
        print(f"  Last update      : {last_update}")
    else:
        print("  Last update      : none found — fetching last 24 hours")

    existing_cves = _count_existing_cves(cve_data_path)
    print(f"  Existing CVEs    : {existing_cves}")
    print()

    t0 = time.time()

    # ------------------------------------------------------------------
    # Step 2: Download new/modified CVEs
    # ------------------------------------------------------------------
    print("  [1/3] Fetching new/modified CVEs from NVD API 2.0 ...")
    new_cve_count = 0
    try:
        from src.llm.rag.nvd_indexer import NVDIndexer

        nvd_indexer = NVDIndexer()
        incr_dir.mkdir(parents=True, exist_ok=True)
        _, new_cve_count = nvd_indexer.download_incremental(
            output_dir=incr_dir,
            last_modified_start=last_update,
        )
        print(f"        ✓ {new_cve_count} new/modified CVEs fetched")
    except Exception as exc:
        print(f"        ✗ NVD download failed: {exc}")
        logger.exception("Incremental NVD download failed")
        sys.exit(1)

    if new_cve_count == 0:
        print()
        print("  No new CVEs to process. Knowledge base is up to date.")

        # Update the timestamp even when no new CVEs are found so the
        # next run only queries from *now*.
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        ts_path.write_text(now_ts, encoding="utf-8")
        print(f"  Timestamp saved  : {now_ts}")
        print()
        return

    # ------------------------------------------------------------------
    # Step 3: Merge incremental data into the NVD raw directory
    # ------------------------------------------------------------------
    print("  [2/3] Merging incremental data ...")
    try:
        nvd_dir.mkdir(parents=True, exist_ok=True)

        # Parse new CVE entries from the incremental download.
        from src.llm.rag.nvd_indexer import NVDIndexer as _NVDIndexer

        new_entries: list[dict] = []
        for jf in sorted(incr_dir.glob("*.json")):
            with open(jf, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for vuln in data.get("vulnerabilities", []):
                entry = _NVDIndexer.parse_cve_entry(vuln)
                if entry["description"]:
                    new_entries.append(entry)

        # Load existing CVE data and merge (deduplicate by CVE ID).
        existing_entries: list[dict] = []
        if cve_data_path.exists():
            with open(cve_data_path, "r", encoding="utf-8") as fh:
                existing_entries = json.load(fh)

        existing_map = {e["id"]: e for e in existing_entries}
        added = 0
        updated = 0
        for entry in new_entries:
            if entry["id"] in existing_map:
                updated += 1
            else:
                added += 1
            existing_map[entry["id"]] = entry

        merged_entries = list(existing_map.values())

        # Write merged CVE data back.
        with open(cve_data_path, "w", encoding="utf-8") as fh:
            json.dump(merged_entries, fh, indent=2)

        print(f"        ✓ {added} new + {updated} updated CVEs merged")
        print(f"        ✓ Total CVEs: {len(merged_entries)}")
    except Exception as exc:
        print(f"        ✗ Merge failed: {exc}")
        logger.exception("Merge failed")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Step 4: Rebuild indexes
    # ------------------------------------------------------------------
    print("  [3/3] Rebuilding FAISS + BM25 indexes ...")
    try:
        from src.llm.rag.knowledge_base import KnowledgeBase

        cwe_dir = data_dir / "cwe_raw"
        faiss_path = data_dir / "faiss_index.bin"
        bm25_path = data_dir / "bm25_index.pkl"
        cwe_data_path_idx = data_dir / "cwe_data.json"

        kb = KnowledgeBase(
            faiss_index_path=faiss_path,
            bm25_index_path=bm25_path,
            cwe_data_path=cwe_data_path_idx,
        )

        # Ensure CWE raw dir exists (may be empty if CWEs were never
        # downloaded — the builder handles this gracefully).
        if not cwe_dir.exists():
            cwe_dir.mkdir(parents=True, exist_ok=True)

        kb.build_from_data(cwe_dir=cwe_dir, nvd_dir=nvd_dir)
        print("        ✓ Indexes rebuilt successfully")
    except Exception as exc:
        print(f"        ✗ Index rebuild failed: {exc}")
        logger.exception("Index rebuild failed")
        sys.exit(1)

    elapsed = time.time() - t0

    # ------------------------------------------------------------------
    # Step 5: Save new timestamp
    # ------------------------------------------------------------------
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    ts_path.parent.mkdir(parents=True, exist_ok=True)
    ts_path.write_text(now_ts, encoding="utf-8")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    print("  ────────────────────────────────────────")
    print("  Update complete!")
    print(f"  New CVEs added   : {added}")
    print(f"  CVEs updated     : {updated}")
    print(f"  Total CVEs       : {len(merged_entries)}")
    print(f"  Timestamp saved  : {now_ts}")
    print(f"  Elapsed time     : {elapsed:.1f}s")
    print()

    # Clean up incremental download files.
    try:
        import shutil
        shutil.rmtree(incr_dir, ignore_errors=True)
        logger.info("Cleaned up incremental download directory: %s", incr_dir)
    except Exception:
        pass


if __name__ == "__main__":
    main()
