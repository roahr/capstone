#!/usr/bin/env python3
"""
SEC-C RAG Knowledge Base Setup -- Real Data Download.

Downloads the actual MITRE CWE catalog (900+ entries) and optionally
NVD CVE data, then builds production FAISS + BM25 indexes.

Usage:
    python scripts/setup_rag.py                  # CWE only (fast, ~2 min)
    python scripts/setup_rag.py --full            # CWE + NVD CVEs (~2-3 hours)
    python scripts/setup_rag.py --full --nvd-key YOUR_KEY  # Faster NVD download
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def setup_cwe(output_dir: Path) -> int:
    """Download and index the MITRE CWE catalog."""
    from src.llm.rag.cwe_indexer import CWEIndexer

    print("\n  --- CWE Catalog Download ---\n")

    indexer = CWEIndexer()
    cwe_dir = output_dir / "cwe_raw"
    cwe_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Download
    print("  [>] Downloading CWE catalog from MITRE ...")
    try:
        xml_path = indexer.download_cwe_catalog(str(cwe_dir))
        print(f"      Downloaded: {xml_path}")
    except Exception as e:
        print(f"  [X] Download failed: {e}")
        print("      Falling back to bundled CWE data ...")
        return _use_bundled_cwe(output_dir)

    # Step 2: Parse
    print("  [>] Parsing CWE XML ...")
    try:
        cwe_entries = indexer.parse_cwe_xml(xml_path)
        print(f"      Parsed: {len(cwe_entries)} CWE entries")
    except Exception as e:
        print(f"  [X] Parse failed: {e}")
        return _use_bundled_cwe(output_dir)

    # Step 3: Save parsed data
    cwe_data_dir = output_dir.parent / "cwe"
    cwe_data_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = cwe_data_dir / "cwe_catalog.json"
    with open(catalog_path, "w", encoding="utf-8") as f:
        json.dump(cwe_entries, f, indent=2, ensure_ascii=False)
    print(f"      Saved catalog: {catalog_path}")

    # Step 4: Build indexes
    print("  [>] Building search indexes ...")
    try:
        _build_indexes_from_entries(cwe_entries, output_dir, "cwe")
    except Exception as e:
        print(f"  [!] Index build warning: {e}")

    print(f"\n  [OK] CWE catalog ready: {len(cwe_entries)} entries indexed\n")
    return len(cwe_entries)


def setup_nvd(output_dir: Path, api_key: str | None = None, years: str = "2024-2026") -> int:
    """Download and index NVD CVE data."""
    from src.llm.rag.nvd_indexer import NVDIndexer

    print("\n  --- NVD CVE Database Download ---\n")

    start_year, end_year = map(int, years.split("-"))
    print(f"  [>] Year range: {start_year} - {end_year}")

    if api_key:
        print(f"  [>] API key: ...{api_key[-4:]} (elevated rate limits)")
    else:
        print("  [>] No API key (5 req/30s -- this will be slow)")
        print("      Get a key at: https://nvd.nist.gov/developers/request-an-api-key")

    indexer = NVDIndexer(api_key=api_key)
    nvd_dir = output_dir / "nvd_raw"
    nvd_dir.mkdir(parents=True, exist_ok=True)

    # Download year by year
    all_cves = []
    for year in range(start_year, end_year + 1):
        print(f"\n  [>] Downloading CVEs for {year} ...")
        try:
            result_dir = indexer.download_nvd_data(
                output_dir=str(nvd_dir),
                year_start=year,
                year_end=year,
            )
            # download_nvd_data returns the output directory Path.
            # Parse the JSON files it wrote to collect CVE entries.
            result_dir = Path(result_dir)
            year_entries = []
            for json_file in sorted(result_dir.glob(f"nvd_{year}_*.json")):
                with open(json_file, encoding="utf-8") as f:
                    data = json.load(f)
                for vuln in data.get("vulnerabilities", []):
                    entry = indexer.parse_cve_entry(vuln)
                    if entry["description"]:
                        year_entries.append(entry)
            all_cves.extend(year_entries)
            print(f"      {year}: {len(year_entries)} CVEs")
        except Exception as e:
            print(f"  [!] {year} failed: {e}")
            continue

    if not all_cves:
        print("  [X] No CVE data downloaded. NVD API may be unavailable.")
        return 0

    # Save combined data
    cve_path = output_dir / "cve_data.json"
    with open(cve_path, "w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2, ensure_ascii=False)
    print(f"\n  [>] Saved {len(all_cves)} CVEs to {cve_path}")

    # Build indexes
    print("  [>] Building NVD search indexes ...")
    try:
        _build_indexes_from_entries(
            [{"id": c.get("id", ""), "text": c.get("description", ""), "name": c.get("id", "")}
             for c in all_cves if c.get("description")],
            output_dir, "nvd"
        )
    except Exception as e:
        print(f"  [!] Index build warning: {e}")

    print(f"\n  [OK] NVD database ready: {len(all_cves)} CVEs indexed\n")
    return len(all_cves)


def _build_indexes_from_entries(entries: list, output_dir: Path, prefix: str) -> None:
    """Build BM25 and FAISS indexes from a list of entries."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Prepare corpus
    corpus = []
    for entry in entries:
        if isinstance(entry, dict):
            text_parts = []
            for key in ("id", "name", "description", "text"):
                if key in entry and entry[key]:
                    text_parts.append(str(entry[key]))
            if text_parts:
                corpus.append({"id": entry.get("id", ""), "text": " ".join(text_parts)})

    if not corpus:
        print(f"      No corpus entries for {prefix}")
        return

    # BM25 index
    try:
        import pickle
        from rank_bm25 import BM25Okapi

        tokenized = [doc["text"].lower().split() for doc in corpus]
        bm25 = BM25Okapi(tokenized)
        bm25_path = output_dir / f"{prefix}_bm25.pkl"
        with open(bm25_path, "wb") as f:
            pickle.dump({"bm25": bm25, "corpus": corpus}, f)
        print(f"      BM25 index: {len(corpus)} docs -> {bm25_path.name}")
    except Exception as e:
        print(f"      BM25 skipped: {e}")

    # FAISS index
    try:
        import faiss
        import numpy as np

        # Build vocabulary-based embeddings (no model download needed)
        vocab: dict[str, int] = {}
        for doc in corpus:
            for word in doc["text"].lower().split():
                if word not in vocab:
                    vocab[word] = len(vocab)

        dim = min(len(vocab), 512)
        vectors = np.zeros((len(corpus), dim), dtype=np.float32)
        for i, doc in enumerate(corpus):
            for word in doc["text"].lower().split():
                idx = vocab.get(word, 0)
                if idx < dim:
                    vectors[i, idx] += 1.0
            norm = np.linalg.norm(vectors[i])
            if norm > 0:
                vectors[i] /= norm

        index = faiss.IndexFlatIP(dim)
        index.add(vectors)
        faiss_path = output_dir / f"{prefix}_faiss.bin"
        faiss.write_index(index, str(faiss_path))

        meta = {"dim": dim, "n_vectors": len(corpus), "vocab_size": len(vocab), "prefix": prefix}
        with open(output_dir / f"{prefix}_faiss_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        print(f"      FAISS index: {len(corpus)} vectors (dim={dim}) -> {faiss_path.name}")
    except Exception as e:
        print(f"      FAISS skipped: {e}")


def _use_bundled_cwe(output_dir: Path) -> int:
    """Fallback to bundled CWE data."""
    bundled = Path("data/cwe/cwe_catalog.json")
    if bundled.exists():
        with open(bundled) as f:
            entries = json.load(f)
        print(f"      Using bundled data: {len(entries)} CWEs")
        _build_indexes_from_entries(entries, output_dir, "cwe")
        return len(entries)
    print("      No bundled data available")
    return 0


def main():
    parser = argparse.ArgumentParser(description="SEC-C RAG Knowledge Base Setup")
    parser.add_argument("--full", action="store_true", help="Download CWE + NVD (slower)")
    parser.add_argument("--nvd-key", default=None, help="NVD API key for faster downloads")
    parser.add_argument("--years", default="2024-2026", help="NVD year range (default: 2024-2026)")
    parser.add_argument("--output", default="data/rag", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print()
    print("  ================================================================")
    print("  Sec-C RAG Knowledge Base Setup")
    print("  ================================================================")

    start = time.time()

    # Always download CWE
    cwe_count = setup_cwe(output_dir)

    # Optionally download NVD
    nvd_count = 0
    if args.full:
        nvd_key = args.nvd_key or __import__("os").environ.get("NVD_API_KEY")
        nvd_count = setup_nvd(output_dir, api_key=nvd_key, years=args.years)

    elapsed = time.time() - start

    print("  ================================================================")
    print("  Summary")
    print("  ================================================================")
    print(f"  CWE entries indexed:  {cwe_count}")
    print(f"  CVE entries indexed:  {nvd_count}")
    print(f"  Output directory:     {output_dir}")
    print(f"  Time elapsed:         {elapsed:.1f}s")
    print("  ================================================================")
    print()


if __name__ == "__main__":
    main()
