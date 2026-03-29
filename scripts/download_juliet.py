#!/usr/bin/env python3
"""
Download NIST Juliet Test Suite for Mini-GAT training.

Downloads Java and C/C++ test cases from NIST SAMATE, organizes them
by CWE, and generates ground-truth labels for training and calibration.

Usage:
    python scripts/download_juliet.py
    python scripts/download_juliet.py --output data/juliet
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import re
import zipfile
from pathlib import Path

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Juliet Test Suite download URLs (NIST SAMATE)
JULIET_URLS = {
    "java": "https://samate.nist.gov/SARD/downloads/test-suites/2023-07-07-juliet-test-suite-for-java-v1.3-with-extra-support.zip",
    "c_cpp": "https://samate.nist.gov/SARD/downloads/test-suites/2023-07-07-juliet-test-suite-for-c-cplusplus-v1.3-with-extra-support.zip",
}

# Fallback: smaller subset URLs from GitHub mirrors
FALLBACK_URLS = {
    "java": "https://github.com/NIST-SARD/juliet-test-suite-java/archive/refs/heads/main.zip",
    "c_cpp": "https://github.com/NIST-SARD/juliet-test-suite-c-cplusplus/archive/refs/heads/main.zip",
}

# CWEs we care about for security analysis
TARGET_CWES = {
    "CWE78", "CWE79", "CWE89", "CWE90", "CWE22", "CWE23",
    "CWE94", "CWE95", "CWE119", "CWE120", "CWE121", "CWE122",
    "CWE134", "CWE190", "CWE191", "CWE200", "CWE209",
    "CWE256", "CWE259", "CWE287", "CWE327", "CWE328", "CWE330",
    "CWE369", "CWE400", "CWE404", "CWE416", "CWE426",
    "CWE476", "CWE502", "CWE601", "CWE611", "CWE614",
    "CWE643", "CWE690", "CWE762", "CWE789",
    "CWE835", "CWE862", "CWE863",
}


def download_and_extract(url: str, output_dir: Path, label: str) -> bool:
    """Download a zip file and extract it."""
    logger.info(f"Downloading {label} from {url[:80]}...")
    try:
        with httpx.Client(timeout=300, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()

        logger.info(f"Downloaded {len(response.content) / 1e6:.1f} MB, extracting...")

        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            zf.extractall(output_dir)

        logger.info(f"Extracted {label} to {output_dir}")
        return True

    except Exception as e:
        logger.warning(f"Failed to download {label}: {e}")
        return False


def organize_test_cases(raw_dir: Path, output_dir: Path) -> dict:
    """Organize test cases by CWE and classify as good/bad."""
    labels = {"vulnerable": [], "safe": [], "stats": {}}

    # Find all test case files
    for ext in ("*.java", "*.c", "*.cpp"):
        for filepath in raw_dir.rglob(ext):
            # Skip non-test files
            name = filepath.name
            if not (name.startswith("CWE") or "CWE" in str(filepath)):
                continue

            # Extract CWE from path or filename
            cwe_match = re.search(r"CWE(\d+)", str(filepath))
            if not cwe_match:
                continue

            cwe_id = f"CWE{cwe_match.group(1)}"

            # Check if it's a target CWE
            if cwe_id not in TARGET_CWES:
                continue

            # Classify: files with "bad" or "s01"/"s02" are vulnerable
            # Files with "good" or "goodG2B"/"goodB2G" are safe
            is_bad = any(marker in name.lower() for marker in ["bad", "_bad", "s01", "s02"])
            is_good = any(marker in name.lower() for marker in ["good", "_good"])

            # Default: if contains "bad" → vulnerable, else safe
            if is_bad:
                is_vulnerable = True
            elif is_good:
                is_vulnerable = False
            else:
                # Infer from directory structure
                is_vulnerable = "bad" in str(filepath).lower()

            # Copy to organized structure
            lang = "java" if name.endswith(".java") else "c_cpp"
            dest_dir = output_dir / lang / cwe_id / ("bad" if is_vulnerable else "good")
            dest_dir.mkdir(parents=True, exist_ok=True)

            dest_file = dest_dir / name
            if not dest_file.exists():
                dest_file.write_bytes(filepath.read_bytes())

            # Track in labels
            entry = {
                "file": str(dest_file.relative_to(output_dir)),
                "cwe": cwe_id,
                "language": lang,
                "vulnerable": is_vulnerable,
            }

            if is_vulnerable:
                labels["vulnerable"].append(entry)
            else:
                labels["safe"].append(entry)

            # Stats
            labels["stats"].setdefault(cwe_id, {"vulnerable": 0, "safe": 0})
            key = "vulnerable" if is_vulnerable else "safe"
            labels["stats"][cwe_id][key] += 1

    return labels


def generate_synthetic_python_cases(output_dir: Path) -> dict:
    """Generate synthetic Python test cases since Juliet doesn't include Python."""
    logger.info("Generating synthetic Python test cases...")

    labels = {"vulnerable": [], "safe": [], "stats": {}}
    python_dir = output_dir / "python"

    # CWE-89: SQL Injection
    vuln_cases = {
        "CWE89": {
            "bad": [
                'import sqlite3\ndef get_user(name):\n    conn = sqlite3.connect("db")\n    conn.execute(f"SELECT * FROM users WHERE name=\'{name}\'")\n',
                'import sqlite3\ndef search(q):\n    conn = sqlite3.connect("db")\n    conn.execute("SELECT * FROM items WHERE name LIKE \'%" + q + "%\'")\n',
            ],
            "good": [
                'import sqlite3\ndef get_user(name):\n    conn = sqlite3.connect("db")\n    conn.execute("SELECT * FROM users WHERE name=?", (name,))\n',
                'import sqlite3\ndef search(q):\n    conn = sqlite3.connect("db")\n    conn.execute("SELECT * FROM items WHERE name LIKE ?", (f"%{q}%",))\n',
            ],
        },
        "CWE78": {
            "bad": [
                'import os\ndef ping(host):\n    os.system(f"ping -c 1 {host}")\n',
                'import subprocess\ndef run(cmd):\n    subprocess.run(f"echo {cmd}", shell=True)\n',
            ],
            "good": [
                'import subprocess\ndef ping(host):\n    subprocess.run(["ping", "-c", "1", host])\n',
                'import subprocess\ndef run(cmd):\n    subprocess.run(["echo", cmd])\n',
            ],
        },
        "CWE22": {
            "bad": [
                'import os\ndef read(name):\n    with open(os.path.join("/uploads", name)) as f:\n        return f.read()\n',
            ],
            "good": [
                'import os\ndef read(name):\n    base = os.path.realpath("/uploads")\n    path = os.path.realpath(os.path.join(base, name))\n    if not path.startswith(base): raise ValueError("traversal")\n    with open(path) as f:\n        return f.read()\n',
            ],
        },
        "CWE502": {
            "bad": [
                'import pickle\ndef load(data):\n    return pickle.loads(data)\n',
            ],
            "good": [
                'import json\ndef load(data):\n    return json.loads(data)\n',
            ],
        },
        "CWE79": {
            "bad": [
                'def greet(name):\n    return f"<h1>Hello {name}</h1>"\n',
            ],
            "good": [
                'import html\ndef greet(name):\n    return f"<h1>Hello {html.escape(name)}</h1>"\n',
            ],
        },
        "CWE95": {
            "bad": [
                'def calc(expr):\n    return eval(expr)\n',
            ],
            "good": [
                'import ast\ndef calc(expr):\n    return ast.literal_eval(expr)\n',
            ],
        },
    }

    for cwe_id, cases in vuln_cases.items():
        for category, snippets in cases.items():
            for i, code in enumerate(snippets):
                is_vulnerable = category == "bad"
                dest_dir = python_dir / cwe_id / category
                dest_dir.mkdir(parents=True, exist_ok=True)

                filename = f"{cwe_id}_{category}_{i+1}.py"
                (dest_dir / filename).write_text(code)

                entry = {
                    "file": f"python/{cwe_id}/{category}/{filename}",
                    "cwe": cwe_id,
                    "language": "python",
                    "vulnerable": is_vulnerable,
                }

                if is_vulnerable:
                    labels["vulnerable"].append(entry)
                else:
                    labels["safe"].append(entry)

                labels["stats"].setdefault(cwe_id, {"vulnerable": 0, "safe": 0})
                key = "vulnerable" if is_vulnerable else "safe"
                labels["stats"][cwe_id][key] += 1

    return labels


def main():
    parser = argparse.ArgumentParser(description="Download Juliet Test Suite for SEC-C")
    parser.add_argument("--output", default="data/juliet", help="Output directory")
    parser.add_argument("--skip-download", action="store_true", help="Skip download, organize existing")
    parser.add_argument("--python-only", action="store_true", help="Only generate Python synthetic cases")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "_raw"

    all_labels = {"vulnerable": [], "safe": [], "stats": {}}

    if not args.python_only and not args.skip_download:
        # Download Juliet
        for lang, url in JULIET_URLS.items():
            success = download_and_extract(url, raw_dir, f"Juliet {lang}")
            if not success:
                # Try fallback
                fallback = FALLBACK_URLS.get(lang)
                if fallback:
                    logger.info(f"Trying fallback URL for {lang}...")
                    download_and_extract(fallback, raw_dir, f"Juliet {lang} (fallback)")

    if not args.python_only and raw_dir.exists():
        # Organize Java/C/C++ test cases
        logger.info("Organizing test cases by CWE...")
        juliet_labels = organize_test_cases(raw_dir, output_dir)
        all_labels["vulnerable"].extend(juliet_labels["vulnerable"])
        all_labels["safe"].extend(juliet_labels["safe"])
        for cwe, counts in juliet_labels["stats"].items():
            existing = all_labels["stats"].get(cwe, {"vulnerable": 0, "safe": 0})
            all_labels["stats"][cwe] = {
                "vulnerable": existing["vulnerable"] + counts["vulnerable"],
                "safe": existing["safe"] + counts["safe"],
            }

    # Generate synthetic Python cases
    python_labels = generate_synthetic_python_cases(output_dir)
    all_labels["vulnerable"].extend(python_labels["vulnerable"])
    all_labels["safe"].extend(python_labels["safe"])
    for cwe, counts in python_labels["stats"].items():
        existing = all_labels["stats"].get(cwe, {"vulnerable": 0, "safe": 0})
        all_labels["stats"][cwe] = {
            "vulnerable": existing["vulnerable"] + counts["vulnerable"],
            "safe": existing["safe"] + counts["safe"],
        }

    # Save labels
    labels_path = output_dir / "labels.json"
    with open(labels_path, "w") as f:
        json.dump(all_labels, f, indent=2)

    # Print summary
    total_vuln = len(all_labels["vulnerable"])
    total_safe = len(all_labels["safe"])
    total = total_vuln + total_safe

    print()
    print("  ◆ Juliet Test Suite Summary")
    print(f"  {'─' * 45}")
    print(f"  Total test cases:  {total}")
    print(f"  Vulnerable (bad):  {total_vuln}")
    print(f"  Safe (good):       {total_safe}")
    print(f"  CWEs covered:      {len(all_labels['stats'])}")
    print(f"  Labels saved to:   {labels_path}")
    print()

    # Per-CWE breakdown
    print(f"  {'CWE':<12} {'Vulnerable':>12} {'Safe':>12}")
    print(f"  {'─' * 36}")
    for cwe in sorted(all_labels["stats"].keys()):
        counts = all_labels["stats"][cwe]
        print(f"  {cwe:<12} {counts['vulnerable']:>12} {counts['safe']:>12}")

    print()
    logger.info("Done! Run 'python scripts/train_gat.py' to train the model.")


if __name__ == "__main__":
    main()
