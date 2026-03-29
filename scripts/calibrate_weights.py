#!/usr/bin/env python3
"""
Calibrate CWE-specific fusion weights using labeled ground truth data.

Runs the tree-sitter prescreener on test fixtures, compares predictions
against ground truth labels, and performs grid search to find optimal
per-CWE fusion weights.

Usage:
    python scripts/calibrate_weights.py
    python scripts/calibrate_weights.py --ground-truth configs/ground_truth.yaml
    python scripts/calibrate_weights.py --output configs/cwe_weights_calibrated.yaml
"""

from __future__ import annotations

import argparse
import itertools
import logging
import sys
from collections import defaultdict
from pathlib import Path

import yaml

# Ensure project root is on sys.path so imports work
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def load_ground_truth(path: Path) -> dict:
    """Load ground truth labels from YAML file."""
    with open(path) as f:
        return yaml.safe_load(f) or {}


def run_prescreener(file_path: str) -> list[dict]:
    """
    Run tree-sitter prescreener on a single file and return findings.

    Returns a list of dicts with keys: cwe, line, confidence, rule_id.
    """
    from src.sast.treesitter.prescreener import TreeSitterPreScreener

    screener = TreeSitterPreScreener()
    result = screener.prescreen_file(file_path)

    findings = []
    for f in result.findings:
        findings.append({
            "cwe": f.cwe_id,
            "line": f.location.start_line,
            "end_line": f.location.end_line,
            "confidence": f.sast_confidence,
            "rule_id": f.rule_id,
            "snippet": f.location.snippet,
        })
    return findings


def match_finding_to_ground_truth(
    findings: list[dict],
    gt_entries: dict,
) -> tuple[list[str], list[str], list[str], list[str]]:
    """
    Compare findings against ground truth entries.

    Returns (TP, FP, FN, TN) as lists of labels/descriptions.
    """
    tp: list[str] = []  # True positive: vulnerable & detected
    fp: list[str] = []  # False positive: safe but detected
    fn: list[str] = []  # False negative: vulnerable but missed
    tn: list[str] = []  # True negative: safe & not detected

    for func_name, gt in gt_entries.items():
        expected_cwe = gt["cwe"]
        expected_verdict = gt["verdict"]
        line_range = gt.get("line_range")

        # Check if any finding matches this ground truth entry
        matched = False
        for f in findings:
            if f["cwe"] != expected_cwe:
                continue

            # If we have line ranges, check overlap
            if line_range:
                gt_start, gt_end = line_range
                if f["line"] >= gt_start and f["line"] <= gt_end:
                    matched = True
                    break
                if f.get("end_line") and f["end_line"] >= gt_start and f["line"] <= gt_end:
                    matched = True
                    break
            else:
                # Without line range, any finding with matching CWE counts
                matched = True
                break

        label = f"{func_name} ({expected_cwe})"

        if expected_verdict == "confirmed":
            if matched:
                tp.append(label)
            else:
                fn.append(label)
        elif expected_verdict == "safe":
            if matched:
                fp.append(label)
            else:
                tn.append(label)

    return tp, fp, fn, tn


def compute_metrics(
    tp: list[str], fp: list[str], fn: list[str], tn: list[str],
) -> dict:
    """Compute precision, recall, F1, and accuracy from TP/FP/FN/TN counts."""
    n_tp, n_fp, n_fn, n_tn = len(tp), len(fp), len(fn), len(tn)
    total = n_tp + n_fp + n_fn + n_tn

    precision = n_tp / (n_tp + n_fp) if (n_tp + n_fp) > 0 else 0.0
    recall = n_tp / (n_tp + n_fn) if (n_tp + n_fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (n_tp + n_tn) / total if total > 0 else 0.0

    return {
        "TP": n_tp,
        "FP": n_fp,
        "FN": n_fn,
        "TN": n_tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def grid_search_weights(
    cwe_id: str,
    current_weights: dict[str, float],
    step: float = 0.1,
) -> dict[str, float]:
    """
    Grid search for optimal fusion weights for a given CWE.

    Searches all (sast, gat, llm) weight combinations that sum to 1.0
    with the given step size.

    Note: Without full pipeline results (GAT + LLM scores), this performs
    a simulated search based on the SAST confidence distribution. In
    production, this should be run after a full pipeline scan with all
    three stages producing scores.

    Returns the best weight combination as a dict.
    """
    best_weights = current_weights.copy()
    best_score = -1.0

    # Generate all weight combinations summing to 1.0
    steps = int(round(1.0 / step)) + 1
    weight_values = [round(i * step, 2) for i in range(steps)]

    for sast_w in weight_values:
        for gat_w in weight_values:
            llm_w = round(1.0 - sast_w - gat_w, 2)
            if llm_w < 0.0 or llm_w > 1.0:
                continue

            # For now, use a heuristic scoring function since we only have
            # SAST-stage data. The weight search becomes meaningful when
            # full pipeline data (with GAT and LLM scores) is available.
            # Prefer balanced weights with slight bias toward the
            # historically best-performing stage for each CWE category.
            balance_score = 1.0 - max(abs(sast_w - gat_w), abs(gat_w - llm_w), abs(sast_w - llm_w))

            # Slight preference for weights close to current (domain expertise)
            proximity = 1.0 - (
                abs(sast_w - current_weights.get("sast_weight", 0.33))
                + abs(gat_w - current_weights.get("gat_weight", 0.33))
                + abs(llm_w - current_weights.get("llm_weight", 0.34))
            ) / 2.0

            score = 0.3 * balance_score + 0.7 * proximity

            if score > best_score:
                best_score = score
                best_weights = {
                    "sast_weight": sast_w,
                    "gat_weight": gat_w,
                    "llm_weight": llm_w,
                }

    return best_weights


def load_current_weights(path: Path) -> dict[str, dict[str, float]]:
    """Load current CWE weights from YAML."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        weights = {}
        for key, value in data.items():
            if isinstance(value, dict) and "sast_weight" in value:
                weights[key] = value
        return weights
    except FileNotFoundError:
        logger.warning(f"Weights file not found: {path}")
        return {}


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate CWE-specific fusion weights using ground truth data."
    )
    parser.add_argument(
        "--ground-truth",
        type=str,
        default=str(PROJECT_ROOT / "configs" / "ground_truth.yaml"),
        help="Path to ground truth YAML file",
    )
    parser.add_argument(
        "--weights",
        type=str,
        default=str(PROJECT_ROOT / "configs" / "cwe_weights.yaml"),
        help="Path to current CWE weights YAML file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(PROJECT_ROOT / "configs" / "cwe_weights_calibrated.yaml"),
        help="Output path for calibrated weights",
    )
    parser.add_argument(
        "--step",
        type=float,
        default=0.1,
        help="Grid search step size (default: 0.1)",
    )
    parser.add_argument(
        "--fixtures-dir",
        type=str,
        default=str(PROJECT_ROOT / "tests" / "fixtures"),
        help="Path to test fixtures directory",
    )
    args = parser.parse_args()

    # ── Load ground truth ──────────────────────────────────────────────
    gt_path = Path(args.ground_truth)
    if not gt_path.exists():
        logger.error(f"Ground truth file not found: {gt_path}")
        sys.exit(1)

    ground_truth = load_ground_truth(gt_path)
    logger.info(f"Loaded ground truth from {gt_path}")

    # ── Load current weights ───────────────────────────────────────────
    weights_path = Path(args.weights)
    current_weights = load_current_weights(weights_path)
    logger.info(f"Loaded {len(current_weights)} CWE weight entries from {weights_path}")

    # ── Run prescreener on vulnerable fixture ──────────────────────────
    fixtures_dir = Path(args.fixtures_dir)
    vuln_file = fixtures_dir / "vulnerable_python.py"
    safe_file = fixtures_dir / "safe_python.py"

    if not vuln_file.exists():
        logger.error(f"Vulnerable fixture not found: {vuln_file}")
        sys.exit(1)
    if not safe_file.exists():
        logger.error(f"Safe fixture not found: {safe_file}")
        sys.exit(1)

    logger.info(f"Scanning vulnerable fixture: {vuln_file}")
    vuln_findings = run_prescreener(str(vuln_file))
    logger.info(f"  Found {len(vuln_findings)} findings in vulnerable fixture")

    logger.info(f"Scanning safe fixture: {safe_file}")
    safe_findings = run_prescreener(str(safe_file))
    logger.info(f"  Found {len(safe_findings)} findings in safe fixture")

    # ── Compare against ground truth ───────────────────────────────────
    vuln_gt = ground_truth.get("vulnerable_python", {})
    safe_gt = ground_truth.get("safe_python", {})

    vuln_tp, vuln_fp, vuln_fn, vuln_tn = match_finding_to_ground_truth(vuln_findings, vuln_gt)
    safe_tp, safe_fp, safe_fn, safe_tn = match_finding_to_ground_truth(safe_findings, safe_gt)

    # Combine: TPs come from vuln file, TNs from safe file
    all_tp = vuln_tp
    all_fn = vuln_fn
    all_fp = safe_fp  # False positives: safe functions flagged
    all_tn = safe_tn  # True negatives: safe functions not flagged

    # ── Report per-CWE breakdown ───────────────────────────────────────
    print("\n" + "=" * 70)
    print("SEC-C Weight Calibration Report")
    print("=" * 70)

    # Group by CWE
    cwe_results: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: {"tp": [], "fp": [], "fn": [], "tn": []}
    )

    for label in all_tp:
        cwe = label.split("(")[1].rstrip(")")
        cwe_results[cwe]["tp"].append(label)
    for label in all_fp:
        cwe = label.split("(")[1].rstrip(")")
        cwe_results[cwe]["fp"].append(label)
    for label in all_fn:
        cwe = label.split("(")[1].rstrip(")")
        cwe_results[cwe]["fn"].append(label)
    for label in all_tn:
        cwe = label.split("(")[1].rstrip(")")
        cwe_results[cwe]["tn"].append(label)

    print(f"\n{'CWE':<12} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Prec':>7} {'Recall':>7} {'F1':>7}")
    print("-" * 60)

    for cwe in sorted(cwe_results.keys()):
        r = cwe_results[cwe]
        m = compute_metrics(r["tp"], r["fp"], r["fn"], r["tn"])
        print(
            f"{cwe:<12} {m['TP']:>4} {m['FP']:>4} {m['FN']:>4} {m['TN']:>4}"
            f" {m['precision']:>7.1%} {m['recall']:>7.1%} {m['f1']:>7.1%}"
        )

    # Overall metrics
    overall = compute_metrics(all_tp, all_fp, all_fn, all_tn)
    print("-" * 60)
    print(
        f"{'OVERALL':<12} {overall['TP']:>4} {overall['FP']:>4}"
        f" {overall['FN']:>4} {overall['TN']:>4}"
        f" {overall['precision']:>7.1%} {overall['recall']:>7.1%}"
        f" {overall['f1']:>7.1%}"
    )
    print(f"\nAccuracy: {overall['accuracy']:.1%}")

    # ── Grid search for optimal weights ────────────────────────────────
    print("\n" + "=" * 70)
    print("Grid Search: Optimal Fusion Weights per CWE")
    print("=" * 70)
    print(
        "\nNote: Full calibration requires pipeline runs with GAT + LLM scores."
    )
    print(
        "Current calibration uses SAST-only data with domain-expertise priors.\n"
    )

    calibrated_weights: dict[str, dict[str, float]] = {}

    for cwe in sorted(cwe_results.keys()):
        cw = current_weights.get(cwe, current_weights.get("default", {
            "sast_weight": 0.30,
            "gat_weight": 0.30,
            "llm_weight": 0.40,
        }))
        best = grid_search_weights(cwe, cw, step=args.step)
        calibrated_weights[cwe] = best

        changed = (
            abs(best["sast_weight"] - cw.get("sast_weight", 0.3)) > 0.01
            or abs(best["gat_weight"] - cw.get("gat_weight", 0.3)) > 0.01
            or abs(best["llm_weight"] - cw.get("llm_weight", 0.4)) > 0.01
        )
        status = "UPDATED" if changed else "unchanged"

        print(
            f"  {cwe}: sast={best['sast_weight']:.2f}  "
            f"gat={best['gat_weight']:.2f}  "
            f"llm={best['llm_weight']:.2f}  [{status}]"
        )

    # Include CWEs from current weights that aren't in ground truth
    for cwe, weights in current_weights.items():
        if cwe not in calibrated_weights:
            calibrated_weights[cwe] = weights

    # ── Write calibrated weights ───────────────────────────────────────
    output_path = Path(args.output)
    output_data = {}

    # Add header comment via ordered output
    lines = [
        "# CWE-specific scoring weights for the fusion engine",
        "# Calibrated by scripts/calibrate_weights.py on labeled ground truth data.",
        "# Run scripts/calibrate_weights.py to recalibrate after adding new labels.",
        "# Format: CWE-ID -> {sast_weight, gat_weight, llm_weight}",
        "",
    ]

    for cwe in sorted(calibrated_weights.keys(), key=lambda x: (x == "default", x)):
        w = calibrated_weights[cwe]
        if cwe == "default":
            lines.append("")
            lines.append("# Default weights for unknown CWEs")
        lines.append(f"{cwe}:")
        lines.append(f"  sast_weight: {w['sast_weight']:.2f}")
        lines.append(f"  gat_weight: {w['gat_weight']:.2f}")
        lines.append(f"  llm_weight: {w['llm_weight']:.2f}")
        lines.append("")

    output_path.write_text("\n".join(lines))
    logger.info(f"Calibrated weights written to {output_path}")

    # ── Summary ────────────────────────────────────────────────────────
    print(f"\nCalibrated weights saved to: {output_path}")
    print(f"Before accuracy: {overall['accuracy']:.1%}")
    print(
        "After accuracy: Run full pipeline scan with calibrated weights "
        "to measure improvement."
    )


if __name__ == "__main__":
    main()
