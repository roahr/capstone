"""
SEC-C Benchmark Runner

Scans all 15 Vulnerable_Repos, captures cascade metrics,
and generates documentation in docs/Test_Check/.

Usage:
    python scripts/run_benchmarks.py
    python scripts/run_benchmarks.py --repo 01_taskflow   # Single repo
    python scripts/run_benchmarks.py --stage graph         # Limit stage
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPOS_DIR = PROJECT_ROOT / "Vulnerable_Repos"
DOCS_DIR = PROJECT_ROOT / "docs" / "Test_Check"
RESULTS_FILE = DOCS_DIR / "per_repo_results.json"


def scan_repo(repo_path: Path, stage: str = "llm") -> dict:
    """Run sec-c scan on a repo and capture results."""
    print(f"\n{'='*60}")
    print(f"  Scanning: {repo_path.name}")
    print(f"{'='*60}")

    sarif_out = PROJECT_ROOT / "data" / f"_benchmark_{repo_path.name}.sarif"

    cmd = [
        sys.executable, "-m", "src.cli.main", "scan",
        str(repo_path),
        "--stage", stage,
        "--output", str(sarif_out),
    ]

    start = time.time()
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        timeout=600,
    )
    elapsed = time.time() - start

    # Combine stdout and stderr (INFO logs go to stderr)
    full_output = (result.stdout or "") + "\n" + (result.stderr or "")

    # Parse cascade stats from output
    metrics = {
        "repo": repo_path.name,
        "language": _detect_language(repo_path),
        "scan_time_sec": round(elapsed, 1),
        "exit_code": result.returncode,
        "total_findings": 0,
        "resolved_sast": 0,
        "resolved_graph": 0,
        "resolved_llm": 0,
        "unresolved": 0,
        "cascade_efficiency": "0%",
        "findings_detail": [],
    }

    # Extract stats from cascade log line
    for line in full_output.split("\n"):
        if "Cascade stats:" in line:
            try:
                stats_str = line.split("Cascade stats: ")[1]
                stats = eval(stats_str)  # It's a dict literal in the log
                metrics["total_findings"] = stats.get("total_findings", 0)
                metrics["resolved_sast"] = stats.get("resolved_at_sast", 0)
                metrics["resolved_graph"] = stats.get("resolved_at_graph", 0)
                metrics["resolved_llm"] = stats.get("resolved_at_llm", 0)
                metrics["unresolved"] = stats.get("unresolved", 0)
                metrics["cascade_efficiency"] = stats.get("cascade_efficiency", "0%")
            except Exception:
                pass

        if "SAST resolved" in line:
            parts = line.split("SAST resolved ")[1] if "SAST resolved " in line else ""
            if ", escalating" in parts:
                try:
                    metrics["resolved_sast"] = int(parts.split(",")[0])
                except Exception:
                    pass

    # Parse SARIF for finding details
    if sarif_out.exists():
        try:
            with open(sarif_out, "r", encoding="utf-8") as f:
                sarif = json.load(f)
            for run in sarif.get("runs", []):
                for result_obj in run.get("results", []):
                    finding = {
                        "rule_id": result_obj.get("ruleId", "unknown"),
                        "message": result_obj.get("message", {}).get("text", "")[:100],
                        "level": result_obj.get("level", "warning"),
                    }
                    locs = result_obj.get("locations", [])
                    if locs:
                        phys = locs[0].get("physicalLocation", {})
                        art = phys.get("artifactLocation", {}).get("uri", "")
                        region = phys.get("region", {})
                        finding["file"] = art
                        finding["line"] = region.get("startLine", 0)
                    metrics["findings_detail"].append(finding)
        except Exception as e:
            print(f"  Warning: Could not parse SARIF: {e}")

    # Print summary
    total = metrics["total_findings"]
    sast = metrics["resolved_sast"]
    gnn = metrics["resolved_graph"]
    llm = metrics["resolved_llm"]
    unr = metrics["unresolved"]
    print(f"  Results: {total} findings | SAST={sast} GNN={gnn} LLM={llm} Unresolved={unr}")
    print(f"  Time: {elapsed:.1f}s")

    return metrics


def _detect_language(repo_path: Path) -> str:
    """Detect primary language of a repo."""
    exts = {}
    for f in repo_path.rglob("*"):
        if f.is_file():
            ext = f.suffix.lower()
            exts[ext] = exts.get(ext, 0) + 1

    lang_map = {
        ".py": "Python", ".js": "JavaScript", ".java": "Java",
        ".c": "C", ".cpp": "C++", ".go": "Go",
    }
    for ext, lang in lang_map.items():
        if ext in exts:
            return lang
    return "Unknown"


def generate_results_md(all_results: list[dict]) -> str:
    """Generate benchmark_results.md content."""
    lines = [
        "# SEC-C Benchmark Results",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Summary Table",
        "",
        "| # | Repo | Language | Findings | SAST | GNN | LLM | Unresolved | Time |",
        "|---|------|----------|----------|------|-----|-----|------------|------|",
    ]

    totals = {"findings": 0, "sast": 0, "gnn": 0, "llm": 0, "unresolved": 0, "time": 0}

    for i, r in enumerate(all_results, 1):
        lines.append(
            f"| {i} | {r['repo']} | {r['language']} | "
            f"{r['total_findings']} | {r['resolved_sast']} | "
            f"{r['resolved_graph']} | {r['resolved_llm']} | "
            f"{r['unresolved']} | {r['scan_time_sec']}s |"
        )
        totals["findings"] += r["total_findings"]
        totals["sast"] += r["resolved_sast"]
        totals["gnn"] += r["resolved_graph"]
        totals["llm"] += r["resolved_llm"]
        totals["unresolved"] += r["unresolved"]
        totals["time"] += r["scan_time_sec"]

    total_f = max(totals["findings"], 1)
    lines.append(
        f"| | **TOTAL** | **Mixed** | **{totals['findings']}** | "
        f"**{totals['sast']}** ({100*totals['sast']//total_f}%) | "
        f"**{totals['gnn']}** ({100*totals['gnn']//total_f}%) | "
        f"**{totals['llm']}** ({100*totals['llm']//total_f}%) | "
        f"**{totals['unresolved']}** | {totals['time']:.0f}s |"
    )

    lines.extend([
        "",
        "## Cascade Efficiency",
        "",
        f"- **Stage 1 (SAST)**: {totals['sast']}/{totals['findings']} "
        f"({100*totals['sast']//total_f}%) resolved at cheapest stage",
        f"- **Stage 2 (GNN)**: {totals['gnn']}/{totals['findings']} "
        f"({100*totals['gnn']//total_f}%) resolved with graph + conformal",
        f"- **Stage 3 (LLM)**: {totals['llm']}/{totals['findings']} "
        f"({100*totals['llm']//total_f}%) resolved with dual-agent consensus",
        f"- **Unresolved**: {totals['unresolved']}/{totals['findings']}",
        f"- **Total scan time**: {totals['time']:.0f}s across {len(all_results)} repos",
        "",
        "## Per-Language Breakdown",
        "",
        "| Language | Repos | Findings | SAST% | GNN% | LLM% |",
        "|----------|-------|----------|-------|------|------|",
    ])

    by_lang = {}
    for r in all_results:
        lang = r["language"]
        if lang not in by_lang:
            by_lang[lang] = {"repos": 0, "findings": 0, "sast": 0, "gnn": 0, "llm": 0}
        by_lang[lang]["repos"] += 1
        by_lang[lang]["findings"] += r["total_findings"]
        by_lang[lang]["sast"] += r["resolved_sast"]
        by_lang[lang]["gnn"] += r["resolved_graph"]
        by_lang[lang]["llm"] += r["resolved_llm"]

    for lang, d in sorted(by_lang.items()):
        f = max(d["findings"], 1)
        lines.append(
            f"| {lang} | {d['repos']} | {d['findings']} | "
            f"{100*d['sast']//f}% | {100*d['gnn']//f}% | {100*d['llm']//f}% |"
        )

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="SEC-C Benchmark Runner")
    parser.add_argument("--repo", help="Scan only this repo (e.g., 01_taskflow)")
    parser.add_argument("--stage", default="llm", help="Max stage: sast, graph, llm")
    args = parser.parse_args()

    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    repos = sorted(REPOS_DIR.iterdir()) if REPOS_DIR.exists() else []
    repos = [r for r in repos if r.is_dir()]

    if args.repo:
        repos = [r for r in repos if args.repo in r.name]
        if not repos:
            print(f"Repo '{args.repo}' not found in {REPOS_DIR}")
            sys.exit(1)

    print(f"SEC-C Benchmark Runner")
    print(f"Repos: {len(repos)}")
    print(f"Stage: {args.stage}")
    print(f"{'='*60}")

    all_results = []
    for repo in repos:
        try:
            result = scan_repo(repo, stage=args.stage)
            all_results.append(result)
        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT: {repo.name} (>600s)")
            all_results.append({
                "repo": repo.name,
                "language": _detect_language(repo),
                "scan_time_sec": 600,
                "exit_code": -1,
                "total_findings": 0,
                "resolved_sast": 0, "resolved_graph": 0,
                "resolved_llm": 0, "unresolved": 0,
                "cascade_efficiency": "TIMEOUT",
                "findings_detail": [],
            })
        except Exception as e:
            print(f"  ERROR: {repo.name}: {e}")

    # Save raw results
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nRaw results saved to {RESULTS_FILE}")

    # Generate markdown report
    md_content = generate_results_md(all_results)
    md_path = DOCS_DIR / "benchmark_results.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"Report saved to {md_path}")

    # Print summary
    total_f = sum(r["total_findings"] for r in all_results)
    total_sast = sum(r["resolved_sast"] for r in all_results)
    total_gnn = sum(r["resolved_graph"] for r in all_results)
    total_llm = sum(r["resolved_llm"] for r in all_results)

    print(f"\n{'='*60}")
    print(f"  BENCHMARK COMPLETE")
    print(f"{'='*60}")
    print(f"  Repos scanned: {len(all_results)}")
    print(f"  Total findings: {total_f}")
    if total_f > 0:
        print(f"  SAST resolved: {total_sast} ({100*total_sast//total_f}%)")
        print(f"  GNN resolved:  {total_gnn} ({100*total_gnn//total_f}%)")
        print(f"  LLM resolved:  {total_llm} ({100*total_llm//total_f}%)")


if __name__ == "__main__":
    main()
