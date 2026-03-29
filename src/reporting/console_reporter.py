"""
Console Reporter: Rich terminal output for SEC-C scan results.

Provides color-coded, human-readable output with cascade statistics
and three-tier classification display.
"""

from __future__ import annotations

import logging
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.sast.sarif.schema import Finding, ScanResult, Severity, StageResolved, Verdict

logger = logging.getLogger(__name__)

# Color scheme
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

VERDICT_COLORS: dict[Verdict, str] = {
    Verdict.CONFIRMED: "bold red",
    Verdict.LIKELY: "yellow",
    Verdict.POTENTIAL: "cyan",
    Verdict.SAFE: "green",
    Verdict.UNKNOWN: "dim",
}

VERDICT_SYMBOLS: dict[Verdict, str] = {
    Verdict.CONFIRMED: "[!]",
    Verdict.LIKELY: "[~]",
    Verdict.POTENTIAL: "[?]",
    Verdict.SAFE: "[ok]",
    Verdict.UNKNOWN: "[--]",
}


class ConsoleReporter:
    """Rich terminal reporter for SEC-C scan results."""

    def __init__(self, verbose: bool = False, show_cascade_stats: bool = True):
        self.console = Console(highlight=False)
        self.verbose = verbose
        self.show_cascade_stats = show_cascade_stats
        # Use ASCII box drawing on Windows to avoid encoding issues
        import sys
        self._safe_box = sys.platform == "win32"

    def report(self, scan_result: ScanResult) -> None:
        """Print a complete scan report to the console."""
        self._print_header(scan_result)
        self._print_findings_table(scan_result)

        if self.show_cascade_stats:
            self._print_cascade_stats(scan_result)

        self._print_summary(scan_result)

    def _print_header(self, result: ScanResult) -> None:
        """Print the report header."""
        header = Text()
        header.append("SEC-C", style="bold cyan")
        header.append(" Multi-Stage Security Scan Report\n", style="bold")
        header.append(f"Target: {result.scan_target}\n")
        header.append(f"Languages: {', '.join(l.value for l in result.languages_detected)}\n")
        header.append(f"Files scanned: {result.total_files_scanned}\n")
        header.append(f"Duration: {result.scan_duration_ms:.0f}ms")

        self.console.print(Panel(header, title="Scan Report", border_style="cyan"))

    def _print_findings_table(self, result: ScanResult) -> None:
        """Print findings in a formatted table."""
        if not result.findings:
            self.console.print("\n[green]No vulnerabilities detected.[/green]\n")
            return

        # Group by verdict for display order
        verdict_order = [Verdict.CONFIRMED, Verdict.LIKELY, Verdict.POTENTIAL, Verdict.SAFE]

        for verdict in verdict_order:
            tier_findings = [f for f in result.findings if f.verdict == verdict]
            if not tier_findings:
                continue

            table = Table(
                title=f"\n{VERDICT_SYMBOLS[verdict]} {verdict.value.upper()} ({len(tier_findings)})",
                title_style=VERDICT_COLORS[verdict],
                show_header=True,
                header_style="bold",
                safe_box=self._safe_box,
            )

            table.add_column("Severity", width=10)
            table.add_column("CWE", width=10)
            table.add_column("Location", width=35)
            table.add_column("Message", width=45)
            table.add_column("Score", width=8, justify="right")
            table.add_column("CVSS", style="bold", justify="center", width=6)
            table.add_column("Stage", width=8)

            for f in tier_findings:
                sev_style = SEVERITY_COLORS.get(f.severity, "")
                cvss_style = "bold red" if f.cvss_severity in ("critical", "high") else ("yellow" if f.cvss_severity == "medium" else "cyan")
                table.add_row(
                    Text(f.severity.value.upper(), style=sev_style),
                    f.cwe_id,
                    f.location.display,
                    f.sast_message[:45],
                    f"{f.fused_score:.2f}",
                    Text(f"{f.cvss_base_score:.1f}", style=cvss_style),
                    f.stage_resolved.value,
                )

            self.console.print(table)

        # Verbose: show detailed explanations
        if self.verbose:
            self._print_detailed_findings(result)

    def _print_detailed_findings(self, result: ScanResult) -> None:
        """Print detailed finding information in verbose mode."""
        confirmed = [f for f in result.findings if f.verdict == Verdict.CONFIRMED]
        likely = [f for f in result.findings if f.verdict == Verdict.LIKELY]

        for f in confirmed + likely:
            self.console.print(f"\n{'='*60}")
            self.console.print(
                f"[{VERDICT_COLORS[f.verdict]}]{f.verdict.value.upper()}[/] "
                f"[{SEVERITY_COLORS[f.severity]}]{f.severity.value.upper()}[/] "
                f"{f.cwe_id} ({f.cwe_name})"
            )
            self.console.print(f"Location: {f.location.display}")
            self.console.print(f"Rule: {f.rule_id}")
            self.console.print(f"Fused Score: {f.fused_score:.3f}")

            if f.location.snippet:
                self.console.print(f"\nCode: {f.location.snippet}")

            if f.nl_explanation:
                self.console.print(f"\n{f.nl_explanation}")

            if f.remediation:
                self.console.print(f"\n[green]Remediation:[/green] {f.remediation}")

    def _print_cascade_stats(self, result: ScanResult) -> None:
        """Print cascade efficiency statistics."""
        total = result.total_findings
        if total == 0:
            return

        stats_table = Table(title="\nCascade Statistics", show_header=True, header_style="bold cyan", safe_box=self._safe_box)
        stats_table.add_column("Stage", width=20)
        stats_table.add_column("Resolved", width=12, justify="right")
        stats_table.add_column("Percentage", width=12, justify="right")
        stats_table.add_column("Bar", width=30)

        stages = [
            ("SAST (Stage 1)", result.resolved_at_sast),
            ("Graph (Stage 2)", result.resolved_at_graph),
            ("LLM (Stage 3)", result.resolved_at_llm),
            ("Unresolved", result.unresolved),
        ]

        colors = ["green", "cyan", "yellow", "red"]

        for (name, count), color in zip(stages, colors):
            pct = (count / total * 100) if total > 0 else 0
            bar_len = int(pct / 100 * 25)
            bar = f"[{color}]{'#' * bar_len}{'-' * (25 - bar_len)}[/{color}]"
            stats_table.add_row(name, str(count), f"{pct:.1f}%", bar)

        self.console.print(stats_table)

    def _print_summary(self, result: ScanResult) -> None:
        """Print the final summary."""
        summary = Text()

        confirmed = result.confirmed_count
        likely = result.likely_count
        potential = result.potential_count
        total = result.total_findings

        summary.append(f"\nTotal findings: {total}\n")

        if confirmed > 0:
            summary.append(f"  Confirmed: {confirmed}", style="bold red")
            summary.append("\n")
        if likely > 0:
            summary.append(f"  Likely: {likely}", style="yellow")
            summary.append("\n")
        if potential > 0:
            summary.append(f"  Potential: {potential}", style="cyan")
            summary.append("\n")

        safe_count = sum(1 for f in result.findings if f.verdict == Verdict.SAFE)
        if safe_count > 0:
            summary.append(f"  Safe (FP filtered): {safe_count}", style="green")
            summary.append("\n")

        if total > 0:
            efficiency = result.cascade_efficiency
            summary.append(f"\nCascade efficiency: {efficiency:.1%} resolved at Stage 1")
        else:
            summary.append("\nNo findings to report.", style="green")

        self.console.print(Panel(summary, title="Summary", border_style="cyan"))
