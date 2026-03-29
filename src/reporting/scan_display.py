"""
Scan Display: Professional CLI output for SEC-C cascade execution.

Renders detailed, PhD-presentation-quality output at each cascade stage
using the ``rich`` library. All output uses ASCII characters only --
no emoji, no Unicode symbols -- ensuring reliable display on any terminal.

Designed to be called by ``PipelineOrchestrator`` during scan execution,
giving the operator real-time visibility into each stage's progress,
findings, and escalation decisions.
"""

from __future__ import annotations

import logging
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.sast.sarif.schema import (
    AttackerVerdict,
    DefenderVerdict,
    Finding,
    LLMValidation,
    ScanResult,
    Severity,
    StageResolved,
    Verdict,
)

logger = logging.getLogger(__name__)

# -- Version constant (kept in sync with src.cli.banner) --------------------
_VERSION = "2.0.0"

# -- Color mappings ---------------------------------------------------------
_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.CONFIRMED: "bold red",
    Verdict.LIKELY: "yellow",
    Verdict.POTENTIAL: "cyan",
    Verdict.SAFE: "green",
    Verdict.UNKNOWN: "dim",
}

_STAGE_LABELS: dict[str, str] = {
    "sast": "Stage 1: SAST Analysis (Tree-sitter + CodeQL)",
    "graph": "Stage 2: Graph Validation (CPG + Structural)",
    "llm": "Stage 3: LLM Dual-Agent Validation",
}

# Width of the full-width divider lines.
_LINE_WIDTH = 68


def _severity_tag(severity: Severity) -> str:
    """Return the severity name in upper case."""
    return severity.value.upper()


def _divider(label: str) -> str:
    """Build a stage-separator line padded to ``_LINE_WIDTH`` with dashes."""
    prefix = f"--- {label} "
    pad = max(0, _LINE_WIDTH - len(prefix))
    return prefix + "-" * pad


class ScanDisplay:
    """Professional scan display for the SEC-C cascade pipeline.

    All methods write to the provided ``rich.console.Console`` (or a
    default one) and return ``None``.  The class is intentionally
    stateless beyond the console reference so that it can be used in
    both synchronous and asynchronous contexts without concern for
    thread safety.

    Parameters
    ----------
    console : Console | None
        Rich console to write to.  A new instance is created if *None*.
    quiet : bool
        When *True*, suppress all output.  Useful for testing or batch
        mode where only the final report matters.
    """

    def __init__(
        self,
        console: Console | None = None,
        quiet: bool = False,
    ) -> None:
        self.console = console or Console()
        self._quiet = quiet

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _print(self, *args: Any, **kwargs: Any) -> None:
        """Print unless quiet mode is active."""
        if not self._quiet:
            self.console.print(*args, **kwargs)

    def _blank(self) -> None:
        """Print a single blank line."""
        self._print()

    def _task(self, text: str) -> None:
        """Print a task indicator line: ``  [>] text``."""
        self._print(f"  [bold cyan]\\[>][/bold cyan] {text}")

    def _detail(self, text: str) -> None:
        """Print an indented detail line (6 spaces)."""
        self._print(f"      {text}")

    # ------------------------------------------------------------------
    # 1. Header / Footer
    # ------------------------------------------------------------------

    def show_header(
        self,
        target: str,
        languages: list[str],
        max_stage: str = "llm",
    ) -> None:
        """Render the top-of-scan banner.

        Parameters
        ----------
        target : str
            Scan target path or repository.
        languages : list[str]
            Detected or requested languages.
        max_stage : str
            Highest cascade stage that will run (``"sast"``, ``"graph"``,
            or ``"llm"``).
        """
        stage_map = {"sast": "1 (SAST only)", "graph": "2 (SAST + Graph)", "llm": "3 (full cascade)"}
        stage_label = stage_map.get(max_stage, max_stage)
        langs = ", ".join(languages) if languages else "auto-detect"

        header = Text()
        header.append(f"Sec-C v{_VERSION}", style="bold cyan")
        header.append(" | Security Scan\n", style="bold")
        header.append(f"Target: {target}", style="")
        header.append(f"  |  Languages: {langs}\n", style="")
        header.append(f"Max stage: {stage_label}", style="dim")

        self._print(Panel(
            header,
            border_style="cyan",
            width=_LINE_WIDTH,
            padding=(0, 2),
        ))

    # ------------------------------------------------------------------
    # 2. Stage 1 -- SAST
    # ------------------------------------------------------------------

    def show_sast_start(self) -> None:
        """Print the Stage 1 divider."""
        self._blank()
        self._print(f"[bold]{_divider(_STAGE_LABELS['sast'])}[/bold]")
        self._blank()

    def show_treesitter_result(
        self,
        files_scanned: int,
        findings_count: int,
        time_ms: float,
    ) -> None:
        """Display Tree-sitter pre-screening results.

        Parameters
        ----------
        files_scanned : int
            Number of source files scanned.
        findings_count : int
            Number of pattern matches found.
        time_ms : float
            Wall-clock time in milliseconds.
        """
        self._task("Tree-sitter pre-screening ...")
        self._detail(f"Scanned {files_scanned} files in {time_ms:.0f}ms")
        self._detail(f"Patterns matched: {findings_count}")
        self._blank()

    def show_codeql_result(
        self,
        db_time: float,
        query_suite: str,
        findings_count: int,
        corroborated: int,
    ) -> None:
        """Display CodeQL deep-analysis results.

        Parameters
        ----------
        db_time : float
            Time (seconds) to create the CodeQL database.
        query_suite : str
            Name of the query suite executed.
        findings_count : int
            Number of taint-tracked findings.
        corroborated : int
            Number of findings that also appeared in Tree-sitter results.
        """
        new = max(0, findings_count - corroborated)
        self._task("CodeQL deep analysis ...")
        self._detail(f"Database: created ({db_time:.1f}s)")
        self._detail(f"Query suite: {query_suite}")
        self._detail(
            f"Findings: {findings_count} taint-tracked "
            f"({new} new, {corroborated} corroborated with Tree-sitter)"
        )
        self._blank()

    def show_codeql_skipped(self, reason: str = "not available") -> None:
        """Indicate that CodeQL was skipped."""
        self._task("CodeQL deep analysis ...")
        self._detail(f"[dim]\\[skipped -- {reason}][/dim]")
        self._blank()

    def show_uncertainty_result(
        self,
        total: int,
        resolved: int,
        escalated: int,
        threshold: float,
    ) -> None:
        """Display uncertainty scoring and routing results.

        Parameters
        ----------
        total : int
            Total number of findings scored.
        resolved : int
            Findings resolved at SAST (U < threshold).
        escalated : int
            Findings escalated to Graph (U >= threshold).
        threshold : float
            Uncertainty threshold used for routing.
        """
        self._task("Uncertainty scoring ...")
        self._detail(f"Total: {total} findings scored")
        self._detail(f"Resolved at SAST (U < {threshold:.2f}): {resolved} findings")
        self._detail(f"Escalated to Graph (U >= {threshold:.2f}): {escalated} findings")
        self._blank()

    # ------------------------------------------------------------------
    # 3. Findings Table (generic, used after any stage)
    # ------------------------------------------------------------------

    def show_findings_table(
        self,
        findings: list[Finding],
        stage_name: str = "",
    ) -> None:
        """Render a compact findings table.

        Parameters
        ----------
        findings : list[Finding]
            Findings to display.  An empty list is handled gracefully.
        stage_name : str
            Optional label shown above the table.
        """
        if not findings:
            return

        title = f"  Escalated Findings" if not stage_name else f"  {stage_name}"

        table = Table(
            title=title,
            title_style="bold",
            show_header=True,
            header_style="bold",
            padding=(0, 1),
            pad_edge=True,
            expand=False,
        )
        table.add_column("#", justify="right", width=4)
        table.add_column("Severity", width=10)
        table.add_column("CWE", width=10)
        table.add_column("Location", width=30)
        table.add_column("U_score", justify="right", width=8)

        for idx, f in enumerate(findings, start=1):
            sev_style = _SEVERITY_STYLES.get(f.severity, "")
            u_score = f.uncertainty.total
            table.add_row(
                str(idx),
                Text(_severity_tag(f.severity), style=sev_style),
                f.cwe_id or "-",
                f.location.display,
                f"{u_score:.2f}",
            )

        self._print(table)
        self._blank()

    # ------------------------------------------------------------------
    # 4. Stage Complete
    # ------------------------------------------------------------------

    def show_stage_complete(
        self,
        stage_name: str,
        resolved: int,
        escalated: int,
        time_s: float,
    ) -> None:
        """Print the stage completion line.

        Parameters
        ----------
        stage_name : str
            Human-readable stage name (e.g. ``"Stage 1"``).
        resolved : int
            Number of findings resolved at this stage.
        escalated : int
            Number of findings escalated to the next stage.
        time_s : float
            Stage wall-clock time in seconds.
        """
        self._print(
            f"  [bold]{stage_name} complete[/bold] | "
            f"{resolved} resolved, {escalated} escalated | "
            f"{time_s:.1f}s"
        )
        self._blank()

    # ------------------------------------------------------------------
    # 5. Stage 2 -- Graph
    # ------------------------------------------------------------------

    def show_graph_start(self) -> None:
        """Print the Stage 2 divider."""
        self._blank()
        self._print(f"[bold]{_divider(_STAGE_LABELS['graph'])}[/bold]")
        self._blank()

    def show_graph_result(
        self,
        cpg_count: int,
        slice_reduction: float,
        gat_status: str,
        cp_status: str,
    ) -> None:
        """Display graph validation results.

        Parameters
        ----------
        cpg_count : int
            Number of findings for which CPGs were built.
        slice_reduction : float
            Average backward-slice reduction percentage (0-100).
        gat_status : str
            Mini-GAT status (e.g. ``"completed"`` or ``"skipped -- model not trained"``).
        cp_status : str
            Conformal prediction status (e.g. ``"completed"`` or
            ``"skipped -- not calibrated"``).
        """
        self._task("CPG generation (Joern) ...")
        self._detail(f"Graphs built for {cpg_count} findings")
        self._detail(f"Backward slicing: {slice_reduction:.0f}% average reduction")
        self._blank()

        self._task("Structural analysis (Mini-GAT) ...")
        if gat_status.startswith("skipped"):
            self._detail(f"[dim]\\[{gat_status}][/dim]")
        else:
            self._detail(gat_status)
        self._blank()

        self._task("Conformal prediction ...")
        if cp_status.startswith("skipped"):
            self._detail(f"[dim]\\[{cp_status}][/dim]")
        else:
            self._detail(cp_status)
        self._blank()

    # ------------------------------------------------------------------
    # 6. Stage 3 -- LLM
    # ------------------------------------------------------------------

    def show_llm_start(self) -> None:
        """Print the Stage 3 divider."""
        self._blank()
        self._print(f"[bold]{_divider(_STAGE_LABELS['llm'])}[/bold]")
        self._blank()

    def show_llm_finding(
        self,
        index: int,
        total: int,
        finding: Finding,
        attacker_verdict: AttackerVerdict,
        defender_verdict: DefenderVerdict,
        consensus: LLMValidation | None = None,
    ) -> None:
        """Display the LLM dual-agent analysis for a single finding.

        Parameters
        ----------
        index : int
            1-based index of this finding in the LLM batch.
        total : int
            Total number of findings in the LLM batch.
        finding : Finding
            The finding being validated.
        attacker_verdict : AttackerVerdict
            Red-team agent results.
        defender_verdict : DefenderVerdict
            Blue-team agent results.
        consensus : LLMValidation | None
            Fused consensus result (if available).
        """
        cwe = finding.cwe_id or "N/A"
        cwe_name = finding.cwe_name or ""
        loc = finding.location.display

        cwe_label = f"{cwe} {cwe_name}".strip()
        self._task(f"Finding {index}/{total}: {cwe_label}")
        self._detail(f"  Location : {loc}")

        # -- Compact Attacker / Defender summary --
        atk_expl = attacker_verdict.exploitable
        atk_conf = attacker_verdict.confidence
        def_cov = defender_verdict.defense_coverage_score
        def_feas = defender_verdict.path_feasible

        atk_str = f"[bold red]EXPLOITABLE[/bold red] ({atk_conf:.0%})" if atk_expl else f"[green]NOT EXPLOITABLE[/green] ({atk_conf:.0%})"
        def_str = f"coverage {def_cov:.0%}, path {'feasible' if def_feas else 'infeasible'}"

        self._detail(f"  Attacker : {atk_str}")
        self._detail(f"  Defender : [cyan]{def_str}[/cyan]")

        # -- Consensus verdict (the main takeaway) --
        if consensus is not None:
            verdict_val = consensus.consensus_verdict.value.upper()
            conf = consensus.consensus_confidence
            verdict_style = _VERDICT_STYLES.get(consensus.consensus_verdict, "")

            if consensus.consensus_verdict in (Verdict.CONFIRMED, Verdict.LIKELY):
                label = f"{verdict_val} (score: {conf:.2f})"
            elif consensus.consensus_verdict == Verdict.SAFE:
                label = f"SAFE -- false positive (score: {conf:.2f})"
            else:
                label = f"{verdict_val} (score: {conf:.2f})"

            self._detail(f"  [{verdict_style}]Verdict  : {label}[/{verdict_style}]")

            if hasattr(consensus, 'cvss_base_score') and consensus.cvss_base_score > 0:
                cvss_style = "bold red" if consensus.cvss_severity in ("critical", "high") else "yellow"
                self._detail(f"  [{cvss_style}]CVSS     : {consensus.cvss_base_score:.1f} ({consensus.cvss_severity.upper()}) {consensus.cvss_vector}[/{cvss_style}]")
        self._blank()

    # ------------------------------------------------------------------
    # 7. Results Summary
    # ------------------------------------------------------------------

    def show_results_summary(self, scan_result: ScanResult) -> None:
        """Render the final results summary panel.

        Includes cascade statistics, severity breakdown, verdict
        classification, and timing information.

        Parameters
        ----------
        scan_result : ScanResult
            The completed scan result.
        """
        total = scan_result.total_findings
        confirmed = scan_result.confirmed_count
        likely = scan_result.likely_count
        potential = scan_result.potential_count
        safe_count = sum(1 for f in scan_result.findings if f.verdict == Verdict.SAFE)
        duration_s = scan_result.scan_duration_ms / 1000.0

        # -- Cascade breakdown table --
        cascade_table = Table(
            show_header=True,
            header_style="bold",
            padding=(0, 1),
            expand=False,
            title="Cascade Breakdown",
            title_style="bold",
        )
        cascade_table.add_column("Stage", width=22)
        cascade_table.add_column("Resolved", justify="right", width=10)
        cascade_table.add_column("Pct", justify="right", width=8)
        cascade_table.add_column("Bar", width=22)

        stages_data = [
            ("SAST   (Stage 1)", scan_result.resolved_at_sast, "green"),
            ("Graph  (Stage 2)", scan_result.resolved_at_graph, "cyan"),
            ("LLM    (Stage 3)", scan_result.resolved_at_llm, "yellow"),
            ("Unresolved", scan_result.unresolved, "red"),
        ]

        for label, count, color in stages_data:
            pct = (count / total * 100) if total > 0 else 0.0
            bar_len = int(round(pct / 100 * 20))
            bar = "#" * bar_len + "-" * (20 - bar_len)
            cascade_table.add_row(
                label,
                str(count),
                f"{pct:.1f}%",
                f"[{color}]{bar}[/{color}]",
            )

        # -- Verdict breakdown --
        verdict_text = Text()
        verdict_text.append("Findings by verdict:\n", style="bold")
        if confirmed > 0:
            verdict_text.append(f"  CONFIRMED:  {confirmed}\n", style="bold red")
        if likely > 0:
            verdict_text.append(f"  LIKELY:     {likely}\n", style="yellow")
        if potential > 0:
            verdict_text.append(f"  POTENTIAL:  {potential}\n", style="cyan")
        if safe_count > 0:
            verdict_text.append(f"  SAFE (FP):  {safe_count}\n", style="green")

        # -- Severity breakdown --
        sev_counts = {s: 0 for s in Severity}
        for f in scan_result.findings:
            sev_counts[f.severity] += 1

        severity_text = Text()
        severity_text.append("Findings by severity:\n", style="bold")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            c = sev_counts[sev]
            if c > 0:
                style = _SEVERITY_STYLES.get(sev, "")
                severity_text.append(f"  {sev.value.upper():<10}  {c}\n", style=style)

        # -- Efficiency line --
        efficiency = scan_result.cascade_efficiency
        efficiency_text = Text()
        efficiency_text.append(f"\nCascade efficiency: {efficiency:.1%}", style="bold")
        efficiency_text.append(" resolved at Stage 1 (SAST)\n")
        efficiency_text.append(f"Total scan time: {duration_s:.1f}s\n")
        efficiency_text.append(f"Total findings: {total}")

        # -- Assemble summary panel --
        self._blank()
        self._print(Panel(
            Text("RESULTS SUMMARY", style="bold"),
            border_style="cyan",
            width=_LINE_WIDTH,
            padding=(0, 2),
        ))
        self._blank()

        self._print(cascade_table)
        self._blank()
        self._print(verdict_text)
        self._print(severity_text)
        self._print(efficiency_text)

        # -- Final status line --
        self._blank()
        if confirmed > 0:
            status_style = "bold red"
            status_msg = (
                f"SCAN COMPLETE: {confirmed} confirmed "
                f"vulnerabilit{'y' if confirmed == 1 else 'ies'} found"
            )
        elif likely > 0:
            status_style = "yellow"
            status_msg = (
                f"SCAN COMPLETE: {likely} likely finding(s) require review"
            )
        elif total > 0:
            status_style = "cyan"
            status_msg = (
                f"SCAN COMPLETE: {total} potential finding(s) for review"
            )
        else:
            status_style = "green"
            status_msg = "SCAN COMPLETE: No vulnerabilities detected"

        self._print(Panel(
            Text(status_msg, style=status_style, justify="center"),
            border_style=status_style.split()[-1],  # last word is the color
            width=_LINE_WIDTH,
            padding=(0, 2),
        ))
