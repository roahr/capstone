"""
SEC-C CLI Branding and Banner.

Professional ASCII art and status display for the SEC-C framework.
All output is strictly ASCII-safe for Windows compatibility.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

VERSION = "2.0.0"

BANNER_ART = r"""
    ____                ____
   / ___|  ___  ___    / ___|
   \___ \ / _ \/ __|  | |
    ___) |  __/ (__   | |___
   |____/ \___|\___|   \____|
"""

BANNER_TEXT = (
    "[bold cyan]" + BANNER_ART + "[/bold cyan]\n"
    "[bold white]   Multi-Stage Code Security Framework[/bold white]\n"
    "[dim]   Adaptive Vulnerability Triage & Detection[/dim]\n"
    f"[dim]   v{VERSION}[/dim]"
)

# Backward-compatible alias
BANNER = BANNER_TEXT

MINI_BANNER = f"[bold cyan]Sec-C[/bold cyan] [dim]v{VERSION}[/dim]"

# Stage markers (ASCII only)
STAGE_ICONS = {
    "sast":   "[bold green][>][/bold green]",
    "graph":  "[bold cyan][*][/bold cyan]",
    "llm":    "[bold yellow][@][/bold yellow]",
    "report": "[bold magenta][#][/bold magenta]",
}

SEVERITY_ICONS = {
    "critical": "[bold red][!!][/bold red]",
    "high":     "[red][!][/red]",
    "medium":   "[yellow][~][/yellow]",
    "low":      "[cyan][-][/cyan]",
    "info":     "[dim][.][/dim]",
}

VERDICT_ICONS = {
    "confirmed": "[bold red][X][/bold red]",
    "likely":    "[yellow][?][/yellow]",
    "potential": "[cyan][~][/cyan]",
    "safe":      "[green][OK][/green]",
    "unknown":   "[dim][--][/dim]",
}


def print_banner(console: Console | None = None) -> None:
    """Print the full SEC-C banner inside a panel."""
    c = console or Console()
    panel = Panel(
        BANNER_TEXT,
        border_style="cyan",
        padding=(0, 2),
        safe_box=sys.platform == "win32",
    )
    c.print(panel)


def print_mini_banner(console: Console | None = None) -> None:
    """Print the compact one-line banner."""
    c = console or Console()
    c.print(MINI_BANNER)


def print_scan_start(
    target: str,
    languages: list[str],
    max_stage: str,
    console: Console | None = None,
) -> None:
    """Print scan configuration summary."""
    c = console or Console()
    c.print()
    c.print(f"  [bold cyan]>>[/bold cyan] Target    [bold]{target}[/bold]")
    c.print(
        f"  [bold cyan]>>[/bold cyan] Languages [bold]"
        f"{', '.join(languages) if languages else 'auto-detect'}[/bold]"
    )
    c.print(f"  [bold cyan]>>[/bold cyan] Pipeline  ", end="")

    stages = []
    if max_stage in ("sast", "graph", "llm"):
        stages.append(f"{STAGE_ICONS['sast']} SAST")
    if max_stage in ("graph", "llm"):
        stages.append(f"{STAGE_ICONS['graph']} Graph")
    if max_stage == "llm":
        stages.append(f"{STAGE_ICONS['llm']} LLM")

    c.print(" -> ".join(stages))
    c.print()
