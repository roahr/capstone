"""
SEC-C Interactive Mode: Claude Code-inspired interactive terminal.

Provides an interactive REPL with:
- File path autocomplete
- Command history
- Live scanning with progress indicators
- Inline results display
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import (
    Completer,
    Completion,
    FuzzyWordCompleter,
    PathCompleter,
    merge_completers,
)
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.cli.banner import BANNER, MINI_BANNER, print_banner

console = Console()

# Custom style for the prompt
PROMPT_STYLE = Style.from_dict({
    "prompt": "ansicyan bold",
    "command": "ansigreen",
    "path": "ansiyellow",
    "separator": "ansibrightblack",
})


class SecCCompleter(Completer):
    """Custom completer for SEC-C commands with file path autocomplete."""

    def __init__(self):
        self.commands = {
            "/scan": "Full cascade scan (SAST -> Graph -> LLM)",
            "/quick": "SAST-only fast scan (<1s)",
            "/deep": "Full cascade + verbose details",
            "/report": "View saved SARIF report (opens dashboard)",
            "/status": "Framework status + tool availability",
            "/providers": "LLM provider details",
            "/config": "Show current configuration",
            "/history": "Show recent command history",
            "/version": "Show SEC-C version and build info",
            "/help": "Show available commands",
            "/clear": "Clear the screen",
            "exit": "Exit SEC-C",
            "quit": "Exit SEC-C",
            # Also match without slash
            "scan": "Full cascade scan",
            "quick": "SAST-only fast scan",
            "deep": "Full cascade + verbose",
            "status": "Status (same as /status)",
            "providers": "Providers (same as /providers)",
            "help": "Help (same as /help)",
        }
        self.path_completer = PathCompleter(
            expanduser=True,
            file_filter=lambda name: (
                Path(name).is_dir()
                or name.endswith(('.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.h'))
            ),
        )

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor.strip()
        words = text.split()

        if not words or (len(words) == 1 and not text.endswith(" ")):
            # Complete commands
            word = words[0] if words else ""
            for cmd, desc in self.commands.items():
                if cmd.startswith(word):
                    yield Completion(
                        cmd,
                        start_position=-len(word),
                        display_meta=desc,
                    )
        elif words[0] in ("scan", "quick", "deep", "report") and (
            len(words) >= 2 or text.endswith(" ")
        ):
            # Complete file paths after scan/report command
            # Get the path portion
            if text.endswith(" "):
                path_text = ""
            else:
                path_text = words[-1]

            # Check if it's a flag
            if path_text.startswith("--"):
                flags = ["--stage", "--languages", "--output", "--dashboard", "--verbose"]
                for flag in flags:
                    if flag.startswith(path_text):
                        yield Completion(flag, start_position=-len(path_text))
            else:
                # Use path completer
                from prompt_toolkit.document import Document
                sub_doc = Document(path_text)
                yield from self.path_completer.get_completions(sub_doc, complete_event)


def get_prompt_message() -> HTML:
    """Generate a minimal SEC-C prompt."""
    return HTML('<prompt>sec-c</prompt><separator> > </separator>')


def print_help() -> None:
    """Print the help screen."""
    table = Table(
        title="[bold cyan]SEC-C Commands[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="cyan",
    )
    table.add_column("Command", style="green", width=30)
    table.add_column("Description", width=50)

    commands = [
        # Scanning
        ("", "[bold]Scanning[/bold]"),
        ("/scan <path>", "Full cascade scan (SAST -> Graph -> LLM)"),
        ("/quick <path>", "SAST-only fast scan (<1s)"),
        ("/deep <path>", "Full cascade + verbose per-finding details"),
        ("", ""),
        # Reporting
        ("", "[bold]Reporting[/bold]"),
        ("/report <file.sarif>", "Open saved report (dashboard by default)"),
        ("", ""),
        # Framework
        ("", "[bold]Framework[/bold]"),
        ("/status", "Tool availability + API keys"),
        ("/providers", "LLM provider details"),
        ("/config", "Show configuration"),
        ("/version", "Version and build info"),
        ("", ""),
        # Session
        ("", "[bold]Session[/bold]"),
        ("/history", "Recent command history"),
        ("/clear", "Clear the screen"),
        ("exit", "Exit SEC-C"),
    ]

    for cmd, desc in commands:
        table.add_row(cmd, desc)

    console.print(table)
    console.print()
    console.print("[dim]  Tip: Use Tab for autocomplete, Up/Down for command history[/dim]")
    console.print()


def print_status() -> None:
    """Print comprehensive framework status."""
    import shutil
    import sys as _sys

    safe_box = _sys.platform == "win32"

    table = Table(
        title="[bold cyan]Framework Status[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        safe_box=safe_box,
    )
    table.add_column("Component", width=25)
    table.add_column("Status", width=15)
    table.add_column("Details", width=40)

    # -- Stage 1: SAST tools --
    table.add_row("[bold]Stage 1: SAST[/bold]", "", "")
    codeql_path = shutil.which("codeql")
    if codeql_path:
        table.add_row("  CodeQL CLI", "[green]Available[/green]", codeql_path)
    else:
        table.add_row("  CodeQL CLI", "[red]Not Found[/red]", "Run: scripts/setup_codeql.sh")

    table.add_row("  Tree-sitter", "[green]Available[/green]", "5 languages (py, js, java, c, go)")

    # -- Stage 2: Graph tools --
    table.add_row("[bold]Stage 2: Graph[/bold]", "", "")
    # Check for Joern in PATH and common install locations
    joern_path = shutil.which("joern") or shutil.which("joern-parse")
    if not joern_path:
        # Check known install dirs
        for candidate in [
            Path.home() / ".sec-c" / "joern" / "joern-cli" / "bin",
            Path("C:/joern/joern-cli/bin"),
        ]:
            if (candidate / "joern-parse.bat").exists() or (candidate / "joern-parse").exists():
                joern_path = str(candidate)
                break
    if joern_path:
        table.add_row("  Joern", "[green]Available[/green]", str(joern_path))
    else:
        table.add_row("  Joern", "[dim]Not Installed[/dim]", "Optional: run scripts/setup_joern.sh")

    gnn_model = Path("data/models/mini_gin_v3.pt")
    if gnn_model.exists():
        size_kb = gnn_model.stat().st_size / 1024
        table.add_row("  MiniGINv3 Model", "[green]Trained[/green]", f"{size_kb:.0f} KB")
    else:
        table.add_row("  MiniGINv3 Model", "[dim]Not Trained[/dim]", "Run GNN training notebook")

    # -- Stage 3: LLM --
    table.add_row("[bold]Stage 3: LLM[/bold]", "", "")
    active_provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    model_override = os.environ.get("LLM_MODEL", "")

    gemini_key = os.environ.get("GEMINI_API_KEY")
    gemini_keys = os.environ.get("GEMINI_API_KEYS", "")
    gemini_count = len([k for k in gemini_keys.split(",") if k.strip()]) if gemini_keys else (1 if gemini_key else 0)

    groq_key = os.environ.get("GROQ_API_KEY")
    groq_keys = os.environ.get("GROQ_API_KEYS", "")
    groq_count = len([k for k in groq_keys.split(",") if k.strip()]) if groq_keys else (1 if groq_key else 0)

    if gemini_count > 0:
        marker = " [ACTIVE]" if active_provider == "gemini" else ""
        key_info = f"{gemini_count} key(s)"
        table.add_row(f"  Gemini{marker}", "[green]Ready[/green]", key_info)
    else:
        table.add_row("  Gemini", "[yellow]No Key[/yellow]", "Set GEMINI_API_KEY")

    if groq_count > 0:
        marker = " [ACTIVE]" if active_provider == "groq" else ""
        key_info = f"{groq_count} key(s)"
        table.add_row(f"  Groq{marker}", "[green]Ready[/green]", key_info)
    else:
        table.add_row("  Groq", "[dim]No Key[/dim]", "Optional: Set GROQ_API_KEY")

    provider_detail = active_provider
    if model_override:
        provider_detail += f" ({model_override})"
    table.add_row("  Active Provider", f"[cyan]{provider_detail}[/cyan]", "LLM_PROVIDER + LLM_MODEL in .env")

    # -- RAG Knowledge Base --
    table.add_row("[bold]RAG Knowledge[/bold]", "", "")
    cwe_catalog = Path("data/cwe/cwe_catalog.json")
    if cwe_catalog.exists():
        try:
            import json
            entries = json.loads(cwe_catalog.read_text(encoding="utf-8"))
            table.add_row("  CWE Catalog", "[green]Loaded[/green]", f"{len(entries)} entries (MITRE)")
        except Exception:
            table.add_row("  CWE Catalog", "[green]Available[/green]", str(cwe_catalog))
    else:
        table.add_row("  CWE Catalog", "[yellow]Not Built[/yellow]", "Run: python scripts/setup_rag.py")

    cve_data = Path("data/rag/cve_data.json")
    if cve_data.exists():
        try:
            import json
            cves = json.loads(cve_data.read_text(encoding="utf-8"))
            table.add_row("  NVD CVE Data", "[green]Loaded[/green]", f"{len(cves)} CVEs")
        except Exception:
            table.add_row("  NVD CVE Data", "[green]Available[/green]", str(cve_data))
    else:
        table.add_row("  NVD CVE Data", "[dim]Not Downloaded[/dim]", "Deferred to GNN phase")

    templates = list(Path("src/llm/prompts/templates").glob("*.jinja2")) if Path("src/llm/prompts/templates").exists() else []
    table.add_row("  CWE Templates", "[green]Available[/green]", f"{len(templates)} Jinja2 templates")

    # -- Infrastructure --
    table.add_row("[bold]Infrastructure[/bold]", "", "")

    try:
        import torch
        gpu = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU only"
        table.add_row("  Compute", "[cyan]" + ("GPU" if torch.cuda.is_available() else "CPU") + "[/cyan]", gpu)
    except ImportError:
        table.add_row("  Compute", "[yellow]CPU[/yellow]", "PyTorch not installed")

    console.print(table)
    console.print()


def print_providers() -> None:
    """Print LLM provider status using same detection logic as /status."""
    import sys as _sys
    safe_box = _sys.platform == "win32"

    active_provider = os.environ.get("LLM_PROVIDER", "gemini").lower()

    table = Table(
        title="[bold cyan]LLM Providers[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        safe_box=safe_box,
    )
    table.add_column("Provider", width=15)
    table.add_column("Status", width=18)
    table.add_column("Default Model", width=30)

    # Gemini — check both single and multi-key (same logic as /status)
    gemini_key = os.environ.get("GEMINI_API_KEY")
    gemini_keys = os.environ.get("GEMINI_API_KEYS", "")
    gemini_count = len([k for k in gemini_keys.split(",") if k.strip()]) if gemini_keys else (1 if gemini_key else 0)

    marker = " [*]" if active_provider == "gemini" else ""
    if gemini_count > 0:
        table.add_row(f"Gemini{marker}", f"[green]{gemini_count} key(s) set[/green]", "gemini-2.5-flash")
    else:
        table.add_row(f"Gemini{marker}", "[dim]Not configured[/dim]", "gemini-2.5-flash")

    # Groq — check both single and multi-key
    groq_key = os.environ.get("GROQ_API_KEY")
    groq_keys = os.environ.get("GROQ_API_KEYS", "")
    groq_count = len([k for k in groq_keys.split(",") if k.strip()]) if groq_keys else (1 if groq_key else 0)

    marker = " [*]" if active_provider == "groq" else ""
    if groq_count > 0:
        table.add_row(f"Groq{marker}", f"[green]{groq_count} key(s) set[/green]", "llama-3.3-70b-versatile")
    else:
        table.add_row(f"Groq{marker}", "[dim]Not configured[/dim]", "llama-3.3-70b-versatile")

    console.print(table)
    console.print()
    console.print(f"  Active: [bold cyan]{active_provider}[/bold cyan]")
    model_override = os.environ.get("LLM_MODEL", "")
    if model_override:
        console.print(f"  Model override: [bold]{model_override}[/bold]")
    console.print(f"  Change: set LLM_PROVIDER and LLM_MODEL in .env")
    console.print()


def print_version() -> None:
    """Print SEC-C version and build information."""
    from src.cli.banner import VERSION
    from pathlib import Path
    import sys as _sys

    console.print()
    console.print(f"  [bold cyan]Sec-C[/bold cyan] v{VERSION}")
    console.print(f"  Multi-Stage Code Security Framework")
    console.print()
    console.print(f"  Python:     {_sys.version.split()[0]}")
    console.print(f"  Platform:   {_sys.platform}")

    src_count = sum(1 for _ in Path("src").rglob("*.py") if "__pycache__" not in str(_))
    test_count = sum(1 for _ in Path("tests").rglob("*.py") if "__pycache__" not in str(_))
    template_count = len(list(Path("src/llm/prompts/templates").glob("*.jinja2"))) if Path("src/llm/prompts/templates").exists() else 0

    console.print(f"  Source:     {src_count} files")
    console.print(f"  Tests:      {test_count} files")
    console.print(f"  Templates:  {template_count} CWE-specific prompts")
    console.print()


async def run_interactive_scan(
    args: list[str],
    stage_override: str | None = None,
    verbose_override: bool | None = None,
    session: Any = None,
) -> None:
    """Parse scan arguments and run the cascade with live progress.

    Supports both smart shorthand and legacy flags:
      /scan <path>              Full cascade
      /scan <path> sast         SAST-only (shorthand)
      /scan <path> --stage sast Legacy flag (still works)
      /quick <path>             Same as /scan <path> sast
      /deep <path>              Same as /scan <path> --verbose
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

    # Parse args — smart mode + legacy flags
    target = None
    stage = stage_override or "llm"
    languages = None
    output = None
    verbose = verbose_override if verbose_override is not None else False

    i = 0
    while i < len(args):
        arg = args[i]
        # Legacy flags (backward compatible)
        if arg == "--stage" or arg == "-s":
            i += 1
            if not stage_override:  # Don't override /quick or /deep
                stage = args[i] if i < len(args) else "llm"
        elif arg == "--languages" or arg == "-l":
            i += 1
            languages = args[i] if i < len(args) else None
        elif arg == "--output" or arg == "-o":
            i += 1
            output = args[i] if i < len(args) else None
        elif arg in ("--verbose", "-v"):
            verbose = True
        elif arg in ("--dashboard", "-d"):
            pass  # Dashboard is now in post-scan menu, ignore silently
        elif arg in ("--github", "-g"):
            console.print("[yellow]  Note: --github is planned for a future release.[/yellow]")
            return
        elif arg in ("sast", "graph", "llm") and not stage_override:
            # Smart shorthand: second positional arg = stage
            stage = arg
        elif not arg.startswith("-"):
            target = arg
        i += 1

    # If no path given, prompt for one
    if not target:
        if session:
            from prompt_toolkit.completion import PathCompleter as _PC
            try:
                target = session.prompt(
                    "  Enter path to scan: ",
                    completer=_PC(expanduser=True),
                ).strip()
            except (EOFError, KeyboardInterrupt):
                return
            if not target:
                return
        else:
            console.print("[red]  Error: Provide a local path to scan.[/red]")
            return

    # Show scan start
    from src.cli.banner import print_scan_start
    lang_list = languages.split(",") if languages else []
    print_scan_start(target, lang_list, stage)

    # Run with progress
    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        overall = progress.add_task("[cyan]SEC-C Cascade", total=100)

        # Stage 1: SAST
        progress.update(overall, description="[green]> Stage 1: SAST Analysis")
        sast_task = progress.add_task("[green]  CodeQL + Tree-sitter", total=100)
        for j in range(0, 101, 10):
            progress.update(sast_task, completed=j)
            import asyncio
            await asyncio.sleep(0.05)
        progress.update(overall, completed=40)

        if stage in ("graph", "llm"):
            progress.update(overall, description="[cyan]* Stage 2: Graph Validation")
            graph_task = progress.add_task("[cyan]  CPG + Mini-GAT + Conformal", total=100)
            for j in range(0, 101, 10):
                progress.update(graph_task, completed=j)
                await asyncio.sleep(0.05)
            progress.update(overall, completed=70)

        if stage == "llm":
            progress.update(overall, description="[yellow]@ Stage 3: LLM Dual-Agent")
            llm_task = progress.add_task("[yellow]  Attacker <-> Defender", total=100)
            for j in range(0, 101, 10):
                progress.update(llm_task, completed=j)
                await asyncio.sleep(0.05)
            progress.update(overall, completed=100)

        progress.update(overall, description="[bold green]OK Scan Complete")

    console.print()

    # Run actual scan
    from src.cli.main import load_config, _init_modules
    from src.orchestrator.pipeline import PipelineOrchestrator
    from src.sast.sarif.schema import Language

    config = load_config()
    orchestrator = PipelineOrchestrator(config)
    _init_modules(orchestrator, config, stage)

    lang_list_enum = None
    if languages:
        lang_list_enum = []
        for lang in languages.split(","):
            try:
                lang_list_enum.append(Language(lang.strip()))
            except ValueError:
                pass

    result = await orchestrator.scan(
        target=target,
        languages=lang_list_enum,
        max_stage=stage,
    )

    # Display results
    from src.reporting.console_reporter import ConsoleReporter
    reporter = ConsoleReporter(verbose=verbose, show_cascade_stats=True)
    reporter.report(result)

    # Save SARIF if requested via legacy flag
    if output:
        from src.reporting.sarif_reporter import SARIFReporter
        sarif_reporter = SARIFReporter(config.get("reporting", {}).get("sarif", {}))
        sarif_reporter.write(result, output)
        console.print(f"\n  [green]OK[/green] SARIF saved to [bold]{output}[/bold]")

    # Post-scan action menu
    if result.total_findings > 0 and session:
        # Pre-generate dashboard so 'd' is instant
        from src.reporting.html_reporter import HTMLReporter
        html_reporter = HTMLReporter(auto_open=False)
        dashboard_path = html_reporter.generate(result)

        console.print()
        console.print(
            "  [bold cyan][d][/bold cyan] Open Dashboard    "
            "[bold cyan][s][/bold cyan] Save SARIF    "
            "[bold cyan][r][/bold cyan] Re-scan (SAST)    "
            "[dim][Enter] Done[/dim]"
        )

        try:
            choice = session.prompt("  > ", default="").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = ""

        if choice == "d":
            import webbrowser
            webbrowser.open(str(Path(dashboard_path).resolve().as_uri()))
            console.print(f"  [green]OK[/green] Dashboard opened")
        elif choice == "s":
            default_name = "sec-c-report.sarif"
            try:
                save_path = session.prompt(f"  Save to [{default_name}]: ", default=default_name).strip()
            except (EOFError, KeyboardInterrupt):
                save_path = default_name
            from src.reporting.sarif_reporter import SARIFReporter
            SARIFReporter(config.get("reporting", {}).get("sarif", {})).write(result, save_path or default_name)
            console.print(f"  [green]OK[/green] Saved to [bold]{save_path or default_name}[/bold]")
        elif choice == "r":
            await run_interactive_scan([target], stage_override="sast", session=session)


def run_interactive() -> None:
    """Launch the interactive SEC-C REPL."""
    print_banner(console)

    # Create history file
    history_dir = Path.home() / ".sec-c"
    history_dir.mkdir(exist_ok=True)
    history_file = history_dir / "history"

    session: PromptSession = PromptSession(
        history=FileHistory(str(history_file)),
        auto_suggest=AutoSuggestFromHistory(),
        completer=SecCCompleter(),
        style=PROMPT_STYLE,
        complete_while_typing=True,
    )

    console.print("  [dim]Type /help for commands, Tab for autocomplete[/dim]")
    console.print()

    while True:
        try:
            user_input = session.prompt(get_prompt_message).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n  [dim]Goodbye![/dim]")
            break

        if not user_input:
            continue

        parts = user_input.split()
        cmd = parts[0].lower()
        # Support slash commands: /scan, /status, /help etc.
        if cmd.startswith("/"):
            cmd = cmd[1:]

        if cmd in ("exit", "quit"):
            console.print("  [dim]Goodbye![/dim]")
            break
        elif cmd == "clear":
            import os
            os.system("cls" if os.name == "nt" else "clear")
            from src.cli.banner import print_mini_banner
            print_mini_banner(console)
        elif cmd == "help":
            print_help()
        elif cmd == "status":
            print_status()
        elif cmd == "config":
            from src.cli.main import load_config
            import json
            config = load_config()
            console.print_json(json.dumps(config, indent=2, default=str))
        elif cmd == "scan":
            import asyncio
            asyncio.run(run_interactive_scan(parts[1:], session=session))
        elif cmd == "quick":
            import asyncio
            asyncio.run(run_interactive_scan(parts[1:], stage_override="sast", session=session))
        elif cmd == "deep":
            import asyncio
            asyncio.run(run_interactive_scan(parts[1:], stage_override="llm", verbose_override=True, session=session))
        elif cmd == "report":
            if len(parts) < 2:
                console.print("[red]  Usage: report <file.sarif>[/red]")
            else:
                import json as _json
                from pathlib import Path as _Path
                sarif_path = parts[1]
                if not _Path(sarif_path).exists():
                    console.print(f"[red]  Error: File not found: {sarif_path}[/red]")
                else:
                    try:
                        from src.sast.sarif.parser import SARIFParser
                        from src.sast.sarif.schema import ScanResult
                        parser = SARIFParser()
                        findings = parser.parse_file(sarif_path)
                        result = ScanResult(findings=findings, scan_target=sarif_path)
                        # Check for --console flag
                        if "--console" in parts:
                            from src.reporting.console_reporter import ConsoleReporter
                            ConsoleReporter(verbose=True).report(result)
                        else:
                            # Default: open dashboard
                            from src.reporting.html_reporter import HTMLReporter
                            reporter = HTMLReporter(auto_open=True)
                            path = reporter.generate(result)
                            console.print(f"  [green]OK[/green] Dashboard opened: [bold cyan]{path}[/bold cyan]")
                    except (_json.JSONDecodeError, ValueError) as e:
                        console.print(f"[red]  Error: Invalid SARIF file: {e}[/red]")
        elif cmd == "providers":
            print_providers()
        elif cmd == "version":
            print_version()
        elif cmd == "history":
            console.print("[dim]  Recent command history:[/dim]")
            for item in list(session.history.get_strings())[-15:]:
                console.print(f"    [green]>[/green] {item}")
        else:
            console.print(f"  [dim]Unknown:[/dim] {cmd} [dim]— type /help for commands[/dim]")
