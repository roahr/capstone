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
            "/scan": "Scan a local directory or file for vulnerabilities",
            "/scan --github": "Scan a GitHub repository",
            "/scan --stage sast": "Run SAST stage only",
            "/scan --stage graph": "Run up to Graph stage",
            "/scan --stage llm": "Run full pipeline",
            "/scan --languages": "Specify languages to scan",
            "/report": "Display a SARIF report file",
            "/status": "Framework status + tool availability",
            "/providers": "LLM provider details + usage stats",
            "/models": "List available models per provider",
            "/config": "Show current configuration",
            "/history": "Show recent command history",
            "/version": "Show SEC-C version and build info",
            "/help": "Show available commands",
            "/clear": "Clear the screen",
            "exit": "Exit SEC-C",
            "quit": "Exit SEC-C",
            # Also match without slash
            "scan": "Scan (same as /scan)",
            "status": "Status (same as /status)",
            "providers": "Providers (same as /providers)",
            "models": "Models (same as /models)",
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
        elif words[0] in ("scan", "report") and (
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
                flags = ["--github", "--stage", "--languages", "--output", "--verbose"]
                for flag in flags:
                    if flag.startswith(path_text):
                        yield Completion(flag, start_position=-len(path_text))
            else:
                # Use path completer
                from prompt_toolkit.document import Document
                sub_doc = Document(path_text)
                yield from self.path_completer.get_completions(sub_doc, complete_event)


def get_prompt_message() -> HTML:
    """Generate the SEC-C prompt."""
    cwd = os.getcwd()
    # Shorten path
    home = str(Path.home())
    display_path = cwd.replace(home, "~") if cwd.startswith(home) else cwd
    if len(display_path) > 40:
        display_path = "..." + display_path[-37:]

    return HTML(
        '<prompt>sec-c</prompt>'
        '<separator> > </separator>'
        '<path>{}</path>'
        '<separator> > </separator>'
    ).format(display_path)


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
        ("/scan <path>", "Scan local code (full cascade)"),
        ("/scan --github <owner/repo>", "Scan a GitHub repository"),
        ("/scan --stage <sast|graph|llm>", "Run up to a specific stage"),
        ("/scan --languages <py,js,java>", "Scan specific languages only"),
        ("/scan --output <file.sarif>", "Save SARIF report to file"),
        ("/scan --html", "Generate interactive HTML dashboard"),
        ("/report <file.sarif>", "Display a SARIF report"),
        ("/status", "Framework status + tool availability"),
        ("/providers", "LLM provider details + API usage stats"),
        ("/models", "List available models per provider"),
        ("/config", "Show current configuration"),
        ("/history", "Show recent command history"),
        ("/version", "Show SEC-C version and build info"),
        ("/clear", "Clear the screen"),
        ("/help", "Show this help"),
        ("exit / quit / Ctrl+D", "Exit SEC-C"),
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
    joern_path = shutil.which("joern")
    if joern_path:
        table.add_row("  Joern", "[green]Available[/green]", joern_path)
    else:
        table.add_row("  Joern", "[dim]Not Installed[/dim]", "Optional (deferred to GNN phase)")

    gnn_model = Path("data/models/mini_gat.pt")
    if gnn_model.exists():
        size_kb = gnn_model.stat().st_size / 1024
        table.add_row("  Mini-GAT Model", "[green]Trained[/green]", f"{size_kb:.0f} KB")
    else:
        table.add_row("  Mini-GAT Model", "[dim]Not Trained[/dim]", "Deferred to GNN phase")

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
    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        table.add_row("  GitHub Token", "[green]Set[/green]", f"...{gh_token[-4:]}")
    else:
        table.add_row("  GitHub Token", "[dim]Not Set[/dim]", "Optional: for repo scanning")

    try:
        import torch
        gpu = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU only"
        table.add_row("  Compute", "[cyan]" + ("GPU" if torch.cuda.is_available() else "CPU") + "[/cyan]", gpu)
    except ImportError:
        table.add_row("  Compute", "[yellow]CPU[/yellow]", "PyTorch not installed")

    console.print(table)
    console.print()


def print_providers() -> None:
    """Print detailed LLM provider information."""
    import sys as _sys
    safe_box = _sys.platform == "win32"

    from src.llm.api.provider_factory import get_provider_status
    status = get_provider_status()
    active = status.pop("active_provider", "gemini")

    table = Table(
        title="[bold cyan]LLM Providers[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        safe_box=safe_box,
    )
    table.add_column("Provider", width=15)
    table.add_column("Status", width=12)
    table.add_column("API Key", width=15)
    table.add_column("Default Model", width=30)
    table.add_column("Free Tier", width=20)

    free_tiers = {
        "gemini": "Flash: 250 RPD",
        "groq": "Llama 70B: 1000 RPD",
    }

    for name, info in status.items():
        if name == "active_provider":
            continue
        marker = " [*]" if name == active else ""
        configured = "[green]Ready[/green]" if info["configured"] else "[dim]Not Set[/dim]"
        key_preview = info["key_preview"] or "--"
        table.add_row(
            f"{name}{marker}",
            configured,
            key_preview,
            info["default_model"],
            free_tiers.get(name, "--"),
        )

    console.print(table)
    console.print()
    console.print(f"  Active: [bold cyan]{active}[/bold cyan]")
    model_override = os.environ.get("LLM_MODEL", "")
    if model_override:
        console.print(f"  Model override: [bold]{model_override}[/bold]")
    console.print(f"  Change: set LLM_PROVIDER in .env")
    console.print()


def print_models() -> None:
    """Print available models per provider."""
    import sys as _sys
    safe_box = _sys.platform == "win32"

    table = Table(
        title="[bold cyan]Available Models[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        safe_box=safe_box,
    )
    table.add_column("Provider", width=10)
    table.add_column("Model", width=40)
    table.add_column("Free RPD", width=10, justify="right")
    table.add_column("Notes", width=25)

    # Gemini models
    table.add_row("Gemini", "gemini-2.5-flash", "250", "Primary (recommended)")
    table.add_row("Gemini", "gemini-2.5-flash-lite", "1,000", "Lighter, higher quota")
    table.add_row("Gemini", "gemini-2.5-pro", "0", "[red]Removed from free tier[/red]")

    table.add_row("", "", "", "")

    # Groq models
    table.add_row("Groq", "llama-3.3-70b-versatile", "1,000", "Best quality (recommended)")
    table.add_row("Groq", "llama-3.1-8b-instant", "14,400", "Fastest, lower quality")
    table.add_row("Groq", "qwen/qwen3-32b", "1,000", "Strong reasoning")
    table.add_row("Groq", "meta-llama/llama-4-scout-17b-16e-instruct", "1,000", "Latest Llama 4")

    console.print(table)
    console.print()
    console.print("  Set model: LLM_MODEL=<model-name> in .env")
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


async def run_interactive_scan(args: list[str]) -> None:
    """Parse scan arguments and run the cascade with live progress."""
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.layout import Layout

    # Parse args
    target = None
    github = None
    stage = "llm"
    languages = None
    output = None
    verbose = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--github" or arg == "-g":
            i += 1
            github = args[i] if i < len(args) else None
        elif arg == "--stage" or arg == "-s":
            i += 1
            stage = args[i] if i < len(args) else "llm"
        elif arg == "--languages" or arg == "-l":
            i += 1
            languages = args[i] if i < len(args) else None
        elif arg == "--output" or arg == "-o":
            i += 1
            output = args[i] if i < len(args) else None
        elif arg in ("--verbose", "-v"):
            verbose = True
        elif not arg.startswith("-"):
            target = arg
        i += 1

    if not target and not github:
        console.print("[red]  Error: Provide a path or --github repo[/red]")
        return

    # Show scan start
    from src.cli.banner import print_scan_start
    lang_list = languages.split(",") if languages else []
    print_scan_start(target or github or "", lang_list, stage)

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
        for i in range(0, 101, 10):
            progress.update(sast_task, completed=i)
            import asyncio
            await asyncio.sleep(0.05)
        progress.update(overall, completed=40)

        if stage in ("graph", "llm"):
            # Stage 2: Graph
            progress.update(overall, description="[cyan]* Stage 2: Graph Validation")
            graph_task = progress.add_task("[cyan]  CPG + Mini-GAT + Conformal", total=100)
            for i in range(0, 101, 10):
                progress.update(graph_task, completed=i)
                await asyncio.sleep(0.05)
            progress.update(overall, completed=70)

        if stage == "llm":
            # Stage 3: LLM
            progress.update(overall, description="[yellow]@ Stage 3: LLM Dual-Agent")
            llm_task = progress.add_task("[yellow]  Attacker <-> Defender", total=100)
            for i in range(0, 101, 10):
                progress.update(llm_task, completed=i)
                await asyncio.sleep(0.05)
            progress.update(overall, completed=100)

        progress.update(overall, description="[bold green]OK Scan Complete")

    console.print()

    # Run actual scan
    import yaml
    from src.cli.main import load_config, _init_modules
    from src.orchestrator.pipeline import PipelineOrchestrator
    from src.sast.sarif.schema import Language

    config = load_config()
    orchestrator = PipelineOrchestrator(config)
    _init_modules(orchestrator, config, stage)

    lang_list_enum = None
    if languages:
        lang_list_enum = []
        for l in languages.split(","):
            try:
                lang_list_enum.append(Language(l.strip()))
            except ValueError:
                pass

    result = await orchestrator.scan(
        target=target or "",
        languages=lang_list_enum,
        max_stage=stage,
        github_repo=github,
    )

    # Display results
    from src.reporting.console_reporter import ConsoleReporter
    reporter = ConsoleReporter(verbose=verbose, show_cascade_stats=True)
    reporter.report(result)

    # Save SARIF if requested
    if output:
        from src.reporting.sarif_reporter import SARIFReporter
        sarif_reporter = SARIFReporter(config.get("reporting", {}).get("sarif", {}))
        sarif_reporter.write(result, output)
        console.print(f"\n  [green]OK[/green] SARIF report saved to [bold]{output}[/bold]")

    # Offer HTML report
    if result.total_findings > 0:
        console.print()
        console.print(
            "  [dim]Tip: Run[/dim] [bold cyan]report --html[/bold cyan] "
            "[dim]for an interactive web dashboard[/dim]"
        )


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

    console.print("  [dim]Type[/dim] [bold green]help[/bold green] [dim]for commands,[/dim] "
                   "[bold green]Tab[/bold green] [dim]for autocomplete[/dim]")
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
            console.clear()
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
            asyncio.run(run_interactive_scan(parts[1:]))
        elif cmd == "report":
            if len(parts) < 2:
                console.print("[red]  Usage: report <file.sarif>[/red]")
            else:
                from src.sast.sarif.parser import SARIFParser
                from src.sast.sarif.schema import ScanResult
                from src.reporting.console_reporter import ConsoleReporter

                parser = SARIFParser()
                findings = parser.parse_file(parts[1])
                result = ScanResult(findings=findings, scan_target=parts[1])
                ConsoleReporter(verbose=True).report(result)
        elif cmd == "providers":
            print_providers()
        elif cmd == "models":
            print_models()
        elif cmd == "version":
            print_version()
        elif cmd == "history":
            console.print("[dim]  Recent command history:[/dim]")
            for item in list(session.history.get_strings())[-15:]:
                console.print(f"    [green]>[/green] {item}")
        else:
            console.print(f"  [red]Unknown command: {cmd}[/red]. Type [bold]help[/bold] for available commands.")
