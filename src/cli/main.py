"""
SEC-C CLI: Command-line interface for the Multi-Stage Security Framework.

Supports two modes:
  1. Direct commands:  sec-c scan <path>, sec-c report <file>, etc.
  2. Interactive mode:  sec-c (launches Claude Code-like REPL with autocomplete)

Usage:
    sec-c                                Launch interactive mode
    sec-c scan <path>                    Scan local code (full cascade)
    sec-c scan --github <owner/repo>     Scan a GitHub repository
    sec-c scan --stage sast              Run SAST only
    sec-c scan --html                    Generate interactive HTML report
    sec-c report <sarif_file>            Display a SARIF report
    sec-c status                         Show tool availability
    sec-c config                         Show current configuration
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console

from src.cli.banner import print_banner, print_scan_start
from src.sast.sarif.schema import Language



def _load_dotenv() -> None:
    """Load .env file if present (no external dependency needed)."""
    for env_path in [Path(".env"), Path(__file__).parent.parent.parent / ".env"]:
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and value and key not in os.environ:
                        os.environ[key] = value
            break


_load_dotenv()

app = typer.Typer(
    name="sec-c",
    help="SEC-C: Multi-Stage Code Security Framework for Adaptive Vulnerability Triage",
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,
)
console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging.

    In normal mode, only WARNING+ from LLM/RAG modules is shown to keep
    the terminal clean.  ``--verbose`` unlocks DEBUG across the board.
    """
    root_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=root_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if not verbose:
        # Silence chatty LLM internals in normal mode — the ScanDisplay
        # handles user-facing output for Stage 3.
        for quiet_mod in (
            "src.llm", "src.llm.api", "src.llm.agents",
            "src.llm.consensus", "src.llm.rag",
            "httpx", "httpcore",
        ):
            logging.getLogger(quiet_mod).setLevel(logging.WARNING)


def load_config(config_path: str | None = None) -> dict:
    """Load framework configuration."""
    if config_path is None:
        default_paths = [
            Path("configs/default.yaml"),
            Path(__file__).parent.parent.parent / "configs" / "default.yaml",
        ]
        for p in default_paths:
            if p.exists():
                config_path = str(p)
                break

    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}

    return {}


@app.callback()
def main(ctx: typer.Context) -> None:
    """SEC-C: Multi-Stage Code Security Framework."""
    if ctx.invoked_subcommand is None:
        # No subcommand → launch interactive mode
        from src.cli.interactive import run_interactive
        run_interactive()


@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="Path to local code directory or file"),
    github: Optional[str] = typer.Option(None, "--github", "-g", help="GitHub repo (owner/repo)"),
    stage: str = typer.Option("llm", "--stage", "-s", help="Max stage: sast, graph, llm"),
    languages: Optional[str] = typer.Option(None, "--languages", "-l", help="Comma-separated languages"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="SARIF output file path"),
    html_report: bool = typer.Option(False, "--html", help="Generate interactive HTML report"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Config file path"),
) -> None:
    """Run a SEC-C security scan with uncertainty-driven cascade."""
    setup_logging(verbose)

    if not target and not github:
        console.print("[red]Error: Provide either a local path or --github repo[/red]")
        raise typer.Exit(1)

    config = load_config(config_file)

    # Parse languages
    lang_list = None
    if languages:
        lang_list = []
        for lang_str in languages.split(","):
            try:
                lang_list.append(Language(lang_str.strip().lower()))
            except ValueError:
                console.print(f"[yellow]Warning: Unknown language '{lang_str}', skipping[/yellow]")

    # Set up scan display and pipeline
    from src.orchestrator.pipeline import PipelineOrchestrator
    from src.reporting.scan_display import ScanDisplay

    display = ScanDisplay(quiet=False)
    orchestrator = PipelineOrchestrator(config)
    orchestrator.set_display(display)
    _init_modules(orchestrator, config, stage)

    # Run the cascade (ScanDisplay handles all real-time stage output)
    scan_result = asyncio.run(
        orchestrator.scan(
            target=target or "",
            languages=lang_list,
            max_stage=stage,
            github_repo=github,
        )
    )

    # SARIF output
    if output:
        from src.reporting.sarif_reporter import SARIFReporter
        sarif_reporter = SARIFReporter(config.get("reporting", {}).get("sarif", {}))
        sarif_reporter.write(scan_result, output)
        console.print(f"\n  [green]OK[/green] SARIF report saved to [bold]{output}[/bold]")

    # HTML report
    if html_report:
        from src.reporting.html_reporter import HTMLReporter
        html_gen = HTMLReporter(auto_open=True)
        html_path = html_gen.generate(scan_result)
        console.print(f"\n  [green]OK[/green] HTML report opened: [bold cyan]{html_path}[/bold cyan]")
    elif scan_result.total_findings > 0:
        console.print(
            "\n  [dim]Run with[/dim] [bold cyan]--html[/bold cyan] "
            "[dim]to open an interactive web dashboard[/dim]"
        )


@app.command()
def report(
    sarif_file: str = typer.Argument(..., help="Path to SARIF file to display"),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Display a formatted report from an existing SARIF file."""
    setup_logging(verbose)

    from src.sast.sarif.parser import SARIFParser
    from src.sast.sarif.schema import ScanResult

    parser = SARIFParser()
    findings = parser.parse_file(sarif_file)
    result = ScanResult(findings=findings, scan_target=sarif_file)

    if html:
        from src.reporting.html_reporter import HTMLReporter
        html_gen = HTMLReporter(auto_open=True)
        html_path = html_gen.generate(result)
        console.print(f"  [green]OK[/green] HTML report opened: [bold cyan]{html_path}[/bold cyan]")
    else:
        from src.reporting.console_reporter import ConsoleReporter
        ConsoleReporter(verbose=verbose).report(result)


@app.command("status")
def show_status() -> None:
    """Show SEC-C tool availability and API quotas."""
    from src.cli.banner import MINI_BANNER
    console.print(MINI_BANNER)
    console.print()
    from src.cli.interactive import print_status
    print_status()


@app.command("providers")
def show_providers() -> None:
    """Show LLM provider details and available models."""
    from src.cli.banner import MINI_BANNER
    console.print(MINI_BANNER)
    console.print()
    from src.cli.interactive import print_providers
    print_providers()


@app.command("models")
def show_models() -> None:
    """List available models per LLM provider."""
    from src.cli.banner import MINI_BANNER
    console.print(MINI_BANNER)
    console.print()
    from src.cli.interactive import print_models
    print_models()


@app.command("version")
def show_version() -> None:
    """Show SEC-C version and build information."""
    from src.cli.interactive import print_version
    print_version()


@app.command("config")
def show_config(
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Show current SEC-C configuration."""
    config = load_config(config_file)

    import json
    from src.cli.banner import MINI_BANNER
    console.print(MINI_BANNER)
    console.print()
    console.print("[bold cyan]Configuration[/bold cyan]")
    console.print_json(json.dumps(config, indent=2, default=str))


def _load_rag_knowledge_base(config: dict):
    """Try to load the RAG KnowledgeBase from ``data/rag/``.

    Returns the loaded :class:`KnowledgeBase` instance or ``None`` if
    the data directory does not exist or loading fails.
    """
    try:
        from src.llm.rag.knowledge_base import KnowledgeBase

        # Resolve data directory -- check config, then default locations
        rag_config = config.get("llm", {}).get("rag", {})
        rag_data_dir = rag_config.get("data_dir", None)

        if rag_data_dir is None:
            # Check default locations relative to project root
            candidates = [
                Path("data/rag"),
                Path(__file__).parent.parent.parent / "data" / "rag",
            ]
            for candidate in candidates:
                if candidate.exists() and any(candidate.glob("cwe_*.pkl")):
                    rag_data_dir = str(candidate)
                    break

        if rag_data_dir is None:
            logging.getLogger(__name__).info(
                "RAG data directory not found -- RAG enrichment will be disabled"
            )
            return None

        rag_dir = Path(rag_data_dir)

        # Find CWE data file (check both locations)
        cwe_data_path = None
        for p in [
            rag_dir / "cwe_data.json",
            rag_dir.parent / "cwe" / "cwe_catalog.json",
            Path("data/cwe/cwe_catalog.json"),
        ]:
            if p.exists():
                cwe_data_path = p
                break

        kb = KnowledgeBase(
            faiss_index_path=rag_dir / "cwe_faiss.bin",
            bm25_index_path=rag_dir / "cwe_bm25.pkl",
            cwe_data_path=cwe_data_path or rag_dir / "cwe_data.json",
        )
        logging.getLogger(__name__).info(
            "RAG KnowledgeBase loaded from %s", rag_data_dir
        )
        return kb

    except ImportError as e:
        logging.getLogger(__name__).info(
            "RAG dependencies not available (sentence-transformers/faiss): %s", e
        )
        return None
    except Exception as e:
        logging.getLogger(__name__).warning(
            "Failed to load RAG KnowledgeBase: %s", e
        )
        return None


def _init_modules(orchestrator, config: dict, max_stage: str) -> None:
    """Initialize pipeline modules based on configuration and max stage."""
    # SAST engine (always needed)
    from src.sast.engine import SASTEngine
    sast_engine = SASTEngine(config.get("sast", {}))
    orchestrator.set_sast_engine(sast_engine)
    logging.getLogger(__name__).info("SAST engine initialized (Tree-sitter + CodeQL)")

    # Score fuser (always needed)
    from src.orchestrator.fusion import ScoreFusionEngine

    cwe_weights_path = str(Path("configs/cwe_weights.yaml"))
    fuser = ScoreFusionEngine(
        config=config.get("orchestrator", {}),
        cwe_weights_path=cwe_weights_path if Path(cwe_weights_path).exists() else None,
    )
    orchestrator.set_score_fuser(fuser)

    # Graph stage (if model is trained)
    if max_stage in ("graph", "llm"):
        try:
            graph_config = config.get("graph", {})
            model_path = Path(
                graph_config.get("gnn", {}).get(
                    "model_path", "data/models/mini_gat.pt"
                )
            )
            if model_path.exists():
                from src.graph.gnn.graph_validator import GraphValidator

                validator = GraphValidator(config=graph_config)
                orchestrator.set_graph_validator(validator)
                logging.getLogger(__name__).info(
                    "Graph validator loaded: %s", model_path
                )
            else:
                logging.getLogger(__name__).info(
                    "GNN model not found -- graph stage skipped"
                )
        except ImportError:
            logging.getLogger(__name__).info(
                "GNN dependencies not installed -- graph stage skipped"
            )
        except Exception as e:
            logging.getLogger(__name__).warning(
                "Graph validator init failed: %s", e
            )

    # LLM stage -- uses provider factory to select Gemini or Groq
    if max_stage == "llm":
        try:
            from src.llm.api.provider_factory import create_llm_client
            from src.llm.consensus.engine import ConsensusEngine

            llm_config = config.get("llm", {})
            client = create_llm_client(llm_config)

            if client is not None and client.is_available:
                # Try to load RAG knowledge base for CWE/CVE context
                rag_kb = _load_rag_knowledge_base(config)

                consensus = ConsensusEngine(
                    client=client,
                    rag_knowledge_base=rag_kb,
                    config=llm_config.get("agents", {}),
                )
                orchestrator.set_llm_validator(consensus)

                rag_status = "with RAG" if rag_kb else "without RAG"
                provider = client.provider_name
                model = client.model_flash
                logging.getLogger(__name__).info(
                    "LLM validator: %s [%s] (%s)", provider, model, rag_status
                )
            else:
                logging.getLogger(__name__).warning(
                    "No LLM provider available -- LLM stage will be skipped. "
                    "Set LLM_PROVIDER and API key in .env"
                )
        except Exception as e:
            logging.getLogger(__name__).warning(f"Could not initialize LLM stage: {e}")


if __name__ == "__main__":
    app()
