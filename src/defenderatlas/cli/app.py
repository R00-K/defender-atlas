"""CLI application for DefenderAtlas."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from defenderatlas import __version__
from defenderatlas.capture.collector import (
    DEFAULT_SOURCE_URL,
    CollectionSummary,
    Collector,
    CollectorConfig,
)
from defenderatlas.capture.procmon import find_procmon
from defenderatlas.capture.taskscheduler import (
    DEFAULT_TASK_NAME,
    install_procmon_task,
    task_exists,
    uninstall_procmon_task,
)
from defenderatlas.capture.trigger import find_trigger_worker
from defenderatlas.cli._logging import get_logger, setup_logging
from defenderatlas.parsers import (
    CSVFormatError,
    HeaderError,
    ParserError,
    parse_procmon_csv,
)
from defenderatlas.statistics import compute_statistics

console = Console()
error_console = Console(stderr=True)

app = typer.Typer(
    name="defenderatlas",
    help=(
        "[bold green]DefenderAtlas[/bold green] - Microsoft Defender "
        "scanning behavior analysis framework."
    ),
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

log = get_logger(__name__)


# ── helpers ────────────────────────────────────────────────────────────


def _handle_error(exc: Exception) -> None:
    """Display an exception inside a Rich error panel and exit."""
    error_console.print(
        Panel(
            f"[bold red]Error:[/bold red] {exc}",
            border_style="red",
            title="DefenderAtlas",
        )
    )
    log.debug("Traceback:", exc_info=True)
    raise typer.Exit(code=1)


def _resolve_output_dir(output_dir: str | None) -> Path:
    """Resolve and optionally create the output directory."""
    out = Path(output_dir) if output_dir else Path("defenderatlas_output")
    out.mkdir(parents=True, exist_ok=True)
    return out


def _print_collect_summary(summary: CollectionSummary) -> None:
    """Render the dataset collection summary."""
    table = Table(show_header=False, border_style="cyan", padding=(0, 2))
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Total PE files discovered", f"{summary.processed:,}")
    table.add_row("Successfully collected", f"{summary.successful:,}")
    table.add_row("Failed", f"{summary.failed:,}")
    table.add_row("Skipped", f"{summary.skipped:,}")
    table.add_section()
    table.add_row("Elapsed time", f"{summary.elapsed_seconds:.2f}s")
    table.add_row("Experiment root", str(summary.experiment_root))

    console.print()
    console.print(
        Panel(
            table,
            title="[bold cyan]Dataset Collection Summary[/bold cyan]",
            border_style="cyan",
        )
    )
    console.print()


# ── commands ───────────────────────────────────────────────────────────


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-V",
            help="Enable verbose / debug logging.",
        ),
    ] = False,
) -> None:
    """DefenderAtlas: Analyze Microsoft Defender file scanning behavior."""
    setup_logging(verbose=verbose)
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@app.command()
def version() -> None:
    """Show the DefenderAtlas version."""
    text = Text.assemble(
        ("defenderatlas ", "bold"),
        (__version__, "bold green"),
    )
    console.print(text)


@app.command()
def install(
    procmon: Annotated[
        Path | None,
        typer.Option(
            "--procmon",
            help="Path to Procmon64.exe (auto-detected when omitted).",
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
    task_name: Annotated[
        str,
        typer.Option(
            "--task-name",
            help="Name of the scheduled task to create.",
        ),
    ] = DEFAULT_TASK_NAME,
) -> None:
    """Create the scheduled task that launches ProcMon elevated (no UAC)."""
    try:
        resolved = procmon or find_procmon()
        if resolved is None:
            error_console.print(
                Panel(
                    "[bold red]ProcMon executable not found.[/bold red]\n\n"
                    "Pass --procmon <path> or set DEFENDERATLAS_PROCMON.",
                    border_style="red",
                    title="DefenderAtlas",
                )
            )
            raise typer.Exit(code=1)

        if task_exists(task_name):
            console.print(
                f"[yellow]Scheduled task {task_name!r} already exists; "
                "updating it.[/yellow]"
            )
        if not install_procmon_task(task_name, resolved):
            _handle_error(RuntimeError("Failed to create the scheduled task."))
        console.print(
            Panel(
                f"[bold]Task name:[/bold] {task_name}\n"
                f"[bold]Executable:[/bold] {resolved}\n"
                "[dim]Run level: Highest privileges[/dim]",
                title="[bold green]Installed[/bold green]",
                border_style="green",
            )
        )
        console.print(
            "[green]ProcMon will now start elevated without a UAC prompt. "
            "Use 'defenderatlas collect --procmon-launch-method task'.[/green]"
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _handle_error(exc)


@app.command()
def uninstall(
    task_name: Annotated[
        str,
        typer.Option(
            "--task-name",
            help="Name of the scheduled task to remove.",
        ),
    ] = DEFAULT_TASK_NAME,
) -> None:
    """Remove the scheduled task used to launch ProcMon elevated."""
    try:
        if not task_exists(task_name):
            error_console.print(
                Panel(
                    f"[bold red]Scheduled task {task_name!r} does not exist.[/bold red]",
                    border_style="red",
                    title="DefenderAtlas",
                )
            )
            raise typer.Exit(code=1)
        if not uninstall_procmon_task(task_name):
            _handle_error(RuntimeError("Failed to remove the scheduled task."))
        console.print(
            Panel(
                f"[bold]Task name:[/bold] {task_name}",
                title="[bold yellow]Uninstalled[/bold yellow]",
                border_style="yellow",
            )
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _handle_error(exc)


@app.command()
def analyze(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to a ProcMon CSV file to analyze.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Analyze a ProcMon CSV trace file's Defender scanning behavior."""
    try:
        start_time = time.perf_counter()

        with console.status("[bold blue]Parsing CSV...[/bold blue]"):
            events = list(parse_procmon_csv(file))

        parse_time = time.perf_counter()

    except (CSVFormatError, HeaderError) as exc:
        error_console.print(
            Panel(
                f"[bold red]CSV Format Error:[/bold red] {exc}\n\n"
                "Please ensure the file is a valid ProcMon CSV export with "
                "the required headers:\n"
                "Time of Day, Process Name, PID, Operation, Path, Result, Detail",
                border_style="red",
                title="DefenderAtlas",
            )
        )
        log.debug("Traceback:", exc_info=True)
        raise typer.Exit(code=1) from None
    except ParserError as exc:
        error_console.print(
            Panel(
                f"[bold red]Parser Error:[/bold red] {exc}",
                border_style="red",
                title="DefenderAtlas",
            )
        )
        log.debug("Traceback:", exc_info=True)
        raise typer.Exit(code=1) from None
    except Exception as exc:
        _handle_error(exc)

    if not events:
        console.print(
            Panel(
                "[yellow]No read events found in the CSV file.[/yellow]\n\n"
                "This could mean:\n"
                "• The file contains no ReadFile/IRP_MJ_READ/FastIORead operations\n"
                "• The CSV format is not recognized as a ProcMon export",
                title="[bold yellow]Empty Trace[/bold yellow]",
                border_style="yellow",
            )
        )
        return

    try:
        with console.status("[bold blue]Computing statistics...[/bold blue]"):
            stats = compute_statistics(events)

        compute_time = time.perf_counter()
        total_time = compute_time - start_time

        table = Table(
            title="Statistics Summary",
            show_header=False,
            border_style="blue",
            padding=(0, 2),
        )
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Total Reads", f"{stats.total_reads:,}")
        table.add_row("Unique Offsets", f"{stats.unique_offsets:,}")
        table.add_row("Repeated Reads", f"{stats.repeated_reads:,}")
        table.add_row("Bytes Read", f"{stats.bytes_read:,}")
        table.add_section()
        table.add_row(
            "Read Amplification",
            (
                f"{stats.read_amplification:.2f}x"
                if stats.read_amplification > 0
                else "N/A (no file size)"
            ),
        )

        table.add_section()
        table.add_row(
            "Processing Time",
            f"{total_time:.3f}s "
            f"(parse: {parse_time - start_time:.3f}s, "
            f"compute: {compute_time - parse_time:.3f}s)",
        )

        console.print()
        console.print(
            Panel(
                table,
                title="[bold blue]Analyze[/bold blue]",
                subtitle=f"[dim]{file.name}[/dim]",
                border_style="blue",
            )
        )
        console.print()

    except Exception as exc:
        _handle_error(exc)


@app.command()
def capture(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to the file to scan (triggers capture).",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    output_dir: Annotated[
        str | None,
        typer.Option(
            "--output-dir",
            "-o",
            help="Directory for capture output.",
        ),
    ] = None,
    duration: Annotated[
        int,
        typer.Option(
            "--duration",
            "-d",
            help="Capture duration in seconds.",
            min=1,
            max=300,
        ),
    ] = 30,
) -> None:
    """Capture ProcMon / ETW events while Defender scans a file."""
    try:
        out = _resolve_output_dir(output_dir)
        console.print(
            Panel(
                f"[bold]File:[/bold]       {file}\n"
                f"[bold]Output:[/bold]     {out}\n"
                f"[bold]Duration:[/bold]   {duration}s",
                title="[bold cyan]Capture[/bold cyan]",
                border_style="cyan",
            )
        )
        log.info("Starting capture for %s ...", file)
        log.warning("Capture engine not yet implemented - placeholder only.")
        console.print("[green]Capture complete.[/green] (placeholder)")
    except Exception as exc:
        _handle_error(exc)


@app.command()
def collect(
    dataset_directory: Annotated[
        Path,
        typer.Argument(
            help=(
                "Directory tree containing *.exe, *.dll and *.sys samples to collect."
            ),
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ],
    experiment_root: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Root directory for generated experiments.",
            file_okay=False,
            dir_okay=True,
        ),
    ] = Path("experiments"),
    working_directory: Annotated[
        Path | None,
        typer.Option(
            "--working-directory",
            help="Directory where triggered samples are placed.",
            file_okay=False,
            dir_okay=True,
        ),
    ] = None,
    procmon_path: Annotated[
        Path | None,
        typer.Option(
            "--procmon",
            help="Path to Procmon64.exe (auto-detected when omitted).",
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
    trigger_worker: Annotated[
        Path | None,
        typer.Option(
            "--trigger-worker",
            help="Path to trigger_worker.exe (auto-detected when omitted).",
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
    source_url: Annotated[
        str,
        typer.Option(
            "--source-url",
            help="URL reported as the download origin.",
        ),
    ] = DEFAULT_SOURCE_URL,
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            help="ProcMon filter profile: minimal, extended or full.",
        ),
    ] = "minimal",
    completion_strategy: Annotated[
        str,
        typer.Option(
            "--completion-strategy",
            help="Scan-completion strategy: timeout.",
        ),
    ] = "timeout",
    trigger_timeout: Annotated[
        int,
        typer.Option(
            "--trigger-timeout",
            help="Completion wait in milliseconds.",
            min=1,
        ),
    ] = 8000,
    worker_timeout: Annotated[
        int,
        typer.Option(
            "--worker-timeout",
            help="Trigger worker timeout in milliseconds.",
            min=1,
        ),
    ] = 30000,
    procmon_ready_timeout: Annotated[
        int,
        typer.Option(
            "--procmon-ready-timeout",
            help="Max wait for ProcMon readiness in milliseconds.",
            min=1,
        ),
    ] = 15000,
    procmon_stop_timeout: Annotated[
        int,
        typer.Option(
            "--procmon-stop-timeout",
            help="Max wait for ProcMon shutdown in milliseconds.",
            min=1,
        ),
    ] = 15000,
    procmon_export_timeout: Annotated[
        int,
        typer.Option(
            "--procmon-export-timeout",
            help="Max wait for PML→CSV export in milliseconds.",
            min=1,
        ),
    ] = 120000,
    procmon_launch_method: Annotated[
        str,
        typer.Option(
            "--procmon-launch-method",
            help=(
                "How ProcMon is started: 'auto' (direct launch when elevated, "
                "elevated scheduled task otherwise), 'process' (same as "
                "'auto'), or 'task' (always via the scheduled task)."
            ),
        ),
    ] = "auto",
    scheduled_task_name: Annotated[
        str,
        typer.Option(
            "--scheduled-task-name",
            help=(
                "Scheduled task used when --procmon-launch-method is 'task' "
                "or when the Collector is not elevated."
            ),
        ),
    ] = DEFAULT_TASK_NAME,
) -> None:
    """Collect a Defender scan experiment for every supported PE sample."""
    try:
        if completion_strategy != "timeout":
            log.warning(
                "Unknown completion strategy %r; using 'timeout'",
                completion_strategy,
            )

        resolved_procmon = procmon_path or find_procmon()
        resolved_worker = trigger_worker or find_trigger_worker()
        if resolved_procmon is None:
            log.warning("ProcMon executable not found; capture steps will fail.")
        else:
            log.info("Using ProcMon: %s", resolved_procmon)
        if resolved_worker is None:
            log.warning("Trigger worker not found; trigger steps will fail.")
        else:
            log.info("Using trigger worker: %s", resolved_worker)

        config = CollectorConfig(
            dataset_root=dataset_directory,
            experiment_root=experiment_root,
            working_directory=working_directory or Path.home() / "Downloads",
            procmon_path=resolved_procmon,
            trigger_worker_path=resolved_worker,
            source_url=source_url,
            trigger_timeout_ms=trigger_timeout,
            trigger_worker_timeout_ms=worker_timeout,
            completion_strategy=completion_strategy,
            procmon_profile=profile,
            procmon_ready_timeout_ms=procmon_ready_timeout,
            procmon_stop_timeout_ms=procmon_stop_timeout,
            procmon_export_timeout_ms=procmon_export_timeout,
            procmon_launch_method=procmon_launch_method,
            scheduled_task_name=scheduled_task_name,
        )

        summary = Collector(config).run()
        _print_collect_summary(summary)
    except Exception as exc:
        _handle_error(exc)


@app.command()
def visualize(
    source: Annotated[
        Path,
        typer.Argument(
            help="Path to analysis data (JSON or CSV).",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    output_dir: Annotated[
        str | None,
        typer.Option(
            "--output-dir",
            "-o",
            help="Directory for generated charts.",
        ),
    ] = None,
) -> None:
    """Generate visualizations from analysis data."""
    try:
        out = _resolve_output_dir(output_dir)
        console.print(
            Panel(
                f"[bold]Input:[/bold]      {source}\n[bold]Output:[/bold]     {out}",
                title="[bold magenta]Visualize[/bold magenta]",
                border_style="magenta",
            )
        )
        log.info("Generating visualizations for %s ...", source)
        log.warning("Visualization engine not yet implemented - placeholder only.")
        console.print("[green]Visualization complete.[/green] (placeholder)")
    except Exception as exc:
        _handle_error(exc)


@app.command()
def report(
    source: Annotated[
        Path,
        typer.Argument(
            help="Path to analysis data (JSON or CSV).",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    output_dir: Annotated[
        str | None,
        typer.Option(
            "--output-dir",
            "-o",
            help="Directory for generated reports.",
        ),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Report format (html, markdown, json).",
        ),
    ] = "markdown",
) -> None:
    """Generate a report from analysis data."""
    try:
        out = _resolve_output_dir(output_dir)
        console.print(
            Panel(
                f"[bold]Input:[/bold]      {source}\n"
                f"[bold]Output:[/bold]     {out}\n"
                f"[bold]Format:[/bold]     {fmt}",
                title="[bold yellow]Report[/bold yellow]",
                border_style="yellow",
            )
        )
        log.info("Generating report for %s ...", source)
        log.warning("Report engine not yet implemented - placeholder only.")
        console.print("[green]Report complete.[/green] (placeholder)")
    except Exception as exc:
        _handle_error(exc)
