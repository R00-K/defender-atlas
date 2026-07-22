"""CLI application for DefenderAtlas."""

import typer
from rich.console import Console

from defenderatlas import __version__

app = typer.Typer(
    name="defenderatlas",
    help="DefenderAtlas - Microsoft Defender scanning behavior analysis framework.",
    add_completion=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version and exit."
    ),
) -> None:
    """DefenderAtlas: Analyze Microsoft Defender file scanning behavior."""
    if version:
        console.print(f"defenderatlas [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.command()
def info() -> None:
    """Show project information."""
    console.print("[bold]DefenderAtlas[/bold]")
    console.print(f"Version: {__version__}")
    console.print("Framework for analyzing Microsoft Defender file scanning behavior.")
