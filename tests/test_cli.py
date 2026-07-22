"""Smoke tests for package initialization and CLI."""

from typer.testing import CliRunner

from defenderatlas import __version__
from defenderatlas.cli.app import app

runner = CliRunner()


def test_version_import() -> None:
    assert __version__ == "0.1.0"


def test_cli_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_info_command() -> None:
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "DefenderAtlas" in result.output
