"""Logging configuration for DefenderAtlas CLI."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(*, verbose: bool = False) -> None:
    """Configure the root logger with a Rich handler.

    Parameters
    ----------
    verbose:
        When *True* the log level is set to ``DEBUG``; otherwise ``INFO``.
    """
    level = logging.DEBUG if verbose else logging.INFO

    handler = RichHandler(
        console=Console(stderr=True),
        show_path=False,
        show_time=True,
        rich_tracebacks=True,
    )
    handler.setLevel(level)

    formatter = logging.Formatter("%(message)s", datefmt="[%X]")
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)

    # Remove any pre-existing handlers so we don't double-print.
    for h in root.handlers[:]:
        root.removeHandler(h)
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger."""
    return logging.getLogger(name)
