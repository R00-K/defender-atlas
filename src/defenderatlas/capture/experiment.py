"""Experiment directory management for the Collector.

Each sample collection run produces one experiment directory::

    experiments/
        000001/
            sample.exe
            capture.pml
            capture.csv
            filtered.csv
            metadata.json
            manifest.json
            trigger.json
        000002/
            ...

Experiment IDs auto-increment and are never reused: ID allocation scans the
experiment root for the highest existing numeric directory and returns the
next value, so existing experiments are never overwritten.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

ID_WIDTH = 6


class ExperimentError(Exception):
    """Raised when an experiment directory cannot be allocated."""


class ExperimentDirectory:
    """A single, freshly allocated experiment directory."""

    def __init__(self, experiment_root: Path) -> None:
        self.root = experiment_root
        self.id = self.next_id(experiment_root)
        self.path = experiment_root / f"{self.id:0{ID_WIDTH}d}"
        try:
            self.path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ExperimentError(
                f"Cannot create experiment directory {self.path}: {exc}"
            ) from exc

    @staticmethod
    def next_id(experiment_root: Path) -> int:
        """Return the next free experiment ID (max numeric directory + 1)."""
        highest = 0
        if experiment_root.is_dir():
            for entry in experiment_root.iterdir():
                if entry.is_dir() and entry.name.isdigit():
                    highest = max(highest, int(entry.name))
        return highest + 1

    @property
    def sample_path(self) -> Path:
        return self.path / "sample.exe"

    @property
    def pml_path(self) -> Path:
        return self.path / "capture.pml"

    @property
    def csv_path(self) -> Path:
        return self.path / "capture.csv"

    @property
    def filtered_csv_path(self) -> Path:
        return self.path / "filtered.csv"

    @property
    def metadata_path(self) -> Path:
        return self.path / "metadata.json"

    @property
    def manifest_path(self) -> Path:
        return self.path / "manifest.json"

    @property
    def trigger_info_path(self) -> Path:
        return self.path / "trigger.json"
