"""ProcMon filter profiles and CSV filtering for the Collector.

The Collector derives a per-experiment filter from the sample's file name
(the dynamic path condition) plus a fixed Defender process rule and the
selected operation profile. The same filter is applied to the raw
``capture.csv`` export to produce ``filtered.csv``.
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)

DEFENDER_PROCESS = "msmpeng.exe"

VALID_PROFILES: tuple[str, ...] = ("minimal", "extended", "full")

_PROFILE_OPERATIONS: dict[str, frozenset[str]] = {
    "minimal": frozenset({"createfile", "readfile"}),
    "extended": frozenset(
        {
            "createfile",
            "readfile",
            "queryinformationfile",
            "querystandardinformationfile",
            "closefile",
        }
    ),
    "full": frozenset(),
}


class FilterError(Exception):
    """Raised when a ProcMon CSV cannot be filtered."""


@dataclass(frozen=True)
class CsvFilterStats:
    """Row counts produced by a CSV filtering pass."""

    input_rows: int
    output_rows: int


@dataclass(frozen=True)
class ProcmonFilter:
    """Per-experiment ProcMon filter rules.

    The path condition is generated from the sample's original file name so it
    always matches the events Defender generates for that sample.
    """

    profile: str
    sample_filename: str

    def __post_init__(self) -> None:
        profile = self.profile.lower()
        if profile not in VALID_PROFILES:
            log.warning("Unknown profile %r; falling back to 'minimal'", self.profile)
            profile = "minimal"
        object.__setattr__(self, "profile", profile)
        object.__setattr__(self, "sample_filename", self.sample_filename.lower())

    @property
    def operations(self) -> frozenset[str]:
        """The operations kept by this profile (empty = keep all)."""
        return _PROFILE_OPERATIONS[self.profile]

    def matches(self, process_name: str, operation: str, path: str) -> bool:
        """Return True when a row satisfies the filter rules."""
        if process_name.strip().lower() != DEFENDER_PROCESS:
            return False
        if self.sample_filename and self.sample_filename not in path.lower():
            return False
        operations = self.operations
        if not operations:
            return True
        return operation.strip().lower() in operations

    def filter_csv(self, input_path: Path, output_path: Path) -> CsvFilterStats:
        """Write the rows of *input_path* matching this filter to *output_path*."""
        with input_path.open("r", newline="", encoding="utf-8-sig") as src:
            reader = csv.reader(src)
            header = next(reader, None)
            if header is None:
                raise FilterError(f"Cannot filter empty CSV: {input_path}")

            process_column = _find_column(header, "Process Name")
            operation_column = _find_column(header, "Operation")
            path_column = _find_column(header, "Path")
            if process_column < 0 or operation_column < 0 or path_column < 0:
                raise FilterError(f"Unrecognized ProcMon CSV header in {input_path}")

            with output_path.open("w", newline="", encoding="utf-8-sig") as dst:
                writer = csv.writer(dst)
                writer.writerow(header)

                input_rows = 0
                output_rows = 0
                for row in reader:
                    if not any(field.strip() for field in row):
                        continue
                    if len(row) <= max(process_column, operation_column, path_column):
                        continue
                    input_rows += 1
                    if self.matches(
                        row[process_column], row[operation_column], row[path_column]
                    ):
                        writer.writerow(row)
                        output_rows += 1

        return CsvFilterStats(input_rows=input_rows, output_rows=output_rows)


def _find_column(header: list[str], name: str) -> int:
    expected = name.lower()
    for index, value in enumerate(header):
        if value.strip().lower() == expected:
            return index
    return -1
