"""Unit tests for the dynamic ProcMon filter and CSV filtering."""

from __future__ import annotations

import csv
from typing import TYPE_CHECKING

import pytest

from defenderatlas.capture.filter import (
    DEFENDER_PROCESS,
    VALID_PROFILES,
    CsvFilterStats,
    FilterError,
    ProcmonFilter,
)

if TYPE_CHECKING:
    from pathlib import Path

HEADER = "Time of Day,Process Name,PID,Operation,Path,Result,Detail"


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER.split(","))
        writer.writerows(rows)


def _read_rows(path: Path) -> list[list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.reader(handle))


def test_supported_profiles() -> None:
    assert set(VALID_PROFILES) == {"minimal", "extended", "full"}


def test_matches_defender_only_case_insensitive(tmp_path: Path) -> None:
    filt = ProcmonFilter("minimal", "sample.exe")
    assert filt.matches(DEFENDER_PROCESS, "CreateFile", "C:\\exp\\sample.exe")
    assert filt.matches("MsMpEng.exe", "CreateFile", "C:\\exp\\sample.exe")
    assert not filt.matches("notepad.exe", "CreateFile", "C:\\exp\\sample.exe")
    assert not filt.matches(DEFENDER_PROCESS, "CreateFile", "C:\\other\\file.exe")


def test_matches_dynamic_sample_path(tmp_path: Path) -> None:
    filt = ProcmonFilter("minimal", "sample.exe")
    assert filt.matches(DEFENDER_PROCESS, "CreateFile", "C:\\Downloads\\sample.exe")
    assert not filt.matches(DEFENDER_PROCESS, "CreateFile", "C:\\Downloads\\other.exe")


def test_operation_profile_is_respected(tmp_path: Path) -> None:
    filt = ProcmonFilter("minimal", "sample.exe")
    assert filt.matches(DEFENDER_PROCESS, "ReadFile", "C:\\sample.exe")
    assert not filt.matches(DEFENDER_PROCESS, "WriteFile", "C:\\sample.exe")


def test_full_profile_matches_any_operation(tmp_path: Path) -> None:
    filt = ProcmonFilter("full", "sample.exe")
    assert filt.matches(DEFENDER_PROCESS, "WriteFile", "C:\\sample.exe")
    assert filt.matches(DEFENDER_PROCESS, "ReadFile", "C:\\sample.exe")


def test_filter_csv_writes_only_matching_rows(tmp_path: Path) -> None:
    source = tmp_path / "capture.csv"
    dest = tmp_path / "filtered.csv"
    _write_csv(
        source,
        [
            [
                "12:00:00.0000000",
                DEFENDER_PROCESS,
                "123",
                "CreateFile",
                "C:\\exp\\sample.exe",
                "SUCCESS",
                "Read",
            ],
            [
                "12:00:00.0010000",
                "notepad.exe",
                "9",
                "ReadFile",
                "C:\\exp\\sample.exe",
                "SUCCESS",
                "Offset: 0x0",
            ],
        ],
    )

    filt = ProcmonFilter("minimal", "sample.exe")
    stats = filt.filter_csv(source, dest)

    assert isinstance(stats, CsvFilterStats)
    assert stats.input_rows == 2
    assert stats.output_rows == 1
    rows = _read_rows(dest)
    assert len(rows) == 2  # header + one kept row
    assert rows[1][1] == DEFENDER_PROCESS


def test_filter_csv_missing_source_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        ProcmonFilter("minimal", "sample.exe").filter_csv(
            tmp_path / "missing.csv", tmp_path / "filtered.csv"
        )


def test_filter_csv_missing_header_raises(tmp_path: Path) -> None:
    source = tmp_path / "capture.csv"
    source.write_text("Col1,Col2,Col3\na,b,c\n", encoding="utf-8")
    with pytest.raises(FilterError):
        ProcmonFilter("minimal", "sample.exe").filter_csv(
            source, tmp_path / "filtered.csv"
        )


def test_unknown_profile_falls_back_to_minimal(tmp_path: Path) -> None:
    filt = ProcmonFilter("bogus", "sample.exe")
    assert filt.profile == "minimal"
    assert filt.matches(DEFENDER_PROCESS, "CreateFile", "C:\\sample.exe")
    assert not filt.matches(DEFENDER_PROCESS, "WriteFile", "C:\\sample.exe")
