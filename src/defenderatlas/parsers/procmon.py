"""Streaming parser for ProcMon exported CSV files.

Converts ProcMon CSV rows into :class:`ReadEvent` models, streaming
one event at a time to keep memory usage constant regardless of file
size.
"""

from __future__ import annotations

import contextlib
import csv
import logging
import re
from collections.abc import Iterator  # noqa: TC003 - used at runtime
from datetime import datetime
from pathlib import Path
from typing import IO

from defenderatlas.models.core import ReadEvent
from defenderatlas.parsers.errors import (
    CSVFormatError,
    HeaderError,
    LengthParseError,
    OffsetParseError,
    RowError,
    TimestampParseError,
)

log = logging.getLogger(__name__)

# Operations we care about (read-oriented).
_READ_OPS: frozenset[str] = frozenset(
    {
        "ReadFile",
        "IRP_MJ_READ",
        "FastIORead",
    }
)

# Expected column names (ProcMon default CSV headers).
_REQUIRED_HEADERS: frozenset[str] = frozenset(
    {
        "Time of Day",
        "Process Name",
        "PID",
        "Operation",
        "Path",
        "Result",
        "Detail",
    }
)

# Patterns for extracting Offset and Length from the Detail column.
# Uses \w+ to capture the full value (hex or decimal) for later validation.
_OFFSET_RE = re.compile(r"Offset:\s*(0x\w+|\d[\d,]*)", re.IGNORECASE)
_LENGTH_RE = re.compile(r"Length:\s*(0x\w+|\d[\d,]*)", re.IGNORECASE)

# ProcMon timestamp format: HH:MM:SS.fffffff (7 digits, truncate to 6)
_TIME_FMT = "%H:%M:%S.%f"
_MAX_FRAC_DIGITS = 6


# ── helpers ────────────────────────────────────────────────────────────


def _strip_commas(value: str) -> str:
    """Remove thousands-separator commas from a numeric string."""
    return value.replace(",", "")


def _parse_hex_or_dec(value: str) -> int:
    """Parse a string as hex (0x...) or decimal.

    Raises
    ------
    ValueError
        If the value cannot be parsed as an integer.
    """
    cleaned = _strip_commas(value)
    if cleaned.lower().startswith("0x"):
        return int(cleaned, 16)
    return int(cleaned)


def _parse_timestamp(raw: str, line_number: int) -> datetime:
    """Parse a ProcMon timestamp string into a datetime.

    ProcMon exports 7-digit fractional seconds; we truncate to 6
    (Python's ``%f`` limit).

    Raises
    ------
    TimestampParseError
        If the string cannot be parsed.
    """
    cleaned = raw.strip()
    # Handle 7+ digit fractional seconds by truncating to 6.
    dot_idx = cleaned.rfind(".")
    if dot_idx != -1:
        frac = cleaned[dot_idx + 1 :]
        if len(frac) > _MAX_FRAC_DIGITS:
            cleaned = cleaned[: dot_idx + 1] + frac[:_MAX_FRAC_DIGITS]

    try:
        return datetime.strptime(cleaned, _TIME_FMT)
    except ValueError as exc:
        raise TimestampParseError(
            line_number=line_number,
            raw=raw,
            reason=f"Cannot parse timestamp: {raw!r}",
        ) from exc


def _parse_detail(detail: str, line_number: int) -> tuple[int, int]:
    """Extract (offset, length) from a ProcMon Detail column.

    Raises
    ------
    OffsetParseError
        If the offset cannot be found or parsed.
    LengthParseError
        If the length cannot be found or parsed.
    """
    off_match = _OFFSET_RE.search(detail)
    if off_match is None:
        raise OffsetParseError(
            line_number=line_number,
            raw=detail,
            reason=f"No 'Offset:' found in detail: {detail!r}",
        )

    len_match = _LENGTH_RE.search(detail)
    if len_match is None:
        raise LengthParseError(
            line_number=line_number,
            raw=detail,
            reason=f"No 'Length:' found in detail: {detail!r}",
        )

    try:
        offset = _parse_hex_or_dec(off_match.group(1))
    except ValueError as exc:
        raise OffsetParseError(
            line_number=line_number,
            raw=detail,
            reason=f"Bad offset value: {off_match.group(1)!r}",
        ) from exc

    try:
        length = _parse_hex_or_dec(len_match.group(1))
    except ValueError as exc:
        raise LengthParseError(
            line_number=line_number,
            raw=detail,
            reason=f"Bad length value: {len_match.group(1)!r}",
        ) from exc

    return offset, length


def _build_read_event(
    *,
    timestamp: datetime,
    process_name: str,
    process_id: int,
    operation: str,
    path: str,
    result: str,
    offset: int,
    length: int,
) -> ReadEvent:
    """Construct a validated ReadEvent."""
    return ReadEvent(
        timestamp=timestamp,
        process_name=process_name,
        process_id=process_id,
        operation=operation,
        path=path,
        result=result,
        offset=offset,
        length=length,
    )


# ── public API ─────────────────────────────────────────────────────────


def parse_procmon_csv(
    source: str | Path | IO[str],
    *,
    skip_errors: bool = True,
) -> Iterator[ReadEvent]:
    """Stream ReadEvent objects from a ProcMon CSV export.

    Parameters
    ----------
    source:
        File path or an already-open text stream.
    skip_errors:
        When *True* (the default), malformed rows are logged and
        skipped.  When *False*, a :class:`RowError` is raised on
        the first bad row.

    Yields
    ------
    ReadEvent
        One event per read operation found in the CSV.

    Raises
    ------
    CSVFormatError
        If the file cannot be opened or is completely empty.
    HeaderError
        If required ProcMon headers are missing.
    RowError
        If *skip_errors* is ``False`` and a row fails to parse.
    """
    opened_here = False
    fh: IO[str]

    if isinstance(source, (str, Path)):
        try:
            fh = open(source, newline="", encoding="utf-8-sig")  # noqa: SIM115
            opened_here = True
        except OSError as exc:
            raise CSVFormatError(f"Cannot open file: {exc}") from exc
    else:
        fh = source

    try:
        # Strip BOM from StringIO streams (utf-8-sig only works on files).
        first_char = fh.read(1)
        if first_char != "\ufeff":
            # Not a BOM - rewind so csv.DictReader sees the full header.
            with contextlib.suppress(OSError):
                fh.seek(0)

        reader = csv.DictReader(fh)

        if reader.fieldnames is None:
            raise CSVFormatError("CSV file is empty or has no header row.")

        missing = _REQUIRED_HEADERS - set(reader.fieldnames)
        if missing:
            raise HeaderError(f"Missing required headers: {', '.join(sorted(missing))}")

        for line_number, row in enumerate(reader, start=2):
            try:
                operation = (row.get("Operation") or "").strip()
                if operation not in _READ_OPS:
                    continue

                timestamp = _parse_timestamp(row.get("Time of Day") or "", line_number)
                process_name = (row.get("Process Name") or "").strip()
                process_id_str = (row.get("PID") or "0").strip()
                path = (row.get("Path") or "").strip()
                result = (row.get("Result") or "").strip()
                detail = row.get("Detail") or ""

                if not process_name or not path or not result:
                    raise RowError(
                        line_number=line_number,
                        raw=str(row),
                        reason="Empty process name, path, or result.",
                    )

                try:
                    pid = int(process_id_str)
                except ValueError as exc:
                    raise RowError(
                        line_number=line_number,
                        raw=str(row),
                        reason=f"Invalid PID: {process_id_str!r}",
                    ) from exc

                offset, length = _parse_detail(detail, line_number)

                yield _build_read_event(
                    timestamp=timestamp,
                    process_name=process_name,
                    process_id=pid,
                    operation=operation,
                    path=path,
                    result=result,
                    offset=offset,
                    length=length,
                )

            except RowError as exc:
                if skip_errors:
                    log.warning("Skipping row %d: %s", exc.line_number, exc.reason)
                    continue
                raise

    finally:
        if opened_here:
            fh.close()
