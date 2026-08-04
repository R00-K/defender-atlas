"""Unit tests for the ProcMon CSV parser."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest

from defenderatlas.models.core import ReadEvent
from defenderatlas.parsers.errors import (
    CSVFormatError,
    HeaderError,
    LengthParseError,
    OffsetParseError,
    RowError,
    TimestampParseError,
)
from defenderatlas.parsers.procmon import (
    _parse_detail,
    _parse_hex_or_dec,
    _parse_timestamp,
    parse_procmon_csv,
)

# ── sample data ────────────────────────────────────────────────────────
# Detail column is quoted because it may contain commas (e.g. 4,096).

_HEADER = "Time of Day,Process Name,PID,Operation,Path,Result,Detail\n"

_VALID_ROW = (
    "10:30:45.1234567,MsMpEng.exe,1234,ReadFile,"
    "C:\\Windows\\System32\\test.dll,SUCCESS,"
    '"Offset: 0x0, Length: 4,096"\n'
)

_VALID_ROW_HEX_LENGTH = (
    "10:30:45.1234567,MsMpEng.exe,1234,ReadFile,"
    "C:\\Windows\\System32\\test.dll,SUCCESS,"
    '"Offset: 0x100, Length: 0x1000"\n'
)

_VALID_ROW_DECIMAL = (
    "10:30:45.1234567,MsMpEng.exe,1234,ReadFile,"
    "C:\\Windows\\System32\\test.dll,SUCCESS,"
    '"Offset: 0, Length: 4096"\n'
)

_NON_READ_ROW = (
    "10:30:45.1234567,MsMpEng.exe,1234,QueryDirectory,"
    'C:\\Windows\\System32,SUCCESS,"Pattern: *.*"\n'
)

_BAD_TIMESTAMP_ROW = (
    "not-a-timestamp,MsMpEng.exe,1234,ReadFile,"
    'C:\\test.dll,SUCCESS,"Offset: 0x0, Length: 0x100"\n'
)

_BAD_PID_ROW = (
    "10:30:45.1234567,MsMpEng.exe,not-a-pid,ReadFile,"
    'C:\\test.dll,SUCCESS,"Offset: 0x0, Length: 0x100"\n'
)

_MISSING_OFFSET_DETAIL = (
    '10:30:45.1234567,MsMpEng.exe,1234,ReadFile,C:\\test.dll,SUCCESS,"Length: 0x100"\n'
)

_MISSING_LENGTH_DETAIL = (
    '10:30:45.1234567,MsMpEng.exe,1234,ReadFile,C:\\test.dll,SUCCESS,"Offset: 0x0"\n'
)

_EMPTY_PATH_ROW = (
    '10:30:45.1234567,MsMpEng.exe,1234,ReadFile,,SUCCESS,"Offset: 0x0, Length: 0x100"\n'
)


def _csv(*rows: str) -> str:
    """Build a CSV string from the header and zero or more data rows."""
    return _HEADER + "".join(rows)


# ── helper function tests ──────────────────────────────────────────────


class TestParseHexOrDec:
    def test_hex(self) -> None:
        assert _parse_hex_or_dec("0x1A2B") == 0x1A2B

    def test_hex_uppercase(self) -> None:
        assert _parse_hex_or_dec("0xFF") == 255

    def test_decimal(self) -> None:
        assert _parse_hex_or_dec("4096") == 4096

    def test_decimal_with_commas(self) -> None:
        assert _parse_hex_or_dec("1,024") == 1024

    def test_zero(self) -> None:
        assert _parse_hex_or_dec("0x0") == 0

    def test_zero_decimal(self) -> None:
        assert _parse_hex_or_dec("0") == 0


class TestParseTimestamp:
    def test_valid_timestamp(self) -> None:
        ts = _parse_timestamp("10:30:45.1234567", 1)
        assert ts.hour == 10
        assert ts.minute == 30
        assert ts.second == 45

    def test_six_digit_timestamp(self) -> None:
        ts = _parse_timestamp("10:30:45.123456", 1)
        assert ts.microsecond == 123456

    def test_invalid_timestamp_raises(self) -> None:
        with pytest.raises(TimestampParseError, match="Cannot parse"):
            _parse_timestamp("not-a-time", 1)

    def test_pm_suffix_shifts_hour(self) -> None:
        ts = _parse_timestamp("11:38:55.7784472 PM", 1)
        assert ts.hour == 23
        assert ts.minute == 38
        assert ts.second == 55

    def test_am_suffix_no_shift(self) -> None:
        ts = _parse_timestamp("11:38:55.7784472 AM", 1)
        assert ts.hour == 11

    def test_am_suffix_midnight(self) -> None:
        ts = _parse_timestamp("12:00:08.2222162 AM", 1)
        assert ts.hour == 0
        assert ts.minute == 0

    def test_pm_suffix_noon(self) -> None:
        ts = _parse_timestamp("12:00:08.2222162 PM", 1)
        assert ts.hour == 12

    def test_am_pm_ordering_correct(self) -> None:
        am = _parse_timestamp("11:59:59.0000001 AM", 1)
        pm = _parse_timestamp("12:00:00.0000001 PM", 1)
        assert am < pm

    def test_error_contains_line_number(self) -> None:
        with pytest.raises(TimestampParseError) as exc_info:
            _parse_timestamp("bad", 42)
        assert exc_info.value.line_number == 42

    def test_error_contains_raw_value(self) -> None:
        with pytest.raises(TimestampParseError) as exc_info:
            _parse_timestamp("bad", 1)
        assert exc_info.value.raw == "bad"


class TestParseDetail:
    def test_hex_offset_and_length(self) -> None:
        offset, length = _parse_detail("Offset: 0x100, Length: 0x200", 1)
        assert offset == 0x100
        assert length == 0x200

    def test_decimal_offset_and_length(self) -> None:
        offset, length = _parse_detail("Offset: 0, Length: 4096", 1)
        assert offset == 0
        assert length == 4096

    def test_comma_separated_length(self) -> None:
        offset, length = _parse_detail("Offset: 0x0, Length: 4,096", 1)
        assert offset == 0
        assert length == 4096

    def test_missing_offset_raises(self) -> None:
        with pytest.raises(OffsetParseError):
            _parse_detail("Length: 0x100", 1)

    def test_missing_length_raises(self) -> None:
        with pytest.raises(LengthParseError):
            _parse_detail("Offset: 0x0", 1)

    def test_bad_offset_value_raises(self) -> None:
        with pytest.raises(OffsetParseError, match="Bad offset"):
            _parse_detail("Offset: 0xZZZZ, Length: 0x100", 1)

    def test_bad_length_value_raises(self) -> None:
        with pytest.raises(LengthParseError, match="Bad length"):
            _parse_detail("Offset: 0x0, Length: 0xZZZZ", 1)


# ── streaming parser tests ─────────────────────────────────────────────


class TestParseProcMonCSV:
    def test_valid_single_row(self) -> None:
        csv_data = _csv(_VALID_ROW)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert len(events) == 1
        ev = events[0]
        assert ev.process_name == "MsMpEng.exe"
        assert ev.process_id == 1234
        assert ev.operation == "ReadFile"
        assert ev.offset == 0
        assert ev.length == 4096
        assert ev.result == "SUCCESS"

    def test_valid_hex_length(self) -> None:
        csv_data = _csv(_VALID_ROW_HEX_LENGTH)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert len(events) == 1
        assert events[0].offset == 0x100
        assert events[0].length == 0x1000

    def test_valid_decimal_only(self) -> None:
        csv_data = _csv(_VALID_ROW_DECIMAL)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert len(events) == 1
        assert events[0].offset == 0
        assert events[0].length == 4096

    def test_non_read_operations_skipped(self) -> None:
        csv_data = _csv(_NON_READ_ROW, _NON_READ_ROW)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert events == []

    def test_multiple_rows(self) -> None:
        csv_data = _csv(_VALID_ROW, _VALID_ROW_HEX_LENGTH, _NON_READ_ROW)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert len(events) == 2

    def test_mixed_valid_and_invalid_skip_errors(self) -> None:
        csv_data = _csv(
            _VALID_ROW,
            _BAD_TIMESTAMP_ROW,  # bad timestamp - should be skipped
            _VALID_ROW_DECIMAL,
        )
        events = list(parse_procmon_csv(StringIO(csv_data), skip_errors=True))
        assert len(events) == 2

    def test_mixed_valid_and_invalid_raises(self) -> None:
        csv_data = _csv(
            _VALID_ROW,
            _BAD_TIMESTAMP_ROW,
            _VALID_ROW_DECIMAL,
        )
        with pytest.raises(TimestampParseError):
            list(parse_procmon_csv(StringIO(csv_data), skip_errors=False))

    def test_bad_pid_skipped(self) -> None:
        csv_data = _csv(_BAD_PID_ROW)
        events = list(parse_procmon_csv(StringIO(csv_data), skip_errors=True))
        assert events == []

    def test_bad_pid_raises(self) -> None:
        csv_data = _csv(_BAD_PID_ROW)
        with pytest.raises(RowError, match="Invalid PID"):
            list(parse_procmon_csv(StringIO(csv_data), skip_errors=False))

    def test_missing_offset_skipped(self) -> None:
        csv_data = _csv(_MISSING_OFFSET_DETAIL)
        events = list(parse_procmon_csv(StringIO(csv_data), skip_errors=True))
        assert events == []

    def test_missing_length_skipped(self) -> None:
        csv_data = _csv(_MISSING_LENGTH_DETAIL)
        events = list(parse_procmon_csv(StringIO(csv_data), skip_errors=True))
        assert events == []

    def test_empty_path_skipped(self) -> None:
        csv_data = _csv(_EMPTY_PATH_ROW)
        events = list(parse_procmon_csv(StringIO(csv_data), skip_errors=True))
        assert events == []

    def test_empty_csv_raises(self) -> None:
        with pytest.raises(CSVFormatError, match="empty"):
            list(parse_procmon_csv(StringIO(""), skip_errors=True))

    def test_no_header_raises(self) -> None:
        with pytest.raises(CSVFormatError):
            list(parse_procmon_csv(StringIO("a,b,c\n"), skip_errors=True))

    def test_missing_required_header_raises(self) -> None:
        bad_header = "Time of Day,Process Name,PID\n"
        with pytest.raises(HeaderError, match="Missing"):
            list(
                parse_procmon_csv(
                    StringIO(bad_header + _VALID_ROW),
                    skip_errors=True,
                )
            )

    def test_file_path(self, tmp_path: Path) -> None:
        csv_file = tmp_path / "test.csv"
        csv_file.write_text(_csv(_VALID_ROW), encoding="utf-8")
        events = list(parse_procmon_csv(csv_file))
        assert len(events) == 1
        assert events[0].process_name == "MsMpEng.exe"

    def test_file_not_found(self) -> None:
        with pytest.raises(CSVFormatError, match="Cannot open"):
            list(parse_procmon_csv(Path("/nonexistent/file.csv")))

    def test_returns_iterator(self) -> None:
        csv_data = _csv(_VALID_ROW, _VALID_ROW_DECIMAL)
        gen = parse_procmon_csv(StringIO(csv_data))
        assert hasattr(gen, "__next__")
        first = next(gen)
        assert isinstance(first, ReadEvent)

    def test_read_event_type(self) -> None:
        csv_data = _csv(_VALID_ROW)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert isinstance(events[0], ReadEvent)

    def test_timestamp_parsed_correctly(self) -> None:
        csv_data = _csv(_VALID_ROW)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        ts = events[0].timestamp
        assert ts.hour == 10
        assert ts.minute == 30
        assert ts.second == 45

    def test_irp_mj_read_accepted(self) -> None:
        row = (
            "10:30:45.1234567,MsMpEng.exe,1234,IRP_MJ_READ,"
            'C:\\test.dll,SUCCESS,"Offset: 0x0, Length: 0x100"\n'
        )
        csv_data = _csv(row)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert len(events) == 1
        assert events[0].operation == "IRP_MJ_READ"

    def test_fast_i_o_read_accepted(self) -> None:
        row = (
            "10:30:45.1234567,MsMpEng.exe,1234,FastIORead,"
            'C:\\test.dll,SUCCESS,"Offset: 0x0, Length: 0x100"\n'
        )
        csv_data = _csv(row)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert len(events) == 1
        assert events[0].operation == "FastIORead"

    def test_utf_8_bom_handled(self) -> None:
        csv_data = "\ufeff" + _csv(_VALID_ROW)
        events = list(parse_procmon_csv(StringIO(csv_data)))
        assert len(events) == 1
