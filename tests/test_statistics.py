"""Unit tests for the statistics computation engine."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from defenderatlas.models.core import ReadEvent, Statistics
from defenderatlas.statistics.compute import compute_statistics

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _make_event(
    *,
    offset: int = 0,
    length: int = 4096,
    process_name: str = "MsMpEng.exe",
    process_id: int = 1234,
    operation: str = "ReadFile",
    path: str = r"C:\Windows\System32\test.dll",
    result: str = "SUCCESS",
    timestamp: datetime | None = None,
) -> ReadEvent:
    return ReadEvent(
        timestamp=timestamp or _now(),
        process_name=process_name,
        process_id=process_id,
        operation=operation,
        path=path,
        offset=offset,
        length=length,
        result=result,
    )


# ===========================================================================
# Empty input
# ===========================================================================


class TestEmptyInput:
    def test_empty_list(self) -> None:
        result = compute_statistics([])
        assert result.total_reads == 0
        assert result.unique_offsets == 0
        assert result.repeated_reads == 0
        assert result.bytes_read == 0
        assert result.read_amplification == 0.0

    def test_empty_generator(self) -> None:
        def gen() -> object:
            return
            yield

        result = compute_statistics(gen())  # type: ignore[arg-type]
        assert result.total_reads == 0
        assert result.unique_offsets == 0

    def test_empty_returns_statistics_instance(self) -> None:
        result = compute_statistics([])
        assert isinstance(result, Statistics)


# ===========================================================================
# Single read
# ===========================================================================


class TestSingleRead:
    def test_single_read_basic(self) -> None:
        events = [_make_event(offset=0, length=4096)]
        result = compute_statistics(events)
        assert result.total_reads == 1
        assert result.unique_offsets == 1
        assert result.repeated_reads == 0
        assert result.bytes_read == 4096

    def test_single_read_no_repeated(self) -> None:
        events = [_make_event(offset=0x1000, length=512)]
        result = compute_statistics(events)
        assert result.repeated_reads == 0

    def test_single_read_amplification_with_file_size(self) -> None:
        events = [_make_event(offset=0, length=4096)]
        result = compute_statistics(events, file_size=4096)
        assert result.read_amplification == 1.0

    def test_single_read_amplification_without_file_size(self) -> None:
        events = [_make_event(offset=0, length=4096)]
        result = compute_statistics(events)
        assert result.read_amplification == 0.0


# ===========================================================================
# Multiple reads
# ===========================================================================


class TestMultipleReads:
    def test_two_distinct_offsets(self) -> None:
        events = [
            _make_event(offset=0, length=4096),
            _make_event(offset=4096, length=4096),
        ]
        result = compute_statistics(events)
        assert result.total_reads == 2
        assert result.unique_offsets == 2
        assert result.repeated_reads == 0
        assert result.bytes_read == 8192

    def test_three_reads_two_offsets(self) -> None:
        events = [
            _make_event(offset=0, length=4096),
            _make_event(offset=4096, length=4096),
            _make_event(offset=0, length=4096),
        ]
        result = compute_statistics(events)
        assert result.total_reads == 3
        assert result.unique_offsets == 2
        assert result.repeated_reads == 1
        assert result.bytes_read == 12288

    def test_bytes_read_sums_lengths(self) -> None:
        events = [
            _make_event(offset=0, length=100),
            _make_event(offset=100, length=200),
            _make_event(offset=300, length=300),
        ]
        result = compute_statistics(events)
        assert result.bytes_read == 600


# ===========================================================================
# Duplicate offsets
# ===========================================================================


class TestDuplicateOffsets:
    def test_all_same_offset(self) -> None:
        events = [
            _make_event(offset=0x1000, length=4096),
            _make_event(offset=0x1000, length=4096),
            _make_event(offset=0x1000, length=4096),
        ]
        result = compute_statistics(events)
        assert result.total_reads == 3
        assert result.unique_offsets == 1
        assert result.repeated_reads == 2
        assert result.bytes_read == 12288

    def test_repeated_offset_middle(self) -> None:
        events = [
            _make_event(offset=0, length=100),
            _make_event(offset=100, length=100),
            _make_event(offset=0, length=100),
            _make_event(offset=200, length=100),
        ]
        result = compute_statistics(events)
        assert result.total_reads == 4
        assert result.unique_offsets == 3
        assert result.repeated_reads == 1
        assert result.bytes_read == 400

    def test_repeated_offset_last(self) -> None:
        events = [
            _make_event(offset=0, length=100),
            _make_event(offset=100, length=100),
            _make_event(offset=200, length=100),
            _make_event(offset=0, length=100),
        ]
        result = compute_statistics(events)
        assert result.repeated_reads == 1
        assert result.unique_offsets == 3


# ===========================================================================
# Amplification calculation
# ===========================================================================


class TestAmplification:
    def test_amplification_exact(self) -> None:
        events = [
            _make_event(offset=0, length=4096),
            _make_event(offset=4096, length=4096),
        ]
        result = compute_statistics(events, file_size=8192)
        assert result.read_amplification == 1.0

    def test_amplification_greater_than_one(self) -> None:
        events = [
            _make_event(offset=0, length=4096),
            _make_event(offset=0, length=4096),
        ]
        result = compute_statistics(events, file_size=4096)
        assert result.read_amplification == 2.0

    def test_amplification_fractional(self) -> None:
        events = [_make_event(offset=0, length=1500)]
        result = compute_statistics(events, file_size=10000)
        assert result.read_amplification == pytest.approx(0.15)

    def test_amplification_file_size_none(self) -> None:
        events = [_make_event(offset=0, length=4096)]
        result = compute_statistics(events, file_size=None)
        assert result.read_amplification == 0.0

    def test_amplification_file_size_zero_raises(self) -> None:
        events = [_make_event(offset=0, length=4096)]
        with pytest.raises(ValueError, match="file_size must be > 0"):
            compute_statistics(events, file_size=0)

    def test_amplification_file_size_negative(self) -> None:
        events = [_make_event(offset=0, length=4096)]
        with pytest.raises(ValueError, match="file_size must be > 0"):
            compute_statistics(events, file_size=-1)

    def test_amplification_large_file(self) -> None:
        events = [
            _make_event(offset=0, length=524288),
            _make_event(offset=524288, length=524288),
            _make_event(offset=0, length=524288),
        ]
        result = compute_statistics(events, file_size=1048576)
        assert result.read_amplification == pytest.approx(1.5)


# ===========================================================================
# Generator input
# ===========================================================================


class TestGeneratorInput:
    def test_generator_yields_events(self) -> None:
        def gen() -> object:
            for i in range(5):
                yield _make_event(offset=i * 4096, length=4096)

        result = compute_statistics(gen())  # type: ignore[arg-type]
        assert result.total_reads == 5
        assert result.unique_offsets == 5
        assert result.repeated_reads == 0
        assert result.bytes_read == 20480

    def test_generator_with_duplicates(self) -> None:
        def gen() -> object:
            yield _make_event(offset=0, length=100)
            yield _make_event(offset=100, length=100)
            yield _make_event(offset=0, length=100)

        result = compute_statistics(gen())  # type: ignore[arg-type]
        assert result.total_reads == 3
        assert result.unique_offsets == 2
        assert result.repeated_reads == 1

    def test_generator_not_buffered(self) -> None:
        count = 0

        def gen() -> object:
            nonlocal count
            for i in range(100):
                count += 1
                yield _make_event(offset=i * 4096, length=4096)

        result = compute_statistics(gen())  # type: ignore[arg-type]
        assert result.total_reads == 100
        assert count == 100


# ===========================================================================
# Large datasets
# ===========================================================================


class TestLargeDatasets:
    def test_1000_distinct_offsets(self) -> None:
        events = [_make_event(offset=i * 4096, length=4096) for i in range(1000)]
        result = compute_statistics(events)
        assert result.total_reads == 1000
        assert result.unique_offsets == 1000
        assert result.repeated_reads == 0
        assert result.bytes_read == 4096000

    def test_1000_repeated_offsets(self) -> None:
        events = [_make_event(offset=0, length=4096) for _ in range(1000)]
        result = compute_statistics(events)
        assert result.total_reads == 1000
        assert result.unique_offsets == 1
        assert result.repeated_reads == 999
        assert result.bytes_read == 4096000

    def test_5000_mixed_offsets(self) -> None:
        events = []
        for i in range(5000):
            events.append(_make_event(offset=i % 100, length=100))
        result = compute_statistics(events)
        assert result.total_reads == 5000
        assert result.unique_offsets == 100
        assert result.repeated_reads == 4900
        assert result.bytes_read == 500000

    def test_large_amplification(self) -> None:
        events = [_make_event(offset=0, length=1024) for _ in range(100)]
        result = compute_statistics(events, file_size=1024)
        assert result.read_amplification == 100.0


# ===========================================================================
# ReadEvent field variations
# ===========================================================================


class TestEventFieldVariations:
    def test_different_process_names(self) -> None:
        events = [
            _make_event(offset=0, process_name="MsMpEng.exe"),
            _make_event(offset=0, process_name="SearchProtocolHost.exe"),
        ]
        result = compute_statistics(events)
        assert result.total_reads == 2
        assert result.unique_offsets == 1
        assert result.repeated_reads == 1

    def test_different_operations(self) -> None:
        events = [
            _make_event(offset=0, operation="ReadFile"),
            _make_event(offset=0, operation="IRP_MJ_READ"),
        ]
        result = compute_statistics(events)
        assert result.total_reads == 2
        assert result.unique_offsets == 1
        assert result.repeated_reads == 1

    def test_different_results(self) -> None:
        events = [
            _make_event(offset=0, result="SUCCESS"),
            _make_event(offset=0, result="FAST IO DISALLOWED"),
        ]
        result = compute_statistics(events)
        assert result.total_reads == 2
        assert result.unique_offsets == 1
        assert result.repeated_reads == 1

    def test_zero_offset(self) -> None:
        events = [_make_event(offset=0, length=100)]
        result = compute_statistics(events)
        assert result.unique_offsets == 1
        assert result.repeated_reads == 0

    def test_large_offset(self) -> None:
        events = [_make_event(offset=2**53, length=100)]
        result = compute_statistics(events)
        assert result.unique_offsets == 1

    def test_varied_lengths(self) -> None:
        events = [
            _make_event(offset=0, length=100),
            _make_event(offset=100, length=200),
            _make_event(offset=300, length=500),
        ]
        result = compute_statistics(events)
        assert result.bytes_read == 800


# ===========================================================================
# Return type
# ===========================================================================


class TestReturnType:
    def test_returns_statistics(self) -> None:
        result = compute_statistics([])
        assert isinstance(result, Statistics)

    def test_model_dump_works(self) -> None:
        events = [_make_event(offset=0, length=4096)]
        result = compute_statistics(events, file_size=4096)
        dumped = result.model_dump()
        assert dumped["total_reads"] == 1
        assert dumped["read_amplification"] == 1.0

    def test_json_roundtrip(self) -> None:
        events = [
            _make_event(offset=0, length=4096),
            _make_event(offset=4096, length=4096),
        ]
        result = compute_statistics(events, file_size=8192)
        json_str = result.model_dump_json()
        restored = Statistics.model_validate_json(json_str)
        assert result == restored


# ===========================================================================
# Validation edge cases
# ===========================================================================


class TestValidation:
    def test_file_size_one(self) -> None:
        events = [_make_event(offset=0, length=1)]
        result = compute_statistics(events, file_size=1)
        assert result.read_amplification == 1.0

    def test_mixed_valid_and_invalid_offsets(self) -> None:
        events = [
            _make_event(offset=0, length=100),
            _make_event(offset=100, length=200),
            _make_event(offset=0, length=300),
            _make_event(offset=200, length=400),
            _make_event(offset=100, length=500),
        ]
        result = compute_statistics(events)
        assert result.total_reads == 5
        assert result.unique_offsets == 3
        assert result.repeated_reads == 2
        assert result.bytes_read == 1500
