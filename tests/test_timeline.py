"""Unit tests for the timeline reconstruction engine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from defenderatlas.mapping.models import MappedReadEvent, PERegion
from defenderatlas.models.core import ReadEvent
from defenderatlas.timeline.timeline_builder import (
    TimelineEntry,
    TimelineResult,
    build_timeline,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _make_event(
    *,
    offset: int = 0,
    length: int = 4096,
    timestamp: datetime | None = None,
    process_name: str = "MsMpEng.exe",
    process_id: int = 1234,
    operation: str = "ReadFile",
    path: str = r"C:\test.exe",
    result: str = "SUCCESS",
) -> ReadEvent:
    return ReadEvent(
        timestamp=timestamp or _NOW,
        process_name=process_name,
        process_id=process_id,
        operation=operation,
        path=path,
        offset=offset,
        length=length,
        result=result,
    )


def _make_region(
    name: str = "DOS Header",
    start: int = 0,
    end: int = 63,
) -> PERegion:
    return PERegion(
        name=name,
        start_offset=start,
        end_offset=end,
        description=f"Test region: {name}.",
    )


def _make_mapped(
    offset: int = 0,
    length: int = 4096,
    region_name: str = ".text",
    region_start: int = 0,
    region_end: int = 4095,
    timestamp: datetime | None = None,
) -> MappedReadEvent:
    event = _make_event(offset=offset, length=length, timestamp=timestamp)
    region = _make_region(name=region_name, start=region_start, end=region_end)
    return MappedReadEvent(original=event, matched_regions=[region])


def _make_mapped_multi(
    offset: int = 0,
    length: int = 4096,
    region_names: list[str] | None = None,
    timestamp: datetime | None = None,
) -> MappedReadEvent:
    event = _make_event(offset=offset, length=length, timestamp=timestamp)
    if region_names is None:
        region_names = ["DOS Header"]
    regions = [
        _make_region(name=n, start=i * 100, end=i * 100 + 99)
        for i, n in enumerate(region_names)
    ]
    return MappedReadEvent(original=event, matched_regions=regions)


def _ts(seconds: float) -> datetime:
    """Shorthand for a UTC datetime offset from _NOW."""
    return _NOW + timedelta(seconds=seconds)


# ===========================================================================
# Empty input
# ===========================================================================


class TestEmptyInput:
    def test_empty_list(self) -> None:
        result = build_timeline([])
        assert result.entries == []
        assert result.duration == timedelta()

    def test_empty_generator(self) -> None:
        def gen() -> object:
            return
            yield  # pragma: no cover

        result = build_timeline(gen())  # type: ignore[arg-type]
        assert result.entries == []
        assert result.duration == timedelta()

    def test_empty_returns_result_instance(self) -> None:
        result = build_timeline([])
        assert isinstance(result, TimelineResult)

    def test_empty_has_valid_timestamps(self) -> None:
        result = build_timeline([])
        assert result.start_time is not None
        assert result.end_time is not None
        assert result.start_time == result.end_time


# ===========================================================================
# Ordered input
# ===========================================================================


class TestOrderedInput:
    def test_single_event(self) -> None:
        events = [_make_mapped(offset=0, length=100, timestamp=_ts(0))]
        result = build_timeline(events)
        assert len(result.entries) == 1
        assert result.entries[0].region_name == ".text"
        assert result.entries[0].offset == 0
        assert result.entries[0].length == 100

    def test_three_events_chronological(self) -> None:
        events = [
            _make_mapped(
                offset=0, length=100, region_name="DOS Header", timestamp=_ts(0)
            ),
            _make_mapped(
                offset=100, length=200, region_name="NT Headers", timestamp=_ts(0.001)
            ),
            _make_mapped(
                offset=300, length=300, region_name=".text", timestamp=_ts(0.002)
            ),
        ]
        result = build_timeline(events)
        names = [e.region_name for e in result.entries]
        assert names == ["DOS Header", "NT Headers", ".text"]

    def test_preserves_operation_and_process(self) -> None:
        event = _make_event(
            offset=0, length=64, timestamp=_ts(0), process_name="MsMpEng.exe"
        )
        mapped = MappedReadEvent(
            original=event,
            matched_regions=[_make_region(name=".text", start=0, end=63)],
        )
        result = build_timeline([mapped])
        assert result.entries[0].process_name == "MsMpEng.exe"
        assert result.entries[0].operation == "ReadFile"


# ===========================================================================
# Unordered input
# ===========================================================================


class TestUnorderedInput:
    def test_events_sorted_by_timestamp(self) -> None:
        events = [
            _make_mapped(offset=200, length=100, region_name="C", timestamp=_ts(0.003)),
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0.001)),
            _make_mapped(offset=100, length=100, region_name="B", timestamp=_ts(0.002)),
        ]
        result = build_timeline(events)
        names = [e.region_name for e in result.entries]
        assert names == ["A", "B", "C"]

    def test_reverse_order_input_sorted_correctly(self) -> None:
        events = [
            _make_mapped(
                offset=0, length=100, region_name="Last", timestamp=_ts(0.010)
            ),
            _make_mapped(
                offset=0, length=100, region_name="First", timestamp=_ts(0.000)
            ),
        ]
        result = build_timeline(events)
        assert result.entries[0].region_name == "First"
        assert result.entries[1].region_name == "Last"


# ===========================================================================
# Duplicate timestamps
# ===========================================================================


class TestDuplicateTimestamps:
    def test_same_timestamp_preserves_input_order(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="Alpha", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="Beta", timestamp=_ts(0)),
            _make_mapped(offset=200, length=100, region_name="Gamma", timestamp=_ts(0)),
        ]
        result = build_timeline(events)
        names = [e.region_name for e in result.entries]
        assert names == ["Alpha", "Beta", "Gamma"]

    def test_mixed_same_and_different_timestamps(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="B", timestamp=_ts(0.001)),
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=0, length=100, region_name="C", timestamp=_ts(0.001)),
        ]
        result = build_timeline(events)
        names = [e.region_name for e in result.entries]
        assert names == ["A", "B", "C"]


# ===========================================================================
# Cross-region reads
# ===========================================================================


class TestCrossRegionReads:
    def test_read_spans_two_regions(self) -> None:
        events = [
            _make_mapped_multi(
                offset=0,
                length=100,
                region_names=["Header", "Table"],
                timestamp=_ts(0),
            ),
        ]
        result = build_timeline(events)
        assert len(result.entries) == 2
        assert result.entries[0].region_name == "Header"
        assert result.entries[0].timestamp == result.entries[1].timestamp
        assert result.entries[1].region_name == "Table"

    def test_cross_region_same_timestamp_as_single(self) -> None:
        events = [
            _make_mapped_multi(
                offset=0,
                length=100,
                region_names=["A", "B"],
                timestamp=_ts(0),
            ),
        ]
        result = build_timeline(events)
        assert result.entries[0].timestamp == result.entries[1].timestamp
        assert result.entries[0].offset == result.entries[1].offset

    def test_cross_region_mixed_with_single(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="Pre", timestamp=_ts(0)),
            _make_mapped_multi(
                offset=100,
                length=100,
                region_names=["A", "B"],
                timestamp=_ts(0.001),
            ),
            _make_mapped(
                offset=200, length=100, region_name="Post", timestamp=_ts(0.002)
            ),
        ]
        result = build_timeline(events)
        names = [e.region_name for e in result.entries]
        assert names == ["Pre", "A", "B", "Post"]


# ===========================================================================
# Duration calculations
# ===========================================================================


class TestDuration:
    def test_duration_single_event(self) -> None:
        events = [_make_mapped(offset=0, length=100, timestamp=_ts(0))]
        result = build_timeline(events)
        assert result.duration == timedelta()
        assert result.start_time == _ts(0)
        assert result.end_time == _ts(0)

    def test_duration_multiple_events(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, timestamp=_ts(0.050)),
        ]
        result = build_timeline(events)
        assert result.duration == timedelta(seconds=0.050)

    def test_duration_cross_region(self) -> None:
        events = [
            _make_mapped_multi(
                offset=0,
                length=100,
                region_names=["A", "B"],
                timestamp=_ts(0),
            ),
            _make_mapped(offset=0, length=100, region_name="C", timestamp=_ts(0.100)),
        ]
        result = build_timeline(events)
        assert result.duration == timedelta(seconds=0.100)

    def test_start_end_time_correct(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, timestamp=_ts(5.0)),
            _make_mapped(offset=100, length=100, timestamp=_ts(1.0)),
            _make_mapped(offset=200, length=100, timestamp=_ts(3.0)),
        ]
        result = build_timeline(events)
        assert result.start_time == _ts(1.0)
        assert result.end_time == _ts(5.0)
        assert result.duration == timedelta(seconds=4.0)


# ===========================================================================
# Repeated region visits
# ===========================================================================


class TestRepeatedVisits:
    def test_revisit_same_region(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.001)
            ),
            _make_mapped(
                offset=200, length=100, region_name=".text", timestamp=_ts(0.002)
            ),
        ]
        result = build_timeline(events)
        assert len(result.entries) == 3
        assert all(e.region_name == ".text" for e in result.entries)

    def test_interleaved_region_visits(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="B", timestamp=_ts(0.001)),
            _make_mapped(offset=200, length=100, region_name="A", timestamp=_ts(0.002)),
            _make_mapped(offset=300, length=100, region_name="B", timestamp=_ts(0.003)),
        ]
        result = build_timeline(events)
        names = [e.region_name for e in result.entries]
        assert names == ["A", "B", "A", "B"]


# ===========================================================================
# Unmapped events
# ===========================================================================


class TestUnmapped:
    def test_no_matched_regions_becomes_unmapped(self) -> None:
        event = _make_event(offset=0x100000, length=100, timestamp=_ts(0))
        mapped = MappedReadEvent(original=event, matched_regions=[])
        result = build_timeline([mapped])
        assert len(result.entries) == 1
        assert result.entries[0].region_name == "Unmapped"

    def test_mixed_mapped_and_unmapped(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            MappedReadEvent(
                original=_make_event(offset=0x100000, length=50, timestamp=_ts(0.001)),
                matched_regions=[],
            ),
            _make_mapped(
                offset=200, length=100, region_name="Import Dir", timestamp=_ts(0.002)
            ),
        ]
        result = build_timeline(events)
        names = [e.region_name for e in result.entries]
        assert names == [".text", "Unmapped", "Import Dir"]

    def test_unmapped_preserves_event_details(self) -> None:
        event = _make_event(
            offset=0x50000,
            length=256,
            operation="FastIORead",
            process_name="ScanThread.exe",
            timestamp=_ts(0),
        )
        mapped = MappedReadEvent(original=event, matched_regions=[])
        result = build_timeline([mapped])
        entry = result.entries[0]
        assert entry.offset == 0x50000
        assert entry.length == 256
        assert entry.operation == "FastIORead"
        assert entry.process_name == "ScanThread.exe"


# ===========================================================================
# Helper methods
# ===========================================================================


class TestTimelineByRegion:
    def test_groups_entries_by_region(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="B", timestamp=_ts(0.001)),
            _make_mapped(offset=200, length=100, region_name="A", timestamp=_ts(0.002)),
        ]
        result = build_timeline(events)
        grouped = result.timeline_by_region()
        assert set(grouped.keys()) == {"A", "B"}
        assert len(grouped["A"]) == 2
        assert len(grouped["B"]) == 1

    def test_preserves_chronological_order_within_region(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0.002)),
            _make_mapped(offset=100, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=200, length=100, region_name="A", timestamp=_ts(0.001)),
        ]
        result = build_timeline(events)
        grouped = result.timeline_by_region()
        timestamps = [e.timestamp for e in grouped["A"]]
        assert timestamps == [_ts(0), _ts(0.001), _ts(0.002)]

    def test_empty_timeline(self) -> None:
        result = build_timeline([])
        assert result.timeline_by_region() == {}


class TestRegionsInOrder:
    def test_unique_regions_first_access_order(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="C", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="A", timestamp=_ts(0.001)),
            _make_mapped(offset=200, length=100, region_name="B", timestamp=_ts(0.002)),
            _make_mapped(offset=300, length=100, region_name="C", timestamp=_ts(0.003)),
        ]
        result = build_timeline(events)
        assert result.regions_in_order() == ["C", "A", "B"]

    def test_single_region(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0))
        ]
        result = build_timeline(events)
        assert result.regions_in_order() == [".text"]

    def test_empty_timeline(self) -> None:
        result = build_timeline([])
        assert result.regions_in_order() == []


class TestFirstAndLastRegionAccessed:
    def test_first_region(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="First", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name="Last", timestamp=_ts(0.001)
            ),
        ]
        result = build_timeline(events)
        assert result.first_region_accessed() == "First"

    def test_last_region(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="First", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name="Last", timestamp=_ts(0.001)
            ),
        ]
        result = build_timeline(events)
        assert result.last_region_accessed() == "Last"

    def test_empty_returns_none(self) -> None:
        result = build_timeline([])
        assert result.first_region_accessed() is None
        assert result.last_region_accessed() is None


class TestMostFrequentlyVisitedRegions:
    def test_returns_top_n(self) -> None:
        events = [
            *[
                _make_mapped(
                    offset=i, length=10, region_name=".text", timestamp=_ts(i * 0.001)
                )
                for i in range(10)
            ],
            *[
                _make_mapped(
                    offset=i,
                    length=10,
                    region_name="Import Dir",
                    timestamp=_ts((10 + i) * 0.001),
                )
                for i in range(3)
            ],
            _make_mapped(
                offset=0, length=10, region_name="Certificate", timestamp=_ts(0.020)
            ),
        ]
        result = build_timeline(events)
        top = result.most_frequently_visited_regions(2)
        assert len(top) == 2
        assert top[0] == (".text", 10)
        assert top[1] == ("Import Dir", 3)

    def test_default_n_is_three(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=10, region_name=f"R{i}", timestamp=_ts(i * 0.001)
            )
            for i in range(5)
        ]
        result = build_timeline(events)
        top = result.most_frequently_visited_regions()
        assert len(top) == 3

    def test_empty_timeline(self) -> None:
        result = build_timeline([])
        assert result.most_frequently_visited_regions() == []


# ===========================================================================
# Large timelines
# ===========================================================================


class TestLargeTimelines:
    def test_1000_events_sorted(self) -> None:
        import random

        rng = random.Random(42)
        timestamps = [_ts(rng.random() * 10) for _ in range(1000)]
        events = [
            _make_mapped(offset=i, length=64, region_name=f"R{i % 10}", timestamp=ts)
            for i, ts in enumerate(timestamps)
        ]
        result = build_timeline(events)
        assert len(result.entries) == 1000
        for i in range(len(result.entries) - 1):
            assert result.entries[i].timestamp <= result.entries[i + 1].timestamp

    def test_5000_events_cross_region(self) -> None:
        events = [
            _make_mapped_multi(
                offset=i,
                length=64,
                region_names=[f"A{i % 3}", f"B{i % 3}"],
                timestamp=_ts(i * 0.001),
            )
            for i in range(5000)
        ]
        result = build_timeline(events)
        assert len(result.entries) == 10000
        for i in range(len(result.entries) - 1):
            assert result.entries[i].timestamp <= result.entries[i + 1].timestamp


# ===========================================================================
# Serialization
# ===========================================================================


class TestSerialization:
    def test_entry_json_roundtrip(self) -> None:
        entry = TimelineEntry(
            timestamp=_ts(0),
            region_name=".text",
            offset=0,
            length=100,
            operation="ReadFile",
            process_name="MsMpEng.exe",
        )
        json_str = entry.model_dump_json()
        restored = TimelineEntry.model_validate_json(json_str)
        assert entry == restored

    def test_result_json_roundtrip(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=50, region_name="Import Dir", timestamp=_ts(0.001)
            ),
        ]
        result = build_timeline(events)
        json_str = result.model_dump_json()
        restored = TimelineResult.model_validate_json(json_str)
        assert result == restored

    def test_model_dump(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
        ]
        result = build_timeline(events)
        dumped = result.model_dump()
        assert dumped["entries"][0]["region_name"] == ".text"
        assert dumped["entries"][0]["offset"] == 0
        assert dumped["start_time"] is not None
        assert dumped["end_time"] is not None


# ===========================================================================
# Model validation
# ===========================================================================


class TestModelValidation:
    def test_entry_rejects_empty_region_name(self) -> None:
        with pytest.raises(ValidationError):
            TimelineEntry(
                timestamp=_ts(0),
                region_name="",
                offset=0,
                length=100,
                operation="ReadFile",
                process_name="MsMpEng.exe",
            )

    def test_entry_rejects_negative_offset(self) -> None:
        with pytest.raises(ValidationError):
            TimelineEntry(
                timestamp=_ts(0),
                region_name=".text",
                offset=-1,
                length=100,
                operation="ReadFile",
                process_name="MsMpEng.exe",
            )

    def test_entry_rejects_zero_length(self) -> None:
        with pytest.raises(ValidationError):
            TimelineEntry(
                timestamp=_ts(0),
                region_name=".text",
                offset=0,
                length=0,
                operation="ReadFile",
                process_name="MsMpEng.exe",
            )

    def test_entry_rejects_empty_operation(self) -> None:
        with pytest.raises(ValidationError):
            TimelineEntry(
                timestamp=_ts(0),
                region_name=".text",
                offset=0,
                length=100,
                operation="",
                process_name="MsMpEng.exe",
            )

    def test_entry_rejects_empty_process_name(self) -> None:
        with pytest.raises(ValidationError):
            TimelineEntry(
                timestamp=_ts(0),
                region_name=".text",
                offset=0,
                length=100,
                operation="ReadFile",
                process_name="",
            )


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_generator_input(self) -> None:
        def gen() -> object:
            for i in range(5):
                yield _make_mapped(
                    offset=i * 100,
                    length=100,
                    region_name=".text",
                    timestamp=_ts(i * 0.001),
                )

        result = build_timeline(gen())  # type: ignore[arg-type]
        assert len(result.entries) == 5

    def test_single_region_multiple_entries(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.001)
            ),
        ]
        result = build_timeline(events)
        assert len(result.entries) == 2
        assert result.first_region_accessed() == ".text"
        assert result.last_region_accessed() == ".text"

    def test_duration_with_microsecond_precision(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, timestamp=_ts(0.000001)),
        ]
        result = build_timeline(events)
        assert result.duration == timedelta(microseconds=1)

    def test_entries_sorted_stable_for_identical_events(self) -> None:
        ts = _ts(0)
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=ts),
            _make_mapped(offset=0, length=100, region_name="A", timestamp=ts),
        ]
        result = build_timeline(events)
        assert len(result.entries) == 2
        assert result.entries[0].timestamp == result.entries[1].timestamp
