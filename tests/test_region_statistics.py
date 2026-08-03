"""Unit tests for the region statistics engine."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from defenderatlas.mapping.models import MappedReadEvent, PERegion
from defenderatlas.models.core import ReadEvent
from defenderatlas.statistics.region_statistics import (
    RegionStatistic,
    RegionStatisticsResult,
    compute_region_statistics,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(UTC)


def _make_event(
    *,
    offset: int = 0,
    length: int = 4096,
    process_name: str = "MsMpEng.exe",
    process_id: int = 1234,
    operation: str = "ReadFile",
    path: str = r"C:\test.exe",
    result: str = "SUCCESS",
) -> ReadEvent:
    return ReadEvent(
        timestamp=_NOW,
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
) -> MappedReadEvent:
    event = _make_event(offset=offset, length=length)
    region = _make_region(name=region_name, start=region_start, end=region_end)
    return MappedReadEvent(original=event, matched_regions=[region])


def _make_mapped_multi(
    offset: int = 0,
    length: int = 4096,
    region_names: list[str] | None = None,
) -> MappedReadEvent:
    event = _make_event(offset=offset, length=length)
    if region_names is None:
        region_names = ["DOS Header"]
    regions = [
        _make_region(name=n, start=i * 100, end=i * 100 + 99)
        for i, n in enumerate(region_names)
    ]
    return MappedReadEvent(original=event, matched_regions=regions)


# ===========================================================================
# Empty input
# ===========================================================================


class TestEmptyInput:
    def test_empty_list(self) -> None:
        result = compute_region_statistics([])
        assert result.total_regions == 0
        assert result.total_reads == 0
        assert result.total_bytes == 0
        assert result.regions == []

    def test_empty_generator(self) -> None:
        def gen() -> object:
            return
            yield

        result = compute_region_statistics(gen())  # type: ignore[arg-type]
        assert result.total_regions == 0
        assert result.total_reads == 0

    def test_empty_returns_result_instance(self) -> None:
        result = compute_region_statistics([])
        assert isinstance(result, RegionStatisticsResult)


# ===========================================================================
# Single region
# ===========================================================================


class TestSingleRegion:
    def test_single_read_single_region(self) -> None:
        events = [_make_mapped(offset=0, length=4096, region_name=".text")]
        result = compute_region_statistics(events)
        assert result.total_regions == 1
        assert result.total_reads == 1
        assert result.total_bytes == 4096
        assert result.regions[0].region_name == ".text"
        assert result.regions[0].read_count == 1
        assert result.regions[0].unique_offsets == 1
        assert result.regions[0].bytes_read == 4096

    def test_single_region_percentage(self) -> None:
        events = [_make_mapped(offset=0, length=4096, region_name=".text")]
        result = compute_region_statistics(events)
        assert result.regions[0].percentage_of_total_reads == 100.0
        assert result.regions[0].percentage_of_total_bytes == 100.0

    def test_multiple_reads_same_region(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text"),
            _make_mapped(offset=100, length=200, region_name=".text"),
            _make_mapped(offset=300, length=300, region_name=".text"),
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 1
        assert result.total_reads == 3
        assert result.total_bytes == 600
        assert result.regions[0].unique_offsets == 3

    def test_repeated_offset_same_region(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text"),
            _make_mapped(offset=0, length=100, region_name=".text"),
            _make_mapped(offset=0, length=100, region_name=".text"),
        ]
        result = compute_region_statistics(events)
        assert result.total_reads == 3
        assert result.regions[0].unique_offsets == 1
        assert result.regions[0].bytes_read == 300


# ===========================================================================
# Multiple regions
# ===========================================================================


class TestMultipleRegions:
    def test_two_regions(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text"),
            _make_mapped(offset=200, length=50, region_name="Import Directory"),
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 2
        assert result.total_reads == 2
        assert result.total_bytes == 150

    def test_three_regions_proportional(self) -> None:
        events = [
            *[
                _make_mapped(offset=i, length=100, region_name=".text")
                for i in range(8)
            ],
            *[
                _make_mapped(offset=i, length=50, region_name="Import Directory")
                for i in range(2)
            ],
            _make_mapped(offset=0, length=25, region_name="Certificate Table"),
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 3
        assert result.total_reads == 11
        assert result.total_bytes == 8 * 100 + 2 * 50 + 25

        text_stat = next(r for r in result.regions if r.region_name == ".text")
        assert text_stat.read_count == 8
        assert text_stat.unique_offsets == 8

        import_stat = next(
            r for r in result.regions if r.region_name == "Import Directory"
        )
        assert import_stat.read_count == 2

        cert_stat = next(
            r for r in result.regions if r.region_name == "Certificate Table"
        )
        assert cert_stat.read_count == 1


# ===========================================================================
# Cross-region reads
# ===========================================================================


class TestCrossRegionReads:
    def test_read_spans_two_regions(self) -> None:
        events = [_make_mapped_multi(offset=0, length=100, region_names=["A", "B"])]
        result = compute_region_statistics(events)
        assert result.total_regions == 2
        assert result.total_reads == 1  # one input event
        assert result.total_bytes == 100  # bytes from input events
        assert result.regions[0].read_count == 1
        assert result.regions[1].read_count == 1

    def test_read_spans_three_regions(self) -> None:
        events = [
            _make_mapped_multi(
                offset=0, length=100, region_names=["Header", "Table", ".text"]
            )
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 3
        assert result.total_reads == 1
        assert result.total_bytes == 100

    def test_cross_region_with_other_reads(self) -> None:
        events = [
            _make_mapped_multi(offset=0, length=100, region_names=["A", "B"]),
            _make_mapped(offset=200, length=50, region_name="A"),
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 2
        assert result.total_reads == 2  # two input events
        assert result.total_bytes == 150  # 100 + 50
        # Region A: 1 cross-region read + 1 direct read = 2
        a_stat = next(r for r in result.regions if r.region_name == "A")
        assert a_stat.read_count == 2
        assert a_stat.bytes_read == 150
        # Region B: 1 cross-region read
        b_stat = next(r for r in result.regions if r.region_name == "B")
        assert b_stat.read_count == 1
        assert b_stat.bytes_read == 100


# ===========================================================================
# Percentage calculations
# ===========================================================================


class TestPercentages:
    def test_even_split(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A"),
            _make_mapped(offset=100, length=100, region_name="B"),
        ]
        result = compute_region_statistics(events)
        for region in result.regions:
            assert region.percentage_of_total_reads == pytest.approx(50.0)
            assert region.percentage_of_total_bytes == pytest.approx(50.0)

    def test_uneven_split(self) -> None:
        events = [
            *[
                _make_mapped(offset=i, length=100, region_name=".text")
                for i in range(9)
            ],
            _make_mapped(offset=0, length=100, region_name="Import Directory"),
        ]
        result = compute_region_statistics(events)
        text_stat = next(r for r in result.regions if r.region_name == ".text")
        assert text_stat.percentage_of_total_reads == pytest.approx(90.0)
        assert text_stat.percentage_of_total_bytes == pytest.approx(90.0)
        import_stat = next(
            r for r in result.regions if r.region_name == "Import Directory"
        )
        assert import_stat.percentage_of_total_reads == pytest.approx(10.0)

    def test_percentage_sum_can_exceed_100(self) -> None:
        """Cross-region reads cause percentages to sum > 100%."""
        events = [_make_mapped_multi(offset=0, length=100, region_names=["A", "B"])]
        result = compute_region_statistics(events)
        total_pct_reads = sum(r.percentage_of_total_reads for r in result.regions)
        assert total_pct_reads == pytest.approx(200.0)

    def test_percentage_rounding(self) -> None:
        events = [
            *[_make_mapped(offset=i, length=1, region_name="A") for i in range(3)],
            _make_mapped(offset=0, length=1, region_name="B"),
        ]
        result = compute_region_statistics(events)
        a_stat = next(r for r in result.regions if r.region_name == "A")
        assert a_stat.percentage_of_total_reads == pytest.approx(75.0)

    def test_zero_reads_percentage(self) -> None:
        result = compute_region_statistics([])
        assert result.total_reads == 0
        assert result.total_bytes == 0


# ===========================================================================
# Sorting
# ===========================================================================


class TestSorting:
    def test_sorted_by_bytes_descending(self) -> None:
        events = [
            _make_mapped(offset=0, length=50, region_name="Small"),
            _make_mapped(offset=100, length=500, region_name="Large"),
            _make_mapped(offset=200, length=200, region_name="Medium"),
        ]
        result = compute_region_statistics(events)
        names = [r.region_name for r in result.regions]
        assert names == ["Large", "Medium", "Small"]

    def test_equal_bytes_stable_order(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="First"),
            _make_mapped(offset=100, length=100, region_name="Second"),
        ]
        result = compute_region_statistics(events)
        assert result.regions[0].bytes_read == result.regions[1].bytes_read

    def test_single_region_sorting(self) -> None:
        events = [_make_mapped(offset=0, length=100, region_name="Only")]
        result = compute_region_statistics(events)
        assert len(result.regions) == 1
        assert result.regions[0].region_name == "Only"


# ===========================================================================
# Helper methods
# ===========================================================================


class TestHelperMethods:
    def test_top_regions_by_reads(self) -> None:
        events = [
            *[
                _make_mapped(offset=i, length=10, region_name=".text")
                for i in range(10)
            ],
            *[
                _make_mapped(offset=i, length=10, region_name="Import Dir")
                for i in range(3)
            ],
            _make_mapped(offset=0, length=10, region_name="Certificate"),
        ]
        result = compute_region_statistics(events)
        top = result.top_regions_by_reads(2)
        assert len(top) == 2
        assert top[0].region_name == ".text"
        assert top[1].region_name == "Import Dir"

    def test_top_regions_by_bytes(self) -> None:
        events = [
            _make_mapped(offset=0, length=1000, region_name="Big"),
            _make_mapped(offset=100, length=100, region_name="Small"),
        ]
        result = compute_region_statistics(events)
        top = result.top_regions_by_bytes(1)
        assert len(top) == 1
        assert top[0].region_name == "Big"

    def test_top_n_regions(self) -> None:
        events = [
            _make_mapped(offset=0, length=300, region_name="A"),
            _make_mapped(offset=100, length=200, region_name="B"),
            _make_mapped(offset=200, length=100, region_name="C"),
        ]
        result = compute_region_statistics(events)
        top = result.top_n_regions(2)
        assert len(top) == 2
        assert top[0].region_name == "A"
        assert top[1].region_name == "B"

    def test_top_n_clamped_to_actual(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="Only"),
        ]
        result = compute_region_statistics(events)
        top = result.top_n_regions(10)
        assert len(top) == 1

    def test_top_regions_empty_result(self) -> None:
        result = compute_region_statistics([])
        assert result.top_regions_by_reads() == []
        assert result.top_regions_by_bytes() == []
        assert result.top_n_regions() == []

    def test_top_regions_by_reads_default_n(self) -> None:
        events = [
            _make_mapped(offset=i, length=10, region_name=f"R{i}") for i in range(5)
        ]
        result = compute_region_statistics(events)
        top = result.top_regions_by_reads()
        assert len(top) == 3  # default n=3


# ===========================================================================
# Large datasets
# ===========================================================================


class TestLargeDatasets:
    def test_1000_events_two_regions(self) -> None:
        events = [
            *[
                _make_mapped(offset=i, length=100, region_name=".text")
                for i in range(800)
            ],
            *[
                _make_mapped(offset=i, length=50, region_name="Import Directory")
                for i in range(200)
            ],
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 2
        assert result.total_reads == 1000
        text_stat = next(r for r in result.regions if r.region_name == ".text")
        assert text_stat.read_count == 800
        assert text_stat.unique_offsets == 800
        assert text_stat.bytes_read == 80000

    def test_5000_events_five_regions(self) -> None:
        names = [".text", ".rdata", ".data", "Import Dir", "Certificate"]
        events = []
        for i in range(5000):
            name = names[i % len(names)]
            events.append(_make_mapped(offset=i, length=100, region_name=name))
        result = compute_region_statistics(events)
        assert result.total_regions == 5
        assert result.total_reads == 5000
        for region in result.regions:
            assert region.read_count == 1000
            assert region.unique_offsets == 1000
            assert region.bytes_read == 100000

    def test_10000_events_performance(self) -> None:
        events = [
            _make_mapped(offset=i, length=64, region_name=f"Region{i % 50}")
            for i in range(10000)
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 50
        assert result.total_reads == 10000
        assert result.total_bytes == 640000


# ===========================================================================
# Model validation
# ===========================================================================


class TestModelValidation:
    def test_region_statistic_valid(self) -> None:
        stat = RegionStatistic(
            region_name=".text",
            read_count=10,
            unique_offsets=8,
            bytes_read=4096,
            percentage_of_total_reads=50.0,
            percentage_of_total_bytes=60.0,
        )
        assert stat.region_name == ".text"

    def test_region_statistic_rejects_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            RegionStatistic(
                region_name="",
                read_count=10,
                unique_offsets=8,
                bytes_read=4096,
                percentage_of_total_reads=50.0,
                percentage_of_total_bytes=60.0,
            )

    def test_region_statistic_rejects_negative_read_count(self) -> None:
        with pytest.raises(ValidationError):
            RegionStatistic(
                region_name=".text",
                read_count=-1,
                unique_offsets=8,
                bytes_read=4096,
                percentage_of_total_reads=50.0,
                percentage_of_total_bytes=60.0,
            )

    def test_region_statistic_rejects_negative_bytes(self) -> None:
        with pytest.raises(ValidationError):
            RegionStatistic(
                region_name=".text",
                read_count=10,
                unique_offsets=8,
                bytes_read=-1,
                percentage_of_total_reads=50.0,
                percentage_of_total_bytes=60.0,
            )

    def test_region_statistic_rejects_over_100_percent(self) -> None:
        with pytest.raises(ValidationError):
            RegionStatistic(
                region_name=".text",
                read_count=10,
                unique_offsets=8,
                bytes_read=4096,
                percentage_of_total_reads=101.0,
                percentage_of_total_bytes=60.0,
            )

    def test_region_statistic_rejects_negative_percent(self) -> None:
        with pytest.raises(ValidationError):
            RegionStatistic(
                region_name=".text",
                read_count=10,
                unique_offsets=8,
                bytes_read=4096,
                percentage_of_total_reads=-1.0,
                percentage_of_total_bytes=60.0,
            )


# ===========================================================================
# Serialization
# ===========================================================================


class TestSerialization:
    def test_region_statistic_json_roundtrip(self) -> None:
        stat = RegionStatistic(
            region_name=".text",
            read_count=10,
            unique_offsets=8,
            bytes_read=4096,
            percentage_of_total_reads=50.0,
            percentage_of_total_bytes=60.0,
        )
        json_str = stat.model_dump_json()
        restored = RegionStatistic.model_validate_json(json_str)
        assert stat == restored

    def test_result_json_roundtrip(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text"),
            _make_mapped(offset=200, length=50, region_name="Import Directory"),
        ]
        result = compute_region_statistics(events)
        json_str = result.model_dump_json()
        restored = RegionStatisticsResult.model_validate_json(json_str)
        assert result == restored

    def test_model_dump(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text"),
        ]
        result = compute_region_statistics(events)
        dumped = result.model_dump()
        assert dumped["total_regions"] == 1
        assert dumped["total_reads"] == 1
        assert dumped["total_bytes"] == 100
        assert dumped["regions"][0]["region_name"] == ".text"


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_event_with_no_matched_regions(self) -> None:
        event = _make_event(offset=0x100000, length=100)
        mapped = MappedReadEvent(original=event, matched_regions=[])
        result = compute_region_statistics([mapped])
        assert result.total_regions == 0
        assert result.total_reads == 1  # one input event processed
        assert result.total_bytes == 100  # bytes from input event

    def test_mixed_mapped_with_and_without_regions(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text"),
            MappedReadEvent(
                original=_make_event(offset=0x100000, length=50),
                matched_regions=[],
            ),
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 1
        assert result.total_reads == 2  # two input events
        assert result.total_bytes == 150  # 100 + 50

    def test_different_region_names_treated_separately(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text"),
            _make_mapped(offset=100, length=100, region_name=".rdata"),
            _make_mapped(offset=200, length=100, region_name=".text"),
        ]
        result = compute_region_statistics(events)
        assert result.total_regions == 2
        text_stat = next(r for r in result.regions if r.region_name == ".text")
        assert text_stat.read_count == 2
        assert text_stat.bytes_read == 200

    def test_zero_length_read(self) -> None:
        """Zero-length reads are prevented by ReadEvent gt=0 validation,
        but region stats handles it gracefully if somehow constructed."""
        event = ReadEvent(
            timestamp=_NOW,
            process_name="test.exe",
            process_id=1,
            operation="ReadFile",
            path=r"C:\test",
            offset=0,
            length=1,
            result="SUCCESS",
        )
        region = _make_region(name="Test", start=0, end=100)
        mapped = MappedReadEvent(original=event, matched_regions=[region])
        result = compute_region_statistics([mapped])
        assert result.total_reads == 1
        assert result.total_bytes == 1

    def test_generator_input(self) -> None:
        def gen() -> object:
            for i in range(5):
                yield _make_mapped(offset=i * 100, length=100, region_name=".text")

        result = compute_region_statistics(gen())  # type: ignore[arg-type]
        assert result.total_regions == 1
        assert result.total_reads == 5
        assert result.total_bytes == 500
