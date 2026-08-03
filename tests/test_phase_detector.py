"""Unit tests for the phase detection framework."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from defenderatlas.mapping.models import MappedReadEvent, PERegion
from defenderatlas.models.core import ReadEvent
from defenderatlas.phases.phase_detector import (
    Phase,
    PhaseDetectionResult,
    PhaseDetector,
    PhaseRule,
)
from defenderatlas.timeline.timeline_builder import build_timeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _make_event(
    *,
    offset: int = 0,
    length: int = 100,
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
    end: int = 99,
) -> PERegion:
    return PERegion(
        name=name,
        start_offset=start,
        end_offset=end,
        description=f"Test region: {name}.",
    )


def _make_mapped(
    offset: int = 0,
    length: int = 100,
    region_name: str = ".text",
    region_start: int = 0,
    region_end: int = 99,
    timestamp: datetime | None = None,
) -> MappedReadEvent:
    event = _make_event(offset=offset, length=length, timestamp=timestamp)
    region = _make_region(name=region_name, start=region_start, end=region_end)
    return MappedReadEvent(original=event, matched_regions=[region])


def _make_mapped_multi(
    offset: int = 0,
    length: int = 100,
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
    return _NOW + timedelta(seconds=seconds)


def _make_rule(
    name: str = "Test Rule",
    description: str = "A test rule.",
    required_regions: set[str] | None = None,
    minimum_reads: int = 1,
    optional_regions: list[str] | None = None,
) -> PhaseRule:
    return PhaseRule(
        name=name,
        description=description,
        required_regions=required_regions or set(),
        minimum_reads=minimum_reads,
        optional_regions=optional_regions or [],
    )


# ===========================================================================
# Empty input
# ===========================================================================


class TestEmptyInput:
    def test_empty_timeline_no_rules(self) -> None:
        result = PhaseDetector([]).detect(build_timeline([]))
        assert result.phases == []
        assert result.confidence == 0.0

    def test_empty_timeline_with_rules(self) -> None:
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline([]))
        assert result.phases == []
        assert result.confidence == 0.0

    def test_result_type(self) -> None:
        result = PhaseDetector([]).detect(build_timeline([]))
        assert isinstance(result, PhaseDetectionResult)


# ===========================================================================
# Single phase detection
# ===========================================================================


class TestSinglePhaseDetection:
    def test_matches_single_run(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=100, region_name=".text", timestamp=_ts(i * 0.001)
            )
            for i in range(5)
        ]
        rule = _make_rule(required_regions={".text"}, minimum_reads=3)
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 1
        assert result.phases[0].name == "Test Rule"
        assert result.phases[0].description == "A test rule."

    def test_phase_has_correct_timing(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.005)
            ),
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert result.phases[0].start_time == _ts(0).isoformat()
        assert result.phases[0].end_time == _ts(0.005).isoformat()
        assert result.phases[0].duration == timedelta(seconds=0.005)

    def test_phase_has_evidence(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.001)
            ),
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases[0].evidence) == 2

    def test_confidence_high_when_all_matched(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=100, region_name=".text", timestamp=_ts(i * 0.001)
            )
            for i in range(5)
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert result.confidence == pytest.approx(0.9)

    def test_insufficient_reads_no_match(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.001)
            ),
        ]
        rule = _make_rule(required_regions={".text"}, minimum_reads=3)
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 0
        assert result.confidence == 0.0

    def test_missing_required_region(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=100, region_name="Header", timestamp=_ts(i * 0.001)
            )
            for i in range(5)
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 0


# ===========================================================================
# Multiple phase detection
# ===========================================================================


class TestMultiplePhaseDetection:
    def test_two_phases_different_regions(self) -> None:
        events = [
            *[
                _make_mapped(
                    offset=i, length=100, region_name=".text", timestamp=_ts(i * 0.001)
                )
                for i in range(3)
            ],
            *[
                _make_mapped(
                    offset=100 + i,
                    length=100,
                    region_name="Import Dir",
                    timestamp=_ts(0.010 + i * 0.001),
                )
                for i in range(3)
            ],
        ]
        rule1 = _make_rule(name="R1", required_regions={".text"}, minimum_reads=2)
        rule2 = _make_rule(name="R2", required_regions={"Import Dir"}, minimum_reads=2)
        result = PhaseDetector([rule1, rule2]).detect(build_timeline(events))
        assert len(result.phases) == 2
        assert result.phases[0].name == "R1"
        assert result.phases[1].name == "R2"

    def test_three_phases(self) -> None:
        events = [
            *[
                _make_mapped(
                    offset=i, length=100, region_name="A", timestamp=_ts(i * 0.001)
                )
                for i in range(2)
            ],
            *[
                _make_mapped(
                    offset=100 + i,
                    length=100,
                    region_name="B",
                    timestamp=_ts(0.010 + i * 0.001),
                )
                for i in range(2)
            ],
            *[
                _make_mapped(
                    offset=200 + i,
                    length=100,
                    region_name="C",
                    timestamp=_ts(0.020 + i * 0.001),
                )
                for i in range(2)
            ],
        ]
        rules = [
            _make_rule(name=f"R{i}", required_regions={r}, minimum_reads=1)
            for i, r in enumerate(["A", "B", "C"])
        ]
        result = PhaseDetector(rules).detect(build_timeline(events))
        assert len(result.phases) == 3

    def test_phases_sorted_by_start_time(self) -> None:
        events = [
            *[
                _make_mapped(
                    offset=i, length=100, region_name="C", timestamp=_ts(i * 0.001)
                )
                for i in range(2)
            ],
            *[
                _make_mapped(
                    offset=100 + i,
                    length=100,
                    region_name="A",
                    timestamp=_ts(0.010 + i * 0.001),
                )
                for i in range(2)
            ],
            *[
                _make_mapped(
                    offset=200 + i,
                    length=100,
                    region_name="B",
                    timestamp=_ts(0.020 + i * 0.001),
                )
                for i in range(2)
            ],
        ]
        rules = [
            _make_rule(name=f"R{i}", required_regions={r}, minimum_reads=1)
            for i, r in enumerate(["C", "A", "B"])
        ]
        result = PhaseDetector(rules).detect(build_timeline(events))
        names = [p.name for p in result.phases]
        assert names == ["R0", "R1", "R2"]

    def test_no_matching_phases(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=100, region_name="Foo", timestamp=_ts(i * 0.001)
            )
            for i in range(5)
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 0
        assert result.confidence == 0.0

    def test_skipped_rule_below_minimum(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.001)
            ),
        ]
        rule = _make_rule(required_regions={".text"}, minimum_reads=10)
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 0


# ===========================================================================
# Confidence calculation
# ===========================================================================


class TestConfidence:
    def test_no_rules_returns_zero(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=100, region_name=".text", timestamp=_ts(i * 0.001)
            )
            for i in range(3)
        ]
        result = PhaseDetector([]).detect(build_timeline(events))
        assert result.confidence == 0.0

    def test_all_rules_matched(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=100, region_name=".text", timestamp=_ts(i * 0.001)
            )
            for i in range(5)
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        # rule_match=1.0, coverage=1.0, bonus=1/(1+1)=0.5
        # 0.4*1.0 + 0.4*1.0 + 0.2*0.5 = 0.9
        assert result.confidence == pytest.approx(0.9)

    def test_partial_rules_matched(self) -> None:
        events = [
            *[
                _make_mapped(
                    offset=i, length=100, region_name=".text", timestamp=_ts(i * 0.001)
                )
                for i in range(3)
            ],
            *[
                _make_mapped(
                    offset=100 + i,
                    length=100,
                    region_name="Data",
                    timestamp=_ts(0.010 + i * 0.001),
                )
                for i in range(3)
            ],
        ]
        rule1 = _make_rule(name="R1", required_regions={".text"})
        rule2 = _make_rule(name="R2", required_regions={"Overlay"})
        result = PhaseDetector([rule1, rule2]).detect(build_timeline(events))
        # rule_match=1/2=0.5, coverage=3/6=0.5, bonus=1/(1+1)=0.5
        # 0.4*0.5 + 0.4*0.5 + 0.2*0.5 = 0.5
        assert result.confidence == pytest.approx(0.5)

    def test_single_entry_high_confidence(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        # rule_match=1.0, coverage=1.0, bonus=1/(1+1)=0.5
        assert result.confidence == pytest.approx(0.9)

    def test_empty_timeline_with_rules_zero_confidence(self) -> None:
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline([]))
        assert result.confidence == 0.0

    def test_timeline_duration_preserved(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.1)
            ),
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert result.timeline_duration == timedelta(seconds=0.1)


# ===========================================================================
# Rule matching / skipping logic
# ===========================================================================


class TestRuleMatching:
    def test_multiple_rules_same_region_first_wins(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.001)
            ),
        ]
        rule1 = _make_rule(name="R1", required_regions={".text"})
        rule2 = _make_rule(name="R2", required_regions={".text"})
        result = PhaseDetector([rule1, rule2]).detect(build_timeline(events))
        assert len(result.phases) == 1
        assert result.phases[0].name == "R1"

    def test_rule_order_matters(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
        ]
        rule1 = _make_rule(name="First", required_regions={"A"})
        rule2 = _make_rule(name="Second", required_regions={"A"})
        detector = PhaseDetector([rule2, rule1])
        result = detector.detect(build_timeline(events))
        assert result.phases[0].name == "Second"

    def test_no_rules_no_phases(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=100, region_name=".text", timestamp=_ts(i * 0.001)
            )
            for i in range(3)
        ]
        result = PhaseDetector([]).detect(build_timeline(events))
        assert len(result.phases) == 0
        assert result.confidence == 0.0

    def test_interleaved_runs_different_rules(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="B", timestamp=_ts(0.001)),
            _make_mapped(offset=200, length=100, region_name="A", timestamp=_ts(0.002)),
            _make_mapped(offset=300, length=100, region_name="B", timestamp=_ts(0.003)),
        ]
        rule = _make_rule(required_regions={"A"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 1
        assert result.phases[0].name == "Test Rule"


# ===========================================================================
# Optional regions
# ===========================================================================


class TestOptionalRegions:
    def test_optional_region_correct_order(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="Header", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name="Data", timestamp=_ts(0.001)
            ),
        ]
        rule = _make_rule(
            required_regions={"Header"},
            optional_regions=["Header", "Data"],
        )
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 1

    def test_optional_region_wrong_order_rejected(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="Data", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name="Header", timestamp=_ts(0.001)
            ),
        ]
        rule = _make_rule(
            required_regions={"Header"},
            optional_regions=["Header", "Data"],
        )
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 0

    def test_optional_region_absent_is_fine(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="Header", timestamp=_ts(0)),
        ]
        rule = _make_rule(
            required_regions={"Header"},
            optional_regions=["Header", "Data"],
        )
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 1


# ===========================================================================
# Multiple required regions
# ===========================================================================


class TestMultipleRequiredRegions:
    def test_all_required_present(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="B", timestamp=_ts(0.001)),
        ]
        rule = _make_rule(required_regions={"A", "B"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 1

    def test_one_required_missing(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
        ]
        rule = _make_rule(required_regions={"A", "B"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 0


# ===========================================================================
# Timeline duration in result
# ===========================================================================


class TestTimelineDuration:
    def test_empty_timeline_duration(self) -> None:
        result = PhaseDetector([]).detect(build_timeline([]))
        assert result.timeline_duration == timedelta()

    def test_nonempty_timeline_duration(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.2)
            ),
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert result.timeline_duration == timedelta(seconds=0.2)


# ===========================================================================
# Model validation
# ===========================================================================


class TestModelValidation:
    def test_rule_rejects_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            PhaseRule(name="", description="desc", required_regions=set())

    def test_rule_rejects_empty_description(self) -> None:
        with pytest.raises(ValidationError):
            PhaseRule(name="R", description="", required_regions=set())

    def test_rule_rejects_zero_minimum_reads(self) -> None:
        with pytest.raises(ValidationError):
            PhaseRule(
                name="R", description="d", required_regions=set(), minimum_reads=0
            )

    def test_rule_rejects_negative_minimum_reads(self) -> None:
        with pytest.raises(ValidationError):
            PhaseRule(
                name="R", description="d", required_regions=set(), minimum_reads=-1
            )

    def test_phase_rejects_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            Phase(
                name="",
                description="d",
                start_time="2026-01-15T12:00:00+00:00",
                end_time="2026-01-15T12:00:00+00:00",
                duration=timedelta(),
            )

    def test_phase_rejects_empty_start_time(self) -> None:
        with pytest.raises(ValidationError):
            Phase(
                name="P",
                description="d",
                start_time="",
                end_time="2026-01-15T12:00:00+00:00",
                duration=timedelta(),
            )

    def test_result_rejects_negative_confidence(self) -> None:
        with pytest.raises(ValidationError):
            PhaseDetectionResult(
                phases=[], confidence=-0.1, timeline_duration=timedelta()
            )

    def test_result_rejects_confidence_above_one(self) -> None:
        with pytest.raises(ValidationError):
            PhaseDetectionResult(
                phases=[], confidence=1.1, timeline_duration=timedelta()
            )


# ===========================================================================
# Serialization
# ===========================================================================


class TestSerialization:
    def test_phase_json_roundtrip(self) -> None:
        phase = Phase(
            name="P",
            description="d",
            start_time="2026-01-15T12:00:00+00:00",
            end_time="2026-01-15T12:00:00+00:00",
            duration=timedelta(),
        )
        json_str = phase.model_dump_json()
        restored = Phase.model_validate_json(json_str)
        assert phase == restored

    def test_result_json_roundtrip(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        json_str = result.model_dump_json()
        restored = PhaseDetectionResult.model_validate_json(json_str)
        assert result == restored

    def test_rule_json_roundtrip(self) -> None:
        rule = _make_rule(required_regions={".text"}, minimum_reads=3)
        json_str = rule.model_dump_json()
        restored = PhaseRule.model_validate_json(json_str)
        assert rule == restored


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_single_entry_single_rule(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
        ]
        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 1

    def test_repeated_region_creates_separate_runs(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="B", timestamp=_ts(0.001)),
            _make_mapped(offset=200, length=100, region_name="A", timestamp=_ts(0.002)),
        ]
        rule = _make_rule(required_regions={"A"})
        result = PhaseDetector([rule]).detect(build_timeline(events))
        assert len(result.phases) == 1

    def test_generator_input(self) -> None:
        def gen() -> object:
            for i in range(5):
                yield _make_mapped(
                    offset=i * 100,
                    length=100,
                    region_name=".text",
                    timestamp=_ts(i * 0.001),
                )

        rule = _make_rule(required_regions={".text"})
        result = PhaseDetector([rule]).detect(build_timeline(gen()))  # type: ignore[arg-type]
        assert len(result.phases) == 1

    def test_large_timeline(self) -> None:
        events = [
            _make_mapped(
                offset=i, length=10, region_name=f"R{i % 3}", timestamp=_ts(i * 0.001)
            )
            for i in range(300)
        ]
        rules = [_make_rule(name=f"R{i}", required_regions={f"R{i}"}) for i in range(3)]
        result = PhaseDetector(rules).detect(build_timeline(events))
        assert len(result.phases) == 3


# ===========================================================================
# Timeline to phases
# ===========================================================================


class TestTimelineToPhases:
    def test_groups_consecutive_entries(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
            _make_mapped(
                offset=100, length=100, region_name=".text", timestamp=_ts(0.001)
            ),
            _make_mapped(
                offset=200, length=100, region_name="Import", timestamp=_ts(0.002)
            ),
        ]
        detector = PhaseDetector()
        phases = detector.timeline_to_phases(build_timeline(events))
        assert len(phases) == 2
        assert phases[0].name == ".text"
        assert phases[1].name == "Import"

    def test_returns_empty_for_empty_timeline(self) -> None:
        detector = PhaseDetector()
        phases = detector.timeline_to_phases(build_timeline([]))
        assert phases == []

    def test_phase_has_correct_time_bounds(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="A", timestamp=_ts(0.005)),
        ]
        detector = PhaseDetector()
        phases = detector.timeline_to_phases(build_timeline(events))
        assert phases[0].start_time == _ts(0).isoformat()
        assert phases[0].end_time == _ts(0.005).isoformat()

    def test_phase_has_evidence(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="A", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="A", timestamp=_ts(0.001)),
        ]
        detector = PhaseDetector()
        phases = detector.timeline_to_phases(build_timeline(events))
        assert len(phases[0].evidence) == 2

    def test_sorted_by_start_time(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="C", timestamp=_ts(0)),
            _make_mapped(offset=100, length=100, region_name="A", timestamp=_ts(0.001)),
        ]
        detector = PhaseDetector()
        phases = detector.timeline_to_phases(build_timeline(events))
        assert phases[0].name == "C"
        assert phases[1].name == "A"


# ===========================================================================
# Matched / unmatched rules
# ===========================================================================


class TestMatchedUnmatchedRules:
    def test_matched_rules_returns_dict(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
        ]
        rule = _make_rule(required_regions={".text"})
        detector = PhaseDetector([rule])
        matched = detector.matched_rules(build_timeline(events))
        assert ".text" not in matched
        assert "Test Rule" in matched

    def test_unmatched_rules_returns_list(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="Foo", timestamp=_ts(0)),
        ]
        rule = _make_rule(required_regions={".text"})
        detector = PhaseDetector([rule])
        unmatched = detector.unmatched_rules(build_timeline(events))
        assert len(unmatched) == 1
        assert unmatched[0].name == "Test Rule"

    def test_all_matched_empty_unmatched(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name=".text", timestamp=_ts(0)),
        ]
        rule = _make_rule(required_regions={".text"})
        detector = PhaseDetector([rule])
        assert len(detector.unmatched_rules(build_timeline(events))) == 0

    def test_all_unmatched_empty_matched(self) -> None:
        events = [
            _make_mapped(offset=0, length=100, region_name="Foo", timestamp=_ts(0)),
        ]
        rule = _make_rule(required_regions={".text"})
        detector = PhaseDetector([rule])
        assert len(detector.matched_rules(build_timeline(events))) == 0


# ===========================================================================
# Phase summary
# ===========================================================================


class TestPhaseSummary:
    def test_empty_phases(self) -> None:
        detector = PhaseDetector()
        result = PhaseDetectionResult(
            phases=[], confidence=0.0, timeline_duration=timedelta()
        )
        summary = detector.phase_summary(result)
        assert "No phases" in summary

    def test_single_phase(self) -> None:
        phase = Phase(
            name="Header",
            description="d",
            start_time="2026-01-15T12:00:00+00:00",
            end_time="2026-01-15T12:00:01+00:00",
            duration=timedelta(seconds=1),
        )
        result = PhaseDetectionResult(
            phases=[phase], confidence=0.85, timeline_duration=timedelta(seconds=5)
        )
        detector = PhaseDetector()
        summary = detector.phase_summary(result)
        assert "Header" in summary
        assert "85%" in summary

    def test_multiple_phases(self) -> None:
        phases = [
            Phase(
                name=f"P{i}",
                description="d",
                start_time=f"2026-01-15T12:00:0{i}+00:00",
                end_time=f"2026-01-15T12:00:0{i}+00:00",
                duration=timedelta(seconds=i),
            )
            for i in range(3)
        ]
        result = PhaseDetectionResult(
            phases=phases, confidence=0.75, timeline_duration=timedelta(seconds=10)
        )
        detector = PhaseDetector()
        summary = detector.phase_summary(result)
        assert "3 phase(s)" in summary
        assert "P0" in summary
        assert "P1" in summary
        assert "P2" in summary
