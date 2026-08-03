"""Unit tests for core data models."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from defenderatlas.models import (
    AnalysisResult,
    Finding,
    ReadEvent,
    ScanPhase,
    Severity,
    Statistics,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _make_read_event(**overrides: object) -> ReadEvent:
    defaults: dict[str, object] = {
        "timestamp": _now(),
        "process_name": "MsMpEng.exe",
        "process_id": 1234,
        "operation": "ReadFile",
        "path": r"C:\Windows\System32\test.dll",
        "offset": 0,
        "length": 4096,
        "result": "SUCCESS",
    }
    defaults.update(overrides)
    return ReadEvent(**defaults)


def _make_scan_phase(**overrides: object) -> ScanPhase:
    defaults: dict[str, object] = {
        "id": 1,
        "name": "PE Header",
        "description": "Initial read of the DOS/PE headers.",
        "start_offset": 0,
        "end_offset": 1023,
    }
    defaults.update(overrides)
    return ScanPhase(**defaults)


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "title": "Suspicious header access",
        "severity": Severity.MEDIUM,
        "description": "Defender read the PE header at offset 0.",
        "evidence": ["ReadFile at offset 0, length 64"],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _make_statistics(**overrides: object) -> Statistics:
    defaults: dict[str, object] = {
        "total_reads": 150,
        "unique_offsets": 80,
        "repeated_reads": 70,
        "bytes_read": 614400,
        "read_amplification": 1.875,
    }
    defaults.update(overrides)
    return Statistics(**defaults)


def _make_result(**overrides: object) -> AnalysisResult:
    defaults: dict[str, object] = {
        "file_type": "PE32",
        "findings": [_make_finding()],
        "phases": [_make_scan_phase()],
        "statistics": _make_statistics(),
    }
    defaults.update(overrides)
    return AnalysisResult(**defaults)


# ===========================================================================
# Severity
# ===========================================================================


class TestSeverity:
    def test_all_members_exist(self) -> None:
        assert Severity.LOW == "low"
        assert Severity.MEDIUM == "medium"
        assert Severity.HIGH == "high"
        assert Severity.CRITICAL == "critical"

    def test_string_value(self) -> None:
        assert Severity("high") is Severity.HIGH

    def test_invalid_value(self) -> None:
        with pytest.raises(ValueError):
            Severity("invalid")


# ===========================================================================
# ReadEvent
# ===========================================================================


class TestReadEvent:
    def test_valid_construction(self) -> None:
        ts = _now()
        ev = _make_read_event(timestamp=ts)
        assert ev.timestamp == ts
        assert ev.process_name == "MsMpEng.exe"
        assert ev.process_id == 1234
        assert ev.operation == "ReadFile"
        assert ev.offset == 0
        assert ev.length == 4096
        assert ev.result == "SUCCESS"

    def test_zero_offset_allowed(self) -> None:
        ev = _make_read_event(offset=0)
        assert ev.offset == 0

    def test_large_offset_allowed(self) -> None:
        ev = _make_read_event(offset=2**53)
        assert ev.offset == 2**53

    def test_rejects_empty_process_name(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_read_event(process_name="")

    def test_rejects_zero_process_id(self) -> None:
        with pytest.raises(ValidationError, match="greater than 0"):
            _make_read_event(process_id=0)

    def test_rejects_negative_process_id(self) -> None:
        with pytest.raises(ValidationError, match="greater than 0"):
            _make_read_event(process_id=-1)

    def test_rejects_negative_offset(self) -> None:
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            _make_read_event(offset=-1)

    def test_rejects_zero_length(self) -> None:
        with pytest.raises(ValidationError, match="greater than 0"):
            _make_read_event(length=0)

    def test_rejects_empty_operation(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_read_event(operation="")

    def test_rejects_empty_path(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_read_event(path="")

    def test_rejects_empty_result(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_read_event(result="")

    def test_serialization_roundtrip(self) -> None:
        ev = _make_read_event()
        dumped = ev.model_dump()
        restored = ReadEvent.model_validate(dumped)
        assert ev == restored

    def test_json_roundtrip(self) -> None:
        ev = _make_read_event()
        json_str = ev.model_dump_json()
        restored = ReadEvent.model_validate_json(json_str)
        assert ev == restored

    def test_json_is_valid_json(self) -> None:
        ev = _make_read_event()
        parsed = json.loads(ev.model_dump_json())
        assert "timestamp" in parsed
        assert "process_name" in parsed
        assert parsed["process_id"] == 1234


# ===========================================================================
# ScanPhase
# ===========================================================================


class TestScanPhase:
    def test_valid_construction(self) -> None:
        phase = _make_scan_phase()
        assert phase.id == 1
        assert phase.name == "PE Header"
        assert phase.start_offset == 0
        assert phase.end_offset == 1023

    def test_end_offset_equals_start_offset(self) -> None:
        phase = _make_scan_phase(start_offset=500, end_offset=500)
        assert phase.start_offset == phase.end_offset

    def test_rejects_zero_id(self) -> None:
        with pytest.raises(ValidationError, match="greater than 0"):
            _make_scan_phase(id=0)

    def test_rejects_empty_name(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_scan_phase(name="")

    def test_rejects_empty_description(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_scan_phase(description="")

    def test_rejects_negative_start_offset(self) -> None:
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            _make_scan_phase(start_offset=-1)

    def test_rejects_negative_end_offset(self) -> None:
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            _make_scan_phase(end_offset=-1)

    def test_rejects_end_before_start(self) -> None:
        with pytest.raises(ValidationError):
            _make_scan_phase(start_offset=100, end_offset=50)

    def test_serialization_roundtrip(self) -> None:
        phase = _make_scan_phase()
        dumped = phase.model_dump()
        restored = ScanPhase.model_validate(dumped)
        assert phase == restored

    def test_json_roundtrip(self) -> None:
        phase = _make_scan_phase()
        json_str = phase.model_dump_json()
        restored = ScanPhase.model_validate_json(json_str)
        assert phase == restored


# ===========================================================================
# Finding
# ===========================================================================


class TestFinding:
    def test_valid_construction(self) -> None:
        f = _make_finding()
        assert f.title == "Suspicious header access"
        assert f.severity == Severity.MEDIUM
        assert len(f.evidence) == 1

    def test_empty_evidence_by_default(self) -> None:
        f = Finding(
            title="Test",
            severity=Severity.LOW,
            description="A test finding.",
        )
        assert f.evidence == []

    def test_rejects_empty_title(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_finding(title="")

    def test_rejects_empty_description(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_finding(description="")

    def test_invalid_severity(self) -> None:
        with pytest.raises(ValidationError):
            _make_finding(severity="extreme")

    def test_all_severity_levels(self) -> None:
        for sev in Severity:
            f = _make_finding(severity=sev)
            assert f.severity == sev

    def test_serialization_roundtrip(self) -> None:
        f = _make_finding()
        dumped = f.model_dump()
        restored = Finding.model_validate(dumped)
        assert f == restored

    def test_json_roundtrip(self) -> None:
        f = _make_finding()
        json_str = f.model_dump_json()
        restored = Finding.model_validate_json(json_str)
        assert f == restored


# ===========================================================================
# Statistics
# ===========================================================================


class TestStatistics:
    def test_valid_construction(self) -> None:
        s = _make_statistics()
        assert s.total_reads == 150
        assert s.unique_offsets == 80
        assert s.repeated_reads == 70
        assert s.bytes_read == 614400
        assert s.read_amplification == 1.875

    def test_zero_statistics(self) -> None:
        s = _make_statistics(
            total_reads=0,
            unique_offsets=0,
            repeated_reads=0,
            bytes_read=0,
            read_amplification=0.0,
        )
        assert s.total_reads == 0

    def test_rejects_negative_total_reads(self) -> None:
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            _make_statistics(total_reads=-1)

    def test_rejects_negative_unique_offsets(self) -> None:
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            _make_statistics(unique_offsets=-1)

    def test_rejects_negative_repeated_reads(self) -> None:
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            _make_statistics(repeated_reads=-1)

    def test_rejects_negative_bytes_read(self) -> None:
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            _make_statistics(bytes_read=-1)

    def test_rejects_negative_amplification(self) -> None:
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            _make_statistics(read_amplification=-0.5)

    def test_serialization_roundtrip(self) -> None:
        s = _make_statistics()
        dumped = s.model_dump()
        restored = Statistics.model_validate(dumped)
        assert s == restored

    def test_json_roundtrip(self) -> None:
        s = _make_statistics()
        json_str = s.model_dump_json()
        restored = Statistics.model_validate_json(json_str)
        assert s == restored


# ===========================================================================
# AnalysisResult
# ===========================================================================


class TestAnalysisResult:
    def test_valid_construction(self) -> None:
        r = _make_result()
        assert r.file_type == "PE32"
        assert len(r.findings) == 1
        assert len(r.phases) == 1
        assert r.statistics.total_reads == 150

    def test_empty_findings_and_phases(self) -> None:
        r = AnalysisResult(
            file_type="PDF",
            findings=[],
            phases=[],
            statistics=_make_statistics(),
        )
        assert r.findings == []
        assert r.phases == []

    def test_rejects_empty_file_type(self) -> None:
        with pytest.raises(ValidationError, match="at least 1 character"):
            _make_result(file_type="")

    def test_multiple_findings(self) -> None:
        f1 = _make_finding(title="Finding 1")
        f2 = _make_finding(title="Finding 2")
        r = _make_result(findings=[f1, f2])
        assert len(r.findings) == 2

    def test_multiple_phases(self) -> None:
        p1 = _make_scan_phase(id=1, name="Phase 1")
        p2 = _make_scan_phase(id=2, name="Phase 2")
        r = _make_result(phases=[p1, p2])
        assert len(r.phases) == 2

    def test_serialization_roundtrip(self) -> None:
        r = _make_result()
        dumped = r.model_dump()
        restored = AnalysisResult.model_validate(dumped)
        assert r == restored

    def test_json_roundtrip(self) -> None:
        r = _make_result()
        json_str = r.model_dump_json()
        restored = AnalysisResult.model_validate_json(json_str)
        assert r == restored

    def test_json_contains_nested_objects(self) -> None:
        r = _make_result()
        parsed = json.loads(r.model_dump_json())
        assert "findings" in parsed
        assert "phases" in parsed
        assert "statistics" in parsed
        assert parsed["statistics"]["total_reads"] == 150
        assert parsed["findings"][0]["severity"] == "medium"

    def test_model_dump_mode_json(self) -> None:
        r = _make_result()
        dumped = r.model_dump(mode="json")
        assert isinstance(dumped["statistics"]["read_amplification"], float)
        assert isinstance(dumped["findings"][0]["severity"], str)

    def test_validate_json_string(self) -> None:
        r = _make_result()
        json_str = r.model_dump_json()
        restored = AnalysisResult.model_validate_json(json_str)
        assert restored == r
