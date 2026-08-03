"""Unit tests for experiment artifact generation."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from defenderatlas.capture.metadata import (
    build_manifest,
    build_metadata,
    build_trigger_info,
    utc_timestamp,
    write_json,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_utc_timestamp_is_iso8601() -> None:
    value = utc_timestamp()
    assert value.endswith("+00:00")


def test_build_metadata_contains_required_fields() -> None:
    meta = build_metadata(
        experiment_id=1,
        sample="sample.exe",
        relative_path="signed/medium/sample.exe",
        sha256="ab" * 32,
        size=12345,
        trigger="trigger_worker.exe",
        completion_strategy="timeout",
        collector_version="1.0",
        procmon_profile="minimal",
        category="signed",
        result="success",
    )
    assert meta["experiment_id"] == 1
    assert meta["sample"] == "sample.exe"
    assert meta["relative_path"] == "signed/medium/sample.exe"
    assert meta["sha256"] == "ab" * 32
    assert meta["size"] == 12345
    assert meta["trigger"] == "trigger_worker.exe"
    assert meta["completion_strategy"] == "timeout"
    assert meta["collector_version"] == "1.0"
    assert meta["procmon_profile"] == "minimal"
    assert meta["category"] == "signed"
    assert meta["result"] == "success"
    assert "timestamp" in meta


def test_build_manifest_marks_completed() -> None:
    manifest = build_manifest(experiment_id=3, status="completed", sample="sample.exe")
    assert manifest["experiment"] == 3
    assert manifest["status"] == "completed"
    assert manifest["sample"] == "sample.exe"


def test_build_manifest_marks_failed() -> None:
    manifest = build_manifest(experiment_id=4, status="failed", sample="sample.exe")
    assert manifest["status"] == "failed"


def test_build_trigger_info_fields() -> None:
    info = build_trigger_info(
        trigger="trigger_worker.exe",
        source_url="https://example.com/download",
        working_copy="sample.exe",
        completion_strategy="timeout",
        procmon_profile="minimal",
        collector_version="1.0",
    )
    assert info["trigger"] == "trigger_worker.exe"
    assert info["source_url"] == "https://example.com/download"
    assert info["working_copy"] == "sample.exe"
    assert info["completion_strategy"] == "timeout"
    assert info["procmon_profile"] == "minimal"
    assert info["collector_version"] == "1.0"


def test_write_json_round_trips(tmp_path: Path) -> None:
    target = tmp_path / "metadata.json"
    payload = {"key": "value", "nested": [1, 2, 3]}
    write_json(target, payload)
    assert json.loads(target.read_text(encoding="utf-8")) == payload
