"""Experiment metadata, manifest and trigger JSON artifacts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def utc_timestamp() -> str:
    """Current UTC time as an ISO 8601 string."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def build_metadata(
    *,
    experiment_id: int,
    sample: str,
    relative_path: str,
    sha256: str,
    size: int,
    trigger: str,
    completion_strategy: str,
    collector_version: str,
    procmon_profile: str,
    category: str,
    result: str,
) -> dict[str, object]:
    """Build the metadata.json experiment descriptor."""
    return {
        "experiment_id": experiment_id,
        "sample": sample,
        "relative_path": relative_path,
        "sha256": sha256,
        "size": size,
        "trigger": trigger,
        "completion_strategy": completion_strategy,
        "collector_version": collector_version,
        "procmon_profile": procmon_profile,
        "category": category,
        "timestamp": utc_timestamp(),
        "result": result,
    }


def build_manifest(
    *, experiment_id: int, status: str, sample: str
) -> dict[str, object]:
    """Build the manifest.json artifact index."""
    return {
        "experiment": experiment_id,
        "status": status,
        "sample": sample,
        "capture": {
            "pml": "capture.pml",
            "csv": "capture.csv",
            "filtered": "filtered.csv",
        },
    }


def build_trigger_info(
    *,
    trigger: str,
    source_url: str,
    working_copy: str,
    completion_strategy: str,
    procmon_profile: str,
    collector_version: str,
) -> dict[str, object]:
    """Build the trigger.json reproduction record."""
    return {
        "trigger": trigger,
        "source_url": source_url,
        "working_copy": working_copy,
        "completion_strategy": completion_strategy,
        "procmon_profile": procmon_profile,
        "collector_version": collector_version,
    }


def write_json(path: Path, data: dict[str, object]) -> None:
    """Write *data* to *path* as pretty-printed JSON."""
    path.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
