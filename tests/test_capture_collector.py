"""Integration tests for the Collector engine."""

from __future__ import annotations

import json
from pathlib import Path

from defenderatlas.capture.collector import (
    CollectionSummary,
    Collector,
    CollectorConfig,
)
from tests._fakes import (
    FAKE_PROCMON_SOURCE,
    FAKE_WORKER_FAILURE_SOURCE,
    FAKE_WORKER_SUCCESS_SOURCE,
)


def _make_sample(path: Path, name: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / name).write_bytes(b"MZ" + b"\x00" * 32)


def _config(
    dataset_root: Path,
    experiment_root: Path,
    procmon: Path | None,
    worker: Path,
) -> CollectorConfig:
    return CollectorConfig(
        dataset_root=dataset_root,
        experiment_root=experiment_root,
        working_directory=Path.home() / "Downloads",
        procmon_path=procmon,
        trigger_worker_path=worker,
        trigger_timeout_ms=50,
    )


def test_full_pipeline_produces_complete_experiment(
    tmp_path: Path, fake_script_factory
) -> None:
    dataset = tmp_path / "dataset"
    _make_sample(dataset, "sample.exe")
    _make_sample(dataset, "lib.dll")

    procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    worker = fake_script_factory("trigger_worker", FAKE_WORKER_SUCCESS_SOURCE)

    experiment_root = tmp_path / "experiments"
    summary = Collector(_config(dataset, experiment_root, procmon, worker)).run()

    assert isinstance(summary, CollectionSummary)
    assert summary.processed == 2
    assert summary.successful == 2
    assert summary.failed == 0
    assert summary.elapsed_seconds >= 0

    for identifier in ("000001", "000002"):
        experiment = experiment_root / identifier
        for filename in (
            "sample.exe",
            "capture.pml",
            "capture.csv",
            "filtered.csv",
            "metadata.json",
            "manifest.json",
            "trigger.json",
        ):
            assert (experiment / filename).is_file(), filename

        metadata = json.loads(
            (experiment / "metadata.json").read_text(encoding="utf-8")
        )
        assert metadata["result"] == "success"
        manifest = json.loads(
            (experiment / "manifest.json").read_text(encoding="utf-8")
        )
        assert manifest["status"] == "completed"

    sample_experiment = experiment_root / "000002"
    filtered = (sample_experiment / "filtered.csv").read_text(encoding="utf-8-sig")
    assert "MsMpEng.exe" in filtered
    assert "notepad.exe" not in filtered


def test_trigger_failure_records_failed_experiment_without_aborting(
    tmp_path: Path, fake_script_factory
) -> None:
    dataset = tmp_path / "dataset"
    _make_sample(dataset, "bad.exe")

    procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    worker = fake_script_factory("trigger_worker", FAKE_WORKER_FAILURE_SOURCE)

    experiment_root = tmp_path / "experiments"
    summary = Collector(_config(dataset, experiment_root, procmon, worker)).run()

    assert summary.processed == 1
    assert summary.successful == 0
    assert summary.failed == 1

    experiment = experiment_root / "000001"
    metadata = json.loads((experiment / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["result"] == "failed"
    manifest = json.loads((experiment / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"


def test_missing_procmon_still_records_failure(
    tmp_path: Path, fake_script_factory
) -> None:
    dataset = tmp_path / "dataset"
    _make_sample(dataset, "mspaint.exe")

    worker = fake_script_factory("trigger_worker", FAKE_WORKER_SUCCESS_SOURCE)
    experiment_root = tmp_path / "experiments"
    summary = Collector(_config(dataset, experiment_root, None, worker)).run()

    assert summary.failed == 1
    metadata = json.loads(
        (experiment_root / "000001" / "metadata.json").read_text(encoding="utf-8")
    )
    assert metadata["result"] == "failed"


def test_empty_dataset_yields_zero_summary(tmp_path: Path, fake_script_factory) -> None:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    worker = fake_script_factory("trigger_worker", FAKE_WORKER_SUCCESS_SOURCE)

    experiment_root = tmp_path / "experiments"
    summary = Collector(_config(dataset, experiment_root, None, worker)).run()

    assert summary.processed == 0
    assert summary.successful == 0
    assert summary.failed == 0
    assert not experiment_root.exists()


def test_sample_filenames_are_used_for_dynamic_filter(
    tmp_path: Path, fake_script_factory
) -> None:
    dataset = tmp_path / "dataset"
    _make_sample(dataset, "unique-driver.sys")

    procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    worker = fake_script_factory("trigger_worker", FAKE_WORKER_SUCCESS_SOURCE)

    experiment_root = tmp_path / "experiments"
    Collector(_config(dataset, experiment_root, procmon, worker)).run()

    experiment = experiment_root / "000001"
    assert (experiment / "sample.exe").is_file()
    metadata = json.loads((experiment / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["relative_path"] == "unique-driver.sys"
    assert metadata["sample"] == "unique-driver.sys"
