"""Unit tests for experiment directory allocation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenderatlas.capture.experiment import ExperimentDirectory

if TYPE_CHECKING:
    from pathlib import Path


def test_first_experiment_is_zero_padded(tmp_path: Path) -> None:
    experiment = ExperimentDirectory(tmp_path)
    assert experiment.id == 1
    assert experiment.path.name == "000001"
    assert experiment.path.is_dir()


def test_experiments_are_sequential(tmp_path: Path) -> None:
    first = ExperimentDirectory(tmp_path)
    second = ExperimentDirectory(tmp_path)
    assert first.id == 1
    assert second.id == 2
    assert second.path.name == "000002"


def test_never_reuses_existing_ids(tmp_path: Path) -> None:
    (tmp_path / "000007").mkdir()
    experiment = ExperimentDirectory(tmp_path)
    assert experiment.id == 8
    assert experiment.path.name == "000008"


def test_skips_over_holes(tmp_path: Path) -> None:
    (tmp_path / "000001").mkdir()
    (tmp_path / "000003").mkdir()
    experiment = ExperimentDirectory(tmp_path)
    assert experiment.id == 4


def test_paths_live_inside_experiment_dir(tmp_path: Path) -> None:
    experiment = ExperimentDirectory(tmp_path)
    assert experiment.sample_path.parent == experiment.path
    assert experiment.pml_path.parent == experiment.path
    assert experiment.csv_path.parent == experiment.path
    assert experiment.filtered_csv_path.parent == experiment.path
    assert experiment.metadata_path.parent == experiment.path
    assert experiment.manifest_path.parent == experiment.path
    assert experiment.trigger_info_path.parent == experiment.path


def test_file_names_match_spec(tmp_path: Path) -> None:
    experiment = ExperimentDirectory(tmp_path)
    assert experiment.sample_path.name == "sample.exe"
    assert experiment.pml_path.name == "capture.pml"
    assert experiment.csv_path.name == "capture.csv"
    assert experiment.filtered_csv_path.name == "filtered.csv"
    assert experiment.metadata_path.name == "metadata.json"
    assert experiment.manifest_path.name == "manifest.json"
    assert experiment.trigger_info_path.name == "trigger.json"
