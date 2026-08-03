"""Unit tests for dataset sample discovery."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from defenderatlas.capture import dataset as dataset_module
from defenderatlas.capture.dataset import DatasetError, enumerate_samples, sha256_file

if TYPE_CHECKING:
    from pathlib import Path


def _make_dataset(root: Path, files: list[str]) -> None:
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"MZ" + b"\x00" * 16)


def test_enumerates_supported_files_recursively(tmp_path: Path) -> None:
    _make_dataset(
        tmp_path,
        [
            "a/b/mspaint.exe",
            "a/c/driver.sys",
            "a/lib.dll",
            "notes.txt",
            "readme.md",
        ],
    )
    samples, skipped = enumerate_samples(tmp_path)
    assert skipped == 0
    assert [s.relative_path for s in samples] == [
        "a/b/mspaint.exe",
        "a/c/driver.sys",
        "a/lib.dll",
    ]


def test_skips_unsupported_suffixes(tmp_path: Path) -> None:
    _make_dataset(tmp_path, ["a.exe", "b.bin", "c.obj"])
    samples, skipped = enumerate_samples(tmp_path)
    assert [s.relative_path for s in samples] == ["a.exe"]
    assert skipped == 0


def test_dll_is_supported(tmp_path: Path) -> None:
    _make_dataset(tmp_path, ["lib.dll"])
    samples, skipped = enumerate_samples(tmp_path)
    assert skipped == 0
    assert len(samples) == 1
    assert samples[0].relative_path == "lib.dll"


def test_records_category_from_layout(tmp_path: Path) -> None:
    _make_dataset(tmp_path, ["signed/medium/mspaint.exe", "top.exe"])
    samples, _ = enumerate_samples(tmp_path)
    by_name = {s.relative_path: s for s in samples}
    assert by_name["signed/medium/mspaint.exe"].category == "signed"
    assert by_name["top.exe"].category == ""


def test_hashes_and_sizes(tmp_path: Path) -> None:
    _make_dataset(tmp_path, ["mspaint.exe"])
    samples, _ = enumerate_samples(tmp_path)
    assert len(samples) == 1
    assert samples[0].size == 18
    assert len(samples[0].sha256) == 64
    assert samples[0].sha256 == sha256_file(tmp_path / "mspaint.exe")


def test_suffixes_are_case_insensitive(tmp_path: Path) -> None:
    _make_dataset(tmp_path, ["upper.EXE", "upper.DLL", "upper.SYS"])
    samples, _ = enumerate_samples(tmp_path)
    assert {s.relative_path for s in samples} == {
        "upper.DLL",
        "upper.EXE",
        "upper.SYS",
    }


def test_empty_dataset(tmp_path: Path) -> None:
    samples, skipped = enumerate_samples(tmp_path)
    assert samples == []
    assert skipped == 0


def test_missing_root_raises(tmp_path: Path) -> None:
    with pytest.raises(DatasetError):
        enumerate_samples(tmp_path / "nope")


def test_unreadable_file_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_dataset(tmp_path, ["a.exe", "b.exe"])
    original_hash = dataset_module.sha256_file

    def broken_hash(path: Path) -> str:
        if path.name == "b.exe":
            raise OSError("locked")
        return original_hash(path)

    monkeypatch.setattr(dataset_module, "sha256_file", broken_hash)
    samples, skipped = enumerate_samples(tmp_path)
    assert [s.relative_path for s in samples] == ["a.exe"]
    assert skipped == 1
