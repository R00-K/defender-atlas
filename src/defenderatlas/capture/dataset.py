"""Dataset sample discovery for the DefenderAtlas Collector.

The Collector discovers candidate samples by walking the dataset directory
tree and selecting files with a supported PE extension (``.exe``, ``.dll``,
``.sys``). Only light file metadata (size, SHA-256) is collected here; the
Collector deliberately does NOT perform PE analysis.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)

SUPPORTED_SUFFIXES: frozenset[str] = frozenset({".exe", ".dll", ".sys"})


class DatasetError(Exception):
    """Raised when the dataset root is missing or unusable."""


@dataclass(frozen=True)
class Sample:
    """One candidate PE sample discovered in the dataset tree."""

    path: Path
    size: int
    sha256: str
    relative_path: str
    category: str


def sha256_file(path: Path) -> str:
    """Compute the lowercase hex SHA-256 digest of *path*.

    Raises
    ------
    OSError
        If the file cannot be opened or read.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def enumerate_samples(dataset_root: Path) -> tuple[list[Sample], int]:
    """Discover every supported PE sample under *dataset_root*.

    Files with a supported extension that cannot be hashed are logged and
    counted as skipped so a single unreadable file never aborts collection.

    Returns
    -------
    tuple[list[Sample], int]
        The sorted list of samples and the number of skipped files.
    """
    if not dataset_root.is_dir():
        raise DatasetError(f"Dataset directory does not exist: {dataset_root}")

    samples: list[Sample] = []
    skipped = 0
    for path in sorted(dataset_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
            sha256 = sha256_file(path)
        except OSError as exc:
            log.warning("Cannot read sample, skipping: %s (%s)", path, exc)
            skipped += 1
            continue

        relative_path = path.relative_to(dataset_root).as_posix()
        first, separator, _ = relative_path.partition("/")
        category = first if separator else ""
        samples.append(
            Sample(
                path=path,
                size=size,
                sha256=sha256,
                relative_path=relative_path,
                category=category,
            )
        )

    samples.sort(key=lambda sample: sample.relative_path)
    return samples, skipped
