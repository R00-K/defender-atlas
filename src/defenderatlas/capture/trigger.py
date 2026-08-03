"""Attachment trigger for the Collector.

The ``IAttachmentExecute::Save()`` download reproduction is executed in the
standalone, single-shot ``trigger_worker.exe`` process (the experimentally
verified lifecycle). Running the shell's attachment machinery out of process
crash-isolates the Collector: a shell background-thread crash kills only the
worker.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class TriggerResult:
    """Outcome of one trigger attempt."""

    success: bool
    message: str


def find_trigger_worker() -> Path | None:
    """Locate ``trigger_worker.exe``, or None when it cannot be found."""
    env_path = os.environ.get("DEFENDERATLAS_TRIGGER_WORKER")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return candidate

    for candidate in (
        Path("collector") / "trigger_worker.exe",
        Path(__file__).resolve().parents[3] / "collector" / "trigger_worker.exe",
    ):
        if candidate.is_file():
            return candidate

    found = shutil.which("trigger_worker.exe")
    return Path(found) if found else None


class AttachmentTrigger:
    """Runs the download reproduction via ``trigger_worker.exe``."""

    name = "attachment"

    def __init__(self, worker_path: Path, source_url: str, timeout: float) -> None:
        self.worker_path = worker_path
        self.source_url = source_url
        self.timeout = timeout

    def run(self, local_path: Path) -> TriggerResult:
        """Trigger ``IAttachmentExecute::Save()`` on *local_path*."""
        if not self.worker_path.is_file():
            return TriggerResult(False, f"trigger worker not found: {self.worker_path}")
        try:
            result = subprocess.run(
                [str(self.worker_path), str(local_path), self.source_url],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except (FileNotFoundError, OSError) as exc:
            return TriggerResult(False, f"failed to start trigger worker: {exc}")
        except subprocess.TimeoutExpired:
            return TriggerResult(
                False, f"trigger worker timed out after {self.timeout:g} s"
            )

        message = (result.stdout or "").strip()
        if result.returncode != 0:
            detail = message or "(no output)"
            return TriggerResult(
                False,
                f"trigger worker exited with code {result.returncode}: {detail}",
            )
        return TriggerResult(
            True, message or "IAttachmentExecute::Save completed successfully"
        )
