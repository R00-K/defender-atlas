"""Unit tests for the AttachmentExecute trigger."""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenderatlas.capture.trigger import (
    AttachmentTrigger,
    TriggerResult,
)
from tests._fakes import FAKE_WORKER_FAILURE_SOURCE, FAKE_WORKER_SUCCESS_SOURCE

if TYPE_CHECKING:
    from pathlib import Path


def test_trigger_success(fake_script_factory, tmp_path: Path) -> None:
    worker = fake_script_factory("trigger_worker", FAKE_WORKER_SUCCESS_SOURCE)
    trigger = AttachmentTrigger(worker, "https://example.com/download", timeout=10)
    result = trigger.run(tmp_path / "sample.exe")
    assert isinstance(result, TriggerResult)
    assert result.success
    assert "completed" in result.message


def test_trigger_failure(fake_script_factory, tmp_path: Path) -> None:
    worker = fake_script_factory("trigger_worker", FAKE_WORKER_FAILURE_SOURCE)
    trigger = AttachmentTrigger(worker, "https://example.com/download", timeout=10)
    result = trigger.run(tmp_path / "sample.exe")
    assert not result.success
    assert "0x80004005" in result.message


def test_trigger_missing_worker(tmp_path: Path) -> None:
    trigger = AttachmentTrigger(tmp_path / "missing.exe", "https://example.com", 10)
    result = trigger.run(tmp_path / "sample.exe")
    assert not result.success
    assert "not found" in result.message


def test_trigger_timeout(fake_script_factory, tmp_path: Path) -> None:
    worker = fake_script_factory(
        "trigger_worker",
        "def main():\n"
        "    import time\n"
        "    time.sleep(10)\n"
        "\n\n"
        'if __name__ == "__main__":\n'
        "    main()\n",
    )
    trigger = AttachmentTrigger(worker, "https://example.com/download", timeout=0.2)
    result = trigger.run(tmp_path / "sample.exe")
    assert not result.success
    assert "timed out" in result.message
