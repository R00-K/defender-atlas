"""Unit tests for ProcMon discovery and controller lifecycle."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from defenderatlas.capture import procmon as procmon_module
from defenderatlas.capture.procmon import ProcmonController, find_procmon
from tests._fakes import FAKE_PROCMON_SOURCE

if TYPE_CHECKING:
    from pathlib import Path


def _no_auto_detection(monkeypatch) -> None:
    """Disable machine-dependent ProcMon auto-discovery."""
    monkeypatch.setattr(procmon_module, "_PROCMON_CANDIDATES", ())
    monkeypatch.setattr(procmon_module.shutil, "which", lambda _name: None)


def test_find_procmon_env_var(tmp_path: Path, fake_script_factory, monkeypatch) -> None:
    exe = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    _no_auto_detection(monkeypatch)
    monkeypatch.setenv("DEFENDERATLAS_PROCMON", str(exe))
    assert find_procmon() == exe


def test_find_procmon_env_var_ignores_missing(
    tmp_path: Path, fake_script_factory, monkeypatch
) -> None:
    _no_auto_detection(monkeypatch)
    monkeypatch.setenv("DEFENDERATLAS_PROCMON", str(tmp_path / "missing.exe"))
    assert find_procmon() is None


def test_controller_start_wait_stop(tmp_path: Path, fake_script_factory) -> None:
    procmon = ProcmonController(fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE))
    pml = tmp_path / "capture.pml"
    assert procmon.start(pml)
    assert procmon.wait_until_ready(timeout=10)
    assert pml.is_file()
    assert procmon.is_running()
    assert procmon.stop(timeout=10)
    assert not procmon.is_running()


def test_controller_export_csv(tmp_path: Path, fake_script_factory) -> None:
    procmon = ProcmonController(fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE))
    pml = tmp_path / "capture.pml"
    csv_path = tmp_path / "capture.csv"
    procmon.start(pml)
    procmon.wait_until_ready(timeout=10)
    procmon.stop(timeout=10)
    assert procmon.export_csv(pml, csv_path, timeout=30)
    assert csv_path.is_file()
    content = csv_path.read_text(encoding="utf-8-sig")
    assert "MsMpEng.exe" in content


def test_export_csv_requires_nonempty_output(tmp_path: Path) -> None:
    procmon = ProcmonController(tmp_path / "missing.exe")
    assert not procmon.export_csv(tmp_path / "a.pml", tmp_path / "b.csv", timeout=1)


# ── task-based (elevated) launch ───────────────────────────────────────


def test_controller_start_via_scheduled_task(
    tmp_path: Path, fake_script_factory, monkeypatch
) -> None:
    exe = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    monkeypatch.setattr(procmon_module, "task_exists", lambda _name: True)
    monkeypatch.setattr(procmon_module, "launch_procmon_task", lambda *_: True)
    monkeypatch.setattr(procmon_module, "is_task_running", lambda _name: True)

    procmon = ProcmonController(exe, launch_method="task")
    pml = tmp_path / "capture.pml"
    assert procmon.start(pml)
    assert procmon._launched_via_task
    assert procmon._process is None
    assert procmon.pml_path == pml
    assert procmon.is_running()


def test_controller_wait_until_ready_via_task(
    tmp_path: Path, fake_script_factory, monkeypatch
) -> None:
    exe = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    monkeypatch.setattr(procmon_module, "task_exists", lambda _name: True)
    monkeypatch.setattr(procmon_module, "launch_procmon_task", lambda *_: True)
    monkeypatch.setattr(procmon_module, "is_task_running", lambda _name: True)

    procmon = ProcmonController(exe, launch_method="task")
    pml = tmp_path / "capture.pml"
    assert procmon.start(pml)
    pml.write_bytes(b"fake pml")
    assert procmon.wait_until_ready(timeout=10)


def test_controller_stop_via_task(
    tmp_path: Path, fake_script_factory, monkeypatch
) -> None:
    exe = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    monkeypatch.setattr(procmon_module, "task_exists", lambda _name: True)
    monkeypatch.setattr(procmon_module, "launch_procmon_task", lambda *_: True)
    state = {"running": True}
    monkeypatch.setattr(
        procmon_module, "is_task_running", lambda _name: state["running"]
    )

    procmon = ProcmonController(exe, launch_method="task")
    pml = tmp_path / "capture.pml"
    assert procmon.start(pml)
    state["running"] = False
    assert procmon.stop(timeout=10)


def test_controller_start_falls_back_when_task_missing(
    tmp_path: Path, fake_script_factory, monkeypatch, caplog
) -> None:
    exe = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    monkeypatch.setattr(procmon_module, "task_exists", lambda _name: False)

    procmon = ProcmonController(exe, launch_method="task")
    pml = tmp_path / "capture.pml"
    with caplog.at_level(logging.WARNING, logger=procmon_module.__name__):
        assert procmon.start(pml)
    assert not procmon._launched_via_task
    assert procmon._process is not None
    assert "falling back" in caplog.text


def test_controller_start_fails_when_task_launch_fails(
    tmp_path: Path, fake_script_factory, monkeypatch
) -> None:
    exe = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
    monkeypatch.setattr(procmon_module, "task_exists", lambda _name: True)
    monkeypatch.setattr(procmon_module, "launch_procmon_task", lambda *_: False)

    procmon = ProcmonController(exe, launch_method="task")
    assert not procmon.start(tmp_path / "capture.pml")
