"""Unit tests for the Windows Task Scheduler integration."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from defenderatlas.capture import taskscheduler as ts


def _result(stdout: str = "", stderr: str = "", returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


class TestTaskExists:
    def test_detects_existing_task(self, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_run_ps", lambda _c: _result(stdout="EXISTS"))
        assert ts.task_exists("DefenderAtlas ProcMon") is True

    def test_detects_missing_task(self, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_run_ps", lambda _c: _result(stdout="MISSING"))
        assert ts.task_exists("DefenderAtlas ProcMon") is False

    def test_failure_reports_missing(self, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_run_ps", lambda _c: None)
        assert ts.task_exists("DefenderAtlas ProcMon") is False


class TestIsTaskRunning:
    def test_running_state(self, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_run_ps", lambda _c: _result(stdout="RUNNING"))
        assert ts.is_task_running("DefenderAtlas ProcMon") is True

    def test_idle_state(self, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_run_ps", lambda _c: _result(stdout="IDLE"))
        assert ts.is_task_running("DefenderAtlas ProcMon") is False

    def test_missing_task(self, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_run_ps", lambda _c: _result(stdout="MISSING"))
        assert ts.is_task_running("DefenderAtlas ProcMon") is False


class TestInstall:
    def test_install_success(self, tmp_path: Path, monkeypatch) -> None:
        calls: list[str] = []

        def fake_run(command: str) -> SimpleNamespace:
            calls.append(command)
            return _result()

        monkeypatch.setattr(ts, "_launcher_dir", lambda: tmp_path)
        monkeypatch.setattr(ts, "_run_ps", fake_run)
        assert (
            ts.install_procmon_task("DefenderAtlas ProcMon", tmp_path / "Procmon64.exe")
            is True
        )
        assert calls
        assert "New-ScheduledTaskPrincipal" in calls[0]
        assert "-RunLevel Highest" in calls[0]
        assert "cmd.exe" in calls[0]
        launcher = tmp_path / ts._LAUNCHER_FILE
        assert launcher.is_file()
        content = launcher.read_text(encoding="utf-8")
        assert "/BackingFile" in content
        assert "start /wait" in content

    def test_install_powershell_failure(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_launcher_dir", lambda: tmp_path)
        monkeypatch.setattr(ts, "_run_ps", lambda _c: None)
        assert (
            ts.install_procmon_task("DefenderAtlas ProcMon", tmp_path / "Procmon64.exe")
            is False
        )

    def test_install_cmdlet_error(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_launcher_dir", lambda: tmp_path)
        monkeypatch.setattr(
            ts, "_run_ps", lambda _c: _result(stderr="access denied", returncode=1)
        )
        assert (
            ts.install_procmon_task("DefenderAtlas ProcMon", tmp_path / "Procmon64.exe")
            is False
        )


class TestUninstall:
    def test_uninstall_success(self, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_run_ps", lambda _c: _result())
        assert ts.uninstall_procmon_task("DefenderAtlas ProcMon") is True

    def test_uninstall_powershell_failure(self, monkeypatch) -> None:
        monkeypatch.setattr(ts, "_run_ps", lambda _c: None)
        assert ts.uninstall_procmon_task("DefenderAtlas ProcMon") is False

    def test_uninstall_cmdlet_error(self, monkeypatch) -> None:
        monkeypatch.setattr(
            ts, "_run_ps", lambda _c: _result(stderr="task not found", returncode=1)
        )
        assert ts.uninstall_procmon_task("DefenderAtlas ProcMon") is False


class TestLaunch:
    def test_launch_success(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(ts, "task_exists", lambda _name: True)
        monkeypatch.setattr(ts, "_launcher_dir", lambda: tmp_path)
        calls: list[str] = []

        def fake_run(command: str) -> SimpleNamespace:
            calls.append(command)
            return _result()

        monkeypatch.setattr(ts, "_run_ps", fake_run)
        pml = tmp_path / "000001" / "capture.pml"
        assert ts.launch_procmon_task("DefenderAtlas ProcMon", pml) is True
        assert calls
        assert "Start-ScheduledTask" in calls[0]
        pml_file = tmp_path / ts._PML_FILE
        assert pml_file.is_file()
        assert pml_file.read_text(encoding="utf-8").strip() == str(pml)

    def test_launch_missing_task(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(ts, "task_exists", lambda _name: False)
        monkeypatch.setattr(ts, "_run_ps", lambda _c: _result())
        assert (
            ts.launch_procmon_task("DefenderAtlas ProcMon", tmp_path / "capture.pml")
            is False
        )

    def test_launch_run_failure(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(ts, "task_exists", lambda _name: True)
        monkeypatch.setattr(ts, "_launcher_dir", lambda: tmp_path)
        monkeypatch.setattr(
            ts, "_run_ps", lambda _c: _result(stderr="boom", returncode=1)
        )
        assert (
            ts.launch_procmon_task("DefenderAtlas ProcMon", tmp_path / "capture.pml")
            is False
        )


class TestLauncherDir:
    def test_uses_localappdata(self, monkeypatch) -> None:
        monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\alice\AppData\Local")
        assert (
            ts._launcher_dir()
            == Path(r"C:\Users\alice\AppData\Local") / "DefenderAtlas"
        )
