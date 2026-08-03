"""Unit tests for the DefenderAtlas CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from defenderatlas import __version__
from defenderatlas.cli.app import app
from tests._fakes import FAKE_PROCMON_SOURCE, FAKE_WORKER_SUCCESS_SOURCE

runner = CliRunner()


# ── fixtures / helpers ─────────────────────────────────────────────────


def _make_sample(tmp_path: Path) -> Path:
    """Create a tiny sample file for commands that require --exists."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    return sample


def _make_procmon_csv(tmp_path: Path, rows: list[str] | None = None) -> Path:
    """Create a minimal ProcMon CSV file for testing."""
    header = "Time of Day,Process Name,PID,Operation,Path,Result,Detail\n"
    if rows is None:
        rows = [
            "12:00:01.0000000,MsMpEng.exe,1234,ReadFile,C:\\test.dll,SUCCESS,Offset: 0x0 Length: 0x1000",
            "12:00:02.0000000,MsMpEng.exe,1234,ReadFile,C:\\test.dll,SUCCESS,Offset: 0x1000 Length: 0x1000",
            "12:00:03.0000000,MsMpEng.exe,1234,ReadFile,C:\\test.dll,SUCCESS,Offset: 0x0 Length: 0x1000",
        ]
    csv_content = header + "\n".join(rows) + "\n"
    csv_file = tmp_path / "trace.csv"
    csv_file.write_text(csv_content, encoding="utf-8-sig")
    return csv_file


# ── version ────────────────────────────────────────────────────────────


class TestVersion:
    def test_version_shows_current(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_version_output_is_clean(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "defenderatlas" in result.output.lower()


# ── help / root ────────────────────────────────────────────────────────


class TestHelp:
    def test_no_args_shows_usage(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code != 0
        assert "Usage" in result.output or "Usage" in result.output.lower()

    def test_root_help_flag(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "analyze" in result.output.lower()
        assert "capture" in result.output.lower()
        assert "collect" in result.output.lower()
        assert "visualize" in result.output.lower()
        assert "report" in result.output.lower()
        assert "version" in result.output.lower()

    def test_analyze_help(self) -> None:
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "file" in result.output.lower()

    def test_capture_help(self) -> None:
        result = runner.invoke(app, ["capture", "--help"])
        assert result.exit_code == 0
        assert "file" in result.output.lower()
        assert "duration" in result.output.lower()

    def test_collect_help(self) -> None:
        result = runner.invoke(app, ["collect", "--help"])
        assert result.exit_code == 0
        assert "dataset" in result.output.lower()
        assert "procmon" in result.output.lower()
        assert "profile" in result.output.lower()

    def test_visualize_help(self) -> None:
        result = runner.invoke(app, ["visualize", "--help"])
        assert result.exit_code == 0
        assert "source" in result.output.lower()

    def test_report_help(self) -> None:
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "source" in result.output.lower()
        assert "format" in result.output.lower()


# ── analyze ────────────────────────────────────────────────────────────


class TestAnalyze:
    def test_runs_with_valid_csv(self, tmp_path: Path) -> None:
        csv_file = _make_procmon_csv(tmp_path)
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 0
        assert "statistics summary" in result.output.lower()

    def test_shows_panel(self, tmp_path: Path) -> None:
        csv_file = _make_procmon_csv(tmp_path)
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert "analyze" in result.output.lower()

    def test_displays_statistics(self, tmp_path: Path) -> None:
        csv_file = _make_procmon_csv(tmp_path)
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 0
        assert "total reads" in result.output.lower()
        assert "unique offsets" in result.output.lower()
        assert "repeated reads" in result.output.lower()
        assert "bytes read" in result.output.lower()

    def test_displays_amplification(self, tmp_path: Path) -> None:
        csv_file = _make_procmon_csv(tmp_path)
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 0
        assert "read amplification" in result.output.lower()

    def test_displays_processing_time(self, tmp_path: Path) -> None:
        csv_file = _make_procmon_csv(tmp_path)
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 0
        assert "processing time" in result.output.lower()

    def test_empty_csv_shows_warning(self, tmp_path: Path) -> None:
        csv_file = _make_procmon_csv(tmp_path, rows=[])
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 0
        assert "no read events found" in result.output.lower()

    def test_invalid_csv_format(self, tmp_path: Path) -> None:
        csv_file = tmp_path / "invalid.csv"
        csv_file.write_text("not,a,valid,csv\n", encoding="utf-8")
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 1
        assert "error" in result.output.lower()

    def test_missing_csv_headers(self, tmp_path: Path) -> None:
        csv_file = tmp_path / "bad_headers.csv"
        csv_file.write_text("Col1,Col2,Col3\na,b,c\n", encoding="utf-8")
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 1
        assert "error" in result.output.lower()

    def test_missing_file_fails(self) -> None:
        result = runner.invoke(app, ["analyze", "/nonexistent/file.csv"])
        assert result.exit_code != 0

    def test_non_read_operations_filtered(self, tmp_path: Path) -> None:
        rows = [
            "12:00:01.0000000,MsMpEng.exe,1234,WriteFile,C:\\test.dll,SUCCESS,Offset: 0x0 Length: 0x1000",
            "12:00:02.0000000,MsMpEng.exe,1234,ReadFile,C:\\test.dll,SUCCESS,Offset: 0x0 Length: 0x1000",
        ]
        csv_file = _make_procmon_csv(tmp_path, rows=rows)
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 0
        assert "total reads" in result.output.lower()

    def test_multiple_processes(self, tmp_path: Path) -> None:
        rows = [
            "12:00:01.0000000,MsMpEng.exe,1234,ReadFile,C:\\test.dll,SUCCESS,Offset: 0x0 Length: 0x1000",
            "12:00:02.0000000,SearchProtocolHost.exe,5678,ReadFile,C:\\test.dll,SUCCESS,Offset: 0x1000 Length: 0x1000",
        ]
        csv_file = _make_procmon_csv(tmp_path, rows=rows)
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 0
        assert "total reads" in result.output.lower()

    def test_large_offset_values(self, tmp_path: Path) -> None:
        rows = [
            "12:00:01.0000000,MsMpEng.exe,1234,ReadFile,C:\\test.dll,SUCCESS,Offset: 0x100000 Length: 0x1000",
        ]
        csv_file = _make_procmon_csv(tmp_path, rows=rows)
        result = runner.invoke(app, ["analyze", str(csv_file)])
        assert result.exit_code == 0
        assert "total reads" in result.output.lower()


# ── capture ────────────────────────────────────────────────────────────


class TestCapture:
    def test_runs_with_valid_file(self, tmp_path: Path) -> None:
        sample = _make_sample(tmp_path)
        result = runner.invoke(app, ["capture", str(sample)])
        assert result.exit_code == 0
        assert "placeholder" in result.output.lower()

    def test_duration_option(self, tmp_path: Path) -> None:
        sample = _make_sample(tmp_path)
        result = runner.invoke(app, ["capture", str(sample), "-d", "10"])
        assert result.exit_code == 0
        assert "10s" in result.output

    def test_creates_output_dir(self, tmp_path: Path) -> None:
        sample = _make_sample(tmp_path)
        out = tmp_path / "capture_out"
        result = runner.invoke(app, ["capture", str(sample), "-o", str(out)])
        assert result.exit_code == 0
        assert out.is_dir()

    def test_missing_file_fails(self) -> None:
        result = runner.invoke(app, ["capture", "/nonexistent/file.exe"])
        assert result.exit_code != 0


# ── collect ─────────────────────────────────────────────────────────────


class TestCollect:
    @pytest.fixture(autouse=True)
    def _setup_tools(self, tmp_path: Path, fake_script_factory, monkeypatch):
        procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
        worker = fake_script_factory("trigger_worker", FAKE_WORKER_SUCCESS_SOURCE)
        monkeypatch.setenv("DEFENDERATLAS_PROCMON", str(procmon))
        monkeypatch.setenv("DEFENDERATLAS_TRIGGER_WORKER", str(worker))
        self.work_dir = tmp_path / "work"

    def _invoke(self, tmp_path: Path, dataset_dir: Path, *extra: str):
        return runner.invoke(
            app,
            [
                "collect",
                str(dataset_dir),
                "--output",
                str(tmp_path / "experiments"),
                "--working-directory",
                str(self.work_dir),
                "--trigger-timeout",
                "50",
                *extra,
            ],
        )

    def test_collects_all_samples(self, tmp_path: Path) -> None:
        dataset = tmp_path / "dataset"
        dataset.mkdir()
        (dataset / "mspaint.exe").write_bytes(b"MZ" + b"\x00" * 16)
        (dataset / "driver.sys").write_bytes(b"MZ" + b"\x00" * 16)

        result = self._invoke(tmp_path, dataset)
        assert result.exit_code == 0
        assert "dataset collection summary" in result.output.lower()
        assert "2" in result.output

        experiment = tmp_path / "experiments" / "000001"
        assert experiment.is_dir()
        assert (experiment / "metadata.json").is_file()
        assert (experiment / "filtered.csv").is_file()
        assert (experiment / "trigger.json").is_file()

    def test_missing_dataset_directory_fails(self) -> None:
        result = self._invoke(tmp_path=Path("."), dataset_dir=Path("/nonexistent/ds"))
        assert result.exit_code != 0

    def test_profile_option_accepted(self, tmp_path: Path) -> None:
        dataset = tmp_path / "dataset"
        dataset.mkdir()
        (dataset / "mspaint.exe").write_bytes(b"MZ" + b"\x00" * 16)

        result = self._invoke(tmp_path, dataset, "--profile", "full")
        assert result.exit_code == 0
        assert "dataset collection summary" in result.output.lower()


# ── visualize ──────────────────────────────────────────────────────────


class TestVisualize:
    def test_runs_with_valid_input(self, tmp_path: Path) -> None:
        inp = tmp_path / "data.json"
        inp.write_text("{}")
        result = runner.invoke(app, ["visualize", str(inp)])
        assert result.exit_code == 0
        assert "placeholder" in result.output.lower()

    def test_creates_output_dir(self, tmp_path: Path) -> None:
        inp = tmp_path / "data.json"
        inp.write_text("{}")
        out = tmp_path / "viz_out"
        result = runner.invoke(app, ["visualize", str(inp), "-o", str(out)])
        assert result.exit_code == 0
        assert out.is_dir()

    def test_missing_file_fails(self) -> None:
        result = runner.invoke(app, ["visualize", "/nonexistent/data.json"])
        assert result.exit_code != 0


# ── report ─────────────────────────────────────────────────────────────


class TestReport:
    def test_runs_with_valid_input(self, tmp_path: Path) -> None:
        inp = tmp_path / "data.json"
        inp.write_text("{}")
        result = runner.invoke(app, ["report", str(inp)])
        assert result.exit_code == 0
        assert "placeholder" in result.output.lower()

    def test_format_option(self, tmp_path: Path) -> None:
        inp = tmp_path / "data.json"
        inp.write_text("{}")
        result = runner.invoke(app, ["report", str(inp), "-f", "html"])
        assert result.exit_code == 0

    def test_creates_output_dir(self, tmp_path: Path) -> None:
        inp = tmp_path / "data.json"
        inp.write_text("{}")
        out = tmp_path / "report_out"
        result = runner.invoke(app, ["report", str(inp), "-o", str(out)])
        assert result.exit_code == 0
        assert out.is_dir()

    def test_missing_file_fails(self) -> None:
        result = runner.invoke(app, ["report", "/nonexistent/data.json"])
        assert result.exit_code != 0


# ── logging ────────────────────────────────────────────────────────────


class TestLogging:
    def test_verbose_flag_accepted(self, tmp_path: Path) -> None:
        csv_file = _make_procmon_csv(tmp_path)
        result = runner.invoke(app, ["-V", "analyze", str(csv_file)])
        assert result.exit_code == 0


# ── install / uninstall (ProcMon elevation task) ──────────────────────


class TestProcMonElevation:
    def test_install_creates_task(
        self, tmp_path: Path, fake_script_factory, monkeypatch
    ) -> None:
        procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
        monkeypatch.setattr("defenderatlas.cli.app.task_exists", lambda _name: False)
        monkeypatch.setattr(
            "defenderatlas.cli.app.install_procmon_task", lambda _name, _path: True
        )

        result = runner.invoke(app, ["install", "--procmon", str(procmon)])
        assert result.exit_code == 0
        assert "installed" in result.output.lower()

    def test_install_updates_existing_task(
        self, tmp_path: Path, fake_script_factory, monkeypatch
    ) -> None:
        procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
        monkeypatch.setattr("defenderatlas.cli.app.task_exists", lambda _name: True)
        monkeypatch.setattr(
            "defenderatlas.cli.app.install_procmon_task", lambda _name, _path: True
        )

        result = runner.invoke(app, ["install", "--procmon", str(procmon)])
        assert result.exit_code == 0
        assert "already exists" in result.output.lower()

    def test_install_missing_procmon_fails(self, monkeypatch) -> None:
        monkeypatch.setattr("defenderatlas.cli.app.find_procmon", lambda: None)
        monkeypatch.setattr("defenderatlas.cli.app.task_exists", lambda _name: False)

        result = runner.invoke(app, ["install"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_uninstall_removes_task(self, monkeypatch) -> None:
        monkeypatch.setattr("defenderatlas.cli.app.task_exists", lambda _name: True)
        monkeypatch.setattr(
            "defenderatlas.cli.app.uninstall_procmon_task", lambda _name: True
        )

        result = runner.invoke(app, ["uninstall"])
        assert result.exit_code == 0
        assert "uninstalled" in result.output.lower()

    def test_uninstall_missing_task_fails(self, monkeypatch) -> None:
        monkeypatch.setattr("defenderatlas.cli.app.task_exists", lambda _name: False)

        result = runner.invoke(app, ["uninstall"])
        assert result.exit_code == 1
        assert "does not exist" in result.output.lower()

    def test_install_failure_reports_error(
        self, tmp_path: Path, fake_script_factory, monkeypatch
    ) -> None:
        procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
        monkeypatch.setattr("defenderatlas.cli.app.task_exists", lambda _name: False)
        monkeypatch.setattr(
            "defenderatlas.cli.app.install_procmon_task", lambda _name, _path: False
        )

        result = runner.invoke(app, ["install", "--procmon", str(procmon)])
        assert result.exit_code == 1
        assert "error" in result.output.lower()

    def test_task_name_option(
        self, tmp_path: Path, fake_script_factory, monkeypatch
    ) -> None:
        procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
        monkeypatch.setattr("defenderatlas.cli.app.task_exists", lambda _name: False)
        installed: dict[str, str] = {}

        def fake_install(name: str, _path) -> bool:
            installed["name"] = name
            return True

        monkeypatch.setattr("defenderatlas.cli.app.install_procmon_task", fake_install)

        result = runner.invoke(
            app,
            ["install", "--procmon", str(procmon), "--task-name", "Custom Task"],
        )
        assert result.exit_code == 0
        assert installed["name"] == "Custom Task"


class TestCollectTaskLaunchMethod:
    @pytest.fixture(autouse=True)
    def _setup_tools(self, tmp_path: Path, fake_script_factory, monkeypatch):
        procmon = fake_script_factory("Procmon64", FAKE_PROCMON_SOURCE)
        worker = fake_script_factory("trigger_worker", FAKE_WORKER_SUCCESS_SOURCE)
        monkeypatch.setenv("DEFENDERATLAS_PROCMON", str(procmon))
        monkeypatch.setenv("DEFENDERATLAS_TRIGGER_WORKER", str(worker))

    def test_task_launch_method_option_accepted(self, tmp_path: Path) -> None:
        dataset = tmp_path / "dataset"
        dataset.mkdir()
        (dataset / "mspaint.exe").write_bytes(b"MZ" + b"\x00" * 16)

        result = runner.invoke(
            app,
            [
                "collect",
                str(dataset),
                "--output",
                str(tmp_path / "experiments"),
                "--working-directory",
                str(tmp_path / "work"),
                "--trigger-timeout",
                "50",
                "--procmon-launch-method",
                "task",
                "--scheduled-task-name",
                "DefenderAtlas ProcMon",
            ],
        )
        assert result.exit_code == 0
        assert "dataset collection summary" in result.output.lower()
