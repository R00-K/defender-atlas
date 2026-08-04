"""Windows Task Scheduler integration for elevated ProcMon launches.

Launching Procmon64.exe directly from an unelevated Collector triggers a UAC
prompt on every capture. Instead of disabling UAC, scheduled tasks are
registered once (``defenderatlas install``) with the "Run with highest
privileges" flag, and the Collector then starts ProcMon through those tasks.

ProcMon must run elevated for *every* invocation: it loads a kernel driver at
startup not only when capturing (``/Quiet /BackingFile``) but also when
terminating (``/Terminate``) and when exporting (``/OpenLog /SaveAs``). Three
scheduled tasks are therefore registered, all running the same elevated
launcher scripts:

* *task_name*              — capture: ``Procmon64 /Quiet /BackingFile <pml>``
* *task_name* + " Stop"    — terminate a running capture
* *task_name* + " Export"  — convert a PML to CSV via ``/OpenLog /SaveAs``

A scheduled task cannot receive per-launch arguments and its action cannot be
modified from an unelevated Collector (``Set-ScheduledTask`` requires an
administrator). Each task therefore runs a small launcher script instead of
ProcMon directly: the Collector writes the relevant arguments to well-known
files (``pml_path.txt`` / ``export_args.txt``) and starts the task; the
launcher reads those files and runs ProcMon. ``Start-ScheduledTask`` works
from an unelevated Collector for a task registered for the current user.

All interaction happens through PowerShell cmdlets targeting the Task
Scheduler API. The module is a no-op fallback on non-Windows platforms: the
query functions report "missing", so callers degrade to a direct launch.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_TASK_NAME = "DefenderAtlas ProcMon"

_STOP_TASK_SUFFIX = " Stop"
_EXPORT_TASK_SUFFIX = " Export"

_PS_TIMEOUT_SECONDS = 30

if sys.platform == "win32":
    _CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)
else:
    _CREATE_NO_WINDOW = 0

_POWERSHELL: tuple[str, ...] = (
    "powershell",
    "-NoProfile",
    "-NonInteractive",
    "-Command",
)

_LAUNCHER_FILE = "launch_procmon.cmd"
_STOP_LAUNCHER_FILE = "launch_procmon_stop.cmd"
_EXPORT_LAUNCHER_FILE = "launch_procmon_export.cmd"
_PML_FILE = "pml_path.txt"
_EXPORT_ARGS_FILE = "export_args.txt"


def stop_task_name(task_name: str) -> str:
    """Return the name of the scheduled task that stops a capture."""
    return task_name + _STOP_TASK_SUFFIX


def export_task_name(task_name: str) -> str:
    """Return the name of the scheduled task that exports a PML to CSV."""
    return task_name + _EXPORT_TASK_SUFFIX


def _launcher_dir() -> Path:
    """Directory holding the launcher scripts and the current argument files."""
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "DefenderAtlas"
    return Path.home() / "AppData" / "Local" / "DefenderAtlas"


def _ps_quote(value: str) -> str:
    """Wrap *value* in a PowerShell single-quoted literal."""
    return "'" + value.replace("'", "''") + "'"


def _run_ps(command: str) -> subprocess.CompletedProcess[str] | None:
    """Run a PowerShell command; return the result or None on hard failure."""
    try:
        return subprocess.run(
            [*_POWERSHELL, command],
            capture_output=True,
            text=True,
            creationflags=_CREATE_NO_WINDOW,
            timeout=_PS_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.error("PowerShell invocation failed: %s", exc)
        return None


def task_exists(task_name: str) -> bool:
    """True when the scheduled task *task_name* is registered."""
    result = _run_ps(
        "if (Get-ScheduledTask -TaskName "
        f"{_ps_quote(task_name)} -ErrorAction SilentlyContinue) "
        "{ Write-Output 'EXISTS' } else { Write-Output 'MISSING' }"
    )
    if result is None:
        return False
    return "EXISTS" in result.stdout


def is_task_running(task_name: str) -> bool:
    """True while the scheduled task's process is still running."""
    result = _run_ps(
        "$t = Get-ScheduledTask -TaskName "
        f"{_ps_quote(task_name)} -ErrorAction SilentlyContinue; "
        "if ($t) { if ($t.State -eq 'Running') { Write-Output 'RUNNING' } "
        "else { Write-Output 'IDLE' } } else { Write-Output 'MISSING' }"
    )
    if result is None:
        return False
    return "RUNNING" in result.stdout


def _write_launcher(procmon_path: Path) -> Path | None:
    """Write the elevated launcher scripts; return the start launcher path."""
    directory = _launcher_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.error("Cannot create launcher directory %s: %s", directory, exc)
        return None
    pml_file = directory / _PML_FILE
    args_file = directory / _EXPORT_ARGS_FILE
    exe = str(procmon_path)

    start = directory / _LAUNCHER_FILE
    start_lines = [
        "@echo off",
        f'set "PML_FILE={pml_file}"',
        'set "PML="',
        'if exist "%PML_FILE%" set /p PML=<"%PML_FILE%"',
        "if not defined PML exit /b 1",
        f'start /wait "" "{exe}" /AcceptEula /Quiet /Minimized /BackingFile "%PML%"',
    ]

    stop = directory / _STOP_LAUNCHER_FILE
    stop_lines = [
        "@echo off",
        f'start /wait "" "{exe}" /AcceptEula /Terminate',
    ]

    export = directory / _EXPORT_LAUNCHER_FILE
    export_lines = [
        "@echo off",
        f'set "ARGS_FILE={args_file}"',
        'set "PML="',
        'set "CSV="',
        'if exist "%ARGS_FILE%" set /p PML=<"%ARGS_FILE%"',
        'for /f "usebackq skip=1 delims=" %%L in ("%ARGS_FILE%") do '
        'if not defined CSV set "CSV=%%L"',
        "if not defined PML exit /b 1",
        "if not defined CSV exit /b 1",
        f'start /wait "" "{exe}" /AcceptEula /OpenLog "%PML%" /SaveAs "%CSV%"',
    ]

    try:
        start.write_text("\r\n".join(start_lines) + "\r\n", encoding="utf-8")
        stop.write_text("\r\n".join(stop_lines) + "\r\n", encoding="utf-8")
        export.write_text("\r\n".join(export_lines) + "\r\n", encoding="utf-8")
    except OSError as exc:
        log.error("Cannot write ProcMon launcher scripts: %s", exc)
        return None
    log.debug("Wrote ProcMon launchers: %s, %s, %s", start, stop, export)
    return start


def _register_task(task_name: str, launcher: Path) -> bool:
    """Register one scheduled task that runs *launcher* elevated."""
    action_argument = _ps_quote(f'/c ""{launcher}""')
    command = (
        "$ErrorActionPreference = 'Stop'; "
        "$action = New-ScheduledTaskAction -Execute 'cmd.exe' "
        f"-Argument {action_argument}; "
        "$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME "
        "-LogonType Interactive -RunLevel Highest; "
        "$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries "
        "-DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero); "
        "Register-ScheduledTask -TaskName "
        f"{_ps_quote(task_name)} -Action $action -Principal $principal "
        "-Settings $settings -Force"
    )
    result = _run_ps(command)
    if result is None:
        return False
    if result.returncode != 0:
        log.error(
            "Failed to install scheduled task %r: %s",
            task_name,
            result.stderr.strip(),
        )
        return False
    log.info("Installed scheduled task %r", task_name)
    return True


def install_procmon_task(task_name: str, procmon_path: Path) -> bool:
    """Register the elevated scheduled tasks that run ProcMon.

    Three tasks are registered for the current interactive user with the
    "Run with highest privileges" flag so every ProcMon invocation (capture
    start, stop, PML export) runs elevated and never prompts for UAC:

    * *task_name*              — capture via ``/BackingFile``
    * *task_name* + " Stop"    — terminate a running capture
    * *task_name* + " Export"  — PML → CSV via ``/OpenLog /SaveAs``
    """
    launcher = _write_launcher(procmon_path)
    if launcher is None:
        return False
    registrations = (
        (task_name, launcher),
        (stop_task_name(task_name), _launcher_dir() / _STOP_LAUNCHER_FILE),
        (export_task_name(task_name), _launcher_dir() / _EXPORT_LAUNCHER_FILE),
    )
    return all(_register_task(name, path) for name, path in registrations)


def uninstall_procmon_task(task_name: str) -> bool:
    """Remove the scheduled tasks used to run ProcMon."""
    names = (task_name, stop_task_name(task_name), export_task_name(task_name))
    command = (
        "$ErrorActionPreference = 'Stop'; "
        + "".join(
            "Unregister-ScheduledTask -TaskName "
            f"{_ps_quote(name)} -Confirm:$false -ErrorAction SilentlyContinue; "
            for name in names
        )
        + "Write-Output 'DONE'"
    )
    result = _run_ps(command)
    if result is None:
        return False
    if result.returncode != 0:
        log.error("Failed to remove scheduled tasks: %s", result.stderr.strip())
        return False
    log.info("Removed scheduled tasks for %r", task_name)
    return True


def _start_task(task_name: str) -> bool:
    """Start *task_name* via the Task Scheduler and log its status."""
    if not task_exists(task_name):
        log.warning("Scheduled task %r does not exist", task_name)
        return False
    result = _run_ps(f"Start-ScheduledTask -TaskName {_ps_quote(task_name)}")
    if result is None:
        return False
    if result.returncode != 0:
        log.error(
            "Failed to launch scheduled task %r: %s",
            task_name,
            result.stderr.strip(),
        )
        return False
    _log_task_status(task_name)
    log.info("Started scheduled task %r", task_name)
    return True


def launch_procmon_task(task_name: str, pml_path: Path) -> bool:
    """Start the elevated ProcMon capture task targeting *pml_path*.

    The absolute PML path is handed to the launcher through the well-known
    ``pml_path.txt`` file; ``Start-ScheduledTask`` does not require an
    elevated Collector for a task registered for the current user.
    """
    if not task_exists(task_name):
        log.warning("Scheduled task %r does not exist", task_name)
        return False
    pml_file = _launcher_dir() / _PML_FILE
    try:
        pml_file.write_text(str(pml_path) + "\n", encoding="utf-8")
    except OSError as exc:
        log.error("Failed to write PML path %s: %s", pml_file, exc)
        return False
    if not _start_task(task_name):
        return False
    log.info("ProcMon launched via scheduled task %r", task_name)
    return True


def terminate_procmon_task(task_name: str) -> bool:
    """Stop a running elevated ProcMon via its scheduled task."""
    name = stop_task_name(task_name)
    if not task_exists(name):
        log.warning(
            "Scheduled task %r does not exist; re-run 'defenderatlas install'",
            name,
        )
        return False
    if not _start_task(name):
        return False
    log.info("ProcMon termination requested via scheduled task %r", name)
    return True


def export_procmon_task(task_name: str, pml_path: Path, csv_path: Path) -> bool:
    """Export *pml_path* to *csv_path* via the elevated scheduled task."""
    name = export_task_name(task_name)
    if not task_exists(name):
        log.warning(
            "Scheduled task %r does not exist; re-run 'defenderatlas install'",
            name,
        )
        return False
    args_file = _launcher_dir() / _EXPORT_ARGS_FILE
    try:
        args_file.write_text(f"{pml_path}\n{csv_path}\n", encoding="utf-8")
    except OSError as exc:
        log.error("Failed to write export args %s: %s", args_file, exc)
        return False
    if not _start_task(name):
        return False
    log.info("PML export started via scheduled task %r", name)
    return True


def _log_task_status(task_name: str) -> None:
    """Log the task state and last run result after a launch."""
    info = _run_ps(
        "$t = Get-ScheduledTask -TaskName "
        f"{_ps_quote(task_name)} -ErrorAction SilentlyContinue; "
        "$i = Get-ScheduledTaskInfo -TaskName "
        f"{_ps_quote(task_name)} -ErrorAction SilentlyContinue; "
        "if ($t) { Write-Output ('State=' + $t.State) }; "
        "if ($i) { Write-Output ('LastRunTime=' + $i.LastRunTime); "
        "Write-Output ('LastTaskResult=' + $i.LastTaskResult) }"
    )
    if info is None:
        return
    for line in info.stdout.splitlines():
        log.debug("Scheduled task status: %s", line)
