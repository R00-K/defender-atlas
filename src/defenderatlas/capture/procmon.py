"""ProcMon capture automation for the Collector.

Wraps the lifecycle of a Procmon.exe capture using the same command-line
contract as the reference collector:

    start:   /AcceptEula /Quiet /Minimized /BackingFile <pml>
    stop:    /AcceptEula /Terminate
    export:  /AcceptEula /OpenLog <pml> /SaveAs <csv>

All ProcMon-specific behavior is isolated here (the Windows code path); the
rest of the Collector only talks to this controller.

ProcMon can be launched elevated through Windows scheduled tasks instead of
``CreateProcess`` so the Collector does not trigger a UAC prompt on every
capture. ProcMon must run elevated for *every* invocation — it loads a kernel
driver at startup even for ``/Terminate`` and ``/OpenLog /SaveAs`` — so the
controller routes start, stop and export through the scheduled tasks whenever
the current process is not elevated. A direct launch is only attempted from an
elevated process; launching ProcMon unelevated would make it self-relaunch
forever and never create the backing file.

Path resolution and ``launch_method``:
- ``"auto"`` (default) — elevated: direct launch; unelevated: scheduled task.
- ``"process"`` — same as ``"auto"`` (direct launch when elevated only).
- ``"task"`` — force the scheduled task; fall back to a direct launch only
  when the current process is elevated.

Paths are always resolved to absolute before being handed to ProcMon: a
scheduled task starts its action with the working directory ``C:\\Windows\\
System32`` (task actions have no working-directory override), so a relative
``/BackingFile`` would be created in the wrong place and the capture would
never become ready.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from defenderatlas.capture.taskscheduler import (
    DEFAULT_TASK_NAME,
    _run_ps,
    export_procmon_task,
    is_task_running,
    launch_procmon_task,
    task_exists,
    terminate_procmon_task,
)

log = logging.getLogger(__name__)

if sys.platform == "win32":
    _CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)
else:
    _CREATE_NO_WINDOW = 0

_POLL_INTERVAL = 0.1
_READINESS_GRACE = 0.2
_QUERY_TIMEOUT = 15.0

_PROCMON_CANDIDATES: tuple[Path, ...] = (
    Path(r"C:\ProcessMonitor\Procmon64.exe"),
    Path(r"C:\ProcessMonitor\Procmon.exe"),
    Path(r"C:\Tools\Procmon64.exe"),
    Path(r"C:\Tools\Procmon.exe"),
)


def _is_elevated() -> bool:
    """True when the current process holds an elevated (administrator) token.

    ProcMon loads a kernel driver at startup, so every invocation (capture,
    ``/Terminate``, ``/OpenLog``) needs an elevated process. Non-Windows hosts
    are treated as elevated so the direct-launch path stays available there.
    """
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_procmon() -> Path | None:
    """Locate a ProcMon executable, or None when none can be found."""
    env_path = os.environ.get("DEFENDERATLAS_PROCMON")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return candidate
    for candidate in _PROCMON_CANDIDATES:
        if candidate.is_file():
            return candidate
    for name in ("Procmon64.exe", "Procmon.exe"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def _procmon_pids(procmon_path: Path) -> list[int]:
    """Return the live PIDs of processes matching the ProcMon image name."""
    try:
        result = subprocess.run(
            [
                "tasklist",
                "/FI",
                f"IMAGENAME eq {procmon_path.name}",
                "/FO",
                "CSV",
                "/NH",
            ],
            capture_output=True,
            text=True,
            creationflags=_CREATE_NO_WINDOW,
            timeout=_QUERY_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    pids: list[int] = []
    for line in result.stdout.splitlines():
        match = re.search(r'"([^"]*)","(\d+)"', line)
        if match:
            pids.append(int(match.group(2)))
    return pids


def _procmon_driver() -> str | None:
    """Describe the ProcMon kernel driver service, or None when absent."""
    command = (
        "$d = Get-CimInstance Win32_SystemDriver | "
        "Where-Object { $_.Name -match 'procmon' -or "
        "$_.PathName -match 'procmon' } | Select-Object -First 5; "
        "if ($d) { $d | ForEach-Object "
        "{ Write-Output ($_.Name + ':' + $_.State) } }"
    )
    result = _run_ps(command)
    if result is None:
        return None
    summary = result.stdout.strip()
    return summary or None


class ProcmonError(Exception):
    """Base error for ProcMon automation."""


class ProcmonController:
    """Owns and controls one ProcMon capture session."""

    def __init__(
        self,
        procmon_path: Path,
        launch_method: str = "auto",
        scheduled_task_name: str = DEFAULT_TASK_NAME,
    ) -> None:
        self.procmon_path = procmon_path
        self.launch_method = launch_method
        self.scheduled_task_name = scheduled_task_name
        self._process: subprocess.Popen[bytes] | None = None
        self.pml_path: Path | None = None
        self._launched_via_task = False
        self._confirmed_pids: list[int] = []
        self._pml_reported = False
        self._driver_checked = False

    def start(self, pml_path: Path) -> bool:
        """Launch ProcMon capturing to *pml_path*.

        ProcMon requires an elevated context to load its kernel driver, so the
        launch is routed through the elevated scheduled task whenever this
        process is not elevated. A direct launch is never attempted from an
        unelevated process: ProcMon would self-elevate and, failing that, hang
        without ever creating the backing file.
        """
        pml_path = pml_path.expanduser().resolve()
        pml_path.unlink(missing_ok=True)
        arguments = [
            "/AcceptEula",
            "/Quiet",
            "/Minimized",
            "/BackingFile",
            str(pml_path),
        ]
        command_line = " ".join([str(self.procmon_path), *arguments])
        elevated = _is_elevated()
        method = (self.launch_method or "auto").lower()
        log.info(
            "Launching ProcMon:\n  executable: %s\n  command line: %s\n"
            "  launch method: %s\n  elevated: %s\n  working directory: %s\n"
            "  PML target: %s\n  PML parent dir exists: %s",
            self.procmon_path,
            command_line,
            method,
            elevated,
            os.getcwd(),
            pml_path,
            pml_path.parent.is_dir(),
        )
        if method not in ("auto", "process", "task"):
            log.warning("Unknown launch method %r; using 'auto'", self.launch_method)
            method = "auto"

        use_task: bool
        if method == "task":
            if task_exists(self.scheduled_task_name):
                use_task = True
            elif elevated:
                log.warning(
                    "Scheduled task %r not found; falling back to direct launch",
                    self.scheduled_task_name,
                )
                use_task = False
            else:
                log.error(
                    "Scheduled task %r not found and this process is not "
                    "elevated; ProcMon cannot capture. Run 'defenderatlas "
                    "install' to create the elevation tasks or run this "
                    "Collector as Administrator.",
                    self.scheduled_task_name,
                )
                return False
        else:  # "auto" / "process"
            if elevated:
                use_task = False
            elif task_exists(self.scheduled_task_name):
                log.warning(
                    "This Collector is not elevated; launching ProcMon via "
                    "scheduled task %r",
                    self.scheduled_task_name,
                )
                use_task = True
            else:
                log.error(
                    "ProcMon must run elevated to load its kernel driver, but "
                    "this Collector is not elevated and the scheduled task %r "
                    "is not installed. Run 'defenderatlas install' (elevated) "
                    "or run this Collector as Administrator; NOT launching "
                    "ProcMon.",
                    self.scheduled_task_name,
                )
                return False

        if use_task:
            if launch_procmon_task(self.scheduled_task_name, pml_path):
                self._launched_via_task = True
                self.pml_path = pml_path
                log.info(
                    "ProcMon started via scheduled task %r",
                    self.scheduled_task_name,
                )
                return True
            log.error(
                "Failed to launch ProcMon via scheduled task %r",
                self.scheduled_task_name,
            )
            return False

        try:
            self._process = subprocess.Popen(
                [str(self.procmon_path), *arguments],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_CREATE_NO_WINDOW,
            )
        except OSError as exc:
            log.error("Failed to start ProcMon: %s", exc)
            return False
        self.pml_path = pml_path
        log.info("ProcMon started (pid %s)", self._process.pid)
        return True

    def wait_until_ready(self, timeout: float) -> bool:
        """Block until the capture is considered active, up to *timeout* seconds."""
        if self.pml_path is None:
            return False
        started = time.monotonic()
        deadline = started + timeout
        last_liveness_check = 0.0
        while time.monotonic() < deadline:
            if self._launched_via_task:
                if time.monotonic() - last_liveness_check >= 1.0:
                    last_liveness_check = time.monotonic()
                    if not is_task_running(self.scheduled_task_name):
                        log.error(
                            "ProcMon task %r exited before becoming ready",
                            self.scheduled_task_name,
                        )
                        return False
                    self._confirm_process()
            else:
                if self._process is None or self._process.poll() is not None:
                    code = self._process.poll() if self._process is not None else None
                    log.error(
                        "ProcMon exited before becoming ready (exit code %s)",
                        code,
                    )
                    return False
            if self.pml_path.exists():
                time.sleep(_READINESS_GRACE)
                if not self._pml_reported:
                    self._pml_reported = True
                    log.info(
                        "Backing PML created: %s (%d bytes, mtime %s)",
                        self.pml_path,
                        self.pml_path.stat().st_size,
                        time.strftime(
                            "%H:%M:%S",
                            time.localtime(self.pml_path.stat().st_mtime),
                        ),
                    )
                log.info(
                    "ProcMon ready after %.1fs (%s)",
                    time.monotonic() - started,
                    self.pml_path,
                )
                return True
            time.sleep(_POLL_INTERVAL)
        self._report_readiness_failure(started)
        return False

    def _confirm_process(self) -> None:
        """Record the ProcMon process(es) visible via tasklist."""
        pids = _procmon_pids(self.procmon_path)
        self._confirmed_pids = pids
        if pids:
            log.info(
                "Confirmed ProcMon process running via tasklist (pids: %s)",
                ", ".join(str(pid) for pid in pids),
            )
        else:
            log.debug("Scheduled task running, but no ProcMon process found yet")
        if not self._driver_checked:
            self._driver_checked = True
            driver = _procmon_driver()
            if driver is not None:
                log.info("ProcMon kernel driver service: %s", driver)
            else:
                log.warning(
                    "No ProcMon kernel driver service found while ProcMon is running"
                )

    def _report_readiness_failure(self, started: float) -> None:
        """Log why ProcMon never became ready."""
        elapsed = time.monotonic() - started
        pml = self.pml_path
        log.error(
            "Timed out after %.1fs waiting for ProcMon to become ready\n"
            "  PML: %s\n  PML parent dir exists: %s",
            elapsed,
            pml,
            pml.parent.is_dir() if pml is not None else "n/a",
        )
        if self._launched_via_task:
            log.error(
                "Scheduled task %r still running: %s",
                self.scheduled_task_name,
                is_task_running(self.scheduled_task_name),
            )
        else:
            code = self._process.poll() if self._process is not None else None
            log.error(
                "ProcMon process state: %s",
                "running" if code is None else f"exited with code {code}",
            )
        if self._confirmed_pids:
            log.error(
                "ProcMon processes found via tasklist: %s",
                ", ".join(str(pid) for pid in self._confirmed_pids),
            )
        else:
            log.error("No ProcMon process found via tasklist")
        driver = _procmon_driver()
        if driver is not None:
            log.error("ProcMon kernel driver service: %s", driver)
        else:
            log.error(
                "No ProcMon kernel driver service found; driver may not be loaded"
            )

    def stop(self, timeout: float) -> bool:
        """Stop the capture and wait for the ProcMon process to exit.

        ``/Terminate`` needs an elevated context too, so it is routed through
        the elevated scheduled task when this process is not elevated.
        """
        started = time.monotonic()
        if _is_elevated():
            graceful = self._run_helper(["/AcceptEula", "/Terminate"], timeout)
        else:
            graceful = terminate_procmon_task(self.scheduled_task_name)
            if not graceful:
                log.error("Failed to stop ProcMon via scheduled task")
                return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.is_running():
            time.sleep(0.25)
        if self._launched_via_task:
            log.info(
                "ProcMon stop completed (elapsed %.1fs, task still running: %s)",
                time.monotonic() - started,
                self.is_running(),
            )
        elif self._process is not None and self._process.poll() is None:
            log.warning("ProcMon did not exit gracefully; forcing termination")
            self._process.kill()
            try:
                self._process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                log.error("ProcMon ignored SIGKILL")
            graceful = False
        else:
            log.info(
                "ProcMon stop completed (elapsed %.1fs)",
                time.monotonic() - started,
            )
        return graceful

    def export_csv(self, pml_path: Path, csv_path: Path, timeout: float) -> bool:
        """Convert *pml_path* into *csv_path* using ProcMon /OpenLog /SaveAs."""
        pml_path = pml_path.expanduser().resolve()
        csv_path = csv_path.expanduser().resolve()
        csv_path.unlink(missing_ok=True)
        if pml_path.is_file():
            log.info(
                "Exporting PML to CSV: %s (%d bytes)",
                pml_path,
                pml_path.stat().st_size,
            )
        else:
            log.error("PML file missing before export: %s", pml_path)
        if _is_elevated():
            ok = self._run_helper(
                ["/AcceptEula", "/OpenLog", str(pml_path), "/SaveAs", str(csv_path)],
                timeout,
            )
        else:
            ok = export_procmon_task(self.scheduled_task_name, pml_path, csv_path)
        if not ok:
            return False
        if not csv_path.is_file() or csv_path.stat().st_size == 0:
            log.error("ProcMon export produced no CSV: %s", csv_path)
            return False
        log.info(
            "CSV export produced %s (%d bytes)",
            csv_path,
            csv_path.stat().st_size,
        )
        return True

    def is_running(self) -> bool:
        """True while the captured ProcMon process is still alive."""
        if self._launched_via_task:
            return is_task_running(self.scheduled_task_name)
        return self._process is not None and self._process.poll() is None

    def _run_helper(self, arguments: list[str], timeout: float) -> bool:
        command = [str(self.procmon_path), *arguments]
        command_line = " ".join(command)
        started = time.monotonic()
        log.debug(
            "Running ProcMon helper:\n  command line: %s\n  working directory: %s",
            command_line,
            os.getcwd(),
        )
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=_CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.error(
                "ProcMon helper failed after %.1fs: %s\n  command line: %s",
                time.monotonic() - started,
                exc,
                command_line,
            )
            return False
        elapsed = time.monotonic() - started
        if result.returncode != 0:
            log.error(
                "ProcMon helper exited with code %s after %.1fs\n"
                "  command line: %s\n  working directory: %s\n"
                "  stdout: %s\n  stderr: %s",
                result.returncode,
                elapsed,
                command_line,
                os.getcwd(),
                result.stdout.strip() or "(empty)",
                result.stderr.strip() or "(empty)",
            )
            return False
        log.debug("ProcMon helper completed in %.1fs (exit code 0)", elapsed)
        return True
