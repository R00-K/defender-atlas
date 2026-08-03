"""Shared fake executables used by the capture tests.

The Collector spawns ``trigger_worker.exe`` and ``Procmon64.exe`` as child
processes. These lightweight, platform-agnostic stand-ins are written as plain
Python scripts wrapped in a launcher by the ``fake_script_factory`` fixture.
"""

from __future__ import annotations

FAKE_PROCMON_SOURCE = """
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STOP_FILE = os.path.join(SCRIPT_DIR, "FAKE_PROCMON_STOP")


def _value(flag):
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def main():
    if "/Terminate" in sys.argv:
        with open(STOP_FILE, "w") as handle:
            handle.write("stop")
        raise SystemExit(0)

    pml = _value("/BackingFile")
    if pml:
        try:
            os.remove(STOP_FILE)
        except OSError:
            pass
        with open(pml, "wb") as handle:
            handle.write(b"fake pml")
        while not os.path.exists(STOP_FILE):
            time.sleep(0.05)
        raise SystemExit(0)

    csv = _value("/SaveAs")
    if csv:
        rows = [
            "Time of Day,Process Name,PID,Operation,Path,Result,Detail",
            "12:00:00.0000000,MsMpEng.exe,123,CreateFile,C:\\exp\\sample.exe,SUCCESS,Read",
            "12:00:00.0010000,MsMpEng.exe,123,ReadFile,C:\\exp\\sample.exe,SUCCESS,Offset: 0x0 Length: 0x100",
            "12:00:00.0020000,notepad.exe,9,ReadFile,C:\\other\\sample.exe,SUCCESS,Offset: 0x0 Length: 0x100",
        ]
        with open(csv, "w", encoding="utf-8-sig") as handle:
            handle.write("\\n".join(rows) + "\\n")
        raise SystemExit(0)

    raise SystemExit(2)


if __name__ == "__main__":
    main()
"""

FAKE_WORKER_SUCCESS_SOURCE = """
def main():
    import sys

    if len(sys.argv) < 2:
        raise SystemExit(2)
    print("IAttachmentExecute::Save completed successfully")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
"""

FAKE_WORKER_FAILURE_SOURCE = """
def main():
    import sys

    print("Save failed: 0x80004005")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
"""
