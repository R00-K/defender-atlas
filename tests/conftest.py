"""Shared pytest fixtures for DefenderAtlas tests."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def fake_script_factory(tmp_path: Path):
    """Return a helper that writes a runnable fake worker / ProcMon script.

    The Collector spawns ``trigger_worker.exe`` and ``Procmon64.exe`` as child
    processes. Tests stand in with plain Python scripts wrapped in a launcher
    that is executable on the current platform (a ``.cmd`` file on Windows, a
    shebang script on POSIX).
    """

    def make(name: str, py_source: str) -> Path:
        script = tmp_path / f"{name}.py"
        script.write_text(py_source, encoding="utf-8")
        if os.name == "nt":
            launcher = tmp_path / f"{name}.cmd"
            launcher.write_text(f'@python "%~dp0{name}.py" %*', encoding="ascii")
        else:
            launcher = tmp_path / name
            launcher.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                f"sys.path.insert(0, {str(tmp_path)!r})\n"
                f"import {name}\n"
                f"{name}.main()\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)
        return launcher

    return make
