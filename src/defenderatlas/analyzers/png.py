"""PNG image analyzer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenderatlas.analyzers.base import Analyzer

if TYPE_CHECKING:
    from pathlib import Path

    from defenderatlas.models.core import AnalysisResult

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class PNGAnalyzer(Analyzer):
    """Analyzer for PNG image files."""

    def supports(self, file_path: Path) -> bool:
        """Return *True* if *file_path* starts with the PNG magic bytes."""
        try:
            with open(file_path, "rb") as fh:
                return fh.read(8) == _PNG_MAGIC
        except OSError:
            return False

    def analyze(self, file_path: Path) -> AnalysisResult:
        """Analyze a PNG file.

        Raises
        ------
        FileNotFoundError
            If *file_path* does not exist.
        NotImplementedError
            Always — this analyzer is not yet implemented.
        """
        if not file_path.exists():
            msg = f"File not found: {file_path}"
            raise FileNotFoundError(msg)

        msg = "PNGAnalyzer is not yet implemented"
        raise NotImplementedError(msg)
