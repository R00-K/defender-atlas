"""ZIP archive analyzer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenderatlas.analyzers.base import Analyzer

if TYPE_CHECKING:
    from pathlib import Path

    from defenderatlas.models.core import AnalysisResult

_ZIP_MAGIC = b"PK\x03\x04"


class ZIPAnalyzer(Analyzer):
    """Analyzer for ZIP-based archives (.zip, .docx, .xlsx, .jar, etc.)."""

    def supports(self, file_path: Path) -> bool:
        """Return *True* if *file_path* starts with the ZIP magic bytes."""
        try:
            with open(file_path, "rb") as fh:
                return fh.read(4) == _ZIP_MAGIC
        except OSError:
            return False

    def analyze(self, file_path: Path) -> AnalysisResult:
        """Analyze a ZIP archive.

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

        msg = "ZIPAnalyzer is not yet implemented"
        raise NotImplementedError(msg)
