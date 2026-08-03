"""PDF document analyzer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenderatlas.analyzers.base import Analyzer

if TYPE_CHECKING:
    from pathlib import Path

    from defenderatlas.models.core import AnalysisResult

_PDF_MAGIC = b"%PDF"


class PDFAnalyzer(Analyzer):
    """Analyzer for PDF documents."""

    def supports(self, file_path: Path) -> bool:
        """Return *True* if *file_path* starts with the PDF magic bytes."""
        try:
            with open(file_path, "rb") as fh:
                return fh.read(4) == _PDF_MAGIC
        except OSError:
            return False

    def analyze(self, file_path: Path) -> AnalysisResult:
        """Analyze a PDF file.

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

        msg = "PDFAnalyzer is not yet implemented"
        raise NotImplementedError(msg)
