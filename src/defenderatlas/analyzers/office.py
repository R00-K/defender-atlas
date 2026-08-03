"""Microsoft Office document analyzer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenderatlas.analyzers.base import Analyzer

if TYPE_CHECKING:
    from pathlib import Path

    from defenderatlas.models.core import AnalysisResult

# Legacy OLE2 magic bytes (doc, xls, ppt)
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class OfficeAnalyzer(Analyzer):
    """Analyzer for Microsoft Office files.

    Supports legacy OLE2 formats (.doc, .xls, .ppt) identified by
    the ``\xd0\xcf\x11\xe0`` magic bytes.  Modern OOXML formats
    (.docx, .xlsx, .pptx) are ZIP-based and will be handled by
    ``ZIPAnalyzer`` instead.
    """

    def supports(self, file_path: Path) -> bool:
        """Return *True* if *file_path* starts with the OLE2 magic bytes."""
        try:
            with open(file_path, "rb") as fh:
                return fh.read(8) == _OLE2_MAGIC
        except OSError:
            return False

    def analyze(self, file_path: Path) -> AnalysisResult:
        """Analyze an Office file.

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

        msg = "OfficeAnalyzer is not yet implemented"
        raise NotImplementedError(msg)
