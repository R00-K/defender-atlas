"""Abstract base class for file type analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from defenderatlas.models.core import AnalysisResult


class Analyzer(ABC):
    """Abstract interface for file scanning behavior analyzers.

    Every concrete analyzer must implement:
    - ``supports()``: fast check whether the analyzer handles the file type.
    - ``analyze()``: full analysis returning an ``AnalysisResult``.
    """

    @abstractmethod
    def supports(self, file_path: Path) -> bool:
        """Return *True* if this analyzer can handle *file_path*.

        The check should be fast (magic-byte sniffing or extension check)
        and must not perform heavy I/O.
        """

    @abstractmethod
    def analyze(self, file_path: Path) -> AnalysisResult:
        """Analyze *file_path* and return structured results.

        Raises
        ------
        FileNotFoundError
            If *file_path* does not exist.
        RuntimeError
            If the analysis engine is not yet implemented.
        """
