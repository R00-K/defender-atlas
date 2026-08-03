"""File type analyzers for DefenderAtlas."""

from defenderatlas.analyzers.base import Analyzer
from defenderatlas.analyzers.office import OfficeAnalyzer
from defenderatlas.analyzers.pdf import PDFAnalyzer
from defenderatlas.analyzers.pe import PEAnalyzer
from defenderatlas.analyzers.png import PNGAnalyzer
from defenderatlas.analyzers.zip import ZIPAnalyzer

__all__ = [
    "Analyzer",
    "OfficeAnalyzer",
    "PDFAnalyzer",
    "PEAnalyzer",
    "PNGAnalyzer",
    "ZIPAnalyzer",
]
