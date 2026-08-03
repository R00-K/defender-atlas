"""Unit tests for the analyzer architecture."""

from __future__ import annotations

from pathlib import Path

import pytest

from defenderatlas.analyzers import (
    Analyzer,
    OfficeAnalyzer,
    PDFAnalyzer,
    PEAnalyzer,
    PNGAnalyzer,
    ZIPAnalyzer,
)
from defenderatlas.models.core import AnalysisResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_file(tmp_path: Path, name: str, content: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(content)
    return p


# ===========================================================================
# Abstract base class
# ===========================================================================


class TestAnalyzerABC:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            Analyzer()  # type: ignore[abstract]

    def test_subclass_must_implement_supports(self) -> None:
        class Incomplete(Analyzer):
            def analyze(self, file_path: Path) -> AnalysisResult:
                raise NotImplementedError

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_subclass_must_implement_analyze(self) -> None:
        class Incomplete(Analyzer):
            def supports(self, file_path: Path) -> bool:
                return True

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_concrete_subclass_instantiates(self) -> None:
        class Complete(Analyzer):
            def supports(self, file_path: Path) -> bool:
                return True

            def analyze(self, file_path: Path) -> AnalysisResult:
                raise NotImplementedError

        assert Complete().supports(Path(".")) is True


# ===========================================================================
# PEAnalyzer
# ===========================================================================


class TestPEAnalyzer:
    def test_supports_pe_file(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.exe", b"MZ" + b"\x00" * 64)
        analyzer = PEAnalyzer()
        assert analyzer.supports(p) is True

    def test_supports_false_for_non_pe(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.txt", b"Hello, world!")
        analyzer = PEAnalyzer()
        assert analyzer.supports(p) is False

    def test_supports_false_for_empty_file(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "empty.exe", b"")
        analyzer = PEAnalyzer()
        assert analyzer.supports(p) is False

    def test_supports_false_for_nonexistent_file(self) -> None:
        analyzer = PEAnalyzer()
        assert analyzer.supports(Path("/nonexistent/file.exe")) is False

    def test_analyze_returns_analysis_result(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.exe", b"MZ" + b"\x00" * 64)
        analyzer = PEAnalyzer()
        result = analyzer.analyze(p)
        assert isinstance(result, AnalysisResult)
        assert result.file_type == "PE"
        assert result.findings == []
        assert result.phases == []
        assert result.statistics.total_reads == 0
        assert result.statistics.read_amplification == 0.0

    def test_analyze_raises_for_nonexistent_file(self) -> None:
        analyzer = PEAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.analyze(Path("/nonexistent/file.exe"))

    def test_is_subclass_of_analyzer(self) -> None:
        assert issubclass(PEAnalyzer, Analyzer)

    def test_instance_is_analyzer(self) -> None:
        assert isinstance(PEAnalyzer(), Analyzer)


# ===========================================================================
# ZIPAnalyzer
# ===========================================================================


class TestZIPAnalyzer:
    def test_supports_zip_file(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.zip", b"PK\x03\x04" + b"\x00" * 64)
        analyzer = ZIPAnalyzer()
        assert analyzer.supports(p) is True

    def test_supports_false_for_non_zip(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.txt", b"Hello, world!")
        analyzer = ZIPAnalyzer()
        assert analyzer.supports(p) is False

    def test_supports_false_for_nonexistent_file(self) -> None:
        analyzer = ZIPAnalyzer()
        assert analyzer.supports(Path("/nonexistent/file.zip")) is False

    def test_analyze_raises_not_implemented(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.zip", b"PK\x03\x04" + b"\x00" * 64)
        analyzer = ZIPAnalyzer()
        with pytest.raises(NotImplementedError, match="ZIPAnalyzer"):
            analyzer.analyze(p)

    def test_analyze_raises_file_not_found(self) -> None:
        analyzer = ZIPAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.analyze(Path("/nonexistent/file.zip"))

    def test_is_subclass_of_analyzer(self) -> None:
        assert issubclass(ZIPAnalyzer, Analyzer)


# ===========================================================================
# PNGAnalyzer
# ===========================================================================


class TestPNGAnalyzer:
    def test_supports_png_file(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        analyzer = PNGAnalyzer()
        assert analyzer.supports(p) is True

    def test_supports_false_for_non_png(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.txt", b"Hello, world!")
        analyzer = PNGAnalyzer()
        assert analyzer.supports(p) is False

    def test_supports_false_for_nonexistent_file(self) -> None:
        analyzer = PNGAnalyzer()
        assert analyzer.supports(Path("/nonexistent/file.png")) is False

    def test_analyze_raises_not_implemented(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        analyzer = PNGAnalyzer()
        with pytest.raises(NotImplementedError, match="PNGAnalyzer"):
            analyzer.analyze(p)

    def test_analyze_raises_file_not_found(self) -> None:
        analyzer = PNGAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.analyze(Path("/nonexistent/file.png"))

    def test_is_subclass_of_analyzer(self) -> None:
        assert issubclass(PNGAnalyzer, Analyzer)


# ===========================================================================
# PDFAnalyzer
# ===========================================================================


class TestPDFAnalyzer:
    def test_supports_pdf_file(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.pdf", b"%PDF-1.4" + b"\x00" * 64)
        analyzer = PDFAnalyzer()
        assert analyzer.supports(p) is True

    def test_supports_false_for_non_pdf(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.txt", b"Hello, world!")
        analyzer = PDFAnalyzer()
        assert analyzer.supports(p) is False

    def test_supports_false_for_nonexistent_file(self) -> None:
        analyzer = PDFAnalyzer()
        assert analyzer.supports(Path("/nonexistent/file.pdf")) is False

    def test_analyze_raises_not_implemented(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.pdf", b"%PDF-1.4" + b"\x00" * 64)
        analyzer = PDFAnalyzer()
        with pytest.raises(NotImplementedError, match="PDFAnalyzer"):
            analyzer.analyze(p)

    def test_analyze_raises_file_not_found(self) -> None:
        analyzer = PDFAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.analyze(Path("/nonexistent/file.pdf"))

    def test_is_subclass_of_analyzer(self) -> None:
        assert issubclass(PDFAnalyzer, Analyzer)


# ===========================================================================
# OfficeAnalyzer
# ===========================================================================


class TestOfficeAnalyzer:
    def test_supports_ole2_file(self, tmp_path: Path) -> None:
        p = _write_file(
            tmp_path,
            "test.doc",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64,
        )
        analyzer = OfficeAnalyzer()
        assert analyzer.supports(p) is True

    def test_supports_false_for_non_ole2(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.txt", b"Hello, world!")
        analyzer = OfficeAnalyzer()
        assert analyzer.supports(p) is False

    def test_supports_false_for_nonexistent_file(self) -> None:
        analyzer = OfficeAnalyzer()
        assert analyzer.supports(Path("/nonexistent/file.doc")) is False

    def test_analyze_raises_not_implemented(self, tmp_path: Path) -> None:
        p = _write_file(
            tmp_path,
            "test.doc",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64,
        )
        analyzer = OfficeAnalyzer()
        with pytest.raises(NotImplementedError, match="OfficeAnalyzer"):
            analyzer.analyze(p)

    def test_analyze_raises_file_not_found(self) -> None:
        analyzer = OfficeAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.analyze(Path("/nonexistent/file.doc"))

    def test_is_subclass_of_analyzer(self) -> None:
        assert issubclass(OfficeAnalyzer, Analyzer)


# ===========================================================================
# Polymorphic dispatch
# ===========================================================================


class TestAnalyzerDispatch:
    """Verify that analyzers can be used polymorphically."""

    def test_all_analyzers_in_registry(self) -> None:
        analyzers: list[Analyzer] = [
            PEAnalyzer(),
            ZIPAnalyzer(),
            PNGAnalyzer(),
            PDFAnalyzer(),
            OfficeAnalyzer(),
        ]
        assert len(analyzers) == 5

    def test_dispatch_by_supports(self, tmp_path: Path) -> None:
        pe = _write_file(tmp_path, "test.exe", b"MZ" + b"\x00" * 64)
        pdf = _write_file(tmp_path, "test.pdf", b"%PDF-1.4" + b"\x00" * 64)

        analyzers: list[Analyzer] = [
            PEAnalyzer(),
            ZIPAnalyzer(),
            PNGAnalyzer(),
            PDFAnalyzer(),
            OfficeAnalyzer(),
        ]

        for path, expected in [(pe, PEAnalyzer), (pdf, PDFAnalyzer)]:
            matched = [a for a in analyzers if a.supports(path)]
            assert len(matched) == 1
            assert isinstance(matched[0], expected)

    def test_pe_returns_result_others_raise(self, tmp_path: Path) -> None:
        files: dict[type[Analyzer], Path] = {
            PEAnalyzer: _write_file(tmp_path, "test.exe", b"MZ" + b"\x00" * 64),
            ZIPAnalyzer: _write_file(
                tmp_path, "test.zip", b"PK\x03\x04" + b"\x00" * 64
            ),
            PNGAnalyzer: _write_file(
                tmp_path, "test.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
            ),
            PDFAnalyzer: _write_file(tmp_path, "test.pdf", b"%PDF-1.4" + b"\x00" * 64),
            OfficeAnalyzer: _write_file(
                tmp_path,
                "test.doc",
                b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64,
            ),
        }

        for cls, path in files.items():
            analyzer = cls()
            if cls is PEAnalyzer:
                result = analyzer.analyze(path)
                assert isinstance(result, AnalysisResult)
            else:
                with pytest.raises(NotImplementedError):
                    analyzer.analyze(path)
