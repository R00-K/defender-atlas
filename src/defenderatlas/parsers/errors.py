"""Custom exceptions for DefenderAtlas parsers."""

from __future__ import annotations


class ParserError(Exception):
    """Base exception for all parser errors."""


class CSVFormatError(ParserError):
    """Raised when the CSV structure is invalid or unreadable."""


class HeaderError(CSVFormatError):
    """Raised when required CSV headers are missing or malformed."""


class RowError(ParserError):
    """Raised when a single row cannot be parsed.

    Attributes
    ----------
    line_number:
        1-based line number in the source file.
    raw:
        The original, unparsed row text.
    reason:
        Human-readable explanation of what went wrong.
    """

    def __init__(
        self,
        line_number: int,
        raw: str,
        reason: str,
    ) -> None:
        self.line_number = line_number
        self.raw = raw
        self.reason = reason
        super().__init__(f"Line {line_number}: {reason}")


class TimestampParseError(RowError):
    """Raised when a timestamp value cannot be parsed."""


class OffsetParseError(RowError):
    """Raised when an offset value cannot be extracted from the detail column."""


class LengthParseError(RowError):
    """Raised when a length value cannot be extracted from the detail column."""
