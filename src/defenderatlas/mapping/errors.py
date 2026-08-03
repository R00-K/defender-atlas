"""Custom exceptions for DefenderAtlas PE mapping engine."""

from __future__ import annotations


class MappingError(Exception):
    """Base exception for all PE mapping errors."""


class InvalidPEError(MappingError):
    """Raised when the file is not a valid PE or cannot be parsed."""

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"Invalid PE file {path}: {reason}")


class TruncatedPEError(MappingError):
    """Raised when the PE file is truncated and structures are incomplete."""

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"Truncated PE file {path}: {reason}")
