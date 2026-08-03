"""File format and structure mapping."""

from defenderatlas.mapping.errors import InvalidPEError, MappingError, TruncatedPEError
from defenderatlas.mapping.models import MappedReadEvent, PERegion
from defenderatlas.mapping.pe_mapper import map_events

__all__ = [
    "InvalidPEError",
    "MappedReadEvent",
    "MappingError",
    "PERegion",
    "TruncatedPEError",
    "map_events",
]
