"""Data models for PE structure mapping.

These models represent the result of mapping ProcMon ReadEvent offsets
to PE file structures.  A :class:`PERegion` describes a contiguous
range within a PE file that corresponds to a known structure (header,
section, directory, etc.).  A :class:`MappedReadEvent` wraps an
original :class:`~defenderatlas.models.core.ReadEvent` with the list
of regions it touches.

PE File Layout
--------------
A PE file is laid out on disk as follows::

    ┌──────────────────────────┐  0x0
    │ DOS Header (64 bytes)    │
    ├──────────────────────────┤  0x40
    │ DOS Stub                │
    ├──────────────────────────┤  e_lfanew
    │ NT Headers              │
    │  ├─ Signature (4 bytes)  │
    │  ├─ File Header (20 B)   │
    │  └─ Optional Header     │
    ├──────────────────────────┤
    │ Section Table            │
    ├──────────────────────────┤
    │ Section data (.text, …)  │
    ├──────────────────────────┤
    │ Overlay (if present)     │
    └──────────────────────────┘

RVA vs File Offset
------------------
PE structures reference each other using Relative Virtual Addresses
(RVAs) — offsets relative to the image base when loaded into memory.
On disk, structures may be at different positions due to section
alignment.  The :func:`~defenderatlas.mapping.pe_mapper.map_events`
function works with raw **file offsets** (as reported by ProcMon),
converting RVAs to file offsets via the section table when needed.

Region Boundaries
-----------------
Each :class:`PERegion` uses **inclusive** start and end offsets
matching the conventions of the existing :class:`ScanPhase` model.
A read at offset ``O`` with length ``L`` touches bytes
``[O, O + L - 1]``.  If that range intersects a region's
``[start_offset, end_offset]`` the read is considered to match
that region.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from defenderatlas.models.core import ReadEvent  # noqa: TC001


class PERegion(BaseModel):
    """A contiguous range within a PE file corresponding to a structure.

    Regions are built once from the parsed PE headers and section
    table, then used to match incoming :class:`ReadEvent` offsets.
    All fields are immutable after construction.

    Attributes
    ----------
    name:
        Short human-readable label, e.g. ``"DOS Header"``,
        ``".text"``, ``"Import Directory"``.
    start_offset:
        First byte offset of the region (inclusive).
    end_offset:
        Last byte offset of the region (inclusive).
    description:
        Detailed explanation of what this PE structure represents.
    """

    name: str = Field(
        min_length=1,
        description="Short label for the PE region.",
    )
    start_offset: int = Field(
        ge=0,
        description="First byte offset of the region (inclusive).",
    )
    end_offset: int = Field(
        ge=0,
        description="Last byte offset of the region (inclusive).",
    )
    description: str = Field(
        min_length=1,
        description="Human-readable explanation of the PE structure.",
    )

    @model_validator(mode="after")
    def _check_offsets(self) -> PERegion:
        if self.end_offset < self.start_offset:
            msg = (
                f"end_offset ({self.end_offset}) must be >= "
                f"start_offset ({self.start_offset})"
            )
            raise ValueError(msg)
        return self

    def overlaps(self, offset: int, length: int) -> bool:
        """Check whether a byte range intersects this region.

        Parameters
        ----------
        offset:
            Start of the read range (inclusive).
        length:
            Number of bytes in the read range.

        Returns
        -------
        bool
            ``True`` if ``[offset, offset + length - 1]`` intersects
            ``[self.start_offset, self.end_offset]``.
        """
        read_end = offset + length - 1
        return offset <= self.end_offset and read_end >= self.start_offset


class MappedReadEvent(BaseModel):
    """A :class:`ReadEvent` annotated with the PE regions it touches.

    When a read spans multiple structures (e.g. it crosses from the
    section table into the first section), *all* matching regions are
    recorded in :attr:`matched_regions`.

    If no PE region matches the read offset, *matched_regions* is
    an empty list — this can happen for reads beyond the last known
    structure or for padding bytes.

    Attributes
    ----------
    original:
        The unmodified :class:`ReadEvent` as captured by ProcMon.
    matched_regions:
        Ordered list of :class:`PERegion` objects whose byte ranges
        intersect the read.
    """

    original: ReadEvent = Field(
        description="The unmodified ReadEvent from ProcMon.",
    )
    matched_regions: list[PERegion] = Field(
        default_factory=list,
        description="PE regions that intersect this read.",
    )
