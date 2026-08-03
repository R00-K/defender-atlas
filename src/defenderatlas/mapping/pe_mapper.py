"""PE structure mapping engine.

Maps ProcMon :class:`ReadEvent` file offsets to PE structures
(headers, directories, sections, overlay) parsed by ``pefile``.

How It Works
------------
1. **Parse** the PE file with ``pefile.PE()`` to obtain headers,
   the section table, data directories, and overlay.
2. **Build regions** — a sorted list of :class:`PERegion` objects,
   one per recognised PE structure (DOS header, NT headers, each
   section, each directory, overlay, etc.).
3. **Map events** — for each :class:`ReadEvent`, find every region
   whose ``[start, end]`` range intersects the read's
   ``[offset, offset + length - 1]`` range.

RVA → File Offset Conversion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PE data directories store Relative Virtual Addresses (RVAs).  To
convert an RVA to a file offset the section table is used::

    for section in sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            file_offset = rva - section.VirtualAddress + section.PointerToRawData
            break

If no section mapping is found (e.g. the RVA falls in the header
area), the RVA is used directly as a file offset.

Performance
~~~~~~~~~~~
Region lookup uses a **sorted list + binary search** to narrow the
candidate set, then checks only nearby regions.  For *n* events and
*m* regions the complexity is ``O(n log m)`` — suitable for thousands
of events and hundreds of regions.
"""

from __future__ import annotations

import bisect
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import pefile  # type: ignore[import-untyped]

from defenderatlas.mapping.errors import InvalidPEError, TruncatedPEError
from defenderatlas.mapping.models import MappedReadEvent, PERegion

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from defenderatlas.models.core import ReadEvent

log = logging.getLogger(__name__)

# ── region name constants ────────────────────────────────────────────

DOS_HEADER = "DOS Header"
DOS_STUB = "DOS Stub"
NT_HEADERS = "NT Headers"
FILE_HEADER = "File Header"
OPTIONAL_HEADER = "Optional Header"
SECTION_TABLE = "Section Table"
IMPORT_DIR = "Import Directory"
EXPORT_DIR = "Export Directory"
RESOURCE_DIR = "Resource Directory"
RELOCATION_DIR = "Relocation Directory"
TLS_DIR = "TLS Directory"
DEBUG_DIR = "Debug Directory"
CERTIFICATE_TABLE = "Certificate Table"
BOUND_IMPORT_DIR = "Bound Import Directory"
DELAY_IMPORT_DIR = "Delay Import Directory"
IAT_DIR = "IAT Directory"
COM_DESCRIPTOR_DIR = "COM Descriptor Directory"
OVERLAY = "Overlay"


# ── helpers ──────────────────────────────────────────────────────────


def _rva_to_file_offset(
    rva: int,
    sections: list[pefile.SectionStructure],
) -> int | None:
    """Convert a Relative Virtual Address to a raw file offset.

    Parameters
    ----------
    rva:
        The RVA to convert.
    sections:
        Sorted list of PE section structures from ``pefile``.

    Returns
    -------
    int or None
        The file offset, or ``None`` if no section maps this RVA.
    """
    for section in sections:
        sec_start = section.VirtualAddress
        sec_end = sec_start + section.Misc_VirtualSize
        if sec_start <= rva < sec_end:
            return rva - sec_start + section.PointerToRawData  # type: ignore[no-any-return]
    return None


def _rva_to_file_offset_safe(
    rva: int,
    sections: list[pefile.SectionStructure],
) -> int:
    """Like ``_rva_to_file_offset`` but falls back to the RVA itself."""
    result = _rva_to_file_offset(rva, sections)
    return result if result is not None else rva


def _build_overlay_region(pe: pefile.PE) -> PERegion | None:
    """Build a PERegion for the overlay, if present.

    The overlay starts after the last section's raw data and extends
    to the end of the file.
    """
    if not hasattr(pe, "OVERLAY_START") or pe.OVERLAY_START is None:
        return None
    overlay_start = pe.OVERLAY_START
    overlay_size = pe.OVERLAY_SIZE if hasattr(pe, "OVERLAY_SIZE") else 0
    if overlay_size <= 0:
        return None
    return PERegion(
        name=OVERLAY,
        start_offset=overlay_start,
        end_offset=overlay_start + overlay_size - 1,
        description=(
            "Data appended after the last section; not loaded into "
            "memory by the PE loader.  Often contains signatures, "
            "resources, or appended payloads."
        ),
    )


# ── region builders ──────────────────────────────────────────────────


def _build_header_regions(
    pe: pefile.PE,
    sections: list[pefile.SectionStructure],
) -> list[PERegion]:
    """Build regions for the fixed-size PE header structures.

    Covers DOS Header, DOS Stub, NT Headers, File Header, and
    Optional Header.
    """
    regions: list[PERegion] = []

    # DOS Header: always at offset 0, 64 bytes.
    dos_size = 64
    regions.append(
        PERegion(
            name=DOS_HEADER,
            start_offset=0,
            end_offset=dos_size - 1,
            description=(
                "MZ DOS header (64 bytes).  Contains the DOS stub "
                "signature, e_lfanew pointer to NT Headers, and "
                "legacy relocation/linker fields."
            ),
        )
    )

    # DOS Stub: between DOS header and NT headers.
    e_lfanew = pe.DOS_HEADER.e_lfanew
    if e_lfanew > dos_size:
        regions.append(
            PERegion(
                name=DOS_STUB,
                start_offset=dos_size,
                end_offset=e_lfanew - 1,
                description=(
                    "DOS stub program — typically prints "
                    "'This program cannot be run in DOS mode'."
                ),
            )
        )

    # NT Headers: starts at e_lfanew.
    nt_start = e_lfanew
    # We need the size; compute from FileHeader + OptionalHeader.
    file_hdr_size = pe.FILE_HEADER.sizeof()
    opt_hdr_size = pe.OPTIONAL_HEADER.sizeof() if hasattr(pe, "OPTIONAL_HEADER") else 0
    nt_end = nt_start + 4 + file_hdr_size + opt_hdr_size - 1
    regions.append(
        PERegion(
            name=NT_HEADERS,
            start_offset=nt_start,
            end_offset=nt_end,
            description=(
                "PE signature + File Header + Optional Header.  "
                "The root of the PE structure."
            ),
        )
    )

    # File Header: immediately after the 4-byte signature.
    file_hdr_start = nt_start + 4
    file_hdr_end = file_hdr_start + file_hdr_size - 1
    regions.append(
        PERegion(
            name=FILE_HEADER,
            start_offset=file_hdr_start,
            end_offset=file_hdr_end,
            description=(
                "COFF File Header (20 bytes): machine type, section "
                "count, timestamp, characteristics."
            ),
        )
    )

    # Optional Header.
    if opt_hdr_size > 0:
        opt_start = file_hdr_start + file_hdr_size
        opt_end = opt_start + opt_hdr_size - 1
        regions.append(
            PERegion(
                name=OPTIONAL_HEADER,
                start_offset=opt_start,
                end_offset=opt_end,
                description=(
                    "Optional Header: entry point, image base, "
                    "section alignment, data directory pointers."
                ),
            )
        )

    return regions


def _build_section_regions(
    pe: pefile.PE,
    sections: list[pefile.SectionStructure],
) -> list[PERegion]:
    """Build PERegion objects for each PE section."""
    regions: list[PERegion] = []
    for section in sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        raw_size = section.SizeOfRawData
        if raw_size <= 0:
            continue
        regions.append(
            PERegion(
                name=name,
                start_offset=section.PointerToRawData,
                end_offset=section.PointerToRawData + raw_size - 1,
                description=(
                    f"Section '{name}': {raw_size:,} bytes on disk, "
                    f"{section.Misc_VirtualSize:,} bytes virtual."
                ),
            )
        )
    return regions


def _build_section_table_region(
    pe: pefile.PE,
    sections: list[pefile.SectionStructure],
) -> PERegion | None:
    """Build a region for the section header table."""
    if not sections:
        return None
    # Section table starts right after the Optional Header.
    opt_end = (
        pe.DOS_HEADER.e_lfanew
        + 4
        + pe.FILE_HEADER.sizeof()
        + pe.OPTIONAL_HEADER.sizeof()
    )
    first_section = sections[0]
    table_start = opt_end
    table_end = first_section.PointerToRawData - 1
    if table_end < table_start:
        return None
    return PERegion(
        name=SECTION_TABLE,
        start_offset=table_start,
        end_offset=table_end,
        description=(
            "Section table: array of section headers describing "
            "each section's name, size, and file/memory offsets."
        ),
    )


def _build_directory_regions(
    pe: pefile.PE,
    sections: list[pefile.SectionStructure],
) -> list[PERegion]:
    """Build PERegion objects for each data directory entry."""
    regions: list[PERegion] = []
    if not hasattr(pe, "OPTIONAL_HEADER"):
        return regions

    # pefile maps directory names by index.
    _dir_names: dict[int, tuple[str, str]] = {
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]: (
            EXPORT_DIR,
            "Export directory: function names and ordinals " "exported by the DLL.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]: (
            IMPORT_DIR,
            "Import directory: DLLs and functions imported by " "this PE.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]: (
            RESOURCE_DIR,
            "Resource directory: icons, manifests, strings, "
            "and other embedded resources.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]: (
            RELOCATION_DIR,
            "Base relocation table: patches needed when the "
            "image base differs from the preferred address.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]: (
            TLS_DIR,
            "Thread-Local Storage directory: initialisation "
            "callbacks and TLS data ranges.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]: (
            DEBUG_DIR,
            "Debug directory: CodeView PDB paths, " "timestamps, and type info.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"]: (
            BOUND_IMPORT_DIR,
            "Bound import directory: pre-computed import "
            "timestamps for faster loading.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]: (
            DELAY_IMPORT_DIR,
            "Delay-load import directory: DLLs loaded on " "first function call.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]: (
            IAT_DIR,
            "Import Address Table: resolved function pointers " "filled at load time.",
        ),
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]: (
            COM_DESCRIPTOR_DIR,
            ".NET COM descriptor (CLR header): metadata " "for managed assemblies.",
        ),
    }

    for idx, (name, desc) in _dir_names.items():
        if idx >= len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            break
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        if directory.VirtualAddress == 0 or directory.Size == 0:
            continue
        file_offset = _rva_to_file_offset_safe(directory.VirtualAddress, sections)
        regions.append(
            PERegion(
                name=name,
                start_offset=file_offset,
                end_offset=file_offset + directory.Size - 1,
                description=desc,
            )
        )

    # Certificate Table is special: its VirtualAddress is a file
    # offset, not an RVA.
    try:
        cert_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_CERTIFICATE"]
    except KeyError:
        cert_idx = None
    if cert_idx is not None and cert_idx < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[cert_idx]
        if cert_dir.VirtualAddress > 0 and cert_dir.Size > 0:
            regions.append(
                PERegion(
                    name=CERTIFICATE_TABLE,
                    start_offset=cert_dir.VirtualAddress,
                    end_offset=cert_dir.VirtualAddress + cert_dir.Size - 1,
                    description=(
                        "Certificate table: Authenticode signature "
                        "embedded in the PE file.  The VirtualAddress "
                        "field is a raw file offset, not an RVA."
                    ),
                )
            )

    return regions


def _build_regions(pe: pefile.PE) -> list[PERegion]:
    """Build the complete ordered list of PE regions from a parsed PE.

    Parameters
    ----------
    pe:
        A parsed ``pefile.PE`` object.

    Returns
    -------
    list[PERegion]
        Regions sorted by ``start_offset``.
    """
    sections: list[pefile.SectionStructure] = list(pe.sections)
    regions: list[PERegion] = []

    regions.extend(_build_header_regions(pe, sections))

    table_region = _build_section_table_region(pe, sections)
    if table_region is not None:
        regions.append(table_region)

    regions.extend(_build_directory_regions(pe, sections))
    regions.extend(_build_section_regions(pe, sections))

    overlay = _build_overlay_region(pe)
    if overlay is not None:
        regions.append(overlay)

    # Sort by start_offset for binary-search lookup.
    regions.sort(key=lambda r: r.start_offset)
    return regions


# ── lookup helpers ───────────────────────────────────────────────────


def _find_overlapping_regions(
    offset: int,
    length: int,
    sorted_regions: list[PERegion],
    starts: list[int],
) -> list[PERegion]:
    """Find all regions overlapping ``[offset, offset + length - 1]``.

    Uses binary search on *starts* to narrow candidates, then checks
    each candidate for actual overlap.  Complexity: O(log m + k)
    where *k* is the number of matching regions.

    Parameters
    ----------
    offset:
        Read start offset.
    length:
        Read length in bytes.
    sorted_regions:
        Regions sorted by ``start_offset``.
    starts:
        Parallel list of ``start_offset`` values for binary search.
    """
    read_end = offset + length - 1

    # Find the first region whose start_offset <= read_end.
    # bisect_right gives us the insertion point; we step back one.
    idx = bisect.bisect_right(starts, read_end) - 1

    matches: list[PERegion] = []
    while idx >= 0:
        region = sorted_regions[idx]
        if region.start_offset > read_end:
            break
        if region.overlaps(offset, length):
            matches.append(region)
        # Regions are sorted by start_offset; once start_offset < offset
        # and the region doesn't overlap, earlier ones won't either.
        if region.end_offset < offset:
            break
        idx -= 1

    # Also check regions that start *after* our offset but before read_end.
    idx = bisect.bisect_left(starts, offset)
    while idx < len(sorted_regions):
        region = sorted_regions[idx]
        if region.start_offset > read_end:
            break
        if region.overlaps(offset, length) and region not in matches:
            matches.append(region)
        idx += 1

    # Maintain sorted order by start_offset.
    matches.sort(key=lambda r: r.start_offset)
    return matches


# ── public API ───────────────────────────────────────────────────────


def map_events(
    pe_path: str | Path,
    events: Iterable[ReadEvent],
) -> Iterator[MappedReadEvent]:
    """Map ProcMon ReadEvents to PE structure regions.

    Parses the PE file at *pe_path* once, builds a sorted list of
    :class:`PERegion` objects, then maps each :class:`ReadEvent` to
    the regions it overlaps.

    Parameters
    ----------
    pe_path:
        Path to a PE file (EXE, DLL, SYS, etc.).
    events:
        Any iterable of :class:`ReadEvent` objects.  Consumed lazily.

    Yields
    ------
    MappedReadEvent
        One result per input event, with :attr:`matched_regions`
        populated.

    Raises
    ------
    InvalidPEError
        If *pe_path* does not exist or cannot be parsed as a PE.
    TruncatedPEError
        If the PE file appears truncated.
    FileNotFoundError
        If *pe_path* does not exist.
    """
    pe_path = Path(pe_path)
    if not pe_path.exists():
        raise FileNotFoundError(f"PE file not found: {pe_path}")

    try:
        pe = pefile.PE(str(pe_path))
    except pefile.PEFormatError as exc:
        raise InvalidPEError(str(pe_path), f"pefile parse error: {exc}") from exc

    try:
        regions = _build_regions(pe)
    except Exception as exc:
        raise TruncatedPEError(str(pe_path), f"Cannot build regions: {exc}") from exc

    # Build parallel sorted arrays for binary search.
    sorted_regions = sorted(regions, key=lambda r: r.start_offset)
    starts = [r.start_offset for r in sorted_regions]

    for event in events:
        matched = _find_overlapping_regions(
            event.offset, event.length, sorted_regions, starts
        )
        yield MappedReadEvent(
            original=event,
            matched_regions=matched,
        )
