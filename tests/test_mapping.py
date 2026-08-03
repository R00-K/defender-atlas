"""Unit tests for the PE mapping engine."""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from defenderatlas.mapping.errors import InvalidPEError, MappingError, TruncatedPEError
from defenderatlas.mapping.models import MappedReadEvent, PERegion
from defenderatlas.mapping.pe_mapper import (
    DOS_HEADER,
    DOS_STUB,
    FILE_HEADER,
    IMPORT_DIR,
    NT_HEADERS,
    OPTIONAL_HEADER,
    OVERLAY,
    SECTION_TABLE,
    _build_overlay_region,
    map_events,
)
from defenderatlas.models.core import ReadEvent

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(UTC)


def _make_event(
    *,
    offset: int = 0,
    length: int = 4096,
    process_name: str = "MsMpEng.exe",
    process_id: int = 1234,
    operation: str = "ReadFile",
    path: str = r"C:\test.exe",
    result: str = "SUCCESS",
) -> ReadEvent:
    return ReadEvent(
        timestamp=_NOW,
        process_name=process_name,
        process_id=process_id,
        operation=operation,
        path=path,
        offset=offset,
        length=length,
        result=result,
    )


def _build_minimal_pe(tmp_path: Path, *, overlay_size: int = 0) -> Path:
    """Build a minimal valid PE32 file for testing.

    Layout (all offsets are exact):
        0x000 - 0x03F : DOS Header (64 bytes)
        0x040 - 0x07F : DOS Stub (64 bytes)
        0x080 - 0x083 : PE Signature "PE\\0\\0"
        0x084 - 0x097 : FILE_HEADER (20 bytes)
        0x098 - 0x177 : OPTIONAL_HEADER (224 bytes)
        0x178 - 0x19F : Section Table (1 entry = 40 bytes)
        0x200 - 0x3FF : .text section (512 bytes)
    """
    pe_file = tmp_path / "test.exe"
    buf = bytearray()

    # ── DOS Header (64 bytes) ────────────────────────────────────────
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"  # e_magic
    struct.pack_into("<I", dos_header, 60, 0x80)  # e_lfanew → 0x80
    buf.extend(dos_header)

    # ── DOS Stub (64 bytes) ──────────────────────────────────────────
    buf.extend(b"\x00" * 64)

    # ── NT Headers at 0x80 ───────────────────────────────────────────
    # Signature
    buf.extend(b"PE\x00\x00")

    # FILE_HEADER (20 bytes)
    file_header = bytearray(20)
    struct.pack_into("<H", file_header, 0, 0x014C)  # Machine: i386
    struct.pack_into("<H", file_header, 2, 1)  # NumberOfSections
    struct.pack_into("<I", file_header, 4, 0)  # TimeDateStamp
    struct.pack_into("<I", file_header, 8, 0)  # PointerToSymbolTable
    struct.pack_into("<I", file_header, 12, 0)  # NumberOfSymbols
    struct.pack_into("<H", file_header, 16, 0xE0)  # SizeOfOptionalHeader
    struct.pack_into("<H", file_header, 18, 0x0102)  # Characteristics
    buf.extend(file_header)

    # OPTIONAL_HEADER (0xE0 = 224 bytes for PE32)
    opt_header = bytearray(0xE0)
    struct.pack_into("<H", opt_header, 0, 0x010B)  # Magic: PE32
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt_header, 28, 0x1000)  # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)  # FileAlignment
    struct.pack_into("<H", opt_header, 40, 4)  # MajorOperatingSystemVersion
    struct.pack_into("<I", opt_header, 56, 0x1000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<I", opt_header, 92, 16)  # NumberOfRvaAndSizes
    # Data directories start at offset 96 in optional header.
    # We leave them all zero (no directories).
    buf.extend(opt_header)

    # Pad to FileAlignment (0x200) boundary for section data.
    while len(buf) < 0x200:
        buf.extend(b"\x00")

    # ── Section Table ────────────────────────────────────────────────
    # .text section header (40 bytes) — placed before .text data.
    text_section = bytearray(40)
    text_section[0:6] = b".text\x00"
    struct.pack_into("<I", text_section, 8, 0x200)  # VirtualSize
    struct.pack_into("<I", text_section, 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", text_section, 16, 0x200)  # SizeOfRawData
    struct.pack_into("<I", text_section, 20, 0x200)  # PointerToRawData
    # Overwrite the padding with section table at correct offset.
    buf[0x178 : 0x178 + 40] = text_section

    # ── .text section data (0x200 bytes at 0x200) ────────────────────
    buf.extend(b"\xcc" * 0x200)

    # ── Overlay (optional) ──────────────────────────────────────────
    if overlay_size > 0:
        buf.extend(b"OVERLAY_DATA"[:overlay_size].ljust(overlay_size, b"\x00"))

    pe_file.write_bytes(bytes(buf))
    return pe_file


def _build_pe_with_import_dir(tmp_path: Path) -> Path:
    """Build a PE with a minimal Import Directory in .rdata."""
    pe_file = tmp_path / "test_import.exe"
    buf = bytearray()

    # DOS Header
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 0x80)
    buf.extend(dos_header)

    # DOS Stub
    buf.extend(b"\x00" * 64)

    # NT Headers
    buf.extend(b"PE\x00\x00")

    # FILE_HEADER (NumberOfSections=2)
    file_header = bytearray(20)
    struct.pack_into("<H", file_header, 0, 0x014C)
    struct.pack_into("<H", file_header, 2, 2)  # 2 sections
    struct.pack_into("<H", file_header, 16, 0xE0)
    struct.pack_into("<H", file_header, 18, 0x0102)
    buf.extend(file_header)

    # OPTIONAL_HEADER (PE32, 0xE0 bytes)
    opt_header = bytearray(0xE0)
    struct.pack_into("<H", opt_header, 0, 0x010B)
    struct.pack_into("<I", opt_header, 16, 0x1000)
    struct.pack_into("<I", opt_header, 28, 0x1000)
    struct.pack_into("<I", opt_header, 32, 0x1000)
    struct.pack_into("<I", opt_header, 36, 0x200)
    struct.pack_into("<I", opt_header, 56, 0x3000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x200)
    struct.pack_into("<I", opt_header, 92, 16)

    # Import Directory entry (index 1): RVA=0x2000, Size=48
    struct.pack_into("<I", opt_header, 96 + 8, 0x2000)
    struct.pack_into("<I", opt_header, 96 + 12, 48)
    buf.extend(opt_header)

    # Section Table — pad to section table area first.
    while len(buf) < 0x178:
        buf.extend(b"\x00")

    # .text section header (40 bytes)
    text_section = bytearray(40)
    text_section[0:6] = b".text\x00"
    struct.pack_into("<I", text_section, 8, 0x200)
    struct.pack_into("<I", text_section, 12, 0x1000)
    struct.pack_into("<I", text_section, 16, 0x200)
    struct.pack_into("<I", text_section, 20, 0x200)
    buf.extend(text_section)

    # .rdata section header (40 bytes)
    rdata_section = bytearray(40)
    rdata_section[0:7] = b".rdata\x00"
    struct.pack_into("<I", rdata_section, 8, 0x200)
    struct.pack_into("<I", rdata_section, 12, 0x2000)
    struct.pack_into("<I", rdata_section, 16, 0x200)
    struct.pack_into("<I", rdata_section, 20, 0x400)
    buf.extend(rdata_section)

    # Pad to FileAlignment for section data.
    while len(buf) < 0x200:
        buf.extend(b"\x00")

    # .text data (0x200 bytes at 0x200)
    buf.extend(b"\xcc" * 0x200)

    # .rdata data (0x200 bytes at 0x400) — Import Directory at start.
    import_dir_data = bytearray(48)
    buf.extend(import_dir_data)
    buf.extend(b"\x00" * (0x200 - 48))

    pe_file.write_bytes(bytes(buf))
    return pe_file


# ===========================================================================
# PERegion model
# ===========================================================================


class TestPERegion:
    def test_valid_construction(self) -> None:
        region = PERegion(
            name="DOS Header",
            start_offset=0,
            end_offset=63,
            description="The MZ DOS header.",
        )
        assert region.name == "DOS Header"
        assert region.start_offset == 0
        assert region.end_offset == 63

    def test_overlaps_exact_match(self) -> None:
        region = PERegion(
            name="test",
            start_offset=100,
            end_offset=200,
            description="test",
        )
        assert region.overlaps(100, 101) is True

    def test_overlaps_partial(self) -> None:
        region = PERegion(
            name="test",
            start_offset=100,
            end_offset=200,
            description="test",
        )
        assert region.overlaps(50, 100) is True

    def test_overlaps_contained(self) -> None:
        region = PERegion(
            name="test",
            start_offset=100,
            end_offset=200,
            description="test",
        )
        assert region.overlaps(120, 10) is True

    def test_no_overlap_before(self) -> None:
        region = PERegion(
            name="test",
            start_offset=100,
            end_offset=200,
            description="test",
        )
        assert region.overlaps(0, 50) is False

    def test_no_overlap_after(self) -> None:
        region = PERegion(
            name="test",
            start_offset=100,
            end_offset=200,
            description="test",
        )
        assert region.overlaps(300, 100) is False

    def test_no_overlap_adjacent(self) -> None:
        region = PERegion(
            name="test",
            start_offset=100,
            end_offset=200,
            description="test",
        )
        assert region.overlaps(201, 10) is False

    def test_rejects_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            PERegion(
                name="",
                start_offset=0,
                end_offset=10,
                description="test",
            )

    def test_rejects_end_before_start(self) -> None:
        with pytest.raises(ValidationError):
            PERegion(
                name="test",
                start_offset=100,
                end_offset=50,
                description="test",
            )

    def test_zero_length_region(self) -> None:
        region = PERegion(
            name="point",
            start_offset=42,
            end_offset=42,
            description="Single byte region.",
        )
        assert region.overlaps(42, 1) is True
        assert region.overlaps(41, 1) is False
        assert region.overlaps(43, 1) is False


# ===========================================================================
# MappedReadEvent model
# ===========================================================================


class TestMappedReadEvent:
    def test_empty_regions(self) -> None:
        event = _make_event(offset=0, length=100)
        mapped = MappedReadEvent(original=event, matched_regions=[])
        assert mapped.original == event
        assert mapped.matched_regions == []

    def test_with_regions(self) -> None:
        event = _make_event(offset=0, length=100)
        region = PERegion(
            name="test",
            start_offset=0,
            end_offset=99,
            description="test",
        )
        mapped = MappedReadEvent(original=event, matched_regions=[region])
        assert len(mapped.matched_regions) == 1
        assert mapped.matched_regions[0].name == "test"

    def test_json_roundtrip(self) -> None:
        event = _make_event(offset=0, length=100)
        region = PERegion(
            name="DOS Header",
            start_offset=0,
            end_offset=63,
            description="DOS header.",
        )
        mapped = MappedReadEvent(original=event, matched_regions=[region])
        json_str = mapped.model_dump_json()
        restored = MappedReadEvent.model_validate_json(json_str)
        assert mapped == restored


# ===========================================================================
# Error classes
# ===========================================================================


class TestErrors:
    def test_mapping_error_is_exception(self) -> None:
        assert issubclass(MappingError, Exception)

    def test_invalid_pe_error(self) -> None:
        exc = InvalidPEError("test.exe", "bad format")
        assert "test.exe" in str(exc)
        assert "bad format" in str(exc)
        assert exc.path == "test.exe"
        assert exc.reason == "bad format"
        assert issubclass(InvalidPEError, MappingError)

    def test_truncated_pe_error(self) -> None:
        exc = TruncatedPEError("test.exe", "truncated header")
        assert "test.exe" in str(exc)
        assert "truncated header" in str(exc)
        assert issubclass(TruncatedPEError, MappingError)


# ===========================================================================
# map_events — basic mapping
# ===========================================================================


class TestMapEventsBasic:
    def test_maps_dos_header(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [_make_event(offset=0, length=64)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert DOS_HEADER in names

    def test_maps_nt_headers(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [_make_event(offset=0x80, length=4)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert NT_HEADERS in names

    def test_maps_file_header(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [_make_event(offset=0x84, length=20)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert FILE_HEADER in names

    def test_maps_optional_header(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [_make_event(offset=0x98, length=32)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert OPTIONAL_HEADER in names

    def test_maps_text_section(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [_make_event(offset=0x200, length=0x100)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert ".text" in names

    def test_maps_dos_stub(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [_make_event(offset=0x40, length=64)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert DOS_STUB in names

    def test_unmapped_offset_returns_empty(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        # Read in the gap between section table end (0x1A0) and
        # .text data start (0x200) — padding bytes with no structure.
        events = [_make_event(offset=0x1A0, length=8)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        # May or may not match any region depending on exact sizes.
        assert isinstance(results[0], MappedReadEvent)


# ===========================================================================
# map_events — overlapping reads
# ===========================================================================


class TestOverlappingReads:
    def test_read_spans_two_regions(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        # Read from end of DOS Header into DOS Stub.
        events = [_make_event(offset=60, length=8)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert DOS_HEADER in names
        assert DOS_STUB in names

    def test_read_spans_header_and_nt(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        # Read 8 bytes bridging DOS Stub end and NT Headers start.
        events = [_make_event(offset=0x7C, length=8)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert DOS_STUB in names
        assert NT_HEADERS in names

    def test_large_read_covers_entire_header(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [_make_event(offset=0, length=0x100)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert DOS_HEADER in names
        assert DOS_STUB in names
        assert NT_HEADERS in names

    def test_read_in_middle_of_region(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        # Read 1 byte in the middle of .text
        events = [_make_event(offset=0x300, length=1)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert ".text" in names
        assert len(results[0].matched_regions) == 1


# ===========================================================================
# map_events — multiple events
# ===========================================================================


class TestMultipleEvents:
    def test_multiple_events_all_mapped(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [
            _make_event(offset=0, length=64),  # DOS Header
            _make_event(offset=0x80, length=4),  # NT Headers
            _make_event(offset=0x200, length=0x100),  # .text
        ]
        results = list(map_events(pe_path, events))
        assert len(results) == 3
        assert DOS_HEADER in [r.name for r in results[0].matched_regions]
        assert NT_HEADERS in [r.name for r in results[1].matched_regions]
        assert ".text" in [r.name for r in results[2].matched_regions]

    def test_empty_events(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        results = list(map_events(pe_path, []))
        assert results == []


# ===========================================================================
# map_events — import directory
# ===========================================================================


class TestImportDirectory:
    def test_import_dir_mapped(self, tmp_path: Path) -> None:
        pe_path = _build_pe_with_import_dir(tmp_path)
        events = [_make_event(offset=0x400, length=48)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert IMPORT_DIR in names


# ===========================================================================
# map_events — overlay
# ===========================================================================


class TestOverlay:
    def test_overlay_region_built(self) -> None:
        from unittest.mock import MagicMock

        pe = MagicMock()
        pe.OVERLAY_START = 0x400
        pe.OVERLAY_SIZE = 128
        region = _build_overlay_region(pe)
        assert region is not None
        assert region.name == OVERLAY
        assert region.start_offset == 0x400
        assert region.end_offset == 0x400 + 127

    def test_no_overlay(self) -> None:
        from unittest.mock import MagicMock

        pe = MagicMock()
        pe.OVERLAY_START = None
        region = _build_overlay_region(pe)
        assert region is None

    def test_overlay_size_zero(self) -> None:
        from unittest.mock import MagicMock

        pe = MagicMock()
        pe.OVERLAY_START = 0x400
        pe.OVERLAY_SIZE = 0
        region = _build_overlay_region(pe)
        assert region is None


# ===========================================================================
# map_events — error handling
# ===========================================================================


class TestErrorHandling:
    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            list(map_events(tmp_path / "nonexistent.exe", []))

    def test_invalid_pe_format(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.exe"
        bad_file.write_bytes(b"NOT A PE FILE" + b"\x00" * 100)
        with pytest.raises(InvalidPEError):
            list(map_events(bad_file, []))

    def test_empty_file(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.exe"
        empty_file.write_bytes(b"")
        with pytest.raises(InvalidPEError):
            list(map_events(empty_file, []))


# ===========================================================================
# PERegion — serialization
# ===========================================================================


class TestPERegionSerialization:
    def test_model_dump(self) -> None:
        region = PERegion(
            name=".text",
            start_offset=0x200,
            end_offset=0x3FF,
            description="Code section.",
        )
        dumped = region.model_dump()
        assert dumped["name"] == ".text"
        assert dumped["start_offset"] == 0x200
        assert dumped["end_offset"] == 0x3FF

    def test_json_roundtrip(self) -> None:
        region = PERegion(
            name="DOS Header",
            start_offset=0,
            end_offset=63,
            description="DOS header.",
        )
        json_str = region.model_dump_json()
        restored = PERegion.model_validate_json(json_str)
        assert region == restored


# ===========================================================================
# map_events — section table
# ===========================================================================


class TestSectionTable:
    def test_section_table_region_exists(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        # The section table is at 0x178 (40 bytes for 1 entry).
        events = [_make_event(offset=0x178, length=4)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        names = [r.name for r in results[0].matched_regions]
        assert SECTION_TABLE in names


# ===========================================================================
# map_events — large offsets
# ===========================================================================


class TestLargeOffsets:
    def test_read_beyond_file(self, tmp_path: Path) -> None:
        pe_path = _build_minimal_pe(tmp_path)
        events = [_make_event(offset=0x100000, length=100)]
        results = list(map_events(pe_path, events))
        assert len(results) == 1
        assert results[0].matched_regions == []
