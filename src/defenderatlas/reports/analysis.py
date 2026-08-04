"""Research analysis engine for Defender scan experiments.

This module orchestrates the full analysis pipeline for completed
collection experiments by *reusing* the existing analysis library
instead of reimplementing it:

- :func:`defenderatlas.parsers.parse_procmon_csv` — CSV parsing
- :func:`defenderatlas.statistics.compute_statistics` — global stats
- :func:`defenderatlas.mapping.map_events` — PE structure mapping
- :func:`defenderatlas.statistics.compute_region_statistics` — per-region stats
- :func:`defenderatlas.timeline.build_timeline` — chronological timeline
- :class:`defenderatlas.phases.PhaseDetector` — scan phase detection

For every experiment it additionally computes derived metrics that the
library modules do not expose directly (coverage, alignment, read-size
distribution, access-pattern entropy, tail probes, scan ordering) and
an :class:`ExperimentAnalysis` model that bundles everything together
for report generation and cross-experiment comparison.

Why This Module
---------------
The ``reports`` package was an empty stub.  Research reports need a
single, reusable entry point that turns an experiment directory
(``filtered.csv`` + ``sample.exe`` + JSON metadata) into a complete,
serialisable analysis.  Keeping it here lets future report and
visualization code share the exact same computation.
"""

from __future__ import annotations

import json
import logging
import math
from collections import Counter
from collections.abc import Iterable
from itertools import pairwise
from typing import TYPE_CHECKING, Any, cast

import pefile  # type: ignore[import-untyped]
from pydantic import BaseModel, Field

from defenderatlas.mapping import (
    InvalidPEError,
    MappedReadEvent,
    map_events,
)
from defenderatlas.parsers import parse_procmon_csv
from defenderatlas.phases import PhaseDetector, PhaseRule
from defenderatlas.statistics import (
    compute_region_statistics,
    compute_statistics,
)
from defenderatlas.timeline import build_timeline

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from defenderatlas.mapping.models import PERegion
    from defenderatlas.models.core import ReadEvent

log = logging.getLogger(__name__)

# ── default phase detection rules ────────────────────────────────────────

DEFAULT_PHASE_RULES: list[PhaseRule] = [
    PhaseRule(
        name="Header Inspection",
        description=(
            "Initial probe of DOS header, NT headers and the section "
            "table while parsing the PE structure."
        ),
        required_regions={"DOS Header", "NT Headers", "Section Table"},
        minimum_reads=1,
    ),
    PhaseRule(
        name="Directory Parsing",
        description=(
            "Parsing of PE data directories (imports, exports, debug "
            "and bound-import tables)."
        ),
        required_regions={"Import Directory"},
        minimum_reads=1,
    ),
    PhaseRule(
        name="Certificate Verification",
        description=(
            "Access to the Authenticode certificate table embedded at "
            "the end of the file."
        ),
        required_regions={"Certificate Table"},
        minimum_reads=1,
    ),
    PhaseRule(
        name="Resource Parsing",
        description="Access to the resource directory / .rsrc data.",
        required_regions={"Resource Directory"},
        minimum_reads=1,
    ),
    PhaseRule(
        name="Code Scanning",
        description="Reads targeting the executable code section (.text).",
        required_regions={".text"},
        minimum_reads=1,
    ),
    PhaseRule(
        name="Overlay Inspection",
        description="Reads past the last section targeting appended data.",
        required_regions={"Overlay"},
        minimum_reads=1,
    ),
    PhaseRule(
        name="Relocation Processing",
        description="Reads targeting the base-relocation table.",
        required_regions={"Relocation Directory"},
        minimum_reads=1,
    ),
]

# Canonical grouping for cross-experiment comparison.  Section names vary
# between binaries (".text", "PAGE", "PROTDATA", ".itext", ...) so we map
# them onto a small set of semantic classes.
_SECTION_CLASSES: dict[str, str] = {
    ".text": "code",
    ".itext": "code",
    "PAGE": "code",
    "PAGELK": "code",
    "POOLCODE": "code",
    "PAGEKD": "code",
    "INIT": "code",
    ".rdata": "readonly",
    ".data": "data",
    ".bss": "data",
    ".didat": "imports",
    ".idata": "imports",
    ".edata": "exports",
    ".rsrc": "resources",
    ".reloc": "relocations",
    ".pdata": "exceptions",
    ".xdata": "exceptions",
    ".tls": "tls",
    "PROTDATA": "protdata",
    "GFIDS": "gfids",
    ".imrsiv": "readonly",
    "Pad1": "padding",
    "?g_Encry": "encrypt",
}


def classify_region(name: str) -> str:
    """Classify a PE region name into a semantic group.

    Headers and data-directory regions get a stable label; section names
    are mapped through :data:`_SECTION_CLASSES` (falling back to
    ``"section"`` for unknown section names).
    """
    if name in {"DOS Header", "DOS Stub"}:
        return "headers"
    if name in {"NT Headers", "File Header", "Optional Header", "Section Table"}:
        return "headers"
    if name in {
        "Import Directory",
        "Export Directory",
        "Resource Directory",
        "Relocation Directory",
        "TLS Directory",
        "Debug Directory",
        "Certificate Table",
        "Bound Import Directory",
        "Delay Import Directory",
        "IAT Directory",
        "COM Descriptor Directory",
    }:
        return "directories"
    if name == "Overlay":
        return "overlay"
    return _SECTION_CLASSES.get(name, "section")


# ── derived metrics ──────────────────────────────────────────────────────


def _compute_coverage(
    events: list[ReadEvent],
    regions: list[PERegion],
) -> dict[str, float]:
    """Compute the fraction of each region's bytes that were read.

    Unions the byte ranges of every read that intersects a region via
    interval merging (O(n log n) per region) and expresses the covered
    bytes as a percentage of the region size.  Interval merging avoids
    materialising per-byte sets for very large sections.
    """
    overlaps: dict[str, list[tuple[int, int]]] = {r.name: [] for r in regions}
    for event in events:
        start = event.offset
        end = event.offset + event.length
        for region in regions:
            if region.overlaps(event.offset, event.length):
                lo = max(start, region.start_offset)
                hi = min(end, region.end_offset + 1)
                if lo < hi:
                    overlaps[region.name].append((lo, hi))

    result: dict[str, float] = {}
    for region in regions:
        ranges = sorted(overlaps[region.name])
        covered = 0
        interval: tuple[int, int] | None = None
        for lo, hi in ranges:
            if interval is None:
                interval = (lo, hi)
            elif lo <= interval[1]:
                interval = (interval[0], max(interval[1], hi))
            else:
                covered += interval[1] - interval[0]
                interval = (lo, hi)
        if interval is not None:
            covered += interval[1] - interval[0]
        size = region.end_offset - region.start_offset + 1
        result[region.name] = (covered / size * 100.0) if size else 0.0
    return result


def _read_length_stats(events: Iterable[ReadEvent]) -> tuple[int, int, float, float]:
    """Return (min, max, mean, median) of read lengths."""
    lengths = [e.length for e in events]
    if not lengths:
        return 0, 0, 0.0, 0.0
    lengths.sort()
    n = len(lengths)
    mid = n // 2
    median = lengths[mid] if n % 2 else (lengths[mid - 1] + lengths[mid]) / 2
    return lengths[0], lengths[-1], sum(lengths) / n, float(median)


def _offset_entropy(events: Iterable[ReadEvent], file_size: int) -> float:
    """Normalized Shannon entropy of the 4 KiB-aligned offset histogram.

    A value of 1.0 means reads are spread uniformly across the file;
    values near 0.0 mean reads are concentrated in a few locations.
    """
    if file_size <= 0:
        return 0.0
    buckets = math.ceil(file_size / 4096)
    counts = Counter(min(e.offset // 4096, buckets - 1) for e in events)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return entropy / math.log2(buckets) if buckets > 1 else 0.0


def _sequential_score(events: list[ReadEvent]) -> float:
    """Fraction of consecutive reads that are byte-contiguous."""
    if len(events) <= 1:
        return 1.0
    contiguous = sum(
        1
        for a, b in pairwise(events)
        if b.offset == a.offset + a.length
    )
    return contiguous / (len(events) - 1)


def _top_repeated_offsets(
    events: list[ReadEvent],
    n: int = 10,
) -> list[dict[str, int]]:
    """Most-frequently re-read byte offsets, with occurrence counts."""
    counts: Counter[int] = Counter()
    for e in events:
        counts[e.offset] += 1
    repeated = [o for o, c in counts.items() if c > 1]
    return [
        {"offset": o, "times": counts[o]}
        for o in sorted(repeated, key=lambda o: counts[o], reverse=True)[:n]
    ]


def _read_length_distribution(events: Iterable[ReadEvent]) -> dict[str, int]:
    """Bucket read lengths into KiB bands (mirrors earlier tooling)."""
    bands = ["<=4K", "4-8K", "8-16K", "16-64K", "64-256K", "256-512K", ">512K"]
    result = dict.fromkeys(bands, 0)
    for e in events:
        n = e.length
        if n <= 4096:
            result["<=4K"] += 1
        elif n <= 8192:
            result["4-8K"] += 1
        elif n <= 16384:
            result["8-16K"] += 1
        elif n <= 65536:
            result["16-64K"] += 1
        elif n <= 262144:
            result["64-256K"] += 1
        elif n <= 524288:
            result["256-512K"] += 1
        else:
            result[">512K"] += 1
    return result


# ── PE introspection ─────────────────────────────────────────────────────


def _pe_overview(pe_path: Path) -> dict[str, Any]:
    """Extract structural facts about a PE needed for comparison."""
    pe = pefile.PE(str(pe_path))
    try:
        machine = pe.FILE_HEADER.Machine
        machine_name = "x86" if machine == 0x14C else ("x64" if machine == 0x8664 else f"0x{machine:X}")
        opt_magic = pe.OPTIONAL_HEADER.Magic
        opt_name = "PE32+" if opt_magic == 0x20B else ("PE32" if opt_magic == 0x10B else f"0x{opt_magic:X}")
        sections = [s.Name.rstrip(b"\x00").decode("utf-8", errors="replace") for s in pe.sections]

        cert_size = 0
        if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            cert_size = int(cert_dir.Size)

        overlay_start = pe.get_overlay_data_start_offset()
        overlay_size = (
            len(pe.__data__) - overlay_start if overlay_start is not None else 0
        )

        return {
            "machine": machine_name,
            "opt_format": opt_name,
            "n_sections": len(sections),
            "sections": sections,
            "has_certificate": cert_size > 0,
            "cert_size": cert_size,
            "has_overlay": overlay_size > 0,
            "has_imports": hasattr(pe, "DIRECTORY_ENTRY_IMPORT"),
            "has_exports": hasattr(pe, "DIRECTORY_ENTRY_EXPORT"),
            "has_resources": hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"),
            "has_debug": hasattr(pe, "DIRECTORY_ENTRY_DEBUG"),
            "has_reloc": hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"),
            "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        }
    finally:
        pe.close()


def _tail_probe(events: list[ReadEvent], last_region_end: int, file_size: int) -> bool:
    """True if any read extends into the trailing region after the last
    mapped PE structure (an end-of-file / signature probe)."""
    return any(e.offset + e.length > last_region_end for e in events)


# ── result models ────────────────────────────────────────────────────────


class RegionSummary(BaseModel):
    """Per-region statistics plus derived coverage for one experiment."""

    region_name: str = Field(description="PE region label.")
    region_class: str = Field(description="Semantic group (headers/section/...).")
    read_count: int = Field(description="Reads touching this region.")
    unique_offsets: int = Field(description="Distinct read start offsets.")
    bytes_read: int = Field(description="Total bytes requested.")
    pct_of_reads: float = Field(description="Percent of aggregate reads.")
    pct_of_bytes: float = Field(description="Percent of aggregate bytes.")
    coverage_pct: float = Field(description="Percent of region bytes actually read.")
    repeated_reads: int = Field(description="Re-reads of offsets in this region.")
    size: int = Field(description="Region size in bytes.")


class PhaseSummary(BaseModel):
    """Serialisable summary of one detected phase."""

    name: str = Field(description="Phase label.")
    start_time: str = Field(description="ISO start timestamp.")
    end_time: str = Field(description="ISO end timestamp.")
    duration_seconds: float = Field(description="Phase span in seconds.")
    entry_count: int = Field(description="Contributing timeline entries.")


class ExperimentAnalysis(BaseModel):
    """Complete analysis of a single Defender scan experiment."""

    experiment_id: int = Field(description="Zero-padded experiment id (int).")
    sample: str = Field(description="Sample file name.")
    category: str = Field(description="Dataset category (signed/unsigned).")
    file_size: int = Field(description="Sample size in bytes.")
    machine: str = Field(description="CPU architecture.")
    opt_format: str = Field(description="PE32 / PE32+.")
    n_sections: int = Field(description="Number of PE sections.")
    section_names: list[str] = Field(default_factory=list)
    has_certificate: bool = Field(description="Embedded Authenticode table present.")
    cert_size: int = Field(description="Certificate table size in bytes.")
    has_overlay: bool = Field(description="Overlay data present after last section.")
    has_resources: bool = Field(description="Resource directory present.")
    has_debug: bool = Field(description="Debug directory present.")
    has_imports: bool = Field(description="Import directory present.")
    has_exports: bool = Field(description="Export directory present.")
    has_reloc: bool = Field(description="Base relocation directory present.")

    total_reads: int = Field(description="Total read events.")
    unique_offsets: int = Field(description="Distinct read start offsets.")
    repeated_reads: int = Field(description="Reads targeting a previously read offset.")
    bytes_read: int = Field(description="Total bytes requested.")
    read_amplification: float = Field(description="bytes_read / file_size.")

    read_size_min: int = Field(description="Smallest read length.")
    read_size_max: int = Field(description="Largest read length.")
    read_size_mean: float = Field(description="Mean read length.")
    read_size_median: float = Field(description="Median read length.")
    aligned_4k_pct: float = Field(description="Percent of reads at 4 KiB alignment.")
    offset_entropy: float = Field(description="Normalized Shannon entropy of read offsets.")
    sequential_score: float = Field(description="Fraction of contiguous consecutive reads.")
    unmapped_reads: int = Field(description="Reads matching no known PE region.")
    tail_probe: bool = Field(description="Reads extending past the last structure.")
    read_length_distribution: dict[str, int] = Field(default_factory=dict)
    top_repeated_offsets: list[dict[str, int]] = Field(default_factory=list)

    regions: list[RegionSummary] = Field(default_factory=list)
    region_count: int = Field(description="Distinct regions touched.")
    top_regions: list[str] = Field(description="Top regions by bytes read.")

    duration_seconds: float = Field(description="Scan wall-clock span.")
    first_region: str = Field(description="First region accessed.")
    regions_in_order: list[str] = Field(default_factory=list)
    first_ten_regions: list[str] = Field(default_factory=list)

    phases: list[PhaseSummary] = Field(default_factory=list)
    phase_count: int = Field(description="Number of detected phases.")
    phase_confidence: float = Field(description="Phase detection confidence.")
    phase_names: list[str] = Field(default_factory=list)
    consecutive_phases: list[str] = Field(default_factory=list)


class AnalysisStatus(BaseModel):
    """Result of attempting to analyse one experiment."""

    experiment_id: int
    ok: bool
    error: str | None = None
    analysis: ExperimentAnalysis | None = None


# ── experiment analysis ──────────────────────────────────────────────────


def _read_metadata(experiment_dir: Path) -> dict[str, Any]:
    """Load metadata.json, tolerating missing/partial files."""
    meta_path = experiment_dir / "metadata.json"
    if not meta_path.exists():
        return {}
    try:
        return cast("dict[str, Any]", json.loads(meta_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Unreadable metadata for %s: %s", experiment_dir.name, exc)
        return {}


def is_completed_experiment(experiment_dir: Path) -> bool:
    """True if an experiment directory looks like a completed capture.

    A completed experiment has ``filtered.csv``, ``sample.exe`` and a
    ``manifest.json`` (or ``metadata.json``) recording ``completed`` /
    ``success`` status.
    """
    if not experiment_dir.is_dir():
        return False
    if not (experiment_dir / "filtered.csv").exists():
        return False
    if not (experiment_dir / "sample.exe").exists():
        return False
    manifest = experiment_dir / "manifest.json"
    metadata = experiment_dir / "metadata.json"
    if manifest.exists():
        try:
            if json.loads(manifest.read_text(encoding="utf-8")).get("status") == "completed":
                return True
        except (OSError, json.JSONDecodeError):
            pass
    if metadata.exists():
        try:
            if json.loads(metadata.read_text(encoding="utf-8")).get("result") == "success":
                return True
        except (OSError, json.JSONDecodeError):
            pass
    return False


def analyze_experiment(experiment_dir: Path) -> ExperimentAnalysis:
    """Run the full analysis pipeline over one experiment directory.

    Reuses the existing parser, statistics engine, PE mapper, region
    statistics, timeline builder and phase detector.

    Parameters
    ----------
    experiment_dir:
        Directory containing ``filtered.csv`` and ``sample.exe``.

    Returns
    -------
    ExperimentAnalysis
        Bundled per-experiment analysis.

    Raises
    ------
    FileNotFoundError
        If ``filtered.csv`` or ``sample.exe`` is missing.
    InvalidPEError
        If ``sample.exe`` is not a parseable PE.
    """
    filtered = experiment_dir / "filtered.csv"
    sample = experiment_dir / "sample.exe"
    if not filtered.exists():
        raise FileNotFoundError(f"filtered.csv missing in {experiment_dir}")
    if not sample.exists():
        raise FileNotFoundError(f"sample.exe missing in {experiment_dir}")

    metadata = _read_metadata(experiment_dir)
    file_size = sample.stat().st_size

    events = list(parse_procmon_csv(filtered))
    stats = compute_statistics(events, file_size=file_size)
    pe_overview = _pe_overview(sample)

    mapped: list[MappedReadEvent] = list(map_events(sample, events))
    region_stats = compute_region_statistics(mapped)
    timeline = build_timeline(mapped)
    detector = PhaseDetector(DEFAULT_PHASE_RULES)
    phases = detector.detect(timeline)
    consecutive = detector.timeline_to_phases(timeline)

    read_min, read_max, read_mean, read_median = _read_length_stats(events)
    aligned = sum(1 for e in events if e.offset % 4096 == 0)
    aligned_pct = aligned / len(events) * 100 if events else 0.0
    entropy = _offset_entropy(events, file_size)
    sequential = _sequential_score(events)
    unmapped = sum(1 for m in mapped if not m.matched_regions)
    length_dist = _read_length_distribution(events)
    top_repeated = _top_repeated_offsets(events)

    # Region summaries enriched with coverage + repeated-read counts.
    regions_by_name: dict[str, PERegion] = {}
    for mapped_event in mapped:
        for region in mapped_event.matched_regions:
            regions_by_name.setdefault(region.name, region)
    coverage = _compute_coverage(events, list(regions_by_name.values()))

    # Count repeated reads per region (offsets seen more than once).
    offset_seen: dict[str, set[int]] = {}
    repeated_per_region: dict[str, int] = {}
    for mapped_event in mapped:
        for region in mapped_event.matched_regions:
            seen = offset_seen.setdefault(region.name, set())
            offset = mapped_event.original.offset
            if offset in seen:
                repeated_per_region[region.name] = repeated_per_region.get(region.name, 0) + 1
            seen.add(offset)

    region_summaries: list[RegionSummary] = []
    for stat_region in region_stats.regions:
        pe_region = regions_by_name[stat_region.region_name]
        size = pe_region.end_offset - pe_region.start_offset + 1
        region_summaries.append(
            RegionSummary(
                region_name=stat_region.region_name,
                region_class=classify_region(stat_region.region_name),
                read_count=stat_region.read_count,
                unique_offsets=stat_region.unique_offsets,
                bytes_read=stat_region.bytes_read,
                pct_of_reads=stat_region.percentage_of_total_reads,
                pct_of_bytes=stat_region.percentage_of_total_bytes,
                coverage_pct=round(coverage.get(stat_region.region_name, 0.0), 2),
                repeated_reads=repeated_per_region.get(stat_region.region_name, 0),
                size=size,
            )
        )

    top_regions = [r.region_name for r in region_stats.regions[:5]]
    first_ten = timeline.regions_in_order()[:10]

    return ExperimentAnalysis(
        experiment_id=int(experiment_dir.name),
        sample=str(metadata.get("sample", sample.name)),
        category=str(metadata.get("category", "unknown")),
        file_size=file_size,
        machine=str(pe_overview["machine"]),
        opt_format=str(pe_overview["opt_format"]),
        n_sections=int(pe_overview["n_sections"]),
        section_names=[str(s) for s in pe_overview["sections"]],
        has_certificate=bool(pe_overview["has_certificate"]),
        cert_size=int(pe_overview["cert_size"]),
        has_overlay=bool(pe_overview["has_overlay"]),
        has_resources=bool(pe_overview["has_resources"]),
        has_debug=bool(pe_overview["has_debug"]),
        has_imports=bool(pe_overview["has_imports"]),
        has_exports=bool(pe_overview["has_exports"]),
        has_reloc=bool(pe_overview["has_reloc"]),
        total_reads=stats.total_reads,
        unique_offsets=stats.unique_offsets,
        repeated_reads=stats.repeated_reads,
        bytes_read=stats.bytes_read,
        read_amplification=round(stats.read_amplification, 3),
        read_size_min=read_min,
        read_size_max=read_max,
        read_size_mean=round(read_mean, 1),
        read_size_median=round(read_median, 1),
        aligned_4k_pct=round(aligned_pct, 2),
        offset_entropy=round(entropy, 4),
        sequential_score=round(sequential, 4),
        unmapped_reads=unmapped,
        tail_probe=_tail_probe(events, max((r.end_offset for r in regions_by_name.values()), default=0), file_size),
        read_length_distribution=length_dist,
        top_repeated_offsets=top_repeated,
        regions=region_summaries,
        region_count=region_stats.total_regions,
        top_regions=top_regions,
        duration_seconds=timeline.duration.total_seconds(),
        first_region=timeline.first_region_accessed() or "none",
        regions_in_order=timeline.regions_in_order(),
        first_ten_regions=first_ten,
        phases=[
            PhaseSummary(
                name=p.name,
                start_time=p.start_time,
                end_time=p.end_time,
                duration_seconds=p.duration.total_seconds(),
                entry_count=len(p.evidence),
            )
            for p in phases.phases
        ],
        phase_count=len(phases.phases),
        phase_confidence=round(phases.confidence, 4),
        phase_names=[p.name for p in phases.phases],
        consecutive_phases=[p.name for p in consecutive],
    )


def analyze_all_experiments(experiment_root: Path) -> list[AnalysisStatus]:
    """Analyse every experiment directory under *experiment_root*.

    Incomplete or failed experiments are reported with ``ok=False`` and
    a short reason instead of aborting the batch.
    """
    results: list[AnalysisStatus] = []
    for directory in sorted(
        experiment_root.iterdir(),
        key=lambda p: int(p.name) if p.name.isdigit() else 0,
    ):
        if not directory.is_dir() or not directory.name.isdigit():
            continue
        experiment_id = int(directory.name)
        if not is_completed_experiment(directory):
            results.append(
                AnalysisStatus(
                    experiment_id=experiment_id,
                    ok=False,
                    error="incomplete experiment: missing filtered.csv/sample.exe or status != completed",
                )
            )
            continue
        try:
            analysis = analyze_experiment(directory)
            results.append(
                AnalysisStatus(experiment_id=experiment_id, ok=True, analysis=analysis)
            )
        except (FileNotFoundError, InvalidPEError, ValueError) as exc:
            results.append(
                AnalysisStatus(
                    experiment_id=experiment_id,
                    ok=False,
                    error=f"analysis failed: {exc}",
                )
            )
    return results
