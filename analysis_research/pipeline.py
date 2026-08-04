"""Research pipeline for Microsoft Defender PE scan analysis.

Reuses the existing DefenderAtlas modules (parser, statistics, PE
mapper, region statistics, timeline, phase detector) and extends them
with the deep per-experiment / cross-experiment metrics required for the
research deliverables.

Methodological note on I/O layers
---------------------------------
ProcMon reports every read request twice: once as ``FAST IO DISALLOWED``
(the fast-I/O path declined the request) and once as ``SUCCESS`` (the
subsequent IRP-based read that actually transferred bytes).  The two
events share the same offset but the requested length (fast-I/O) can
exceed the actual transferred length (IRP) when a request is clamped at
EOF.

Throughout this analysis the *primary* read statistics are computed from
``SUCCESS`` events only (actual bytes transferred from disk).  Fast-I/O
attempts are tracked separately as an I/O-layer signal.  Both numbers
are reported so the reader can compare against analyses that counted all
events.
"""

from __future__ import annotations

import json
import math
import pickle
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median, pstdev, quantiles
from typing import Any

import pefile

from defenderatlas.mapping import map_events
from defenderatlas.mapping.models import MappedReadEvent
from defenderatlas.parsers.procmon import parse_procmon_csv
from defenderatlas.phases import PhaseDetector
from defenderatlas.reports.analysis import (
    DEFAULT_PHASE_RULES,
    classify_region,
)
from defenderatlas.statistics import compute_region_statistics
from defenderatlas.timeline import build_timeline

ROOT = Path("/home/godwin/Desktop/000/DefenderAtlas")
CSV_DIR = ROOT / "CSVs" / "experiment"
EXP_DIR = ROOT / "experiments"
OUT_DIR = ROOT / "reports"

BLOCK = 4096
CHUNK_BANDS = [
    (1, 512, "<=512B"),
    (513, 1024, "513B-1K"),
    (1025, 2048, "1-2K"),
    (2049, 4096, "2-4K"),
    (4097, 8192, "4-8K"),
    (8193, 16384, "8-16K"),
    (16385, 32768, "16-32K"),
    (32769, 65536, "32-64K"),
    (65537, 131072, "64-128K"),
    (131073, 262144, "128-256K"),
    (262145, 524288, "256-512K"),
    (524289, 1048576, "512K-1M"),
    (1048577, 2**40, ">1M"),
]

REGION_CLASSES = [
    "headers",
    "directories",
    "code",
    "readonly",
    "data",
    "resources",
    "relocations",
    "exceptions",
    "tls",
    "overlay",
    "section",
    "padding",
    "encrypt",
]


def chunk_band(length: int) -> str:
    for lo, hi, name in CHUNK_BANDS:
        if lo <= length <= hi:
            return name
    return ">1M"


def load_metadata() -> dict[int, dict[str, Any]]:
    meta: dict[int, dict[str, Any]] = {}
    for d in sorted(EXP_DIR.glob("0000*")):
        eid = int(d.name)
        mfile = d / "metadata.json"
        if not mfile.exists():
            continue
        try:
            m = json.loads(mfile.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            m = {}
        meta[eid] = m
    return meta


def experiment_paths(eid: int) -> tuple[Path, Path]:
    csv = CSV_DIR / f"{eid:06d}_filtered.csv"
    sample = EXP_DIR / f"{eid:06d}" / "sample.exe"
    return csv, sample


def _read_size_stats(lengths: list[int]) -> dict[str, float]:
    if not lengths:
        return {
            "min": 0, "max": 0, "mean": 0.0, "median": 0.0, "std": 0.0,
            "q1": 0.0, "q3": 0.0, "mode": 0.0, "mode_count": 0,
        }
    s = sorted(lengths)
    n = len(s)
    mid = n // 2
    med = s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2
    q = quantiles(s, n=4)
    counts = Counter(s)
    (mode, mode_count) = counts.most_common(1)[0]
    return {
        "min": min(s), "max": max(s), "mean": sum(s) / n, "median": med,
        "std": pstdev(s), "q1": q[0], "q3": q[2],
        "mode": mode, "mode_count": mode_count,
    }


def _offset_entropy(offsets: list[int], size: int) -> float:
    if size <= 0 or not offsets:
        return 0.0
    buckets = max(1, math.ceil(size / BLOCK))
    counts: Counter[int] = Counter()
    for o in offsets:
        counts[min(o // BLOCK, buckets - 1)] += 1
    total = sum(counts.values())
    ent = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return ent / math.log2(buckets) if buckets > 1 else 0.0


def _coverage_fraction(ranges: list[tuple[int, int]], size: int) -> float:
    if size <= 0 or not ranges:
        return 0.0
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    covered = sum(hi - lo for lo, hi in merged)
    return min(covered / size, 1.0)


def _sequential_metrics(events: list) -> dict[str, float]:
    """Contiguity and direction statistics over an ordered event list."""
    if len(events) <= 1:
        return {"contiguous": 1.0, "forward": 1.0, "runs": 1, "avg_jump": 0.0}
    contiguous = 0
    forward = 0
    gaps: list[int] = []
    for a, b in zip(events[:-1], events[1:]):
        gap = b.offset - (a.offset + a.length)
        if gap == 0:
            contiguous += 1
        if b.offset >= a.offset:
            forward += 1
        gaps.append(abs(b.offset - a.offset))
    n = len(events) - 1
    return {
        "contiguous": contiguous / n,
        "forward": forward / n,
        "runs": 1,
        "avg_jump": sum(gaps) / len(gaps),
    }


def _scan_passes(offsets: list[int]) -> tuple[int, list[int]]:
    """Detect forward sweeps: count how many times a new pass restarts
    the scan at an offset below the maximum seen so far.

    Returns (n_passes, pass_starts) where pass_starts are the indices
    at which a new sweep begins.
    """
    if not offsets:
        return 0, []
    max_seen = offsets[0]
    passes = 1
    starts = [0]
    for i in range(1, len(offsets)):
        if offsets[i] < max_seen and offsets[i - 1] >= max_seen:
            passes += 1
            starts.append(i)
        max_seen = max(max_seen, offsets[i])
    return passes, starts


def _time_gap_stages(events: list) -> list[dict[str, Any]]:
    """Split an event list into temporal stages using time gaps.

    Stage boundaries are inserted where the inter-event gap exceeds
    10x the median inter-event gap (with a floor to avoid noise on
    fast traces)."""
    if len(events) < 3:
        return [{"start": 0, "end": len(events) - 1, "events": len(events)}]
    gaps = []
    for a, b in zip(events[:-1], events[1:]):
        gaps.append((b.timestamp - a.timestamp).total_seconds())
    med = median(gaps) if gaps else 0.0
    threshold = max(med * 10, 0.0005)
    boundaries = [0]
    for i, g in enumerate(gaps):
        if g > threshold:
            boundaries.append(i + 1)
    boundaries.append(len(events))
    stages = []
    for s, e in zip(boundaries[:-1], boundaries[1:]):
        stages.append({"start": s, "end": e - 1, "events": e - s})
    return stages


@dataclass
class RegionInfo:
    name: str
    rclass: str
    start: int
    end: int
    size: int
    reads: int = 0
    unique_offsets: int = 0
    bytes_read: int = 0
    repeated_reads: int = 0
    coverage_pct: float = 0.0
    first_access: int | None = None
    access_index: list[int] = field(default_factory=list)


@dataclass
class ExpResult:
    exp_id: int
    sample: str
    category: str
    relative_path: str
    file_size: int
    pe_overview: dict[str, Any]

    n_read_ops: int = 0
    n_success: int = 0
    n_fastio: int = 0

    reads: list[dict[str, Any]] = field(default_factory=list)

    total_reads: int = 0
    unique_offsets: int = 0
    repeated_reads: int = 0
    bytes_read: int = 0
    bytes_requested_fastio: int = 0
    read_amplification: float = 0.0
    coverage_pct: float = 0.0
    blocks_4k: int = 0
    blocks_4k_total: int = 0
    block_coverage_pct: float = 0.0
    offset_entropy: float = 0.0
    sequential: float = 0.0
    forward: float = 0.0
    avg_jump: float = 0.0
    passes: int = 0
    pass_starts: list[int] = field(default_factory=list)
    min_offset: int = 0
    max_offset: int = 0
    min_read: int = 0
    max_read: int = 0
    mean_read: float = 0.0
    median_read: float = 0.0
    std_read: float = 0.0
    q1_read: float = 0.0
    q3_read: float = 0.0
    mode_read: float = 0.0
    mode_read_count: int = 0
    chunk_dist: dict[str, int] = field(default_factory=dict)
    tail_probe: bool = False
    read_beyond_eof: int = 0

    duration_seconds: float = 0.0
    first_region: str = ""
    regions_in_order: list[str] = field(default_factory=list)
    first_ten_regions: list[str] = field(default_factory=list)
    last_region: str = ""
    time_stages: list[dict[str, Any]] = field(default_factory=list)
    phases: list[dict[str, Any]] = field(default_factory=list)
    phase_count: int = 0
    phase_confidence: float = 0.0
    phase_names: list[str] = field(default_factory=list)

    regions: dict[str, RegionInfo] = field(default_factory=dict)
    region_classes: dict[str, dict[str, Any]] = field(default_factory=dict)
    region_count: int = 0


def _pe_overview(sample: Path) -> dict[str, Any]:
    pe = pefile.PE(str(sample))
    try:
        machine = pe.FILE_HEADER.Machine
        machine_name = (
            "x86" if machine == 0x14C else ("x64" if machine == 0x8664 else f"0x{machine:X}")
        )
        opt_magic = pe.OPTIONAL_HEADER.Magic
        opt_name = "PE32+" if opt_magic == 0x20B else ("PE32" if opt_magic == 0x10B else f"0x{opt_magic:X}")
        sections = [
            s.Name.rstrip(b"\x00").decode("utf-8", errors="replace") for s in pe.sections
        ]
        cert_size = 0
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            cert_size = int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)
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


def _to_ranges(events: list) -> list[tuple[int, int]]:
    return [(e["offset"], e["offset"] + e["length"]) for e in events]


def analyze_experiment(eid: int) -> ExpResult:
    csv_path, sample = experiment_paths(eid)
    meta = load_metadata().get(eid, {})
    file_size = sample.stat().st_size
    pe_overview = _pe_overview(sample)

    events = list(parse_procmon_csv(csv_path))

    success = [e for e in events if e.result == "SUCCESS"]
    fastio = [e for e in events if e.result == "FAST IO DISALLOWED"]

    # ---- primary read stream: SUCCESS only ----
    success_ev = sorted(success, key=lambda e: e.timestamp)
    offsets = [e.offset for e in success_ev]
    lengths = [e.length for e in success_ev]

    total_reads = len(success_ev)
    unique_offsets = len(set(offsets))
    repeated_reads = total_reads - unique_offsets
    bytes_read = sum(lengths)
    read_amplification = bytes_read / file_size if file_size else 0.0

    ranges = [(e.offset, e.offset + e.length) for e in success_ev]
    coverage_pct = _coverage_fraction(ranges, file_size) * 100.0

    blocks_touched = {o // BLOCK for o in offsets}
    blocks_total = max(1, math.ceil(file_size / BLOCK))
    block_coverage_pct = len(blocks_touched) / blocks_total * 100.0

    entropy = _offset_entropy(offsets, file_size)
    seq = _sequential_metrics(success_ev)
    passes, pass_starts = _scan_passes(offsets)
    size_stats = _read_size_stats(lengths)

    chunk_dist: dict[str, int] = defaultdict(int)
    for l in lengths:
        chunk_dist[chunk_band(l)] += 1

    min_offset = min(offsets) if offsets else 0
    max_offset = max(offsets) if offsets else 0
    read_beyond_eof = sum(1 for e in success_ev if e.offset + e.length > file_size)
    tail_probe = read_beyond_eof > 0 or (offsets and max_offset + max(lengths) > file_size)

    # ---- PE mapping ----
    mapped: list[MappedReadEvent] = list(map_events(sample, success_ev))
    region_stats = compute_region_statistics(mapped)
    timeline = build_timeline(mapped)
    detector = PhaseDetector(DEFAULT_PHASE_RULES)
    phases = detector.detect(timeline)

    region_map: dict[str, RegionInfo] = {}
    for mapped_event in mapped:
        for region in mapped_event.matched_regions:
            if region.name not in region_map:
                region_map[region.name] = RegionInfo(
                    name=region.name,
                    rclass=classify_region(region.name),
                    start=region.start_offset,
                    end=region.end_offset,
                    size=region.end_offset - region.start_offset + 1,
                )
            ri = region_map[region.name]
            ri.reads += 1
            ri.bytes_read += mapped_event.original.length

    # coverage per region
    cov = _compute_region_coverage(success_ev, region_map)
    for name, c in cov.items():
        region_map[name].coverage_pct = c

    # unique offsets + repeated + first access order per region
    seen: dict[str, set[int]] = defaultdict(set)
    first_access: dict[str, int] = {}
    access_index: dict[str, list[int]] = defaultdict(list)
    for idx, me in enumerate(mapped):
        for region in me.matched_regions:
            name = region.name
            off = me.original.offset
            access_index[name].append(idx)
            if name not in first_access:
                first_access[name] = idx
            if off in seen[name]:
                region_map[name].repeated_reads += 1
            seen[name].add(off)
    for name, ri in region_map.items():
        ri.unique_offsets = len(seen.get(name, set()))
        ri.first_access = first_access.get(name)

    # region class aggregation
    region_classes: dict[str, dict[str, Any]] = {}
    for ri in region_map.values():
        rc = region_classes.setdefault(
            ri.rclass,
            {"reads": 0, "bytes": 0, "unique": 0, "repeated": 0, "regions": 0},
        )
        rc["reads"] += ri.reads
        rc["bytes"] += ri.bytes_read
        rc["unique"] += ri.unique_offsets
        rc["repeated"] += ri.repeated_reads
        rc["regions"] += 1

    # sort regions by bytes for stable ordering
    for name, ri in region_map.items():
        ri.access_index = sorted(access_index.get(name, []))

    regions_in_order = timeline.regions_in_order()
    first_ten = regions_in_order[:10]
    first_region = timeline.first_region_accessed() or ""
    last_region = timeline.last_region_accessed() or ""

    time_stages = _time_gap_stages(success_ev)

    phases_out = [
        {
            "name": p.name,
            "start_time": p.start_time,
            "end_time": p.end_time,
            "duration_seconds": p.duration.total_seconds(),
            "entry_count": len(p.evidence),
        }
        for p in phases.phases
    ]

    fastio_bytes = sum(e.length for e in fastio)

    return ExpResult(
        exp_id=eid,
        sample=str(meta.get("sample", sample.name)),
        category=str(meta.get("category", "unknown")),
        relative_path=str(meta.get("relative_path", "")),
        file_size=file_size,
        pe_overview=pe_overview,
        n_read_ops=len(events),
        n_success=total_reads,
        n_fastio=len(fastio),
        reads=[
            {
                "i": i,
                "t": e.timestamp.strftime("%H:%M:%S.%f"),
                "result": e.result,
                "offset": e.offset,
                "length": e.length,
            }
            for i, e in enumerate(success_ev)
        ],
        total_reads=total_reads,
        unique_offsets=unique_offsets,
        repeated_reads=repeated_reads,
        bytes_read=bytes_read,
        bytes_requested_fastio=fastio_bytes,
        read_amplification=round(read_amplification, 4),
        coverage_pct=round(coverage_pct, 3),
        blocks_4k=len(blocks_touched),
        blocks_4k_total=blocks_total,
        block_coverage_pct=round(block_coverage_pct, 3),
        offset_entropy=round(entropy, 4),
        sequential=round(seq["contiguous"], 4),
        forward=round(seq["forward"], 4),
        avg_jump=round(seq["avg_jump"], 1),
        passes=passes,
        pass_starts=pass_starts,
        min_offset=min_offset,
        max_offset=max_offset,
        min_read=size_stats["min"],
        max_read=size_stats["max"],
        mean_read=round(size_stats["mean"], 1),
        median_read=round(size_stats["median"], 1),
        std_read=round(size_stats["std"], 1),
        q1_read=round(size_stats["q1"], 1),
        q3_read=round(size_stats["q3"], 1),
        mode_read=size_stats["mode"],
        mode_read_count=size_stats["mode_count"],
        chunk_dist=dict(chunk_dist),
        tail_probe=tail_probe,
        read_beyond_eof=read_beyond_eof,
        duration_seconds=round(timeline.duration.total_seconds(), 4),
        first_region=first_region,
        regions_in_order=regions_in_order,
        first_ten_regions=first_ten,
        last_region=last_region,
        time_stages=time_stages,
        phases=phases_out,
        phase_count=len(phases_out),
        phase_confidence=round(phases.confidence, 4),
        phase_names=[p["name"] for p in phases_out],
        regions=region_map,
        region_classes=region_classes,
        region_count=len(region_map),
    )


def _compute_region_coverage(
    events: list, region_map: dict[str, "RegionInfo"]
) -> dict[str, float]:
    overlaps: dict[str, list[tuple[int, int]]] = {n: [] for n in region_map}
    for e in events:
        start = e.offset
        end = e.offset + e.length
        for name, ri in region_map.items():
            if ri.start <= end and start <= ri.end + 1:
                lo = max(start, ri.start)
                hi = min(end, ri.end + 1)
                if lo < hi:
                    overlaps[name].append((lo, hi))
    result: dict[str, float] = {}
    for name, ri in region_map.items():
        merged: list[tuple[int, int]] = []
        for lo, hi in sorted(overlaps[name]):
            if merged and lo <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        covered = sum(hi - lo for lo, hi in merged)
        result[name] = covered / ri.size * 100.0 if ri.size else 0.0
    return result


def run_all() -> list[ExpResult]:
    results = []
    for eid in range(1, 31):
        res = analyze_experiment(eid)
        results.append(res)
        print(
            f"exp {eid:03d} {res.sample:<36} reads={res.total_reads:<5} "
            f"bytes={res.bytes_read:<12} amp={res.read_amplification:6.2f}x "
            f"cov={res.coverage_pct:6.1f}% passes={res.passes}"
        )
    return results


def region_info_to_dict(ri: RegionInfo) -> dict[str, Any]:
    return {
        "name": ri.name,
        "rclass": ri.rclass,
        "start": ri.start,
        "end": ri.end,
        "size": ri.size,
        "reads": ri.reads,
        "unique_offsets": ri.unique_offsets,
        "bytes_read": ri.bytes_read,
        "repeated_reads": ri.repeated_reads,
        "coverage_pct": round(ri.coverage_pct, 3),
        "first_access": ri.first_access,
    }


def exp_result_to_dict(r: ExpResult) -> dict[str, Any]:
    d = {
        k: getattr(r, k)
        for k in (
            "exp_id", "sample", "category", "relative_path", "file_size",
            "pe_overview", "n_read_ops", "n_success", "n_fastio", "reads",
            "total_reads", "unique_offsets", "repeated_reads", "bytes_read",
            "bytes_requested_fastio", "read_amplification", "coverage_pct",
            "blocks_4k", "blocks_4k_total", "block_coverage_pct",
            "offset_entropy", "sequential", "forward", "avg_jump", "passes",
            "pass_starts", "min_offset", "max_offset", "min_read", "max_read",
            "mean_read", "median_read", "std_read", "q1_read", "q3_read",
            "mode_read", "mode_read_count", "chunk_dist", "tail_probe",
            "read_beyond_eof", "duration_seconds", "first_region",
            "regions_in_order", "first_ten_regions", "last_region",
            "time_stages", "phases", "phase_count", "phase_confidence",
            "phase_names", "region_classes",
        )
    }
    d["regions"] = {
        name: region_info_to_dict(ri) for name, ri in sorted(r.regions.items())
    }
    d["region_count"] = r.region_count
    return d


def exp_result_from_dict(d: dict[str, Any]) -> ExpResult:
    res = ExpResult(
        exp_id=d["exp_id"],
        sample=d["sample"],
        category=d["category"],
        relative_path=d.get("relative_path", ""),
        file_size=d["file_size"],
        pe_overview=d["pe_overview"],
    )
    for k in (
        "n_read_ops", "n_success", "n_fastio", "reads", "total_reads",
        "unique_offsets", "repeated_reads", "bytes_read",
        "bytes_requested_fastio", "read_amplification", "coverage_pct",
        "blocks_4k", "blocks_4k_total", "block_coverage_pct",
        "offset_entropy", "sequential", "forward", "avg_jump", "passes",
        "pass_starts", "min_offset", "max_offset", "min_read", "max_read",
        "mean_read", "median_read", "std_read", "q1_read", "q3_read",
        "mode_read", "mode_read_count", "chunk_dist", "tail_probe",
        "read_beyond_eof", "duration_seconds", "first_region",
        "regions_in_order", "first_ten_regions", "last_region",
        "time_stages", "phases", "phase_count", "phase_confidence",
        "phase_names", "region_classes",
    ):
        setattr(res, k, d.get(k, res.__dict__.get(k)))
    res.region_count = d.get("region_count", len(d.get("regions", {})))
    regions = {}
    for name, rd in d.get("regions", {}).items():
        regions[name] = RegionInfo(
            name=name,
            rclass=rd["rclass"],
            start=rd["start"],
            end=rd["end"],
            size=rd["size"],
            reads=rd["reads"],
            unique_offsets=rd["unique_offsets"],
            bytes_read=rd["bytes_read"],
            repeated_reads=rd["repeated_reads"],
            coverage_pct=rd["coverage_pct"],
            first_access=rd.get("first_access"),
        )
    res.regions = regions
    return res


def save(results: list[ExpResult], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump([exp_result_to_dict(r) for r in results], fh, indent=1)


def load(path: Path) -> list[ExpResult]:
    with path.open("r", encoding="utf-8") as fh:
        return [exp_result_from_dict(d) for d in json.load(fh)]


if __name__ == "__main__":
    import sys

    results = run_all()
    save(results, OUT_DIR / "pipeline_results.json")
    print(f"saved {len(results)} results")
