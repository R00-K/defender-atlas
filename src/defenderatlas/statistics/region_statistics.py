"""Per-region statistics for PE structure scanning analysis.

Why Region-Level Analysis Matters
---------------------------------
ProcMon traces tell us *which bytes* Defender reads, but not *why*.
By mapping read offsets to PE structures (DOS Header, .text section,
Import Directory, etc.) via the PE Mapping Engine, we can answer:

- Which PE structures receive the most attention during a scan?
- Does Defender focus on the import table (malware indicator)?
- How much of the code section is actually inspected?
- Is the overlay being read (potential payload hiding)?

This is critical for understanding Defender's detection logic and
identifying evasion opportunities.

How Percentages Are Calculated
------------------------------
``percentage_of_total_reads`` and ``percentage_of_total_bytes`` are
computed against the **aggregate** totals across all regions.  A read
that spans two regions (e.g. crosses from the section table into
.text) is counted in **both** regions.  This means percentages can
sum to more than 100% — this is intentional and reflects overlapping
access patterns accurately.

Example::

    .text          80 reads   800 KB   66.7% of reads
    Import Dir     12 reads    48 KB   10.0% of reads
    Certificate     8 reads    32 KB    6.7% of reads
                  ────────   ──────
    Total         100 reads   880 KB

If .text and Import Directory overlap for one read, that read is
counted in both rows, so the percentages sum to > 100%.

How Repeated Reads Influence Statistics
---------------------------------------
A single offset read multiple times contributes multiple read counts
but only once to ``unique_offsets``.  This mirrors the global
:class:`~defenderatlas.models.core.Statistics` model's treatment of
repeated reads.  High repeated-read counts on a region indicate
Defender revisits that structure — a strong signal for detection
logic focusing on a specific table or header.

Performance
-----------
The engine performs a single O(n) pass over the mapped events,
maintaining a ``dict`` of per-region accumulators keyed by region
name.  For *n* events touching an average of *k* regions each, the
complexity is O(n * k) with O(m) space where *m* is the number of
unique regions.  Sorting at the end is O(m log m).
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from defenderatlas.mapping.models import MappedReadEvent  # noqa: TC001

if TYPE_CHECKING:
    from collections.abc import Iterable


class RegionStatistic(BaseModel):
    """Statistics for a single PE region.

    Attributes
    ----------
    region_name:
        Label of the PE region, e.g. ``".text"`` or
        ``"Import Directory"``.
    read_count:
        Number of read operations that touched this region.
    unique_offsets:
        Number of distinct byte offsets accessed within this region.
    bytes_read:
        Total bytes requested across all reads touching this region.
    percentage_of_total_reads:
        ``read_count / total_reads * 100``.  ``0.0`` when there are
        no reads.
    percentage_of_total_bytes:
        ``bytes_read / total_bytes * 100``.  ``0.0`` when there are
        no bytes.
    """

    region_name: str = Field(
        min_length=1,
        description="Label of the PE region.",
    )
    read_count: int = Field(
        ge=0,
        description="Number of reads touching this region.",
    )
    unique_offsets: int = Field(
        ge=0,
        description="Number of distinct byte offsets accessed.",
    )
    bytes_read: int = Field(
        ge=0,
        description="Total bytes requested across all reads.",
    )
    percentage_of_total_reads: float = Field(
        ge=0.0,
        le=100.0,
        description="Percentage of aggregate reads targeting this region.",
    )
    percentage_of_total_bytes: float = Field(
        ge=0.0,
        le=100.0,
        description="Percentage of aggregate bytes read from this region.",
    )


class RegionStatisticsResult(BaseModel):
    """Aggregate result of per-region statistics computation.

    Regions are sorted by ``bytes_read`` descending so the most
    accessed structures appear first — ideal for CLI table rendering::

        Region              Reads    Bytes
        ─────────────────────────────────────
        .text                 41    1048576
        Import Directory      12      49152
        Certificate Table      8      32768

    Attributes
    ----------
    total_regions:
        Number of unique PE regions that received at least one read.
    total_reads:
        Sum of ``read_count`` across all regions.  May exceed the
        number of input events when reads span multiple regions.
    total_bytes:
        Sum of ``bytes_read`` across all regions.
    regions:
        Sorted list of :class:`RegionStatistic` objects.
    """

    total_regions: int = Field(
        ge=0,
        description="Number of regions with at least one read.",
    )
    total_reads: int = Field(
        ge=0,
        description=(
            "Number of input events processed.  May be less than the "
            "sum of per-region read_counts when reads span multiple "
            "regions."
        ),
    )
    total_bytes: int = Field(
        ge=0,
        description=(
            "Total bytes requested across all input events.  May be "
            "less than the sum of per-region bytes_read when reads "
            "span multiple regions."
        ),
    )
    regions: list[RegionStatistic] = Field(
        default_factory=list,
        description="Per-region statistics, sorted by bytes_read desc.",
    )

    def top_regions_by_reads(self, n: int = 3) -> list[RegionStatistic]:
        """Return the top *n* regions by read count.

        Parameters
        ----------
        n:
            Number of regions to return.  Clamped to the actual
            number of regions.

        Returns
        -------
        list[RegionStatistic]
            Up to *n* regions sorted by ``read_count`` descending.
        """
        sorted_by_reads = sorted(self.regions, key=lambda r: r.read_count, reverse=True)
        return sorted_by_reads[:n]

    def top_regions_by_bytes(self, n: int = 3) -> list[RegionStatistic]:
        """Return the top *n* regions by bytes read.

        Parameters
        ----------
        n:
            Number of regions to return.  Clamped to the actual
            number of regions.

        Returns
        -------
        list[RegionStatistic]
            Up to *n* regions sorted by ``bytes_read`` descending.
        """
        sorted_by_bytes = sorted(self.regions, key=lambda r: r.bytes_read, reverse=True)
        return sorted_by_bytes[:n]

    def top_n_regions(self, n: int = 3) -> list[RegionStatistic]:
        """Return the top *n* regions by bytes read (default sort).

        This is a convenience alias for :meth:`top_regions_by_bytes`.

        Parameters
        ----------
        n:
            Number of regions to return.

        Returns
        -------
        list[RegionStatistic]
            Up to *n* regions sorted by ``bytes_read`` descending.
        """
        return self.top_regions_by_bytes(n)


def compute_region_statistics(
    events: Iterable[MappedReadEvent],
) -> RegionStatisticsResult:
    """Compute per-region statistics from mapped read events.

    Performs a single pass over *events*, accumulating per-region
    counters in a dictionary.  A read that touches multiple regions
    (cross-region boundary) is counted in each touched region.

    ``total_reads`` in the result is the number of input events
    (not the sum of per-region counts).  This means per-region
    read percentages can sum to more than 100% when reads span
    multiple regions.

    Parameters
    ----------
    events:
        Any iterable of :class:`MappedReadEvent` objects.

    Returns
    -------
    RegionStatisticsResult
        Aggregate result with per-region statistics sorted by
        ``bytes_read`` descending.
    """
    read_counts: dict[str, int] = defaultdict(int)
    unique_offsets: dict[str, set[int]] = defaultdict(set)
    bytes_read: dict[str, int] = defaultdict(int)

    input_event_count = 0
    total_bytes_all = 0

    for mapped in events:
        input_event_count += 1
        offset = mapped.original.offset
        length = mapped.original.length
        total_bytes_all += length

        for region in mapped.matched_regions:
            name = region.name
            read_counts[name] += 1
            unique_offsets[name].add(offset)
            bytes_read[name] += length

    total_bytes = sum(bytes_read.values())

    region_stats: list[RegionStatistic] = []
    for name in read_counts:
        rc = read_counts[name]
        uo = len(unique_offsets[name])
        br = bytes_read[name]
        pct_reads = (rc / input_event_count * 100) if input_event_count > 0 else 0.0
        pct_bytes = (br / total_bytes * 100) if total_bytes > 0 else 0.0
        region_stats.append(
            RegionStatistic(
                region_name=name,
                read_count=rc,
                unique_offsets=uo,
                bytes_read=br,
                percentage_of_total_reads=round(pct_reads, 2),
                percentage_of_total_bytes=round(pct_bytes, 2),
            )
        )

    region_stats.sort(key=lambda r: r.bytes_read, reverse=True)

    return RegionStatisticsResult(
        total_regions=len(region_stats),
        total_reads=input_event_count,
        total_bytes=total_bytes_all,
        regions=region_stats,
    )
