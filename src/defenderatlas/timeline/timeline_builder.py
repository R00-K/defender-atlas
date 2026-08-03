"""Chronological reconstruction of Defender file accesses.

Why Timeline Reconstruction Matters
------------------------------------
ProcMon traces record individual file read operations, but the raw
event stream doesn't reveal the *sequence* in which Defender inspects
different PE structures.  By sorting events by timestamp and mapping
each access to its corresponding PE region, we can reconstruct the
chronological scan path:

    00.000s  DOS Header
    00.002s  NT Headers
    00.004s  Import Directory
    00.008s  Certificate Table
    00.020s  .text

This reveals the order in which Defender explores a file's structure,
which is essential for identifying scanning phases, understanding
detection logic, and finding evasion opportunities.

How Chronological Ordering Is Preserved
----------------------------------------
Each :class:`MappedReadEvent` carries an original :class:`ReadEvent`
with a UTC timestamp.  When building the timeline, entries are sorted
by ``(timestamp, original_order)`` where ``original_order`` is the
index of the source event in the input iterable.  This guarantees:

1. Events are ordered by wall-clock time.
2. Events with identical timestamps preserve their input order
   (stable sort).

For cross-region reads (a single read spanning multiple PE structures),
one :class:`TimelineEntry` is created per touched region.  All entries
from the same read share the same timestamp, preserving the simultaneity
of cross-region accesses.

How This Prepares for Phase Detection
--------------------------------------
The ordered timeline produced by :func:`build_timeline` is the primary
input for phase detection (a future component).  Phase detection will
scan the timeline for *runs* of consecutive accesses to the same region
(or region group), identifying distinct scanning phases such as:

- Header inspection (DOS Header, NT Headers, Section Table)
- Import table analysis (Import Directory, IAT)
- Code section scanning (.text)
- Certificate verification (Certificate Table / Security Directory)

The timeline provides the raw chronological data; phase detection
groups and labels contiguous segments.

Performance
-----------
Building the timeline requires sorting *n* entries, which is
O(n log n) where *n* is the total number of :class:`TimelineEntry`
objects (sum of per-event region counts).  Helper methods perform
linear scans or dictionary lookups on the sorted entries list.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from defenderatlas.mapping.models import MappedReadEvent  # noqa: TC001

if TYPE_CHECKING:
    from collections.abc import Iterable


class TimelineEntry(BaseModel):
    """A single chronological access in the scan timeline.

    When a read spans multiple PE regions, one entry is created per
    touched region.  All entries from the same read share the same
    timestamp and offset/length values.

    Attributes
    ----------
    timestamp:
        UTC time of the access.
    region_name:
        PE region that was accessed (``"Unmapped"`` when the read did
        not match any known region).
    offset:
        Byte offset of the read within the file.
    length:
        Number of bytes requested in the read.
    operation:
        I/O operation type (e.g. ``"ReadFile"``).
    process_name:
        Name of the process that performed the read.
    """

    timestamp: datetime = Field(
        description="UTC timestamp when the access occurred.",
    )
    region_name: str = Field(
        min_length=1,
        description="PE region that was accessed.",
    )
    offset: int = Field(
        ge=0,
        description="Byte offset of the read within the file.",
    )
    length: int = Field(
        gt=0,
        description="Number of bytes requested in the read.",
    )
    operation: str = Field(
        min_length=1,
        description="I/O operation type.",
    )
    process_name: str = Field(
        min_length=1,
        description="Name of the process that performed the read.",
    )


class TimelineResult(BaseModel):
    """Complete chronological reconstruction of a scan.

    Entries are sorted by timestamp (ascending).  When timestamps are
    identical the original input order is preserved.

    Attributes
    ----------
    start_time:
        Timestamp of the first access.
    end_time:
        Timestamp of the last access.
    duration:
        Wall-clock span from first to last access.
    entries:
        Chronologically sorted timeline entries.
    """

    start_time: datetime = Field(
        description="Timestamp of the first access.",
    )
    end_time: datetime = Field(
        description="Timestamp of the last access.",
    )
    duration: timedelta = Field(
        description="Wall-clock span from first to last access.",
    )
    entries: list[TimelineEntry] = Field(
        default_factory=list,
        description="Chronologically sorted timeline entries.",
    )

    def timeline_by_region(self) -> dict[str, list[TimelineEntry]]:
        """Group entries by PE region, preserving chronological order.

        Returns
        -------
        dict[str, list[TimelineEntry]]
            Mapping from region name to its entries in time order.
        """
        result: dict[str, list[TimelineEntry]] = {}
        for entry in self.entries:
            result.setdefault(entry.region_name, []).append(entry)
        return result

    def regions_in_order(self) -> list[str]:
        """Unique regions in order of first access.

        Returns
        -------
        list[str]
            Region names sorted by the timestamp of their first
            appearance in the timeline.
        """
        seen: set[str] = set()
        ordered: list[str] = []
        for entry in self.entries:
            if entry.region_name not in seen:
                seen.add(entry.region_name)
                ordered.append(entry.region_name)
        return ordered

    def first_region_accessed(self) -> str | None:
        """Region of the earliest entry.

        Returns
        -------
        str | None
            Region name, or ``None`` if the timeline is empty.
        """
        if not self.entries:
            return None
        return self.entries[0].region_name

    def last_region_accessed(self) -> str | None:
        """Region of the latest entry.

        Returns
        -------
        str | None
            Region name, or ``None`` if the timeline is empty.
        """
        if not self.entries:
            return None
        return self.entries[-1].region_name

    def most_frequently_visited_regions(
        self,
        n: int = 3,
    ) -> list[tuple[str, int]]:
        """Top *n* regions by number of timeline entries.

        Parameters
        ----------
        n:
            Number of regions to return.

        Returns
        -------
        list[tuple[str, int]]
            ``(region_name, entry_count)`` pairs sorted by count
            descending.
        """
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.region_name] = counts.get(entry.region_name, 0) + 1
        sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_counts[:n]


_UNMAPPED = "Unmapped"


def _build_entries(
    events: Iterable[MappedReadEvent],
) -> list[tuple[datetime, int, TimelineEntry]]:
    """Expand mapped events into sortable (timestamp, order, entry) tuples."""
    result: list[tuple[datetime, int, TimelineEntry]] = []

    for order, mapped in enumerate(events):
        original = mapped.original
        ts = original.timestamp

        if not mapped.matched_regions:
            entry = TimelineEntry(
                timestamp=ts,
                region_name=_UNMAPPED,
                offset=original.offset,
                length=original.length,
                operation=original.operation,
                process_name=original.process_name,
            )
            result.append((ts, order, entry))
        else:
            for region in mapped.matched_regions:
                entry = TimelineEntry(
                    timestamp=ts,
                    region_name=region.name,
                    offset=original.offset,
                    length=original.length,
                    operation=original.operation,
                    process_name=original.process_name,
                )
                result.append((ts, order, entry))

    return result


def build_timeline(events: Iterable[MappedReadEvent]) -> TimelineResult:
    """Build a chronological timeline from mapped read events.

    Each :class:`MappedReadEvent` is expanded into one or more
    :class:`TimelineEntry` objects — one per matched region.  Events
    with no matched regions produce a single entry labelled
    ``"Unmapped"``.

    The resulting entries are sorted by ``(timestamp, original_order)``
    to guarantee chronological order with stable tie-breaking.

    Parameters
    ----------
    events:
        Any iterable of :class:`MappedReadEvent` objects.

    Returns
    -------
    TimelineResult
        Sorted timeline with duration and helper methods.
    """
    tuples = _build_entries(events)

    if not tuples:
        now = datetime.now(UTC)
        return TimelineResult(
            start_time=now,
            end_time=now,
            duration=timedelta(),
            entries=[],
        )

    tuples.sort(key=lambda t: (t[0], t[1]))
    entries = [t[2] for t in tuples]

    start_time = entries[0].timestamp
    end_time = entries[-1].timestamp
    duration = end_time - start_time

    return TimelineResult(
        start_time=start_time,
        end_time=end_time,
        duration=duration,
        entries=entries,
    )
