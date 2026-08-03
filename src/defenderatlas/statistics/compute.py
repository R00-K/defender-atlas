"""Compute aggregate statistics from a stream of read events.

Read amplification measures how many times more data Defender reads
from disk compared to the actual file size.  A value of 1.0 means every
byte was read exactly once; a value of 6.0 means the file was effectively
read six times over.  High amplification indicates multi-pass scanning.

Repeated reads target offsets that were already accessed in an earlier
read.  A high ratio of repeated reads to total reads suggests the
scanner revisits specific regions (e.g. headers, import tables) rather
than performing a single sequential pass.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenderatlas.models.core import Statistics

if TYPE_CHECKING:
    from collections.abc import Iterable

    from defenderatlas.models.core import ReadEvent


def compute_statistics(
    events: Iterable[ReadEvent],
    *,
    file_size: int | None = None,
) -> Statistics:
    """Compute aggregate statistics from an iterable of read events.

    Performs a single O(n) pass over *events*, tracking the set of
    unique offsets and accumulating totals.  Works with generators
    without buffering all events into memory.

    Parameters
    ----------
    events:
        Any iterable (including generators) of :class:`ReadEvent`
        objects.  Consumed lazily.
    file_size:
        Size of the target file in bytes.  Used to compute the read
        amplification ratio (``bytes_read / file_size``).  When
        ``None`` (the default) or ``<= 0``, amplification is set to
        ``0.0``.

    Returns
    -------
    Statistics
        A validated Pydantic model with the computed aggregates.

    Raises
    ------
    ValueError
        If *file_size* is provided and is ``<= 0``.
    """
    if file_size is not None and file_size <= 0:
        msg = f"file_size must be > 0, got {file_size}"
        raise ValueError(msg)

    total_reads = 0
    bytes_read = 0
    repeated_reads = 0
    seen_offsets: set[int] = set()

    for event in events:
        total_reads += 1
        bytes_read += event.length

        if event.offset in seen_offsets:
            repeated_reads += 1
        else:
            seen_offsets.add(event.offset)

    unique_offsets = len(seen_offsets)

    if file_size is not None and file_size > 0:
        read_amplification = bytes_read / file_size
    else:
        read_amplification = 0.0

    return Statistics(
        total_reads=total_reads,
        unique_offsets=unique_offsets,
        repeated_reads=repeated_reads,
        bytes_read=bytes_read,
        read_amplification=read_amplification,
    )
