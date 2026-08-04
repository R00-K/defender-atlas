"""Rule-based phase detection for scan timeline analysis.

Why Phase Detection Matters
---------------------------
ProcMon traces reveal *what* Defender reads, but raw event streams
don't directly show the *logical phases* of a scan.  By applying
rules over a reconstructed timeline, we can identify distinct phases
such as header inspection, import table analysis, code section
scanning, or certificate verification — without hardcoding any
specific scanner's behavior.

The :class:`PhaseDetector` accepts a set of :class:`PhaseRule`
objects and scans a
:class:`~defenderatlas.timeline.timeline_builder.TimelineResult`
for entries that satisfy each rule.  A phase represents a logical
behavior — all qualifying entries across the timeline are aggregated
into a single phase unless future gap-splitting logic divides them.

A rule matches when:

1. All ``required_regions`` appear in the collected entries.
2. The collected entries reach ``minimum_reads``.
3. All ``optional_regions`` that *do* appear are in the order
   specified by the rule.

How Collection Works
--------------------
For each rule, the detector scans the full timeline and collects
every entry whose ``region_name`` belongs to the rule's relevant
region set (``required_regions`` U ``optional_regions``), excluding
entries already claimed by a prior rule.  The collected entries
are checked as a whole — there is no fragmentation by interleaving.

Priority is determined by rule order: earlier rules claim entries
first, leaving fewer entries for later rules.  A later rule only
matches if unclaimed entries still satisfy its requirements.

Confidence Calculation
----------------------
Detection confidence is the average of three factors (each in
[0, 1]):

- **rule_match**: fraction of rules that matched.
- **phase_coverage**: fraction of unique timeline timestamps
  explained by detected phases.
- **phase_count_bonus**: ``1 / (1 + len(phases))`` — higher when
  fewer, more coherent phases are found.

Future Extension: Gap Splitting
-------------------------------
The collection step is separated from phase creation so that a
future ``gap_threshold`` parameter on :class:`PhaseRule` can split
collected entries into sub-phases at time gaps without changing
any public API.  See the ``_collect_entries`` function for where
this would be inserted.

Performance
-----------
Collection is O(n) per rule where *n* is the timeline length.
Total complexity is O(r * n) where *r* is the number of rules.
In practice *r* is small (< 10) and *n* dominates.
"""

from __future__ import annotations

from datetime import timedelta  # noqa: TC003
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from collections.abc import Sequence

    from defenderatlas.timeline.timeline_builder import (
        TimelineEntry,
        TimelineResult,
    )


class PhaseRule(BaseModel):
    """A rule defining when collected entries constitute a phase.

    Rules are evaluated against *all* qualifying entries across the
    timeline, not just contiguous runs.  A phase aggregates every
    entry whose region belongs to the rule's relevant set.

    Attributes
    ----------
    name:
        Short label for the phase this rule detects.
    description:
        Human-readable explanation of the phase.
    required_regions:
        Set of region names that must **all** appear in the
        collected entries for the rule to match.
    minimum_reads:
        Minimum number of collected entries required for a match.
        Defaults to 1.
    optional_regions:
        Ordered list of region names that may appear in the
        collected entries.  When present, optional regions must
        appear in the specified order relative to each other.
    """

    name: str = Field(
        min_length=1,
        description="Short label for the detected phase.",
    )
    description: str = Field(
        min_length=1,
        description="Human-readable explanation of the phase.",
    )
    required_regions: set[str] = Field(
        default_factory=set,
        description="Region names that must all appear in collected entries.",
    )
    minimum_reads: int = Field(
        default=1,
        ge=1,
        description="Minimum number of entries required for a match.",
    )
    optional_regions: list[str] = Field(
        default_factory=list,
        description="Ordered list of optional region names.",
    )


class Phase(BaseModel):
    """A detected scanning phase with timing and evidence.

    Attributes
    ----------
    name:
        Short label for the phase.
    description:
        Human-readable explanation of what the phase covers.
    start_time:
        ISO-formatted timestamp of the first entry in the phase.
    end_time:
        ISO-formatted timestamp of the last entry in the phase.
    duration:
        Wall-clock span from first to last entry.
    evidence:
        Supporting details — one string per contributing timeline
        entry.
    """

    name: str = Field(
        min_length=1,
        description="Short label for the phase.",
    )
    description: str = Field(
        min_length=1,
        description="Human-readable explanation of the phase.",
    )
    start_time: str = Field(
        min_length=1,
        description="ISO-formatted timestamp of the first entry.",
    )
    end_time: str = Field(
        min_length=1,
        description="ISO-formatted timestamp of the last entry.",
    )
    duration: timedelta = Field(
        description="Wall-clock span from first to last entry.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Supporting details from timeline entries.",
    )


class PhaseDetectionResult(BaseModel):
    """Result of applying phase-detection rules to a timeline.

    Attributes
    ----------
    phases:
        Detected phases sorted by start time.
    confidence:
        Detection confidence in [0.0, 1.0].
    timeline_duration:
        Total wall-clock span of the input timeline.
    """

    phases: list[Phase] = Field(
        default_factory=list,
        description="Detected phases sorted by start time.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Detection confidence in [0.0, 1.0].",
    )
    timeline_duration: timedelta = Field(
        description="Total wall-clock span of the input timeline.",
    )


def _group_same_region(
    entries: list[TimelineEntry],
) -> list[tuple[str, list[TimelineEntry]]]:
    """Group consecutive entries by region name.

    Returns ``(region_name, entries)`` tuples for each maximal run
    of consecutive entries sharing the same ``region_name``.  Used
    by :meth:`PhaseDetector.timeline_to_phases`.
    """
    if not entries:
        return []

    runs: list[tuple[str, list[TimelineEntry]]] = []
    current_region = entries[0].region_name
    current_entries: list[TimelineEntry] = [entries[0]]

    for entry in entries[1:]:
        if entry.region_name == current_region:
            current_entries.append(entry)
        else:
            runs.append((current_region, current_entries))
            current_region = entry.region_name
            current_entries = [entry]

    runs.append((current_region, current_entries))
    return runs


def _collect_entries(
    entries: list[TimelineEntry],
    relevant: set[str],
    claimed: set[object],
) -> list[TimelineEntry]:
    """Collect all entries whose region is in *relevant* and unclaimed.

    Scans the full entry list in order, returning every entry whose
    ``region_name`` belongs to *relevant* and whose ``timestamp``
    has not been added to *claimed*.

    This is the collection step separated from phase creation so that
    a future gap-splitting pass can be inserted between collection
    and ``Phase`` construction without changing any public API.
    """
    return [
        e for e in entries if e.region_name in relevant and e.timestamp not in claimed
    ]


def _check_segment(
    rule: PhaseRule,
    entries: list[TimelineEntry],
) -> Phase | None:
    """Check if collected entries satisfy a rule.

    Returns a :class:`Phase` if the entries meet all criteria, or
    ``None`` if they do not.
    """
    if len(entries) < rule.minimum_reads:
        return None

    entry_regions = {e.region_name for e in entries}

    if not rule.required_regions.issubset(entry_regions):
        return None

    if rule.optional_regions:
        seen: list[str] = []
        for entry in entries:
            if (
                entry.region_name in rule.optional_regions
                and entry.region_name not in seen
            ):
                seen.append(entry.region_name)
        expected = [r for r in rule.optional_regions if r in entry_regions]
        if seen != expected:
            return None

    return Phase(
        name=rule.name,
        description=rule.description,
        start_time=entries[0].timestamp.isoformat(),
        end_time=entries[-1].timestamp.isoformat(),
        duration=entries[-1].timestamp - entries[0].timestamp,
        evidence=[repr(e) for e in entries],
    )


class PhaseDetector:
    """Rule-based detector that scans a timeline for scanning phases.

    Parameters
    ----------
    rules:
        Phase detection rules applied during :meth:`detect`.
    """

    def __init__(self, rules: Sequence[PhaseRule] | None = None) -> None:
        self._rules: list[PhaseRule] = list(rules) if rules else []

    def detect(self, timeline: TimelineResult) -> PhaseDetectionResult:
        """Detect phases in a timeline by applying all rules.

        For each rule the detector collects *all* qualifying entries
        across the timeline (excluding entries claimed by prior
        rules), then creates a single phase spanning the first to
        last collected entry.  A phase represents a logical behavior,
        not a contiguous run.

        Parameters
        ----------
        timeline:
            Chronologically sorted timeline produced by
            :func:`~defenderatlas.timeline.timeline_builder.build_timeline`.

        Returns
        -------
        PhaseDetectionResult
            Detected phases, confidence, and timeline duration.
        """
        phases: list[Phase] = []
        matched_timestamps: set[object] = set()

        for rule in self._rules:
            relevant = rule.required_regions | set(rule.optional_regions)
            collected = _collect_entries(timeline.entries, relevant, matched_timestamps)

            phase = _check_segment(rule, collected)
            if phase is not None:
                phases.append(phase)
                for e in collected:
                    matched_timestamps.add(e.timestamp)

        phases.sort(key=lambda p: p.start_time)
        matched_rule_names = {p.name for p in phases}
        confidence = self._compute_confidence(
            phases, matched_rule_names, matched_timestamps, timeline
        )

        return PhaseDetectionResult(
            phases=phases,
            confidence=confidence,
            timeline_duration=timeline.duration,
        )

    def phase_summary(self, result: PhaseDetectionResult) -> str:
        """Human-readable summary of detected phases.

        Parameters
        ----------
        result:
            Detection result from :meth:`detect`.

        Returns
        -------
        str
            Multi-line summary with phase names and durations.
        """
        if not result.phases:
            return "No phases detected."
        lines = [f"Detected {len(result.phases)} phase(s):"]
        for p in result.phases:
            lines.append(f"  - {p.name}: {p.duration}")
        lines.append(f"Confidence: {result.confidence:.0%}")
        return "\n".join(lines)

    def timeline_to_phases(
        self,
        timeline: TimelineResult,
    ) -> list[Phase]:
        """Convert a timeline into phase candidates grouped by region.

        Each run of consecutive entries sharing the same region name
        becomes one :class:`Phase` candidate with the region name
        as its label.  This method does *not* apply rules or compute
        confidence — use :meth:`detect` for full analysis.

        Parameters
        ----------
        timeline:
            Chronologically sorted timeline.

        Returns
        -------
        list[Phase]
            Phase candidates, one per run, sorted by start time.
        """
        runs = _group_same_region(timeline.entries)
        phases: list[Phase] = []
        for region_name, run_entries in runs:
            phases.append(
                Phase(
                    name=region_name,
                    description=f"Accesses to {region_name}.",
                    start_time=run_entries[0].timestamp.isoformat(),
                    end_time=run_entries[-1].timestamp.isoformat(),
                    duration=(run_entries[-1].timestamp - run_entries[0].timestamp),
                    evidence=[repr(e) for e in run_entries],
                )
            )
        phases.sort(key=lambda p: p.start_time)
        return phases

    def matched_rules(
        self,
        timeline: TimelineResult,
    ) -> dict[str, Phase]:
        """Return rules that matched, keyed by rule name.

        Parameters
        ----------
        timeline:
            Chronologically sorted timeline.

        Returns
        -------
        dict[str, Phase]
            ``{rule_name: Phase}`` for each rule that matched.
        """
        result = self.detect(timeline)
        matched: dict[str, Phase] = {}
        for phase in result.phases:
            for rule in self._rules:
                if rule.name == phase.name:
                    matched[rule.name] = phase
                    break
        return matched

    def unmatched_rules(
        self,
        timeline: TimelineResult,
    ) -> list[PhaseRule]:
        """Return rules that did not match.

        Parameters
        ----------
        timeline:
            Chronologically sorted timeline.

        Returns
        -------
        list[PhaseRule]
            Rules that failed to match.
        """
        matched = self.matched_rules(timeline)
        return [r for r in self._rules if r.name not in matched]

    def _compute_confidence(
        self,
        phases: list[Phase],
        matched_rule_names: set[str],
        matched_timestamps: set[object],
        timeline: TimelineResult,
    ) -> float:
        """Compute overall detection confidence.

        Combines three factors:

        - **rule_match** (40%): fraction of rules that matched.
        - **phase_coverage** (40%): fraction of unique timestamps
          covered by detected phases.
        - **phase_count_bonus** (20%): ``1 / (1 + len(phases))``,
          rewarding fewer, more coherent phases.

        Returns ``0.0`` when no phases were detected.
        """
        if not self._rules or not phases:
            return 0.0

        if not timeline.entries:
            return 0.0

        rule_match = len(matched_rule_names) / len(self._rules)

        all_timestamps = {e.timestamp for e in timeline.entries}
        phase_coverage = (
            len(matched_timestamps) / len(all_timestamps) if all_timestamps else 0.0
        )

        phase_count_bonus = 1.0 / (1.0 + len(phases))

        return 0.4 * rule_match + 0.4 * phase_coverage + 0.2 * phase_count_bonus
