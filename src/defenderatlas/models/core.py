"""Core data models for DefenderAtlas.

All models use Pydantic v2 with strict validation, serialization,
and JSON schema generation.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 - needed at runtime by Pydantic
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class Severity(StrEnum):
    """Severity level for a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReadEvent(BaseModel):
    """A single file read operation captured from ProcMon or ETW.

    Represents one discrete I/O read event against a target file,
    including the process responsible, the byte range accessed,
    and the operation outcome.
    """

    timestamp: datetime = Field(
        description="UTC timestamp when the read occurred.",
    )
    process_name: str = Field(
        min_length=1,
        description="Name of the process that performed the read.",
    )
    process_id: int = Field(
        gt=0,
        description="PID of the process that performed the read.",
    )
    operation: str = Field(
        min_length=1,
        description="I/O operation type, e.g. 'ReadFile', 'IRP_MJ_READ'.",
    )
    path: str = Field(
        min_length=1,
        description="Absolute path of the file that was read.",
    )
    offset: int = Field(
        ge=0,
        description="Byte offset within the file where the read started.",
    )
    length: int = Field(
        gt=0,
        description="Number of bytes requested in the read.",
    )
    result: str = Field(
        min_length=1,
        description=("Operation outcome, e.g. 'SUCCESS', 'FAST IO DISALLOWED'."),
    )


class ScanPhase(BaseModel):
    """A distinct phase identified in Defender's scanning behavior.

    Phases are sequential regions of a file that Defender accesses
    during a scan, typically corresponding to structural elements
    such as headers, import tables, overlay data, etc.
    """

    id: int = Field(
        gt=0,
        description="Unique identifier for this phase (1-indexed).",
    )
    name: str = Field(
        min_length=1,
        description="Short label for the phase, e.g. 'PE Header'.",
    )
    description: str = Field(
        min_length=1,
        description="Human-readable explanation of what this phase covers.",
    )
    start_offset: int = Field(
        ge=0,
        description="Byte offset where the phase begins (inclusive).",
    )
    end_offset: int = Field(
        ge=0,
        description="Byte offset where the phase ends (inclusive).",
    )

    @model_validator(mode="after")
    def _check_offsets(self) -> ScanPhase:
        if self.end_offset < self.start_offset:
            msg = (
                f"end_offset ({self.end_offset}) must be >= "
                f"start_offset ({self.start_offset})"
            )
            raise ValueError(msg)
        return self

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": 1,
                    "name": "PE Header",
                    "description": "Initial read of the DOS/PE headers.",
                    "start_offset": 0,
                    "end_offset": 1023,
                }
            ]
        }
    }


class Finding(BaseModel):
    """An observation or security finding from the analysis.

    Findings describe noteworthy patterns, anomalies, or indicators
    discovered during the analysis of Defender's scan behavior.
    """

    title: str = Field(
        min_length=1,
        description="Short, descriptive title for the finding.",
    )
    severity: Severity = Field(
        description="How severe or impactful this finding is.",
    )
    description: str = Field(
        min_length=1,
        description="Detailed explanation of the finding.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Supporting evidence: log lines, byte offsets, or "
            "references to ReadEvent records."
        ),
    )


class Statistics(BaseModel):
    """Aggregate statistics over a set of read events.

    Captures the overall read profile of a scan, including total
    volume, uniqueness of accessed offsets, and read amplification
    ratio (total reads / unique offsets touched).
    """

    total_reads: int = Field(
        ge=0,
        description="Total number of read operations observed.",
    )
    unique_offsets: int = Field(
        ge=0,
        description="Number of distinct byte offsets accessed.",
    )
    repeated_reads: int = Field(
        ge=0,
        description="Number of reads targeting an already-read offset.",
    )
    bytes_read: int = Field(
        ge=0,
        description="Total bytes requested across all reads.",
    )
    read_amplification: float = Field(
        ge=0.0,
        description=(
            "Ratio of total reads to unique offsets touched. "
            "A value of 1.0 means every offset was read exactly once."
        ),
    )


class AnalysisResult(BaseModel):
    """Top-level container for a complete file analysis.

    Bundles the identified file type, all findings, scan phases,
    and aggregate statistics into a single serializable object.
    """

    file_type: str = Field(
        min_length=1,
        description="Detected file type, e.g. 'PE32', 'PDF', 'Office XML'.",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings discovered during analysis.",
    )
    phases: list[ScanPhase] = Field(
        default_factory=list,
        description="Ordered list of scan phases identified.",
    )
    statistics: Statistics = Field(
        description="Aggregate read-event statistics for the scan.",
    )
