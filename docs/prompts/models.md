Implement the core models for DefenderAtlas.

Use Pydantic v2.

Create:

ReadEvent

Fields:
- timestamp
- process_name
- process_id
- operation
- path
- offset
- length
- result

ScanPhase

Fields:
- id
- name
- description
- start_offset
- end_offset

Finding

Fields:
- title
- severity
- description
- evidence

Statistics

Fields:
- total_reads
- unique_offsets
- repeated_reads
- bytes_read
- read_amplification

AnalysisResult

Fields:
- file_type
- findings
- phases
- statistics

Requirements

• Type hints
• Validation
• Serialization
• Docstrings
• Unit tests

No parsing.

No analysis.

No reports.
