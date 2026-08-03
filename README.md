# DefenderAtlas

Framework for analyzing Microsoft Defender file scanning behavior using ProcMon, ETW, reverse engineering, and file format analysis.

## Installation

```bash
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```bash
# Show version
defenderatlas --version

# Analyze a ProcMon CSV trace file
defenderatlas analyze trace.csv
```

### Example Output

```
╭─────── Analyze ─────────────────────────────────────╮
│                                                     │
│           Statistics Summary                        │
│                                                     │
│  Total Reads          3,412                         │
│  Unique Offsets         842                         │
│  Repeated Reads       2,570                         │
│  Bytes Read        15,248,384                       │
│                                                     │
│  Read Amplification      3.81x                      │
│                                                     │
│  Processing Time   0.125s (parse: 0.089s, compute: 0.036s) │
│                                                     │
╰────────────────────── trace.csv ─────────────────────╯
```

## Project Structure

```
src/defenderatlas/
├── analyzers/     # File scanning behavior analysis
├── capture/       # ProcMon and ETW capture modules
├── cli/           # CLI entry points (Typer)
├── detectors/     # Detection logic for Defender patterns
├── mapping/       # File format and structure mapping
├── models/        # Pydantic v2 data models
├── parsers/       # File format parsers (PE, PDF, Office, etc.)
├── reports/       # Report generation
├── reverse/       # Reverse engineering analysis tools
├── statistics/    # Statistical analysis of scan behavior
├── utils/         # Shared utilities
└── visualization/ # Scan behavior visualization
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linters
ruff check src/ tests/
black --check src/ tests/
mypy src/

# Run tests
pytest
```

## License

MIT
