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
defenderatlas --version
defenderatlas info
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
