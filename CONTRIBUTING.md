# Contributing to DefenderAtlas

Thank you for your interest in contributing to DefenderAtlas!

## Development Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/DefenderAtlas/DefenderAtlas.git
   cd DefenderAtlas
   ```

2. Create a virtual environment:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate   # Windows
   ```

3. Install the package in editable mode with dev dependencies:

   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks:

   ```bash
   pre-commit install
   ```

## Code Style

- **Formatter**: Black (line length 88)
- **Linter**: Ruff
- **Type checker**: mypy (strict mode)
- All code must be typed.
- All public functions and classes must have docstrings.

## Running Checks

```bash
# Linting
ruff check src/ tests/
black --check src/ tests/

# Type checking
mypy src/

# Tests
pytest
```

## Pull Requests

1. Fork the repository and create a branch from `main`.
2. Add tests for any new functionality.
3. Ensure all checks pass.
4. Update documentation if needed.
5. Submit a pull request with a clear description.

## Reporting Issues

Use the GitHub issue tracker to report bugs or request features.
