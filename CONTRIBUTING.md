# Contributing to PolicyBound

Thank you for considering a contribution to PolicyBound.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Development Workflow

### Running Tests

```bash
pytest
```

### Linting

```bash
ruff check src/ tests/
```

### Type Checking

```bash
mypy src/
```

## Submitting Changes

1. Create a feature branch from `main`
2. Write tests for your changes
3. Ensure all tests pass and linting is clean
4. Submit a pull request with a clear description of the change

## Reporting Issues

Use [GitHub Issues](https://github.com/ikilic-tech/policybound/issues) to report bugs or request features. Include:

- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Python version and OS

## Code Style

- Follow existing code conventions
- Use type hints
- Keep functions focused and small
- Write docstrings for public APIs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
