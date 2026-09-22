# Contributing to TokenGuard

Thank you for your interest in improving TokenGuard! Contributions from the community are warmly welcome.

## Development Setup

TokenGuard is designed to be **zero-dependency**, requiring only Python 3.12+ and `pytest` / `ruff` for development.

```bash
# Clone the repository
git clone https://github.com/umutgungorr/tokenguard.git
cd tokenguard

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install editable package with dev dependencies
pip install -e .
pip install pytest ruff
```

## Running Tests & Linters

```bash
# Run test suite
pytest tests contract_tests -v

# Run linter
ruff check .
```

## Adding New Secret Rules

1. Define the regex and metadata in `src/tokenguard/rules.py` within `RULES`.
2. Add a corresponding test case in `tests/test_tokenguard.py`.
3. Verify entropy handling and ensure no false positives on normal code syntax.
4. Submit a Pull Request!
