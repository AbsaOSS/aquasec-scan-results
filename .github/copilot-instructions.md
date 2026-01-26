Copilot instructions for AquaSec Scan Results GitHub Action

Purpose
GitHub Action that fetches security scan results from AquaSec and integrates them into GitHub Security tab.

Structure
- Entry point: `main.py`
- Action config: `action.yml`
- Constants: `src/utils/constants.py`

Inputs (via environment variables with INPUT_ prefix)
- AQUA_KEY, AQUA_SECRET (required)
- VERBOSE_LOGGING (optional, default false)

Python style
- Python 3.14
- Type hints for public functions and classes
- Use `logging.getLogger(__name__)`, not print
- Lazy % formatting in logging: `logger.info("msg %s", var)`
- F-strings in exceptions: `raise ValueError(f"Error {var}")`
- Google-style docstrings

Patterns
- Classes with `__init__` cannot throw exceptions
- Modules raise exceptions, main.py handles sys.exit(1)

Quality gates (run after changes)
- black .
- mypy .
- pylint $(git ls-files '*.py') >= 9.5
- pytest tests/ >= 80% coverage
