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
- Single blank line at end of file

Patterns
- Classes with `__init__` cannot throw exceptions
- Modules raise exceptions, main.py handles sys.exit(1)

Testing
- Mirror src structure: `src/module.py` -> `tests/test_module.py`
- Minimal tests, no redundant tests
- Comment sections: `# method_name` before tests
- Use `mocker.patch("module.dependency")` or `mocker.patch.object(Class, "method")`
- Assert pattern: `assert expected == actual`
- Use `pytest.raises(Exception)` for exceptions

Quality gates (run after changes, fix only if below threshold)
- black .
- mypy .
- pylint $(git ls-files '*.py') >= 9.5
- pytest tests/ >= 80% coverage
