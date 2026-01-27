Copilot instructions for AquaSec Scan Results GitHub Action

Purpose
GitHub Action that fetches security scan results from AquaSec and integrates them into GitHub Security tab.

Structure
- Entry point: `main.py`
- Action config: `action.yml`
- Constants: `src/utils/constants.py`

Inputs (via environment variables with INPUT_ prefix)
- AQUA_KEY, AQUA_SECRET, REPOSITORY_ID (required)
- VERBOSE_LOGGING (optional, default false)

Python style
- Python 3.14
- Type hints for public functions and classes
- Use `logging.getLogger(__name__)`, not print
- Lazy % formatting in logging: `logger.info("msg %s", var)`
- F-strings in exceptions: `raise ValueError(f"Error {var}")`
- Google-style docstrings
- Single blank line at end of file
- No documentation for `__init__` methods

Patterns
- Classes with `__init__` cannot throw exceptions
- Modules raise exceptions, main.py handles sys.exit(1)
- Use private methods (`_method_name`) for internal class helpers
- ActionInputs class validates only, use `get_action_input()` from utils to get inputs elsewhere
- All info logs must start with "AquaSec Scan Results -" prefix

Testing
- Mirror src structure: `src/module.py` -> `tests/test_module.py`
- Minimal tests, no redundant tests
- All imports at the top of test files (never inside test functions)
- Use conftest.py fixtures for repeated mocking patterns across tests
- Comment sections: `# method_name` before tests
- Use `mocker.patch("module.dependency")` or `mocker.patch.object(Class, "method")`
- Use `monkeypatch.setenv("VAR", "value")` for environment variables
- Assert pattern: `assert expected == actual`
- Use `pytest.raises(Exception)` for exceptions

Quality gates (run after changes, fix only if below threshold)
- black .
- mypy .
- pylint $(git ls-files '*.py') >= 9.5
- pytest tests/ >= 80% coverage
