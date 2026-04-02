Copilot instructions for AquaSec Scan Results GitHub Action

Purpose
GitHub Action that fetches security scan results from AquaSec. Two operational modes:
- **Night Scan** (default): converts findings to SARIF for GitHub Security tab integration.
- **Branch Comparison** (`dev-branch-comparison: 'true'`): triggers a dev-branch scan, compares findings against master, posts a Markdown summary to the PR, and fails the workflow when new findings are detected.

Structure
- Entry point: `main.py`
- Action config: `action.yml`
- Central input access and validation: `src/action_inputs.py`
- Shared type aliases and dataclasses: `src/types.py`
- Constants: `src/utils/constants.py`
- Utilities: `src/utils/utils.py`, `src/utils/logging_config.py`
- Mode orchestrators: `src/modes/night_scan_mode.py`, `src/modes/branch_comparison_mode.py`
- Services: `src/services/` (authenticator, scan_fetcher, scan_trigger, sarif_convertor, branch_comparator)

Inputs (via environment variables with INPUT_ prefix)
- AQUA_KEY, AQUA_SECRET, GROUP_ID, REPOSITORY_ID (required)
- VERBOSE_LOGGING (optional, default false)
- DEV_BRANCH_COMPARISON (optional, default false)
- BRANCH_COMPARISON_POLL_INTERVAL (optional, default 30)
- BRANCH_COMPARISON_POLL_TIMEOUT (optional, default 600)

Outputs
- `nightscan-sarif-file` — path to SARIF file (night scan mode)
- `comparison-summary-file` — path to Markdown summary (branch comparison mode)

Failure behaviour
- `BranchComparisonMode.run()` returns `(summary_file, has_new_findings: bool)`
- `main.py` calls `set_action_failed()` after saving outputs when `has_new_findings` is `True`
- This ensures the PR comment is always posted before the workflow check turns red

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
- Use `set_action_failed()` from utils to fail the action with a user-visible `::error::` message
- Use private methods (`_method_name`) for internal class helpers
- ActionInputs class validates only, use `get_action_input()` from utils to get inputs elsewhere
- All info logs must start with "AquaSec Scan Results -" prefix
- Never disable pylint behaviour in the code

Testing
- Mirror src structure: `src/module.py` -> `tests/test_module.py`
- Minimal tests, no redundant tests
- All imports at the top of test files (never inside test functions)
- Use conftest.py fixtures for repeated mocking patterns across tests
- Comment sections: `# method_name` before tests
- Use `mocker.patch("module.dependency")` or `mocker.patch.object(Class, "method")`
- Use `monkeypatch.setenv("VAR", "value")` for cleaning up environment variables
- Assert pattern: `assert expected == actual`
- Use `pytest.raises(Exception)` for exceptions
- Use `@pytest.mark.parametrize` for data-driven tests (negative/failure scenarios with multiple similar cases)

Quality gates (run after changes, fix only if below threshold)
- black .
- mypy .
- pylint $(git ls-files '*.py') >= 9.5
- pytest tests/ >= 80% coverage
- Pre-commit hooks configured in `.pre-commit-config.yaml`
