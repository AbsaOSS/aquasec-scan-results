# AquaSec Scan Results for developers

- [Project Setup](#project-setup)
- [Run Project Scripts Locally](#run-project-scripts-locally)
- [Run Pylint Check Locally](#run-pylint-check-locally)
- [Run Black Tool Locally](#run-black-tool-locally)
- [Run mypy Tool Locally](#run-mypy-tool-locally)
- [Run Unit Tests Locally](#run-unit-tests-locally)
- [Code Coverage](#code-coverage)
- [Pre-Commit Quality Check Tool](#pre-commit-quality-check-tool)
- [Releasing](#releasing)

## Project Setup

If you need to build the action locally, follow these steps for project setup:

### Prerequisites
- Python 3.14 (current required runtime)

### Set Up Python Environment

```shell
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---
## Run Project Scripts Locally

If you need to run the scripts locally, follow these steps:

### Create the Shell Script

Create the shell file in the root directory. We use `run_script.sh` for demonstration.
```shell
touch run_script.sh
```
Add the shebang line at the top of the sh script file.
```shell
#!/bin/sh
```

### Set the Environment Variables

Set the configuration environment variables in the shell script following the structure below.

```shell
# Environment variables for GitHub Action full functionality
export INPUT_AQUA_KEY="your-aquasec-api-key"
export INPUT_AQUA_SECRET="your-aquasec-api-secret"
export INPUT_REPOSITORY_ID="your-aquasec-repository-id-uuid-format"
export INPUT_GROUP_ID="1234"
export INPUT_VERBOSE_LOGGING="true"  # Optional
```

### Running the script locally

For running the GitHub action locally, incorporate these commands into the shell script and save it.
```shell
python3 main.py
```
The whole script should look like this example:
```shell
#!/bin/sh

# Environment variables for GitHub Action full functionality
export INPUT_AQUA_KEY="your-aquasec-api-key"
export INPUT_AQUA_SECRET="your-aquasec-api-secret"
export INPUT_REPOSITORY_ID="your-aquasec-repository-id-uuid-format"
export INPUT_GROUP_ID="1234"
export INPUT_VERBOSE_LOGGING="true"  # Optional

python3 main.py
```

### Make the Script Executable

From the terminal, at the root of this project, make the script executable:
```shell
chmod +x run_script.sh
```

### Run the Script

```shell
./run_script.sh
```

### Night scan workflow (CI)

The nightly scan execution in CI is orchestrated via a shared reusable workflow.

- This repository contains the delegating workflow: `.github/workflows/aquasec-night-scan.yml`
- The detailed implementation lives in: `AbsaOSS/organizational-workflows/.github/workflows/aquasec-night-scan.yml`

If you need to align local runs with the CI behaviour (permissions, secrets, notifications, step ordering), use the workflow file as the source of truth.

---
## Run Pylint Check Locally

This project uses the [Pylint](https://pypi.org/project/pylint/) tool for static code analysis.
Pylint analyses your code without actually running it.
It checks for errors, enforces coding standards, looks for code smells, etc.
We do exclude the `tests/` file from the Pylint check.

Pylint displays a global evaluation score for the code, rated out of a maximum score of 10.0.
We are aiming to keep our code quality high above the score 9.5.

Follow these steps to run Pylint check locally:

- Perform the [setup of python venv](#set-up-python-environment).

### Run Pylint

Run Pylint on all files that are currently tracked by Git in the project.
```shell
pylint $(git ls-files '*.py')
```

To run Pylint on a specific file, follow the pattern `pylint <path_to_file>/<name_of_file>.py`.

Example:
```shell
pylint src/model/authenticator.py
```

### Expected Output

This is an example of the expected console output after running the tool:
```text
************* Module main
main.py:30:0: C0116: Missing function or method docstring (missing-function-docstring)

------------------------------------------------------------------
Your code has been rated at 9.41/10 (previous run: 8.82/10, +0.59)
```

---
## Run Black Tool Locally

This project uses the [Black](https://github.com/psf/black) tool for code formatting.
Black aims for consistency, generality, readability and reducing git diffs.
The coding style used can be viewed as a strict subset of PEP 8.

The root project file `pyproject.toml` defines the Black tool configuration.
In this project we accept a line length of 120 characters.
We also exclude the `tests/` files from black formatting.

Follow these steps to format your code with Black locally:

- Perform the [setup of python venv](#set-up-python-environment).

### Run Black

Run Black on all files that are currently tracked by Git in the project.
```shell
black $(git ls-files '*.py')
```

To run Black on a specific file, follow the pattern `black <path_to_file>/<name_of_file>.py`.

Example:
```shell
black src/model/sarif_convertor.py
```

### Expected Output

This is an example of the expected console output after running the tool:
```text
All done! ✨ 🍰 ✨
1 file reformatted.
```

---

## Run my[py] Tool Locally

This project uses the [my[py]](https://mypy.readthedocs.io/en/stable/)
tool which is a static type checker for Python.

> Type checkers help ensure that you're using variables and functions in your code correctly.
> With mypy, add type hints (PEP 484) to your Python programs,
> and mypy will warn you when you use those types incorrectly.

my[py] configuration is in `pyproject.toml` file.

Follow these steps to format your code with my[py] locally:

### Run my[py]

Run my[py] on all files in the project.
```shell
  mypy .
```

To run my[py] check on a specific file, follow the pattern `mypy <path_to_file>/<name_of_file>.py --check-untyped-defs`.

Example:
```shell
   mypy src/action_inputs.py
```

### Expected Output

This is an example of the expected console output after running the tool:
```text
Success: no issues found in 1 source file
```

---
## Run Unit Tests Locally

Unit tests are written using the Pytest framework.

Execute all tests located in the tests directory:
```shell
pytest tests/
```

Run a single test file:
```shell
pytest tests/test_main.py -q
```

Run a single test function (node id):
```shell
pytest tests/test_main.py::test_run_successful -q
```

---
## Code Coverage

This project uses the [pytest-cov](https://pypi.org/project/pytest-cov/) plugin to generate test coverage reports.
The objective of the project is to achieve a minimum score of 80 %. We do exclude the `tests/` file from the coverage report.

To generate the coverage report, run the following command:
```shell
pytest tests/ --cov=. tests/ --cov-fail-under=80 --cov-report=html
```

See the coverage report on the path:

```shell
open htmlcov/index.html
```

---
## Pre-Commit Quality Check Tool

This project uses [pre-commit](https://pre-commit.com/) to automatically run code quality checks before each commit.
Pre-commit hooks ensure that all code meets quality standards before it enters the repository.

### Configured Hooks

The following hooks run automatically on every commit:
- **Black** - Code formatting (formats the code if the hook fails)
- **my[py]** - Static type checking
- **Pylint** - Static code analysis (minimum score 9.5)
- **Pytest** - Unit tests with coverage (minimum 80%)
- **check-yaml** - Validates YAML file syntax
- **name-tests-test** - Enforces test file naming convention (must start with `test_`)
- **end-of-file-fixer** - Ensures files end with a single newline (fix if the hook fails)

### Install Pre-Commit Hooks

After setting up your Python environment, install the pre-commit hooks:

```shell
pre-commit install
```

### Run Pre-Commit Manually

To run all hooks on all files without committing:

```shell
pre-commit run --all-files
```

To run pre-commit on specific files:

```shell
pre-commit run --files src/model/authenticator.py
```

### Skip Pre-Commit Hooks

If you need to commit without running hooks:

```shell
git commit --no-verify -m "your commit message"
```

### Update Pre-Commit Hooks

To update hooks to their latest versions:

```shell
pre-commit autoupdate
```

---
## Releasing

This project uses GitHub Actions for deployment draft creation. The deployment process is semi-automated by a workflow defined in `.github/workflows/release_draft.yml`.

- **Trigger the workflow**: The `release_draft.yml` workflow is triggered on workflow_dispatch.
- **Create a new draft release**: The workflow creates a new draft release in the repository.
- **Finalize the release draft**: Edit the draft release to add a title, description, and any other necessary details related to the GitHub Action.
- **Publish the release**: Once the draft is ready, publish the release to make it publicly available.
