# AquaSec Scan Results

<!--- toc -->
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Adding the Action to Your Workflow](#adding-the-action-to-your-workflow)
  - [Night Scan Mode](#night-scan-mode)
  - [Branch Comparison Mode](#branch-comparison-mode)
- [Action Configuration](#action-configuration)
- [Action Outputs](#action-outputs)
- [Developer & Contribution Guide](#developer--contribution-guide)
- [License & Support](#license--support)
- [Acknowledgements](#acknowledgements)
<!--- end of toc -->


## Overview
This GitHub Action automates the integration of AquaSec security scan results into your GitHub workflow.
It supports two operational modes:

- **Night Scan** (default) — retrieves scan findings via the AquaSec API, converts them to SARIF format,
  and makes them available for upload to GitHub's Code Scanning feature (Security tab).
- **Branch Comparison** — triggers a scan on the developer branch, compares findings against master,
  posts a severity breakdown as a PR comment, and **fails the workflow when new findings are detected**.

This provides developers with immediate visibility into security vulnerabilities within their familiar
GitHub workflow, eliminating the need to log in to the AquaSec platform.

> For a detail look at both modes see [Night Scan Mode](docs/night-scan-mode.md) and [Branch Comparison Mode](docs/branch-comparison-mode.md).

---
## Prerequisites

To run this action successfully, make sure your environment meets the following requirements:
- Python 3.14
- AquaSec API credentials (Key and Secret)
- AquaSec Group ID for authentication
- AquaSec Repository ID (UUID format) for the target scan results

---
## Adding the Action to Your Workflow

### Night Scan Mode

Create a workflow file (e.g., `.github/workflows/aquasec-night-scan.yml`) to run daily:

```yaml
name: AquaSec Night Scan

on:
  schedule:
    - cron: '23 2 * * *'  # Runs at 02:23 UTC daily (modify as needed)
  workflow_dispatch:
    
concurrency:
  group: aquasec-security-night-scan-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  security-events: write

jobs:
  aquasec-night-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v6
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: '3.14'

      - name: Fetch AquaSec Scan Results
        id: aquasec
        uses: AbsaOSS/aquasec-scan-results@v0.2.0
        with:
          aqua-key: ${{ secrets.AQUA_KEY }}
          aqua-secret: ${{ secrets.AQUA_SECRET }}
          group-id: ${{ secrets.AQUA_GROUP_ID }}
          repository-id: ${{ secrets.AQUA_REPOSITORY_ID }}
          verbose-logging: 'false'

      - name: Upload Scan Results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.aquasec.outputs.nightscan-sarif-file }}
          category: aquasec
```

### Branch Comparison Mode

Create a workflow file (e.g., `.github/workflows/aquasec-branch-comparison.yml`) to run on pull requests:

```yaml
name: AquaSec Branch Comparison

on:
  pull_request:
    types: [ opened, synchronize, reopened ]

concurrency:
  group: aquasec-branch-comparison-${{ github.event.pull_request.number }}
  cancel-in-progress: true

permissions:
  contents: read
  pull-requests: write

jobs:
  branch-comparison:
    name: AquaSec Branch Comparison
    if: ${{ !github.event.pull_request.head.repo.fork }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Compare branches
        id: aquasec
        uses: AbsaOSS/aquasec-scan-results@v0.2.0
        with:
          aqua-key: ${{ secrets.AQUA_KEY }}
          aqua-secret: ${{ secrets.AQUA_SECRET }}
          group-id: ${{ secrets.AQUA_GROUP_ID }}
          repository-id: ${{ secrets.AQUA_REPOSITORY_ID }}
          dev-branch-comparison: 'true'
          # branch-comparison-poll-interval: '60'   # optional, default 30s
          # branch-comparison-poll-timeout: '5400'   # optional, default 600s

      - name: Find existing PR comment
        if: always() && steps.aquasec.outputs.comparison-summary-file != ''
        uses: peter-evans/find-comment@v4
        id: find-comment
        with:
          issue-number: ${{ github.event.pull_request.number }}
          comment-author: 'github-actions[bot]'
          body-includes: '<!-- aquasec-branch-comparison -->'

      - name: Post or update PR comment
        if: always() && steps.aquasec.outputs.comparison-summary-file != ''
        uses: peter-evans/create-or-update-comment@v5
        with:
          issue-number: ${{ github.event.pull_request.number }}
          comment-id: ${{ steps.find-comment.outputs.comment-id }}
          edit-mode: replace
          body-path: ${{ steps.aquasec.outputs.comparison-summary-file }}

      - name: Upload comparison summary as artifact
        if: always() && steps.aquasec.outputs.comparison-summary-file != ''
        uses: actions/upload-artifact@v7
        with:
          name: aquasec-comparison-summary-pr-${{ github.event.pull_request.number }}
          path: ${{ steps.aquasec.outputs.comparison-summary-file }}
          retention-days: 7
```

> **Note:** The `Compare branches` step **fails the workflow** when new security findings are
> detected in the developer branch. The PR comment steps use `if: always()` so the summary is
> always posted, even when the comparison step fails.

### Credentials Configuration

**For AbsaOSS / absa-group Organization:**
- `AQUA_KEY` and `AQUA_SECRET` are stored as **organization secrets** and automatically available to all repositories.
- You only need to configure `AQUA_GROUP_ID` and `AQUA_REPOSITORY_ID` as **repository secrets**.

**For Other Organizations:**
- Store all four credentials (`AQUA_KEY`, `AQUA_SECRET`, `AQUA_GROUP_ID`, `AQUA_REPOSITORY_ID`) as [GitHub repository secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets).
- Contact your AquaSec administrator if you don't have API credentials (`AQUA_KEY`, `AQUA_SECRET`).

---
## Action Configuration

### Input Parameters

The action requires the following inputs:

| Name                                | Description                                              | Required | Default |
|-------------------------------------|----------------------------------------------------------|----------|---------|
| `aqua-key`                          | AquaSec API Key credential                               | Yes      | -       |
| `aqua-secret`                       | AquaSec API Secret credential                            | Yes      | -       |
| `group-id`                          | AquaSec Group ID for authentication                      | Yes      | -       |
| `repository-id`                     | AquaSec Repository ID (UUID format)                      | Yes      | -       |
| `verbose-logging`                   | Enable detailed logging                                  | No       | false   |
| `dev-branch-comparison`             | Enable developer branch comparison                       | No       | false   |
| `branch-comparison-poll-interval`   | Polling interval in seconds for branch scan completion   | No       | 30      |
| `branch-comparison-poll-timeout`    | Maximum wait time in seconds for branch scan completion  | No       | 600     |

### How to Obtain AquaSec Group ID

**Option 1: Via User Management (requires User Management access)**

1. Navigate to **User Management** → **Groups** in the AquaSec platform.
2. Search for and select your specific group.
3. Click on the group to view its details.
4. The **Group ID** is displayed at the end of the URL after `/groups/`.

**Option 2: Via JWT Token Inspection**

1. Open your browser's Developer Tools and navigate to the **Network** tab.
2. Reload the AquaSec platform and locate any API request in the **Request Headers** section.
3. Copy your **Authorization Bearer token** from the headers.
4. Decode the token using for example [jwt.io](https://jwt.io/).
5. In the decoded payload, look for the **user_groups_user** field containing your accessible Group IDs.

### How to Obtain AquaSec Repository ID

1. Navigate to **Code Repositories** in the AquaSec platform.
2. Use the search bar to filter and locate your repository.
3. Click on the repository name to open its overview page.
4. The **Repository ID** (UUID format) is displayed in the URL after `/repositories/`.

**Example:** `https://aquasec.com/repositories/9d93jajb-6c6e-438d-8bef-afb5a12396e5/overview`  
→ Repository ID: `9d93jajb-6c6e-438d-8bef-afb5a12396e5`

---
## Action Outputs

The action provides the following outputs depending on the mode:

| Output Name                | Mode              | Description                                      | Example Value                                                |
|----------------------------|-------------------|--------------------------------------------------|--------------------------------------------------------------|
| `nightscan-sarif-file`     | Night Scan        | Full path to the generated SARIF file             | `/home/runner/work/repo/aquasec_scan_2026-03-06_09-38.sarif` |
| `comparison-summary-file`  | Branch Comparison | Full path to the Markdown comparison summary file | `/home/runner/work/repo/comparison_summary.md`               |

> **Branch Comparison behavior:** When the comparison detects new findings in the developer branch,
> the action **fails with exit code 1** and emits a `::error::` annotation. The summary file is
> written _before_ the failure, so subsequent steps guarded with `if: always()` can still post it.

**Night Scan — usage example:**
```yaml
- name: Fetch AquaSec Scan Results
  id: aquasec
  uses: AbsaOSS/aquasec-scan-results@v0.2.0
  with:
    aqua-key: ${{ secrets.AQUA_KEY }}
    aqua-secret: ${{ secrets.AQUA_SECRET }}
    group-id: ${{ secrets.AQUA_GROUP_ID }}
    repository-id: ${{ secrets.AQUA_REPOSITORY_ID }}

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.aquasec.outputs.nightscan-sarif-file }}
    category: aquasec
```

**Branch Comparison — usage example:**
```yaml
- name: Compare branches
  id: aquasec
  uses: AbsaOSS/aquasec-scan-results@v0.2.0
  with:
    aqua-key: ${{ secrets.AQUA_KEY }}
    aqua-secret: ${{ secrets.AQUA_SECRET }}
    group-id: ${{ secrets.AQUA_GROUP_ID }}
    repository-id: ${{ secrets.AQUA_REPOSITORY_ID }}
    dev-branch-comparison: 'true'
    branch-comparison-poll-interval: '60'   # optional, default 30s
    branch-comparison-poll-timeout: '5400'   # optional, default 600s

- name: Post or update PR comment
  if: always() && steps.aquasec.outputs.comparison-summary-file != ''
  uses: peter-evans/create-or-update-comment@v5
  with:
    issue-number: ${{ github.event.pull_request.number }}
    body-path: ${{ steps.aquasec.outputs.comparison-summary-file }}
```

---
## Developer & Contribution Guide

We love community contributions!
- [Developer Guide](DEVELOPER.md)
- [Contributing Guide](CONTRIBUTING.md)

Typical contributions include:
- Fixing bugs or edge cases
- Improving documentation or examples
- Adding new configuration options

## License & Support

This project is licensed under the **Apache License 2.0**.
See the [LICENSE](/LICENSE) file for full terms.

### Support & Contact
- [Issues](https://github.com/AbsaOSS/aquasec-scan-results/issues)
- [Discussions](https://github.com/AbsaOSS/aquasec-scan-results/discussions)

## Acknowledgements

Thanks to all contributors and teams who helped evolve this Action.
Your feedback drives continuous improvement and automation quality.
