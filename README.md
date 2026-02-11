# AquaSec Scan Results

<!--- toc -->
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Adding the Action to Your Workflow](#adding-the-action-to-your-workflow)
- [Action Configuration](#action-configuration)
- [Action Outputs](#action-outputs)
- [Developer & Contribution Guide](#developer--contribution-guide)
- [License & Support](#license--support)
- [Acknowledgements](#acknowledgements)
<!--- end of toc -->


## Overview
This GitHub Action automates the integration of AquaSec security scan results into your repository's Security tab. 
It retrieves scan findings via the AquaSec API, converts them to SARIF format, and makes them available for upload 
to GitHub's Code Scanning feature. This provides developers with immediate visibility into security vulnerabilities 
within their familiar GitHub workflow, eliminating the need to log in into AquaSec platform.

---
## Prerequisites

To run this action successfully, make sure your environment meets the following requirements:
- Python 3.14
- AquaSec API credentials (Key and Secret)
- AquaSec Group ID for authentication
- AquaSec Repository ID (UUID format) for the target scan results

---
## Adding the Action to Your Workflow

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
        uses: actions/checkout@v8e8c483db84b4bee98b60c0593521ed34d9990e8
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548
        with:
          python-version: '3.14'

      - name: Fetch AquaSec Scan Results
        id: aquasec
        uses: AbsaOSS/aquasec-scan-results@v0.1.0
        with:
          aqua-key: ${{ secrets.AQUA_KEY }}
          aqua-secret: ${{ secrets.AQUA_SECRET }}
          group-id: ${{ secrets.AQUA_GROUP_ID }}
          repository-id: ${{ secrets.AQUA_REPOSITORY_ID }}
          verbose-logging: 'false'

      - name: Upload Scan Results to GitHub Security
        uses: github/codeql-action/upload-sarif@v4e94bd11f71e507f7f87df81788dff88d1dacbfb
        with:
          sarif_file: ${{ steps.aquasec.outputs.aquasec-sarif-file }}
          category: aquasec
```

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

| Name              | Description                         | Required | Default |
|-------------------|-------------------------------------|----------|---------|
| `aqua-key`        | AquaSec API Key credential          | Yes      | -       |
| `aqua-secret`     | AquaSec API Secret credential       | Yes      | -       |
| `group-id`        | AquaSec Group ID for authentication | Yes      | -       |
| `repository-id`   | AquaSec Repository ID (UUID format) | Yes      | -       |
| `verbose-logging` | Enable detailed logging             | No       | false   |

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

The action provides the following output for use in subsequent workflow steps:

| Output Name          | Description                                                | Example Value                                                |
|----------------------|------------------------------------------------------------|--------------------------------------------------------------|
| `aquasec-sarif-file` | Full unique path to the generated SARIF file with findings | `/home/runner/work/repo/aquasec_scan_2026-02-05_09-38.sarif` |

**Usage Example:**
```yaml
- name: Fetch AquaSec Scan Results
  id: aquasec
  uses: AbsaOSS/aquasec-scan-results@v0.1.0
  with:
    aqua-key: ${{ secrets.AQUA_KEY }}
    aqua-secret: ${{ secrets.AQUA_SECRET }}
    group-id: ${{ secrets.AQUA_GROUP_ID }}
    repository-id: ${{ secrets.AQUA_REPOSITORY_ID }}

- name: Use SARIF output
  run: |
    echo "SARIF file generated: ${{ steps.aquasec.outputs.aquasec-sarif-file }}"
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
