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

Create a workflow file (e.g., `.github/workflows/aquasec-security-scan.yml`) to run daily at the midnight UTC:

```yaml
name: AquaSec Night Scan

on:
  schedule:
    - cron: '0 0 * * *'
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
          repository-id: ${{ secrets.AQUA_REPOSITORY_ID }}
          group-id: '1234'
          verbose-logging: 'true'

      - name: Upload Scan Results to GitHub Security
        uses: github/codeql-action/upload-sarif@v4e94bd11f71e507f7f87df81788dff88d1dacbfb
        with:
          sarif_file: ${{ steps.aquasec.outputs.aquasec-sarif-file }}
          category: aquasec
```

**Note:** Store your AquaSec credentials as [GitHub repository secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets).

---
## Action Configuration

Only a few inputs are required to get started:

| Name              | Description                         | Required | Default |
|-------------------|-------------------------------------|----------|---------|
| `aqua-key`        | AquaSec API Key credential          | Yes      | -       |
| `aqua-secret`     | AquaSec API Secret credential       | Yes      | -       |
| `repository-id`   | AquaSec Repository ID (UUID format) | Yes      | -       |
| `group-id`        | AquaSec Group ID for authentication | Yes      | -       |
| `verbose-logging` | Enable detailed logging             | No       | false   |

---
## Action Outputs

The action provides the following output for use in subsequent workflow steps:

| Output Name          | Description                                           | Example Value                                                |
|----------------------|-------------------------------------------------------|--------------------------------------------------------------|
| `aquasec-sarif-file` | Full path to the generated SARIF file with findings   | `/home/runner/work/repo/aquasec_scan_2026-02-05_09-38.sarif` |

**Usage Example:**
```yaml
- name: Fetch AquaSec Scan Results
  id: aquasec
  uses: AbsaOSS/aquasec-scan-results@v0.1.0
  with:
    aqua-key: ${{ secrets.AQUA_KEY }}
    aqua-secret: ${{ secrets.AQUA_SECRET }}
    repository-id: ${{ secrets.AQUA_REPOSITORY_ID }}
    group-id: '1234'

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
