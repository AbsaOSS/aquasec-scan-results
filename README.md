# aquasec-scan-results

GitHub Action to fetch AquaSec security scan results. Modular design supports JSON to SARIF 2.1.0 conversion, GitHub Security tab integration, and extensible notifications.

See [DEVELOPER.md](DEVELOPER.md) for development-related information.
See [CONTRIBUTING.md](CONTRIBUTING.md) before contributing, to understand our contributing guidelines.

## Security Alerts to Issues

A reusable workflow [security_alerts_to_issues.yml](.github/workflows/security_alerts_to_issues.yml) is included that **orchestrates** the synchronisation of GitHub Security Alerts to GitHub Issues after SARIF is **imported into GitHub** (so alerts exist in GitHub Security / code scanning). The external automation creates/updates/reopens issues as needed.

The external logic models:

- One **Issue per alert** (unique tracking per finding)
- One **parent Epic Issue per ruleId** that links all related alert issues together

> **Important:** All mapping, grouping, and state-management logic is maintained externally in [absa-group/cps-qa](https://github.com/absa-group/cps-qa). This repository contains **only** the orchestration workflow — no business logic is duplicated here. The external scripts query the GitHub API to read alerts and manage issues in the repository.

### Usage

Call the reusable workflow from your pipeline after SARIF has been **imported into GitHub**:

```yaml
jobs:
  aquasec-scan:
    # ... your existing scan job that produces SARIF ...

  sync-alerts:
    needs: aquasec-scan
    uses: AbsaOSS/aquasec-scan-results/.github/workflows/security_alerts_to_issues.yml@master
```

The workflow can also be triggered manually via `workflow_dispatch`.
