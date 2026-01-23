# aquasec-scan-results
GitHub Action to fetch AquaSec security scan results. Modular design supports JSON to SARIF 2.1.0 conversion, GitHub Security tab integration, and extensible notifications.

## Usage

This action authenticates with the AquaSec API and generates a Bearer token for use in downstream steps.

```yaml
- name: Authenticate with AquaSec
  id: aquasec-auth
  uses: AbsaOSS/aquasec-scan-results@v1
  with:
    aqua-key: ${{ secrets.AQUA_KEY }}
    aqua-secret: ${{ secrets.AQUA_SECRET }}

- name: Use Bearer Token
  run: |
    echo "Token received (masked): ***"
    # Use the token in subsequent steps
    # curl -H "Authorization: Bearer ${{ steps.aquasec-auth.outputs.bearer-token }}" ...
```

## Inputs

| Input | Description | Required |
|-------|-------------|----------|
| `aqua-key` | AquaSec API Key | Yes |
| `aqua-secret` | AquaSec API Secret | Yes |

## Outputs

| Output | Description |
|--------|-------------|
| `bearer-token` | AquaSec Bearer Token for authentication |

## Security

- All secrets are automatically masked in GitHub Actions logs
- The Bearer token is masked to prevent accidental exposure
- HMAC-SHA256 signature ensures request integrity

## Development

See [DEVELOPER.md](DEVELOPER.md) for development setup and local testing instructions.
