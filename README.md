# Local Secret Leak Preflight

[![CI](https://github.com/Singularity777x/local-secret-leak-preflight/actions/workflows/ci.yml/badge.svg)](https://github.com/Singularity777x/local-secret-leak-preflight/actions/workflows/ci.yml)

A tiny pre-commit and CLI tool that scans staged Git changes for common secret leaks before they reach GitHub.

It is intentionally small and dependency-light: install it, stage your changes, and run `secret-preflight`.

## What It Catches

- API key, token, password, and secret assignments with high-entropy values
- Common provider tokens, including OpenAI, Anthropic, GitHub, AWS, Stripe, Slack, and Google API keys
- JWT-like tokens
- Private key headers and staged key material files such as `.pem`, `.key`, `.p12`, and `.pfx`
- Real `.env` files while allowing `.env.example`, `.env.sample`, and `.env.template`
- Screenshot-like image files, for example `Screen Shot 2026-06-01.png`

## Install

```bash
python -m pip install git+https://github.com/Singularity777x/local-secret-leak-preflight.git
```

For local development:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Usage

```bash
secret-preflight
```

The command scans staged changes and exits non-zero when it finds likely leaks.

Example output:

```text
Secret preflight blocked this commit:
- [high] .env.local env-file: A real .env file is staged. Commit an example file instead.
- [high] app.py:12 secret-assignment: High-entropy secret-like assignment is staged.

Remove the secret, unstage the file, or commit a safe example instead.
```

For scripts that only need an exit code:

```bash
secret-preflight --quiet
```

Check the installed version:

```bash
secret-preflight --version
```

## Intentional Examples

Prefer placeholder values such as `your_api_key_here`, `redacted`, or `example`. For rare cases where you need to commit a synthetic token that intentionally matches a detector, add an inline allow marker:

```python
API_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"  # secret-preflight: allow
```

You can also commit a `.secret-preflight-ignore` file. Each non-empty, non-comment line is a glob pattern matched against:

```text
path
path:rule
path:line
path:line:rule
```

Examples:

```text
tests/fixtures/*
docs/*.png:screenshot
examples/app.py:12:secret-assignment
```

Disable ignore-file loading for a one-off scan:

```bash
secret-preflight --ignore-file ""
```

## JSON Output

Use JSON output for CI, editor integrations, or custom scripts:

```bash
secret-preflight --format json
```

Example blocked payload:

```json
{
  "finding_count": 1,
  "findings": [
    {
      "line": 12,
      "message": "High-entropy secret-like assignment is staged.",
      "path": "app.py",
      "rule": "secret-assignment",
      "severity": "high"
    }
  ],
  "ok": false
}
```

## SARIF Output

Use SARIF output when you want GitHub-compatible security annotations:

```bash
secret-preflight --format sarif > secret-preflight.sarif
```

The command still exits `1` when findings are present, so in GitHub Actions you can upload the SARIF file from an `if: always()` step after the scan.

## Pre-commit Hook

```bash
secret-preflight install-hook
```

This writes `.git/hooks/pre-commit` for the current repository.

If you use the `pre-commit` framework, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Singularity777x/local-secret-leak-preflight
    rev: v0.1.3
    hooks:
      - id: secret-preflight
```

## Design

The scanner reads staged Git data, not your working tree. It checks staged paths for dangerous files and parses added lines from `git diff --cached --unified=0` for secret-like content. Existing secrets outside the staged diff are not reported unless the dangerous file path itself is staged.

This keeps the tool fast and focused on the exact commit being prepared.

## License

MIT
