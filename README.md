# Local Secret Leak Preflight

A tiny pre-commit and CLI tool that scans staged Git changes for common secret leaks before they reach GitHub.

It is intentionally small and dependency-light: install it, stage your changes, and run `secret-preflight`.

## What It Catches

- API key, token, password, and secret assignments with high-entropy values
- Common provider tokens, including GitHub, AWS, Stripe, Slack, and Google API keys
- JWT-like tokens
- Private key headers and staged key material files such as `.pem`, `.key`, `.p12`, and `.pfx`
- Real `.env` files while allowing `.env.example`, `.env.sample`, and `.env.template`
- Screenshot-like image files, for example `Screen Shot 2026-06-01.png`

## Install

```bash
python -m pip install local-secret-leak-preflight
```

For local development:

```bash
python -m pip install -e .
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

## Pre-commit Hook

```bash
secret-preflight install-hook
```

This writes `.git/hooks/pre-commit` for the current repository.

If you use the `pre-commit` framework, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Singularity777x/local-secret-leak-preflight
    rev: v0.1.0
    hooks:
      - id: secret-preflight
```

## Design

The scanner reads staged Git data, not your working tree. It checks staged paths for dangerous files and parses added lines from `git diff --cached --unified=0` for secret-like content. Existing secrets outside the staged diff are not reported unless the dangerous file path itself is staged.

This keeps the tool fast and focused on the exact commit being prepared.

## License

MIT
