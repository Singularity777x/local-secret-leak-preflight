# Local Secret Leak Preflight

A tiny pre-commit and CLI tool that scans staged Git changes for common secret leaks before they reach GitHub.

It is intentionally small and dependency-light: install it, stage your changes, and run `secret-preflight`.

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

## Pre-commit Hook

```bash
secret-preflight install-hook
```

This writes `.git/hooks/pre-commit` for the current repository.

## License

MIT
