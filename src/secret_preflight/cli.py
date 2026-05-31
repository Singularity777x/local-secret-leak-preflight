from __future__ import annotations

import argparse
import stat
import sys
from pathlib import Path

from secret_preflight.scanner import Finding, git_root, scan_staged


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-preflight",
        description="Scan staged Git changes for likely secret leaks.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["scan", "install-hook"],
        default="scan",
        help="Command to run. Defaults to scan.",
    )
    return parser


def format_findings(findings: list[Finding]) -> str:
    lines = ["Secret preflight blocked this commit:"]
    for finding in findings:
        lines.append(f"- [{finding.severity}] {finding.location()} {finding.rule}: {finding.message}")
    lines.append("")
    lines.append("Remove the secret, unstage the file, or commit a safe example instead.")
    return "\n".join(lines)


def install_hook(root: Path) -> None:
    hooks_dir = root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text(
        "#!/bin/sh\n"
        "secret-preflight\n",
        encoding="utf-8",
    )
    mode = hook_path.stat().st_mode
    hook_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root = git_root(Path.cwd())
        if args.command == "install-hook":
            install_hook(root)
            print(f"Installed pre-commit hook at {root / '.git' / 'hooks' / 'pre-commit'}")
            return 0

        findings = scan_staged(root)
    except RuntimeError as exc:
        print(f"secret-preflight: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"secret-preflight: {exc}", file=sys.stderr)
        return 2

    if findings:
        print(format_findings(findings), file=sys.stderr)
        return 1

    print("Secret preflight passed: no staged leaks found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
