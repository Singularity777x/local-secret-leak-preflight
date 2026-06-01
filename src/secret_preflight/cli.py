from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path

from secret_preflight import __version__
from secret_preflight.scanner import DEFAULT_MAX_FILE_BYTES, Finding, git_root, scan_all, scan_staged


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
    parser.add_argument(
        "--ignore-file",
        default=".secret-preflight-ignore",
        help="Repository-relative ignore file. Use an empty value to disable ignores.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--staged",
        action="store_true",
        help="Scan staged changes only. This is the default.",
    )
    mode.add_argument(
        "--all",
        action="store_true",
        help="Scan all tracked files in the repository.",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="Maximum tracked file size to read in --all mode. Use -1 for no limit.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format. Defaults to text.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress scan output and only return an exit code.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def format_findings(findings: list[Finding]) -> str:
    lines = ["Secret preflight blocked this commit:"]
    for finding in findings:
        lines.append(f"- [{finding.severity}] {finding.location()} {finding.rule}: {finding.message}")
    lines.append("")
    lines.append("Remove the secret, unstage the file, or commit a safe example instead.")
    return "\n".join(lines)


def findings_payload(findings: list[Finding]) -> dict[str, object]:
    return {
        "ok": not findings,
        "finding_count": len(findings),
        "findings": [
            {
                "path": finding.path,
                "line": finding.line,
                "rule": finding.rule,
                "severity": finding.severity,
                "message": finding.message,
            }
            for finding in findings
        ],
    }


def print_json(findings: list[Finding]) -> None:
    print(json.dumps(findings_payload(findings), indent=2, sort_keys=True))


def sarif_level(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def sarif_payload(findings: list[Finding]) -> dict[str, object]:
    rules = {
        finding.rule: {
            "id": finding.rule,
            "name": finding.rule,
            "shortDescription": {"text": finding.message},
            "defaultConfiguration": {"level": sarif_level(finding.severity)},
        }
        for finding in findings
    }
    results = []
    for finding in findings:
        physical_location: dict[str, object] = {
            "artifactLocation": {"uri": finding.path},
        }
        if finding.line is not None:
            physical_location["region"] = {"startLine": finding.line}
        results.append(
            {
                "ruleId": finding.rule,
                "level": sarif_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [{"physicalLocation": physical_location}],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Local Secret Leak Preflight",
                        "informationUri": "https://github.com/Singularity777x/local-secret-leak-preflight",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def print_sarif(findings: list[Finding]) -> None:
    print(json.dumps(sarif_payload(findings), indent=2, sort_keys=True))


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

        if args.all:
            findings = scan_all(root, ignore_file=args.ignore_file or None, max_file_bytes=args.max_file_bytes)
        else:
            findings = scan_staged(root, ignore_file=args.ignore_file or None)
    except RuntimeError as exc:
        print(f"secret-preflight: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"secret-preflight: {exc}", file=sys.stderr)
        return 2

    if args.quiet:
        pass
    elif args.format == "json":
        print_json(findings)
    elif args.format == "sarif":
        print_sarif(findings)
    elif findings:
        print(format_findings(findings), file=sys.stderr)
    else:
        print("Secret preflight passed: no staged leaks found.")

    if findings:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
