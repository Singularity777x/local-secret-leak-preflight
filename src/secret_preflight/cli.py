from __future__ import annotations

import argparse


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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    print("secret-preflight scanner is not implemented yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
