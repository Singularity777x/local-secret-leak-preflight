from __future__ import annotations

import math
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCREENSHOT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".tiff", ".bmp"}
SCREENSHOT_NAME = re.compile(
    r"(screen[\s_-]?shot|screen[\s_-]?capture|screencap|clean[\s_-]?shot|capture)",
    re.IGNORECASE,
)
ENV_EXAMPLE_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.defaults",
    ".env.dist",
}
KEY_MATERIAL_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".asc", ".gpg"}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int | None
    rule: str
    message: str
    severity: str = "high"

    def location(self) -> str:
        if self.line is None:
            return self.path
        return f"{self.path}:{self.line}"


@dataclass(frozen=True)
class AddedLine:
    path: str
    line_number: int
    text: str


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    message: str
    severity: str = "high"
    validator: object | None = None


def _is_plausible_jwt(secret: str) -> bool:
    parts = secret.split(".")
    return len(parts) == 3 and all(len(part) >= 8 for part in parts[:2])


def _has_high_entropy(secret: str) -> bool:
    if len(secret) < 20:
        return False
    counts = {char: secret.count(char) for char in set(secret)}
    entropy = -sum((count / len(secret)) * math.log2(count / len(secret)) for count in counts.values())
    return entropy >= 3.4


def _is_placeholder(secret: str) -> bool:
    lowered = secret.lower().strip("\"'")
    placeholders = (
        "example",
        "sample",
        "placeholder",
        "changeme",
        "change_me",
        "your_",
        "xxx",
        "todo",
        "test",
        "dummy",
        "fake",
        "redacted",
        "replace",
    )
    if lowered.startswith(("$", "${", "%")):
        return True
    return any(token in lowered for token in placeholders)


SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(api[_-]?key|secret|token|password|passwd|client[_-]?secret|private[_-]?key)\b
    \s*[:=]\s*
    ["']?
    (?P<secret>[A-Za-z0-9_./+=:@!$%^-]{12,})
    """,
)

RULES = [
    Rule(
        "private-key",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        "Private key material is staged.",
    ),
    Rule(
        "jwt",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
        "JWT-like token is staged.",
        validator=_is_plausible_jwt,
    ),
    Rule(
        "aws-access-key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "AWS access key id is staged.",
    ),
    Rule(
        "github-token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
        "GitHub token is staged.",
    ),
    Rule(
        "stripe-secret-key",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "Stripe secret key is staged.",
    ),
    Rule(
        "slack-token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        "Slack token is staged.",
    ),
    Rule(
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Google API key is staged.",
    ),
]


def run_git(args: list[str], cwd: Path, *, text: bool = True) -> str | bytes:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=text,
            errors="replace" if text else None,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode(errors="replace")
        raise RuntimeError(stderr.strip() or "git command failed") from exc
    return completed.stdout


def git_root(cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return Path(str(run_git(["rev-parse", "--show-toplevel"], base)).strip())


def staged_paths(root: Path) -> list[str]:
    output = str(
        run_git(
            ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
            root,
        )
    )
    return [path for path in output.split("\0") if path]


def staged_added_lines(root: Path, paths: Iterable[str]) -> list[AddedLine]:
    lines: list[AddedLine] = []
    for path in paths:
        diff = str(
            run_git(
                ["diff", "--cached", "--unified=0", "--no-ext-diff", "--", path],
                root,
            )
        )
        current_line: int | None = None
        for raw in diff.splitlines():
            if raw.startswith("@@"):
                match = re.search(r"\+(\d+)(?:,(\d+))?", raw)
                current_line = int(match.group(1)) if match else None
                continue
            if current_line is None:
                continue
            if raw.startswith("+") and not raw.startswith("+++"):
                lines.append(AddedLine(path=path, line_number=current_line, text=raw[1:]))
                current_line += 1
            elif not raw.startswith("-"):
                current_line += 1
    return lines


def _is_env_mistake(path: str) -> bool:
    name = os.path.basename(path)
    if name in ENV_EXAMPLE_NAMES:
        return False
    return name == ".env" or name.startswith(".env.")


def _is_screenshot(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in SCREENSHOT_EXTENSIONS and bool(SCREENSHOT_NAME.search(path))


def scan_paths(paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        suffix = Path(path).suffix.lower()
        if _is_env_mistake(path):
            findings.append(
                Finding(
                    path=path,
                    line=None,
                    rule="env-file",
                    message="A real .env file is staged. Commit an example file instead.",
                )
            )
        if suffix in KEY_MATERIAL_EXTENSIONS:
            findings.append(
                Finding(
                    path=path,
                    line=None,
                    rule="key-material-file",
                    message="Key material file is staged.",
                )
            )
        if _is_screenshot(path):
            findings.append(
                Finding(
                    path=path,
                    line=None,
                    rule="screenshot",
                    message="Screenshot-like image file is staged.",
                    severity="medium",
                )
            )
    return findings


def scan_added_lines(lines: Iterable[AddedLine]) -> list[Finding]:
    findings: list[Finding] = []
    for added in lines:
        if not added.text.strip():
            continue
        for rule in RULES:
            for match in rule.pattern.finditer(added.text):
                secret = match.group(1) if match.groups() else match.group(0)
                validator = rule.validator
                if validator is not None and not validator(secret):
                    continue
                findings.append(
                    Finding(
                        path=added.path,
                        line=added.line_number,
                        rule=rule.name,
                        message=rule.message,
                        severity=rule.severity,
                    )
                )
        assignment = SECRET_ASSIGNMENT.search(added.text)
        if assignment:
            secret = assignment.group("secret")
            if not _is_placeholder(secret) and _has_high_entropy(secret):
                findings.append(
                    Finding(
                        path=added.path,
                        line=added.line_number,
                        rule="secret-assignment",
                        message="High-entropy secret-like assignment is staged.",
                    )
                )
    return findings


def scan_staged(root: Path | None = None) -> list[Finding]:
    repo_root = root or git_root()
    paths = staged_paths(repo_root)
    return scan_paths(paths) + scan_added_lines(staged_added_lines(repo_root, paths))
