from __future__ import annotations

import json
import subprocess
from pathlib import Path

from secret_preflight.cli import main
from secret_preflight.scanner import scan_staged


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def init_repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    return tmp_path


def stage_file(repo: Path, name: str, content: str | bytes) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    git(repo, "add", name)


def test_blocks_secret_assignment(tmp_path, monkeypatch):
    repo = init_repo(tmp_path)
    stage_file(repo, "app.py", 'API_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"\n')
    monkeypatch.chdir(repo)

    findings = scan_staged(repo)

    assert {finding.rule for finding in findings} == {"secret-assignment"}
    assert findings[0].location() == "app.py:1"


def test_blocks_ai_provider_keys(tmp_path):
    repo = init_repo(tmp_path)
    stage_file(
        repo,
        "config.txt",
        "\n".join(
            [
                "OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
                "ANTHROPIC_API_KEY=sk-ant-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
                "",
            ]
        ),
    )

    findings = scan_staged(repo)

    assert {finding.rule for finding in findings} >= {"openai-api-key", "anthropic-api-key"}


def test_blocks_env_file_and_jwt(tmp_path, monkeypatch, capsys):
    repo = init_repo(tmp_path)
    stage_file(
        repo,
        ".env.local",
        "TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signedpayload\n",
    )
    monkeypatch.chdir(repo)

    assert main([]) == 1
    err = capsys.readouterr().err
    assert ".env.local env-file" in err
    assert ".env.local:1 jwt" in err


def test_allows_env_example_and_placeholders(tmp_path):
    repo = init_repo(tmp_path)
    stage_file(repo, ".env.example", "API_KEY=your_api_key_here\n")
    stage_file(repo, "README.md", "Use TOKEN=placeholder in docs.\n")

    assert scan_staged(repo) == []


def test_flags_screenshot_like_image(tmp_path):
    repo = init_repo(tmp_path)
    stage_file(repo, "docs/Screen Shot 2026-06-01.png", b"\x89PNG\r\n\x1a\n")

    findings = scan_staged(repo)

    assert len(findings) == 1
    assert findings[0].rule == "screenshot"
    assert findings[0].severity == "medium"


def test_clean_staged_file_passes(tmp_path, monkeypatch, capsys):
    repo = init_repo(tmp_path)
    stage_file(repo, "notes.txt", "hello\n")
    monkeypatch.chdir(repo)

    assert main([]) == 0
    assert "passed" in capsys.readouterr().out


def test_inline_allow_marker_suppresses_line_finding(tmp_path):
    repo = init_repo(tmp_path)
    stage_file(
        repo,
        "tests/fixtures.py",
        'API_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"  # secret-preflight: allow\n',
    )

    assert scan_staged(repo) == []


def test_ignore_file_suppresses_matching_path_and_rule(tmp_path):
    repo = init_repo(tmp_path)
    stage_file(repo, ".secret-preflight-ignore", "docs/*.png:screenshot\n")
    stage_file(repo, "docs/Screen Shot 2026-06-01.png", b"\x89PNG\r\n\x1a\n")

    assert scan_staged(repo) == []


def test_cli_can_disable_ignore_file(tmp_path, monkeypatch, capsys):
    repo = init_repo(tmp_path)
    stage_file(repo, ".secret-preflight-ignore", "app.py:secret-assignment\n")
    stage_file(repo, "app.py", 'API_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"\n')
    monkeypatch.chdir(repo)

    assert main(["--ignore-file", ""]) == 1
    assert "secret-assignment" in capsys.readouterr().err


def test_cli_json_output_for_findings(tmp_path, monkeypatch, capsys):
    repo = init_repo(tmp_path)
    stage_file(repo, "app.py", 'API_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"\n')
    monkeypatch.chdir(repo)

    assert main(["--format", "json"]) == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""
    assert payload["ok"] is False
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["path"] == "app.py"
    assert payload["findings"][0]["line"] == 1
    assert payload["findings"][0]["rule"] == "secret-assignment"
    assert payload["findings"][0]["severity"] == "high"


def test_cli_json_output_for_clean_scan(tmp_path, monkeypatch, capsys):
    repo = init_repo(tmp_path)
    stage_file(repo, "notes.txt", "hello\n")
    monkeypatch.chdir(repo)

    assert main(["--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload == {"finding_count": 0, "findings": [], "ok": True}


def test_cli_sarif_output_for_findings(tmp_path, monkeypatch, capsys):
    repo = init_repo(tmp_path)
    stage_file(repo, "app.py", 'API_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"\n')
    monkeypatch.chdir(repo)

    assert main(["--format", "sarif"]) == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    result = payload["runs"][0]["results"][0]

    assert captured.err == ""
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "Local Secret Leak Preflight"
    assert result["ruleId"] == "secret-assignment"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_cli_sarif_output_for_clean_scan(tmp_path, monkeypatch, capsys):
    repo = init_repo(tmp_path)
    stage_file(repo, "notes.txt", "hello\n")
    monkeypatch.chdir(repo)

    assert main(["--format", "sarif"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []
