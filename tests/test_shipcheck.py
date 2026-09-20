"""Tests for shipcheck: checks engine, report renderers, CLI exit codes."""

from __future__ import annotations

import json
import os
import textwrap

import pytest

from shipcheck.checks import run_all_checks, check_secrets
from shipcheck.report import render_json, render_markdown
from shipcheck.cli import main


def make_repo(tmp_path, files: dict):
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))
    return str(tmp_path)


def test_clean_repo_passes(tmp_path):
    root = make_repo(tmp_path, {
        "README.md": "# demo\n",
        ".gitignore": ".env\n",
        "app.py": "def main():\n    return 0\n",
    })
    findings = run_all_checks(root)
    assert findings == []


def test_aws_key_detected(tmp_path):
    root = make_repo(tmp_path, {
        "config.py": 'KEY = "AKIAABCDEFGHIJKLMNOP"\n',
    })
    findings = check_secrets(root)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_env_file_flagged(tmp_path):
    root = make_repo(tmp_path, {".env": "API_KEY=abcdef123456\n"})
    findings = run_all_checks(root)
    # .env both triggers hygiene finding AND generic secret pattern
    categories = {f.category for f in findings}
    assert "hygiene" in categories


def test_bare_except_flagged(tmp_path):
    root = make_repo(tmp_path, {"app.py": "try:\n    pass\nexcept:\n    pass\n"})
    findings = run_all_checks(root)
    assert any("Bare" in f.problem for f in findings)


def test_markdown_report_verdict_fail(tmp_path):
    root = make_repo(tmp_path, {"config.py": 'TOKEN = "ghp_' + "a" * 30 + '"\n'})
    findings = run_all_checks(root)
    report = render_markdown(findings, root)
    assert "**Verdict: FAIL**" in report


def test_json_report_shape(tmp_path):
    findings = run_all_checks(str(tmp_path))
    data = json.loads(render_json(findings, str(tmp_path)))
    assert data["finding_count"] == len(findings)
    assert isinstance(data["findings"], list)


def test_cli_exit_code_zero_on_clean(tmp_path):
    root = make_repo(tmp_path, {"README.md": "# ok\n", ".gitignore": ".env\n"})
    assert main([root]) == 0


def test_cli_exit_code_one_on_secret(tmp_path):
    root = make_repo(tmp_path, {"config.py": 'KEY = "AKIAABCDEFGHIJKLMNOP"\n'})
    assert main([root, "--fail-on", "CRITICAL"]) == 1


def test_cli_rejects_bad_path():
    assert main(["/definitely/not/a/real/path/xyz"]) == 2
