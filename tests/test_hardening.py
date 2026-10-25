"""Regression tests for the v1.0.8 hardening changes."""

import json
import subprocess
import sys

import pytest

from dockerdna.ai.remediation import _read_redacted
from dockerdna.scanner import scan
from dockerdna.scanners.compose import ComposeScanner

GH_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_missing_dockerfile_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan(dockerfile=str(tmp_path / "nope"), output_dir=str(tmp_path / "o"))


def test_missing_compose_raises(tmp_path):
    df = _write(tmp_path, "Dockerfile", "FROM alpine:3.20\n")
    with pytest.raises(FileNotFoundError):
        scan(dockerfile=df, compose_file=str(tmp_path / "x.yml"), output_dir=str(tmp_path / "o"))


def test_invalid_compose_yaml_recorded_and_strict_exits_2(tmp_path):
    df = _write(tmp_path, "Dockerfile", "FROM alpine:3.20\nUSER app\n")
    bad = _write(tmp_path, "compose.yml", "services: [unclosed\n  - : :\n")
    out = str(tmp_path / "o")
    report = scan(dockerfile=df, compose_file=bad, output_dir=out, formats=["json"])
    assert report["scan_errors"]
    with pytest.raises(SystemExit) as exc:
        scan(dockerfile=df, compose_file=bad, output_dir=out, formats=["json"], strict=True)
    assert exc.value.code == 2


def test_threshold_with_scan_error_exits_2_not_0(tmp_path):
    df = _write(tmp_path, "Dockerfile", "FROM alpine:3.20\nUSER app\n")
    bad = _write(tmp_path, "compose.yml", "- just\n- a list\n")
    with pytest.raises(SystemExit) as exc:
        scan(dockerfile=df, compose_file=bad, output_dir=str(tmp_path / "o"), threshold="HIGH")
    assert exc.value.code == 2


def test_cli_missing_file_exit_code(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "dockerdna.cli", str(tmp_path / "nope")],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2


def test_privileged_string_true_detected(tmp_path):
    p = _write(tmp_path, "c.yml", 'services:\n  a:\n    image: x:1\n    privileged: "true"\n')
    assert "privileged" in {f.check_key for f in ComposeScanner().scan(p)}


def test_privileged_false_string_not_flagged(tmp_path):
    p = _write(tmp_path, "c.yml", 'services:\n  a:\n    image: x:1\n    privileged: "false"\n')
    assert "privileged" not in {f.check_key for f in ComposeScanner().scan(p)}


@pytest.mark.parametrize("user", ["root", "0", "0:0", "root:root"])
def test_compose_user_root_detected(tmp_path, user):
    p = _write(tmp_path, "c.yml", f'services:\n  a:\n    image: x:1\n    user: "{user}"\n')
    assert "no_user" in {f.check_key for f in ComposeScanner().scan(p)}


def test_compose_nonroot_user_ok(tmp_path):
    p = _write(tmp_path, "c.yml", 'services:\n  a:\n    image: x:1\n    user: "1000:1000"\n')
    assert "no_user" not in {f.check_key for f in ComposeScanner().scan(p)}


def test_ai_context_never_contains_raw_secrets(tmp_path):
    df = _write(
        tmp_path,
        "Dockerfile",
        f"FROM alpine:3.20\nARG TOKEN={GH_TOKEN}\nENV DB_PASSWORD=hunter2\n",
    )
    text = _read_redacted(df)
    assert GH_TOKEN not in text
    assert "hunter2" not in text


def test_report_json_has_scan_errors_key(tmp_path):
    df = _write(tmp_path, "Dockerfile", "FROM alpine:3.20\nUSER app\n")
    out = tmp_path / "o"
    scan(dockerfile=df, output_dir=str(out), formats=["json"])
    assert json.loads((out / "report.json").read_text(encoding="utf-8"))["scan_errors"] == []
