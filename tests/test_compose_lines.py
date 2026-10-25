"""Compose findings carry the real source line (1-based)."""

import json

from dockerdna.scanner import scan
from dockerdna.scanners.compose import ComposeScanner

COMPOSE = """\
services:
  web:
    image: nginx
    privileged: true
    ports:
      - "8080:8080"
      - "80:80"
    volumes:
      - ./data:/data
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      LOG_LEVEL: info
      DB_PASSWORD: hunter2
    network_mode: host
    user: root
  worker:
    image: app:1.2
"""


def _by_check(tmp_path):
    p = tmp_path / "compose.yml"
    p.write_text(COMPOSE, encoding="utf-8")
    out = {}
    for f in ComposeScanner().scan(p):
        out.setdefault((f.service, f.check_key), f)
    return out


def test_key_level_lines(tmp_path):
    f = _by_check(tmp_path)
    assert f[("web", "privileged")].line_hint == 4
    assert f[("web", "latest_tag")].line_hint == 3
    assert f[("web", "host_network")].line_hint == 14
    assert f[("web", "no_user")].line_hint == 15


def test_list_item_lines(tmp_path):
    f = _by_check(tmp_path)
    assert f[("web", "docker_socket")].line_hint == 10
    assert f[("web", "privileged_ports")].line_hint == 7


def test_env_secret_points_at_the_variable(tmp_path):
    assert _by_check(tmp_path)[("web", "env_secret")].line_hint == 13


def test_missing_setting_anchors_to_service_line(tmp_path):
    f = _by_check(tmp_path)
    assert f[("web", "no_healthcheck")].line_hint == 2
    assert f[("worker", "no_healthcheck")].line_hint == 16


def test_every_finding_has_a_line_and_file(tmp_path):
    p = tmp_path / "compose.yml"
    p.write_text(COMPOSE, encoding="utf-8")
    findings = ComposeScanner().scan(p)
    assert findings
    assert all(f.line_hint and f.file == str(p) for f in findings)


def test_sarif_uses_real_compose_path_and_line(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\nUSER a\n")
    (tmp_path / "compose.yml").write_text(COMPOSE, encoding="utf-8")
    out = tmp_path / "o"
    scan(
        dockerfile=str(tmp_path / "Dockerfile"),
        compose_file=str(tmp_path / "compose.yml"),
        output_dir=str(out),
        formats=["sarif"],
    )
    sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
    locs = [
        r["locations"][0]["physicalLocation"]
        for r in sarif["runs"][0]["results"]
        if r["message"]["text"].startswith("web: Privileged mode")
    ]
    assert locs[0]["artifactLocation"]["uri"] == "compose.yml"
    assert locs[0]["region"]["startLine"] == 4
