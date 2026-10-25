"""Tests for v1.1 detection rules and the golden example scan."""

import pytest

from dockerdna.scanner import scan
from dockerdna.scanners.compose import ComposeScanner
from dockerdna.scanners.dockerfile import DockerfileScanner


def _df_checks(tmp_path, body):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM alpine:3.20\n" + body + "\nUSER app\n", encoding="utf-8")
    _, findings = DockerfileScanner().scan(p)
    return {f.check_key for f in findings}


@pytest.mark.parametrize(
    "run",
    [
        "RUN curl -sSL https://x.sh | bash",
        "RUN wget -qO- https://x.sh | sudo sh",
        "RUN curl https://x.sh | sh -s -- -y",
    ],
)
def test_pipe_to_shell(tmp_path, run):
    assert "pipe_to_shell" in _df_checks(tmp_path, run)


def test_download_to_file_is_not_pipe_to_shell(tmp_path):
    assert "pipe_to_shell" not in _df_checks(
        tmp_path, "RUN curl -o /tmp/a.sh https://x/a.sh && sha256sum -c a.sum"
    )


@pytest.mark.parametrize(
    "run",
    [
        "RUN wget --no-check-certificate https://x/a",
        "RUN curl -k https://x/a -o /a",
        "RUN pip install --trusted-host pypi.org foo",
    ],
)
def test_insecure_download(tmp_path, run):
    assert "insecure_download" in _df_checks(tmp_path, run)


def test_chmod_777(tmp_path):
    assert "world_writable" in _df_checks(tmp_path, "RUN chmod -R 777 /app")
    assert "world_writable" not in _df_checks(tmp_path, "RUN chmod 750 /app")


def test_apt_recommends(tmp_path):
    assert "apt_recommends" in _df_checks(tmp_path, "RUN apt-get install -y git")
    assert "apt_recommends" not in _df_checks(
        tmp_path, "RUN apt-get install -y --no-install-recommends git"
    )


def test_secret_in_run_redacted(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text(
        'FROM alpine:3.20\nRUN echo "password=Sup3rS3cretValue99" > /c\nUSER a\n'
    )
    _, findings = DockerfileScanner().scan(p)
    hit = [f for f in findings if f.check_key == "secret_in_run"]
    assert hit and "Sup3rS3cretValue99" not in hit[0].detail


def test_secret_in_run_ignores_variable_reference(tmp_path):
    assert "secret_in_run" not in _df_checks(tmp_path, "RUN echo $TOKEN_FILE")


def test_compose_untagged_image_flagged(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("services:\n  a:\n    image: nginx\n  b:\n    image: nginx:1.27\n")
    scanner = ComposeScanner()
    flagged = {f.service for f in scanner.scan(p) if f.check_key == "latest_tag"}
    assert flagged == {"a"}


def test_compose_registry_port_not_mistaken_for_tag(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("services:\n  a:\n    image: localhost:5000/app\n")
    assert "latest_tag" in {f.check_key for f in ComposeScanner().scan(p)}


def test_compose_env_file_secrets_scanned(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\nUSER a\n")
    (tmp_path / "app.env").write_text(
        "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
    )
    (tmp_path / "c.yml").write_text(
        "services:\n  a:\n    image: x:1\n    env_file:\n      - app.env\n"
    )
    report = scan(
        dockerfile=str(tmp_path / "Dockerfile"),
        compose_file=str(tmp_path / "c.yml"),
        output_dir=str(tmp_path / "o"),
        formats=["json"],
    )
    files = [f["file"] for f in report["findings"]["secrets"]]
    assert any(f.endswith("app.env") for f in files)


def test_compose_image_gets_supply_chain_finding(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\nUSER a\n")
    (tmp_path / "c.yml").write_text("services:\n  a:\n    image: someuser/thing\n")
    report = scan(
        dockerfile=str(tmp_path / "Dockerfile"),
        compose_file=str(tmp_path / "c.yml"),
        output_dir=str(tmp_path / "o"),
        formats=["json"],
    )
    assert any(f["stage"] == "compose:a" for f in report["findings"]["supply_chain"])


def test_golden_vulnerable_example_minimum_findings(tmp_path):
    report = scan(
        dockerfile="examples/Dockerfile.vulnerable",
        compose_file="examples/docker-compose.vulnerable.yml",
        output_dir=str(tmp_path),
        formats=["json"],
    )
    df = {f["check"] for f in report["findings"]["dockerfile"]}
    cf = {f["check"] for f in report["findings"]["compose"]}
    assert {
        "latest_tag",
        "env_secret",
        "update_without_install",
        "ssh_in_container",
        "no_user",
    } <= df
    assert {"privileged", "docker_socket", "host_network"} <= cf
    assert len(report["findings"]["secrets"]) >= 2
    assert report["summary"]["by_severity"]["CRITICAL"] >= 3


def test_golden_secure_example_has_no_critical(tmp_path):
    report = scan(
        dockerfile="examples/Dockerfile.secure",
        compose_file="examples/docker-compose.secure.yml",
        output_dir=str(tmp_path),
        formats=["json"],
    )
    assert report["summary"]["by_severity"]["CRITICAL"] == 0
    assert report["scan_errors"] == []
