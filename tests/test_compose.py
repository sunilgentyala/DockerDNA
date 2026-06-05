"""Tests for the docker-compose security scanner."""

import os
import tempfile
import pytest

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from dockerdna.scanners.compose import ComposeScanner


@pytest.fixture
def scanner():
    return ComposeScanner()


def _scan_yaml(scanner, content: str):
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        path = f.name
    try:
        return scanner.scan(path)
    finally:
        os.unlink(path)


@pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
class TestComposeScanner:
    def test_detects_privileged(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx
    privileged: true
""")
        assert any(f.check_key == "privileged" for f in findings)

    def test_detects_docker_socket(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""")
        assert any(f.check_key == "docker_socket" for f in findings)

    def test_detects_host_network(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx
    network_mode: host
""")
        assert any(f.check_key == "host_network" for f in findings)

    def test_detects_cap_add_all(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx
    cap_add:
      - ALL
""")
        assert any(f.check_key == "excess_capabilities" for f in findings)

    def test_detects_no_memory_limit(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx
""")
        assert any(f.check_key == "no_memory_limit" for f in findings)

    def test_detects_no_readonly_fs(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx
""")
        assert any(f.check_key == "no_readonly_fs" for f in findings)

    def test_detects_privileged_port(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx
    ports:
      - "80:80"
""")
        assert any(f.check_key == "privileged_ports" for f in findings)

    def test_detects_env_secret(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx
    environment:
      - DB_PASSWORD=mysecret123
""")
        assert any(f.check_key == "env_secret" for f in findings)

    def test_no_findings_for_secure_config(self, scanner):
        findings = _scan_yaml(scanner, """
services:
  app:
    image: nginx:1.25
    read_only: true
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
    cap_drop:
      - ALL
    ports:
      - "127.0.0.1:8080:8080"
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
""")
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert len(critical) == 0
