"""Tests for the Dockerfile scanner."""

import os
import tempfile

import pytest

from dockerdna.scanners.dockerfile import DockerfileScanner


def _scan_text(scanner, text: str):
    with tempfile.NamedTemporaryFile(
        mode="w", suffix="", delete=False, encoding="utf-8"
    ) as f:
        f.write(text)
        path = f.name
    try:
        return scanner.scan(path)
    finally:
        os.unlink(path)


class TestEnvSecretRedaction:
    def test_flags_secret_in_env(self):
        scanner = DockerfileScanner(redact=True)
        _, findings = _scan_text(scanner, "FROM alpine\nENV PASSWORD=mysupersecret123\n")
        assert any(f.check_key == "env_secret" for f in findings)

    def test_redacts_env_secret_value_by_default(self):
        # Regression test: the ENV/ARG secret check had no redaction path
        # at all and always spliced the raw value into `detail`, which is
        # serialised verbatim into the JSON, HTML, and SARIF reports.
        scanner = DockerfileScanner(redact=True)
        _, findings = _scan_text(scanner, "FROM alpine\nENV PASSWORD=mysupersecret123\n")
        env_findings = [f for f in findings if f.check_key == "env_secret"]
        assert env_findings
        for f in env_findings:
            assert "mysupersecret123" not in f.detail

    def test_no_redaction_when_disabled(self):
        scanner = DockerfileScanner(redact=False)
        _, findings = _scan_text(scanner, "FROM alpine\nENV PASSWORD=mysupersecret123\n")
        env_findings = [f for f in findings if f.check_key == "env_secret"]
        assert env_findings
        assert any("mysupersecret123" in f.detail for f in env_findings)


@pytest.mark.parametrize("mode", ["a+w", "-R a+w", "a+rw", "a+rwx", "777", "-R 0777"])
def test_world_writable_mode_has_layer_attribution(mode):
    _, findings = _scan_text(
        DockerfileScanner(), f"FROM alpine:3.20 AS app\nRUN chmod {mode} /app\nUSER app\n"
    )
    hits = [f for f in findings if f.check_key == "world_writable"]
    assert len(hits) == 1
    assert hits[0].line_number == 2
    assert hits[0].stage == "app"


@pytest.mark.parametrize("mode", ["750", "u+w", "g+w", "a+r", "a+rx", "a-w", "a+w-w", "a+w,o-w"])
def test_restricted_chmod_mode_is_not_world_writable(mode):
    _, findings = _scan_text(DockerfileScanner(), f"FROM alpine:3.20\nRUN chmod {mode} /app\n")
    assert not any(f.check_key == "world_writable" for f in findings)
