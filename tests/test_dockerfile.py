"""Tests for the Dockerfile scanner."""

import os
import tempfile

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
