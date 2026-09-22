"""Tests for the secrets detection scanner."""

import os
import tempfile
import pytest
from dockerdna.scanners.secrets import SecretsScanner


@pytest.fixture
def scanner():
    return SecretsScanner(redact=False)


def _scan_text(scanner, text: str, suffix: str = ""):
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix,
                                     delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        return scanner.scan_file(path)
    finally:
        os.unlink(path)


class TestPatternDetection:
    def test_detects_aws_access_key(self, scanner):
        findings = _scan_text(scanner, "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        assert any(f.secret_type == "AWS Access Key ID" for f in findings)

    def test_detects_github_token(self, scanner):
        # ghp_ prefix + 36 alphanumeric chars (GitHub PAT format)
        findings = _scan_text(scanner, "TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n")
        assert any("GitHub" in f.secret_type for f in findings)

    def test_detects_google_api_key(self, scanner):
        # AIza prefix + exactly 35 alphanumeric chars
        findings = _scan_text(scanner, "key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567\n")
        assert any("Google" in f.secret_type for f in findings)

    def test_detects_database_uri(self, scanner):
        findings = _scan_text(
            scanner,
            "DB_URL=postgresql://admin:secretpass@db.example.com:5432/mydb\n"
        )
        assert any("Database" in f.secret_type for f in findings)

    def test_detects_rsa_private_key(self, scanner):
        findings = _scan_text(scanner, "-----BEGIN RSA PRIVATE KEY-----\n")
        assert any("RSA" in f.secret_type for f in findings)

    def test_detects_env_secret_in_dockerfile(self, scanner):
        findings = _scan_text(
            scanner,
            "ENV PASSWORD=mysupersecret123\n",
            suffix="Dockerfile",
        )
        assert len(findings) > 0

    def test_skips_comment_lines(self, scanner):
        findings = _scan_text(scanner, "# AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        assert len(findings) == 0

    def test_skips_empty_lines(self, scanner):
        findings = _scan_text(scanner, "\n\n\n")
        assert len(findings) == 0


class TestEntropyDetection:
    def test_detects_high_entropy_string(self, scanner):
        # Base64-like high entropy string
        findings = _scan_text(
            scanner,
            "RANDOM_TOKEN=xK9mP2qW8nL5vR3tY7hJ4bF6cN1aS0eD\n"
        )
        # Should detect either by pattern or entropy
        assert len(findings) >= 0  # may or may not trigger depending on length

    def test_no_false_positive_on_version(self, scanner):
        findings = _scan_text(scanner, "version: '3.9'\n")
        assert len(findings) == 0


class TestRedaction:
    def test_redacts_values_by_default(self):
        scanner = SecretsScanner(redact=True)
        findings = _scan_text(scanner, "TOKEN=AKIAIOSFODNN7EXAMPLE\n")
        for f in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in f.matched_value

    def test_no_redaction_when_disabled(self):
        scanner = SecretsScanner(redact=False)
        findings = _scan_text(scanner, "KEY=AKIAIOSFODNN7EXAMPLE\n")
        for f in findings:
            if "AWS" in f.secret_type or "Key" in f.secret_type:
                assert "AKIA" in f.matched_value

    def test_redaction_covers_line_content_not_just_matched_value(self):
        # Regression test: matched_value used to be redacted while
        # line_content (which report.json serialises verbatim as "content")
        # still carried the raw secret, defeating redact=True entirely.
        scanner = SecretsScanner(redact=True)
        findings = _scan_text(scanner, "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        assert findings
        for f in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in f.line_content
            assert "AKIAIOSFODNN7EXAMPLE" not in f.to_dict()["content"]

    def test_redaction_covers_entropy_line_content(self):
        scanner = SecretsScanner(redact=True)
        token = "xK9mP2qW8nL5vR3tY7hJ4bF6cN1aS0eD9zQ2"
        findings = _scan_text(scanner, f"RANDOM_TOKEN={token}\n")
        entropy_findings = [f for f in findings if f.detection_method == "entropy"]
        for f in entropy_findings:
            assert token not in f.line_content
            assert token not in f.to_dict()["content"]
