"""Regression test: secret findings must show a message in the CLI summary."""

from dockerdna.cli import _print_summary


def test_secret_finding_has_message_in_summary(capsys):
    report = {
        "summary": {"total_findings": 1, "by_severity": {"CRITICAL": 1}},
        "findings": {
            "secrets": [
                {
                    "file": "Dockerfile",
                    "line": 2,
                    "type": "AWS Access Key ID",
                    "severity": "CRITICAL",
                    "cis_id": "CIS-4.10",
                    "matched_value": "AKIA****MPLE",
                }
            ]
        },
    }
    _print_summary(report)
    out = capsys.readouterr().out
    assert "AWS Access Key ID" in out
    assert "line 2" in out
