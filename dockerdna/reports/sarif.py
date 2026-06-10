"""
SARIF 2.1.0 output for GitHub Advanced Security integration.

DockSec lacks SARIF output (it is listed as an open issue #45).
DockerDNA ships with full SARIF support out of the box, enabling
GitHub Security tab annotations on pull requests.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_TOOL = {
    "driver": {
        "name": "DockerDNA",
        "version": "1.0.0",
        "informationUri": "https://github.com/sunilgentyala/DockerDNA",
        "rules": [],
    }
}

_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def generate_sarif(
    dockerfile_findings: list[Any],
    compose_findings: list[Any],
    secret_findings: list[Any],
    supply_chain_findings: list[Any],
    base_path: str = "",
) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    def _add_rule(rule_id: str, name: str, description: str, severity: str):
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": description},
                "defaultConfiguration": {
                    "level": _SEVERITY_MAP.get(severity, "warning")
                },
                "helpUri": f"https://github.com/sunilgentyala/DockerDNA/wiki/{rule_id}",
            }

    def _add_result(
        rule_id: str, message: str, filepath: str, line: int, severity: str
    ):
        uri = Path(filepath).as_posix() if filepath else "unknown"
        if base_path:
            try:
                uri = Path(filepath).relative_to(base_path).as_posix()
            except ValueError:
                pass
        results.append(
            {
                "ruleId": rule_id,
                "level": _SEVERITY_MAP.get(severity, "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": max(1, line)},
                        }
                    }
                ],
            }
        )

    # Dockerfile findings
    for f in dockerfile_findings:
        _add_rule(f.cis_id, f.title, f.remediation, f.severity)
        _add_result(f.cis_id, f.detail, "Dockerfile", f.line_number, f.severity)

    # Compose findings
    for f in compose_findings:
        _add_rule(f.cis_id, f.title, f.remediation, f.severity)
        _add_result(
            f.cis_id,
            f"{f.service}: {f.detail}",
            "docker-compose.yml",
            f.line_hint or 1,
            f.severity,
        )

    # Secret findings
    for f in secret_findings:
        _add_rule(f.cis_id, f"Secret: {f.secret_type}", f.remediation, f.severity)
        _add_result(
            f.cis_id,
            f"{f.secret_type} detected (method: {f.detection_method})",
            f.file,
            f.line_number,
            f.severity,
        )

    # Supply chain findings
    for f in supply_chain_findings:
        if f.risk_score >= 15:
            rule_id = f"{f.cis_id}-SUPPLY-CHAIN"
            _add_rule(
                rule_id, f"Supply chain risk: {f.image}", f.remediation, f.severity
            )
            _add_result(
                rule_id,
                f"Risk score {f.risk_score}/100 — {'; '.join(f.factors)}",
                "Dockerfile",
                1,
                f.severity,
            )

    tool = dict(_TOOL)
    tool["driver"]["rules"] = list(rules.values())

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": tool,
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
