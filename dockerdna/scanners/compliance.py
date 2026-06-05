"""
CIS Docker Benchmark v1.6 compliance report generator.

Aggregates findings from all scanners and maps them to CIS controls,
producing a structured pass/fail scorecard that DockSec does not provide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from dockerdna.utils.patterns import CIS_RULES, CISRule


@dataclass
class ControlResult:
    rule: CISRule
    status: str                  # PASS | FAIL | NOT_CHECKED
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.rule.id,
            "level": self.rule.level,
            "title": self.rule.title,
            "severity": self.rule.severity,
            "status": self.status,
            "findings_count": len(self.findings),
            "remediation": self.rule.remediation if self.status == "FAIL" else "",
        }


@dataclass
class ComplianceReport:
    total: int
    passed: int
    failed: int
    not_checked: int
    score: float           # 0–100 compliance score
    controls: list[ControlResult]

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_controls": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "not_checked": self.not_checked,
                "compliance_score": round(self.score, 1),
            },
            "controls": [c.to_dict() for c in self.controls],
        }


class ComplianceMapper:
    """Map raw findings to CIS Docker Benchmark controls."""

    def generate(
        self,
        dockerfile_findings: list[Any],
        compose_findings: list[Any],
        secret_findings: list[Any],
        supply_chain_findings: list[Any],
    ) -> ComplianceReport:

        # Build a map: check_key -> list of findings
        hit_map: dict[str, list[dict]] = {}

        for f in dockerfile_findings:
            hit_map.setdefault(f.check_key, []).append(f.to_dict())

        for f in compose_findings:
            hit_map.setdefault(f.check_key, []).append(f.to_dict())

        for f in secret_findings:
            # map secret type to a check_key
            key = "hardcoded_secret" if f.detection_method == "pattern" else "env_secret"
            hit_map.setdefault(key, []).append(f.to_dict())

        for f in supply_chain_findings:
            if f.risk_score >= 15:
                hit_map.setdefault("no_content_trust", []).append(f.to_dict())

        results: list[ControlResult] = []
        passed = failed = not_checked = 0

        for rule in CIS_RULES:
            findings_for_rule = hit_map.get(rule.check_key, [])
            if findings_for_rule:
                status = "FAIL"
                failed += 1
            else:
                # We only mark PASS for checks we actually ran
                if rule.check_key in self._checked_keys():
                    status = "PASS"
                    passed += 1
                else:
                    status = "NOT_CHECKED"
                    not_checked += 1

            results.append(ControlResult(
                rule=rule,
                status=status,
                findings=findings_for_rule,
            ))

        total = len(CIS_RULES)
        checkable = passed + failed
        score = (passed / checkable * 100) if checkable else 0.0

        return ComplianceReport(
            total=total,
            passed=passed,
            failed=failed,
            not_checked=not_checked,
            score=score,
            controls=results,
        )

    @staticmethod
    def _checked_keys() -> set[str]:
        """The set of check_keys that DockerDNA actually evaluates."""
        return {
            "no_user", "latest_tag", "unnecessary_packages", "no_healthcheck",
            "update_without_install", "env_secret", "hardcoded_secret",
            "no_content_trust", "privileged", "excess_capabilities",
            "sensitive_mount", "docker_socket", "host_network",
            "no_memory_limit", "no_cpu_limit", "no_readonly_fs",
            "no_new_privileges", "privileged_ports", "no_apparmor",
            "ssh_in_container",
        }
