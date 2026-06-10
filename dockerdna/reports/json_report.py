"""JSON report assembler."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def generate_json_report(
    dockerfile_findings: list[Any],
    compose_findings: list[Any],
    secret_findings: list[Any],
    supply_chain_findings: list[Any],
    compliance_report: Any,
    sbom: dict,
    metadata: dict,
) -> dict:

    def _count(findings: list[Any]) -> dict:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = getattr(f, "severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    df_counts = _count(dockerfile_findings)
    cf_counts = _count(compose_findings)
    sf_counts = _count(secret_findings)
    sc_counts = _count(supply_chain_findings)

    total_critical = sum(
        c["CRITICAL"] for c in [df_counts, cf_counts, sf_counts, sc_counts]
    )
    total_high = sum(
        c["HIGH"] for c in [df_counts, cf_counts, sf_counts, sc_counts]
    )

    risk_score = min(100, total_critical * 15 + total_high * 5)

    return {
        "tool": "DockerDNA",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": metadata,
        "summary": {
            "risk_score": risk_score,
            "compliance_score": compliance_report.score if compliance_report else 0,
            "total_findings": (
                len(dockerfile_findings)
                + len(compose_findings)
                + len(secret_findings)
                + len(supply_chain_findings)
            ),
            "by_severity": {
                "CRITICAL": total_critical,
                "HIGH": total_high,
                "MEDIUM": sum(c["MEDIUM"] for c in [df_counts, cf_counts, sf_counts, sc_counts]),
                "LOW": sum(c["LOW"] for c in [df_counts, cf_counts, sf_counts, sc_counts]),
            },
        },
        "findings": {
            "dockerfile": [f.to_dict() for f in dockerfile_findings],
            "compose": [f.to_dict() for f in compose_findings],
            "secrets": [f.to_dict() for f in secret_findings],
            "supply_chain": [f.to_dict() for f in supply_chain_findings],
        },
        "compliance": compliance_report.to_dict() if compliance_report else {},
        "sbom": sbom,
    }
