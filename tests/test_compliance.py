"""Tests for the CIS compliance mapper."""

import pytest
from dockerdna.scanners.compliance import ComplianceMapper
from dockerdna.utils.patterns import CIS_RULES


def test_all_cis_rules_have_unique_ids():
    ids = [r.id for r in CIS_RULES]
    assert len(ids) == len(set(ids)), "Duplicate CIS rule IDs found"


def test_all_cis_rules_have_check_key():
    for rule in CIS_RULES:
        assert rule.check_key, f"{rule.id} has no check_key"


def test_compliance_mapper_no_findings():
    mapper = ComplianceMapper()
    report = mapper.generate([], [], [], [])
    assert report.total == len(CIS_RULES)
    assert report.failed == 0
    assert 0 <= report.score <= 100


def test_compliance_mapper_with_mock_dockerfile_finding():
    from dockerdna.scanners.dockerfile import DockerfileFinding

    finding = DockerfileFinding(
        line_number=1,
        instruction="FROM",
        check_key="latest_tag",
        cis_id="CIS-4.2",
        title="latest tag",
        severity="MEDIUM",
        detail="Using :latest",
        layer_index=0,
        stage="stage-1",
        remediation="Pin the tag.",
    )

    mapper = ComplianceMapper()
    report = mapper.generate([finding], [], [], [])

    failed_controls = [c for c in report.controls if c.status == "FAIL"]
    failed_ids = [c.rule.id for c in failed_controls]
    assert "CIS-4.2" in failed_ids
    assert report.failed >= 1


def test_compliance_score_decreases_with_findings():
    from dockerdna.scanners.dockerfile import DockerfileFinding

    def _make_finding(check_key: str, cis_id: str) -> DockerfileFinding:
        return DockerfileFinding(
            line_number=1, instruction="RUN",
            check_key=check_key, cis_id=cis_id,
            title="test", severity="HIGH",
            detail="test", layer_index=0,
            stage="stage-1", remediation="fix it",
        )

    mapper = ComplianceMapper()
    base = mapper.generate([], [], [], [])
    with_findings = mapper.generate(
        [_make_finding("no_user", "CIS-4.1"),
         _make_finding("latest_tag", "CIS-4.2")],
        [], [], [],
    )
    assert with_findings.score <= base.score
