"""
DockerDNA main orchestrator.

Runs all sub-scanners and assembles a unified report.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from dockerdna.reports.html import generate_html
from dockerdna.reports.json_report import generate_json_report
from dockerdna.reports.sarif import generate_sarif
from dockerdna.reports.sbom import extract_components, generate_cyclonedx
from dockerdna.scanners.compliance import ComplianceMapper
from dockerdna.scanners.compose import ComposeScanner
from dockerdna.scanners.dockerfile import DockerfileScanner
from dockerdna.scanners.secrets import SecretsScanner
from dockerdna.scanners.supply_chain import SupplyChainScanner


def scan(
    dockerfile: Optional[str] = None,
    compose_file: Optional[str] = None,
    extra_files: Optional[list[str]] = None,
    scan_directory: Optional[str] = None,
    ai_remediation: bool = False,
    ai_model: str = "claude-sonnet-4-6",
    output_dir: str = "dockerdna-results",
    formats: list[str] | None = None,
    threshold: Optional[str] = None,  # CRITICAL | HIGH | MEDIUM | LOW
    redact_secrets: bool = True,
    verbose: bool = False,
    strict: bool = False,
) -> dict:
    """
    Run all DockerDNA scanners and write reports.

    Returns the full report dict. Raises SystemExit with code 1 if
    ``threshold`` is set and findings at that severity or above are found.

    The scan fails closed: an explicitly named file that does not exist raises
    ``FileNotFoundError``, and any file that could not be fully analysed is
    listed under ``report["scan_errors"]``. With ``strict`` or ``threshold``
    set, scan errors exit with code 2 so a broken scan can never pass a gate.
    """
    for label, given in (("Dockerfile", dockerfile), ("compose file", compose_file)):
        if given and not Path(given).is_file():
            raise FileNotFoundError(f"{label} not found: {given}")
    if scan_directory and not Path(scan_directory).is_dir():
        raise FileNotFoundError(f"directory not found: {scan_directory}")
    for ef in extra_files or []:
        if not Path(ef).is_file():
            raise FileNotFoundError(f"file not found: {ef}")

    if formats is None:
        formats = ["json", "html"]

    # ------------------------------------------------------------------ #
    # Auto-discover files
    # ------------------------------------------------------------------ #
    search_roots: list[Path] = []
    if scan_directory:
        search_roots.append(Path(scan_directory))
    if dockerfile:
        search_roots.append(Path(dockerfile).parent)

    if dockerfile is None and scan_directory:
        for candidate in ["Dockerfile", "dockerfile"]:
            p = Path(scan_directory) / candidate
            if p.exists():
                dockerfile = str(p)
                break

    if compose_file is None and scan_directory:
        for candidate in [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ]:
            p = Path(scan_directory) / candidate
            if p.exists():
                compose_file = str(p)
                break

    # ------------------------------------------------------------------ #
    # Run scanners
    # ------------------------------------------------------------------ #
    secrets_scanner = SecretsScanner(redact=redact_secrets)
    compose_scanner = ComposeScanner()
    dockerfile_scanner = DockerfileScanner(redact=redact_secrets)
    supply_chain_scanner = SupplyChainScanner()
    compliance_mapper = ComplianceMapper()

    # Secrets
    secret_findings = []
    if dockerfile:
        secret_findings.extend(secrets_scanner.scan_file(dockerfile))
    if compose_file:
        secret_findings.extend(secrets_scanner.scan_file(compose_file))
    if scan_directory:
        secret_findings.extend(secrets_scanner.scan_directory(scan_directory))
    if extra_files:
        for ef in extra_files:
            secret_findings.extend(secrets_scanner.scan_file(ef))

    # Deduplicate secrets by (file, line)
    seen_secrets: set[tuple[str, int]] = set()
    deduped_secrets = []
    for sf in secret_findings:
        key = (sf.file, sf.line_number)
        if key not in seen_secrets:
            seen_secrets.add(key)
            deduped_secrets.append(sf)
    secret_findings = deduped_secrets

    # Compose
    compose_findings = []
    if compose_file:
        compose_findings = compose_scanner.scan(compose_file)

    # Dockerfile + layers
    layers: list = []
    dockerfile_findings = []
    if dockerfile:
        layers, dockerfile_findings = dockerfile_scanner.scan(dockerfile)

    # Supply chain
    supply_chain_findings = supply_chain_scanner.analyze_base_images(layers)

    # Compliance
    compliance_report = compliance_mapper.generate(
        dockerfile_findings,
        compose_findings,
        secret_findings,
        supply_chain_findings,
    )

    # SBOM
    components = extract_components(layers)
    image_name = Path(dockerfile).stem if dockerfile else "unknown"
    sbom = generate_cyclonedx(components, image_name, dockerfile or "Dockerfile")

    scan_errors = (
        secrets_scanner.errors + compose_scanner.errors + dockerfile_scanner.errors
    )

    # Metadata
    metadata = {
        "scanned_path": dockerfile or scan_directory or ".",
        "compose_file": compose_file or "",
        "dockerfile": dockerfile or "",
        "files_scanned": (
            ([dockerfile] if dockerfile else [])
            + ([compose_file] if compose_file else [])
            + (extra_files or [])
        ),
    }

    # ------------------------------------------------------------------ #
    # Assemble report
    # ------------------------------------------------------------------ #
    report = generate_json_report(
        dockerfile_findings,
        compose_findings,
        secret_findings,
        supply_chain_findings,
        compliance_report,
        sbom,
        metadata,
    )

    report["scan_errors"] = scan_errors
    for err in scan_errors:
        print(f"[DockerDNA] WARNING: {err}", file=sys.stderr)

    # ------------------------------------------------------------------ #
    # AI remediation (optional)
    # ------------------------------------------------------------------ #
    if ai_remediation:
        from dockerdna.ai.remediation import get_ai_remediation

        ai_result = get_ai_remediation(
            dockerfile,
            compose_file,
            dockerfile_findings,
            compose_findings,
            secret_findings,
            supply_chain_findings,
            compliance_report.score,
            model=ai_model,
        )
        report["ai_remediation"] = ai_result

    # ------------------------------------------------------------------ #
    # Write outputs
    # ------------------------------------------------------------------ #
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if "json" in formats:
        json_path = out / "report.json"
        json_path.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        if verbose:
            print(f"[DockerDNA] JSON report: {json_path}")

    if "html" in formats:
        html_path = out / "report.html"
        html_path.write_text(generate_html(report), encoding="utf-8")
        if verbose:
            print(f"[DockerDNA] HTML report: {html_path}")

    if "sarif" in formats:
        sarif_data = generate_sarif(
            dockerfile_findings,
            compose_findings,
            secret_findings,
            supply_chain_findings,
            base_path=str(Path(dockerfile).parent) if dockerfile else "",
        )
        sarif_path = out / "report.sarif"
        sarif_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        if verbose:
            print(f"[DockerDNA] SARIF report: {sarif_path}")

    if "sbom" in formats:
        sbom_path = out / "sbom.cyclonedx.json"
        sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        if verbose:
            print(f"[DockerDNA] SBOM: {sbom_path}")

    # ------------------------------------------------------------------ #
    # Threshold gate (CI/CD)
    # ------------------------------------------------------------------ #
    if scan_errors and (strict or threshold):
        print(
            f"[DockerDNA] ERROR: {len(scan_errors)} file(s) could not be fully "
            "scanned; refusing to report a clean result.",
            file=sys.stderr,
        )
        sys.exit(2)

    if threshold:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threshold_level = order.get(threshold.upper(), 3)
        by_sev = report["summary"]["by_severity"]
        should_fail = any(
            count > 0
            for sev, count in by_sev.items()
            if order.get(sev, 99) <= threshold_level
        )
        if should_fail:
            print(
                f"[DockerDNA] FAIL: findings at or above {threshold} severity detected.",
                file=sys.stderr,
            )
            sys.exit(1)

    return report
