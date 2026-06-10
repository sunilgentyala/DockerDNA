"""
DockerDNA CLI entry point.

Usage examples:
  dockerdna Dockerfile
  dockerdna Dockerfile --compose docker-compose.yml
  dockerdna --dir ./myapp --format json html sarif sbom
  dockerdna Dockerfile --ai --threshold HIGH
  dockerdna --dir . --format sarif --output-dir .github/security
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dockerdna.scanner import scan


def _print_summary(report: dict) -> None:
    summary = report.get("summary", {})
    by_sev  = summary.get("by_severity", {})
    meta    = report.get("metadata", {})
    print()
    print("  ____             _             ____  _   _    _")
    print(" |  _ \\  ___   ___| | _____ _ __| __ )| \\ | |  / \\")
    print(" | | | |/ _ \\ / __| |/ / _ \\ '__|  _ \\|  \\| | / _ \\")
    print(" | |_| | (_) | (__|   <  __/ |  | |_) | |\\  |/ ___ \\")
    print(" |____/ \\___/ \\___|_|\\_\\___|_|  |____/|_| \\_/_/   \\_\\")
    print()
    print("  Layer-by-Layer Container Security DNA Analysis")
    print("  github.com/sunilgentyala/DockerDNA\n")
    print(f"  Scanned : {meta.get('scanned_path','')}")
    if meta.get("compose_file"):
        print(f"  Compose : {meta.get('compose_file')}")
    print()
    print(f"  Risk Score          : {summary.get('risk_score', 0)}/100")
    print(f"  CIS Compliance      : {summary.get('compliance_score', 0):.1f}%")
    print(f"  Total Findings      : {summary.get('total_findings', 0)}")
    print()
    print(f"  CRITICAL  {by_sev.get('CRITICAL', 0):>4}")
    print(f"  HIGH      {by_sev.get('HIGH', 0):>4}")
    print(f"  MEDIUM    {by_sev.get('MEDIUM', 0):>4}")
    print(f"  LOW       {by_sev.get('LOW', 0):>4}")
    print()

    # Print critical / high findings inline
    findings = report.get("findings", {})
    all_findings = (
        findings.get("secrets", [])
        + findings.get("dockerfile", [])
        + findings.get("compose", [])
        + findings.get("supply_chain", [])
    )
    critical_high = [
        f for f in all_findings
        if f.get("severity") in ("CRITICAL", "HIGH")
    ]
    if critical_high:
        print("  Top findings requiring immediate attention:")
        for f in critical_high[:10]:
            sev  = f.get("severity", "")
            cis  = f.get("cis_id", "")
            msg  = f.get("detail") or f.get("description") or str(f.get("factors", ""))
            svc  = f.get("service", "") or f.get("file", "")
            loc  = f" [{svc}]" if svc else ""
            print(f"  [{sev}] {cis}{loc}: {msg[:90]}")
        if len(critical_high) > 10:
            print(f"  ... and {len(critical_high) - 10} more (see report)")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dockerdna",
        description="DockerDNA — Layer-by-Layer Container Security DNA Analysis",
    )
    parser.add_argument(
        "dockerfile",
        nargs="?",
        help="Path to Dockerfile (optional if --dir is used)",
    )
    parser.add_argument(
        "--compose", "-c",
        metavar="FILE",
        help="Path to docker-compose.yml",
    )
    parser.add_argument(
        "--dir", "-d",
        metavar="DIRECTORY",
        help="Scan an entire project directory",
    )
    parser.add_argument(
        "--file", "-f",
        metavar="FILE",
        action="append",
        dest="extra_files",
        help="Additional file to scan for secrets (repeatable)",
    )
    parser.add_argument(
        "--format",
        nargs="+",
        choices=["json", "html", "sarif", "sbom"],
        default=["json", "html"],
        metavar="FORMAT",
        help="Output formats: json html sarif sbom (default: json html)",
    )
    parser.add_argument(
        "--output", "-o",
        default="dockerdna-results",
        metavar="DIR",
        help="Output directory (default: ./dockerdna-results)",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI-powered remediation via Anthropic Claude",
    )
    parser.add_argument(
        "--ai-model",
        default="claude-sonnet-4-6",
        metavar="MODEL",
        help="Claude model to use for AI remediation",
    )
    parser.add_argument(
        "--threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        metavar="SEVERITY",
        help="Exit with code 1 if findings at this severity or above are found",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Do not redact secret values in reports (use with caution)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print verbose output",
    )

    args = parser.parse_args()

    if not args.dockerfile and not args.dir:
        parser.print_help()
        sys.exit(1)

    report = scan(
        dockerfile=args.dockerfile,
        compose_file=args.compose,
        extra_files=args.extra_files,
        scan_directory=args.dir,
        ai_remediation=args.ai,
        ai_model=args.ai_model,
        output_dir=args.output,
        formats=args.format,
        threshold=args.threshold,
        redact_secrets=not args.no_redact,
        verbose=args.verbose,
    )

    _print_summary(report)

    out = Path(args.output)
    if "json" in args.format:
        print(f"  JSON   : {out / 'report.json'}")
    if "html" in args.format:
        print(f"  HTML   : {out / 'report.html'}")
    if "sarif" in args.format:
        print(f"  SARIF  : {out / 'report.sarif'}")
    if "sbom" in args.format:
        print(f"  SBOM   : {out / 'sbom.cyclonedx.json'}")
    print()


if __name__ == "__main__":
    main()
