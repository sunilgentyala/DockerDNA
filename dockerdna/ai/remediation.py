"""
AI-powered remediation using Anthropic Claude.

Unlike DockSec which uses AI to explain Trivy/Hadolint output,
DockerDNA's AI module synthesises findings from ALL scanners
(Dockerfile, compose, secrets, supply-chain) and produces:
  1. A prioritised fix plan with CIS control IDs
  2. A rewritten Dockerfile with all issues corrected
  3. A rewritten docker-compose with all misconfigs fixed
"""

from __future__ import annotations

import os
from typing import Any, Optional


def _build_context(
    dockerfile_path: Optional[str],
    compose_path: Optional[str],
    dockerfile_findings: list[Any],
    compose_findings: list[Any],
    secret_findings: list[Any],
    supply_chain_findings: list[Any],
    compliance_score: float,
) -> str:
    parts: list[str] = []

    parts.append(f"CIS Docker Benchmark compliance score: {compliance_score:.1f}%\n")

    if dockerfile_findings:
        parts.append("=== Dockerfile Findings ===")
        for f in dockerfile_findings:
            parts.append(
                f"[{f.severity}] {f.cis_id} line {f.line_number}: {f.detail}"
            )

    if compose_findings:
        parts.append("\n=== docker-compose.yml Findings ===")
        for f in compose_findings:
            parts.append(
                f"[{f.severity}] {f.cis_id} service '{f.service}': {f.detail}"
            )

    if secret_findings:
        parts.append("\n=== Secrets Detected ===")
        for f in secret_findings:
            parts.append(
                f"[{f.severity}] {f.cis_id} {f.file} line {f.line_number}: "
                f"{f.secret_type} ({f.detection_method})"
            )

    if supply_chain_findings:
        parts.append("\n=== Supply Chain Risks ===")
        for f in supply_chain_findings:
            parts.append(
                f"[{f.severity}] {f.image} — risk score {f.risk_score}/100: "
                + "; ".join(f.factors)
            )

    # Append file contents (truncated)
    if dockerfile_path and os.path.exists(dockerfile_path):
        try:
            content = open(dockerfile_path).read()[:3000]
            parts.append(f"\n=== Current Dockerfile ===\n{content}")
        except Exception:
            pass

    if compose_path and os.path.exists(compose_path):
        try:
            content = open(compose_path).read()[:3000]
            parts.append(f"\n=== Current docker-compose.yml ===\n{content}")
        except Exception:
            pass

    return "\n".join(parts)


def get_ai_remediation(
    dockerfile_path: Optional[str],
    compose_path: Optional[str],
    dockerfile_findings: list[Any],
    compose_findings: list[Any],
    secret_findings: list[Any],
    supply_chain_findings: list[Any],
    compliance_score: float,
    model: str = "claude-sonnet-4-6",
) -> dict:
    """
    Call Anthropic Claude to produce a fix plan and corrected files.
    Requires ANTHROPIC_API_KEY environment variable.
    """
    try:
        import anthropic
    except ImportError:
        return {"error": "anthropic package not installed. Run: pip install anthropic"}

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"error": "ANTHROPIC_API_KEY environment variable not set"}

    context = _build_context(
        dockerfile_path, compose_path,
        dockerfile_findings, compose_findings,
        secret_findings, supply_chain_findings,
        compliance_score,
    )

    system_prompt = (
        "You are a senior DevSecOps engineer specialising in Docker and container security. "
        "You have been given a set of security findings from the DockerDNA scanner. "
        "Your task is to:\n"
        "1. Produce a prioritised fix plan (Critical first, then High, Medium, Low).\n"
        "2. Write a corrected Dockerfile that resolves all Dockerfile findings.\n"
        "3. Write a corrected docker-compose.yml that resolves all compose findings.\n"
        "4. Provide specific advice on rotating any detected secrets.\n"
        "Map every recommendation to its CIS Docker Benchmark control ID. "
        "Be concise, specific, and actionable."
    )

    user_prompt = (
        f"Here are the security findings from DockerDNA:\n\n{context}\n\n"
        "Please provide:\n"
        "## 1. Prioritised Fix Plan\n"
        "## 2. Corrected Dockerfile\n"
        "## 3. Corrected docker-compose.yml (if applicable)\n"
        "## 4. Secret Remediation Steps\n"
    )

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": user_prompt}],
        system=system_prompt,
    )

    response_text = message.content[0].text if message.content else ""
    return {
        "model": model,
        "input_tokens": message.usage.input_tokens,
        "output_tokens": message.usage.output_tokens,
        "remediation": response_text,
    }
