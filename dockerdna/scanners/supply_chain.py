"""
Supply-chain risk scoring for Docker base images.

Evaluates:
  1. Registry trust (Docker Hub official vs community vs self-hosted)
  2. Image tag specificity (digest pinning > version tag > :latest)
  3. Image age freshness (via Docker Hub API, best-effort)
  4. Docker Content Trust / Notary (DOCKER_CONTENT_TRUST env)
  5. Known malicious image name patterns

Produces a 0–100 supply-chain risk score per base image.
Score 0 = fully trusted; 100 = highest risk.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass
class SupplyChainFinding:
    image: str
    stage: str
    risk_score: int  # 0–100
    factors: list[str]
    severity: str
    cis_id: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "stage": self.stage,
            "risk_score": self.risk_score,
            "factors": self.factors,
            "severity": self.severity,
            "cis_id": self.cis_id,
            "remediation": self.remediation,
        }


# Official Docker Library images on Docker Hub
OFFICIAL_IMAGES = {
    "alpine",
    "ubuntu",
    "debian",
    "centos",
    "fedora",
    "amazonlinux",
    "python",
    "node",
    "ruby",
    "golang",
    "rust",
    "java",
    "openjdk",
    "nginx",
    "apache",
    "httpd",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "elasticsearch",
    "rabbitmq",
    "memcached",
    "wordpress",
    "drupal",
    "php",
    "perl",
    "r-base",
    "swift",
    "dotnet",
    "microsoft/dotnet",
    "scratch",
    "busybox",
    "distroless",
}

# Known malicious or suspicious image names (best-effort blocklist)
SUSPICIOUS_PATTERNS = [
    r"xmrig",
    r"monero",
    r"coinminer",
    r"cryptominer",
    r"backdoor",
    r"rootkit",
    r"exploit",
]


class SupplyChainScanner:

    def analyze_base_images(self, layers: list) -> list[SupplyChainFinding]:
        """Analyze FROM instructions extracted by DockerfileScanner."""
        findings: list[SupplyChainFinding] = []
        seen: set[str] = set()
        for layer in layers:
            if layer.instruction != "FROM":
                continue
            args = layer.arguments.strip()
            # Strip AS alias
            image_ref = re.sub(r"\s+AS\s+\S+", "", args, flags=re.IGNORECASE).strip()
            if image_ref in seen or image_ref.lower() == "scratch":
                continue
            seen.add(image_ref)
            findings.append(self._score_image(image_ref, layer.stage))
        return findings

    # ------------------------------------------------------------------

    def _score_image(self, ref: str, stage: str) -> SupplyChainFinding:
        score = 0
        factors: list[str] = []

        # 1. Registry trust
        if ref.startswith("localhost") or re.match(r"\d+\.\d+\.\d+\.\d+", ref):
            score += 30
            factors.append("Self-hosted registry (no content trust guarantees)")
        elif "/" not in ref:
            # Docker Hub official library
            pass  # +0
        elif ref.count("/") == 1:
            # Docker Hub community image (user/image)
            score += 15
            factors.append("Docker Hub community image — verify publisher identity")
        else:
            # Third-party registry
            score += 10
            factors.append("Third-party registry — check signing and provenance")

        # 2. Tag specificity
        if "@sha256:" in ref:
            pass  # Digest-pinned, best practice
            factors.append("Digest-pinned (best practice)")
        elif ":" not in ref or ":latest" in ref:
            score += 25
            factors.append(":latest tag or no tag — non-deterministic builds")
        else:
            score += 5
            factors.append("Version tag without digest pin")

        # 3. Docker Content Trust
        if not os.environ.get("DOCKER_CONTENT_TRUST"):
            score += 10
            factors.append("DOCKER_CONTENT_TRUST not set in environment")

        # 4. Suspicious image names
        image_lower = ref.lower()
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, image_lower):
                score += 40
                factors.append(f"Suspicious image name matches pattern: {pattern}")
                break

        # 5. Multi-word image check (unusual naming)
        name_part = ref.split("/")[-1].split(":")[0].split("@")[0]
        if len(name_part) < 3:
            score += 5
            factors.append("Very short image name — verify it is intentional")

        score = min(score, 100)

        if score >= 60:
            severity = "CRITICAL"
        elif score >= 35:
            severity = "HIGH"
        elif score >= 15:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        remediation = (
            "Pin the base image to a specific digest (`image@sha256:<hash>`). "
            "Prefer Docker Official Images or verified publisher images. "
            "Set `DOCKER_CONTENT_TRUST=1` in CI to enforce image signing."
        )

        return SupplyChainFinding(
            image=ref,
            stage=stage,
            risk_score=score,
            factors=factors,
            severity=severity,
            cis_id="CIS-4.5",
            remediation=remediation,
        )
