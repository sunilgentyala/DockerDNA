"""
CycloneDX SBOM (Software Bill of Materials) generator.

Parses Dockerfile package install instructions to produce a
CycloneDX 1.5 JSON SBOM documenting what is installed in each layer.

DockSec does not generate SBOMs. DockerDNA fills this gap,
enabling supply-chain transparency and NTIA minimum-elements compliance.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class Component:
    name: str
    version: str
    pkg_type: str  # "deb" | "rpm" | "apk" | "pip" | "npm" | "gem" | "unknown"
    source_layer: int
    stage: str
    purl: str = ""

    def to_cyclonedx(self) -> dict:
        comp: dict = {
            "type": "library",
            "name": self.name,
            "version": self.version or "unknown",
            "properties": [
                {"name": "dockerdna:layer", "value": str(self.source_layer)},
                {"name": "dockerdna:stage", "value": self.stage},
                {"name": "dockerdna:pkg_type", "value": self.pkg_type},
            ],
        }
        if self.purl:
            comp["purl"] = self.purl
        return comp


# Package manager install patterns
_INSTALLERS: list[tuple[str, str, re.Pattern]] = [
    (
        "deb",
        "apt",
        re.compile(
            r"apt(?:-get)?\s+install\s+(?:-[^\s]+\s+)*(.+?)(?:\s*&&|\s*$|\s*\\)",
            re.DOTALL,
        ),
    ),
    (
        "apk",
        "apk",
        re.compile(r"apk\s+add\s+(?:--[^\s]+\s+)*(.+?)(?:\s*&&|\s*$|\s*\\)", re.DOTALL),
    ),
    (
        "rpm",
        "yum",
        re.compile(
            r"yum\s+install\s+(?:-[^\s]+\s+)*(.+?)(?:\s*&&|\s*$|\s*\\)", re.DOTALL
        ),
    ),
    (
        "rpm",
        "dnf",
        re.compile(
            r"dnf\s+install\s+(?:-[^\s]+\s+)*(.+?)(?:\s*&&|\s*$|\s*\\)", re.DOTALL
        ),
    ),
    (
        "pip",
        "pip",
        re.compile(
            r"pip(?:3)?\s+install\s+(?:--[^\s]+\s+)*(.+?)(?:\s*&&|\s*$|\s*\\)",
            re.DOTALL,
        ),
    ),
    (
        "npm",
        "npm",
        re.compile(
            r"npm\s+install\s+(?:-[^\s]+\s+)*(.+?)(?:\s*&&|\s*$|\s*\\)", re.DOTALL
        ),
    ),
    (
        "gem",
        "gem",
        re.compile(
            r"gem\s+install\s+(?:--[^\s]+\s+)*(.+?)(?:\s*&&|\s*$|\s*\\)", re.DOTALL
        ),
    ),
]

_PKG_TOKEN = re.compile(r"[A-Za-z0-9_\-\.]+(?:=[^\s]+)?")
_VERSION_SEP = re.compile(r"[=><~!]+")


def _parse_pkg(token: str, pkg_type: str) -> tuple[str, str]:
    """Split 'pkg=1.2.3' into (name, version)."""
    parts = _VERSION_SEP.split(token, maxsplit=1)
    name = parts[0].strip()
    version = parts[1].strip() if len(parts) > 1 else ""
    return name, version


def _make_purl(pkg_type: str, name: str, version: str) -> str:
    if not name:
        return ""
    v = f"@{version}" if version else ""
    return f"pkg:{pkg_type}/{name}{v}"


def extract_components(layers: list[Any]) -> list[Component]:
    components: list[Component] = []
    for layer in layers:
        if layer.instruction != "RUN":
            continue
        args = layer.arguments
        for pkg_type, _, pattern in _INSTALLERS:
            for match in pattern.finditer(args):
                raw_pkgs = match.group(1)
                for token in _PKG_TOKEN.findall(raw_pkgs):
                    if token.startswith("-"):
                        continue
                    name, version = _parse_pkg(token, pkg_type)
                    if len(name) < 2:
                        continue
                    components.append(
                        Component(
                            name=name,
                            version=version,
                            pkg_type=pkg_type,
                            source_layer=layer.index,
                            stage=layer.stage,
                            purl=_make_purl(pkg_type, name, version),
                        )
                    )
    return components


def generate_cyclonedx(
    components: list[Component],
    image_name: str = "unknown",
    dockerfile_path: str = "Dockerfile",
) -> dict:
    """Return a CycloneDX 1.5 BOM as a Python dict (serialise to JSON)."""
    now = datetime.now(timezone.utc).isoformat()
    bom_ref = str(uuid.uuid4())

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{bom_ref}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "DockerDNA",
                    "name": "DockerDNA SBOM Generator",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "container",
                "name": image_name,
                "version": "unknown",
                "properties": [
                    {"name": "dockerdna:dockerfile", "value": dockerfile_path}
                ],
            },
        },
        "components": [c.to_cyclonedx() for c in components],
    }
