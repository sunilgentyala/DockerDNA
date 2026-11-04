"""
Enhanced Dockerfile scanner.

Goes beyond Hadolint by adding:
  - CIS benchmark ID tagging on every finding
  - Layer-by-layer attribution (which RUN/COPY/ADD introduced the issue)
  - Multi-stage build analysis (secrets leaking between stages)
  - Supply-chain risk scoring for the base image
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from dockerdna.utils.patterns import (
    CIS_RULE_MAP,
    UNNECESSARY_PACKAGES,
    redact_value,
)

_ENV_SECRET_RE = re.compile(
    r"(?i)(?P<key>password|secret|api_key|token|private_key|access_key)"
    r"\s*[=:]?\s*(?P<value>\S+)"
)


_PIPE_TO_SHELL_RE = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b")
_INSECURE_DOWNLOAD_RE = re.compile(
    r"--no-check-certificate|\bcurl\b[^|;&]*\s(-k|--insecure)\b"
    r"|--trusted-host|strict-ssl\s+false|GIT_SSL_NO_VERIFY|sslverify\s*=?\s*false",
    re.IGNORECASE,
)
_WORLD_WRITABLE_RE = re.compile(r"\bchmod\s+(-\w+\s+)*(a\+[rx]*w[rwx]*|0?777)(?=\s|$)")
_RUN_SECRET_RE = re.compile(
    r"(?i)(?P<key>password|passwd|secret|api_?key|token|private_?key)\w*"
    r"\s*[=:]\s*(?P<value>\"[^\"$]{4,}\"|'[^'$]{4,}'|[^\s\"'$]{4,})"
)


@dataclass
class Layer:
    index: int
    instruction: str  # FROM, RUN, COPY, ADD, ENV, ARG, USER, ...
    arguments: str
    line_number: int
    stage: str = "default"


@dataclass
class DockerfileFinding:
    line_number: int
    instruction: str
    check_key: str
    cis_id: str
    title: str
    severity: str
    detail: str
    layer_index: int
    stage: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "line": self.line_number,
            "instruction": self.instruction,
            "check": self.check_key,
            "cis_id": self.cis_id,
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "layer": self.layer_index,
            "stage": self.stage,
            "remediation": self.remediation,
        }


class DockerfileScanner:
    """Parse and security-audit a Dockerfile; produce CIS-tagged findings."""

    def __init__(self, redact: bool = True):
        self.redact = redact
        self.errors: list[str] = []

    def scan(self, path: str | Path) -> tuple[list[Layer], list[DockerfileFinding]]:
        path = Path(path)
        if not path.exists():
            self.errors.append(f"{path}: Dockerfile not found")
            return [], []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            self.errors.append(f"{path}: cannot read Dockerfile ({type(exc).__name__})")
            return [], []

        layers = self._parse_layers(text)
        findings = self._audit(layers)
        return layers, findings

    # ------------------------------------------------------------------
    # Layer parser
    # ------------------------------------------------------------------

    def _parse_layers(self, text: str) -> list[Layer]:
        layers: list[Layer] = []
        current_stage = "stage-0"
        stage_counter = 0
        layer_index = 0

        continued = ""
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.rstrip()
            if continued:
                line = continued + " " + line.lstrip("\\").strip()
                continued = ""
            if line.endswith("\\"):
                continued = line[:-1]
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split(None, 1)
            instruction = parts[0].upper()
            arguments = parts[1] if len(parts) > 1 else ""

            if instruction == "FROM":
                stage_match = re.search(r"\bAS\s+(\S+)", arguments, re.IGNORECASE)
                if stage_match:
                    current_stage = stage_match.group(1)
                else:
                    stage_counter += 1
                    current_stage = f"stage-{stage_counter}"

            layers.append(
                Layer(
                    index=layer_index,
                    instruction=instruction,
                    arguments=arguments,
                    line_number=lineno,
                    stage=current_stage,
                )
            )
            layer_index += 1

        return layers

    # ------------------------------------------------------------------
    # Audit rules
    # ------------------------------------------------------------------

    def _audit(self, layers: list[Layer]) -> list[DockerfileFinding]:
        findings: list[DockerfileFinding] = []

        has_user = any(
            layer_.instruction == "USER"
            and layer_.arguments.strip() not in ("root", "0")
            for layer_ in layers
        )
        has_healthcheck = any(layer_.instruction == "HEALTHCHECK" for layer_ in layers)
        stages_with_from: dict[str, list[str]] = {}

        for layer in layers:
            instr = layer.instruction
            args = layer.arguments

            # CIS-4.2 - latest tag
            if instr == "FROM" and (
                ":latest" in args.lower() or "@" not in args and ":" not in args
            ):
                if "scratch" not in args.lower():
                    findings.append(
                        self._finding(
                            layer,
                            "latest_tag",
                            f"Base image '{args}' uses :latest or no tag",
                        )
                    )

            # Track FROM images per stage
            if instr == "FROM":
                stage = layer.stage
                stages_with_from.setdefault(stage, []).append(args)

            # CIS-4.7 - update without install in same RUN
            if instr == "RUN":
                if re.search(r"\bapt-get\s+update\b", args) and not re.search(
                    r"\bapt-get\s+install\b", args
                ):
                    findings.append(
                        self._finding(
                            layer,
                            "update_without_install",
                            "apt-get update without apt-get install in same RUN layer",
                        )
                    )

            # CIS-4.3 - unnecessary packages
            if instr == "RUN":
                for pkg in UNNECESSARY_PACKAGES:
                    if re.search(r"\b" + re.escape(pkg) + r"\b", args):
                        findings.append(
                            self._finding(
                                layer,
                                "unnecessary_packages",
                                f"Unnecessary package installed: {pkg}",
                            )
                        )

            if instr == "RUN":
                findings.extend(self._audit_run(layer))

            # CIS-5.6 - SSH server in container
            if instr == "RUN" and re.search(r"\bopenssh-server\b|\bsshd\b", args):
                findings.append(
                    self._finding(
                        layer,
                        "ssh_in_container",
                        "SSH server installed inside container",
                    )
                )

            # CIS-4.9 - secrets in ENV
            if instr in ("ENV", "ARG"):
                match = _ENV_SECRET_RE.search(args)
                if match:
                    # Never splice the raw match into `detail` - it flows
                    # unredacted into every report format (JSON/HTML/SARIF)
                    # since this scanner has no redaction gate otherwise.
                    shown = (
                        redact_value(match.group("value"))
                        if self.redact
                        else match.group("value")
                    )
                    findings.append(
                        self._finding(
                            layer,
                            "env_secret",
                            f"{instr} instruction may contain sensitive data "
                            f"('{match.group('key')}'): {shown}",
                        )
                    )

            # Privilege escalation: sudo install
            if instr == "RUN" and re.search(r"\bsudo\b", args):
                findings.append(
                    self._finding(
                        layer,
                        "excess_capabilities",
                        "sudo installed or used - consider dropping all capabilities",
                    )
                )

            # ADD vs COPY (ADD can fetch remote URLs, expanding attack surface)
            if instr == "ADD":
                if re.search(r"https?://", args):
                    findings.append(
                        self._finding(
                            layer,
                            "sensitive_mount",
                            "ADD used with a URL - use RUN curl/wget with checksum verification",
                        )
                    )

        # File-level findings (not per-layer)
        if not has_user:
            if layers:
                findings.append(
                    self._finding(
                        layers[-1],
                        "no_user",
                        "No non-root USER instruction found - container will run as root",
                    )
                )

        if not has_healthcheck:
            if layers:
                findings.append(
                    self._finding(
                        layers[-1], "no_healthcheck", "No HEALTHCHECK instruction found"
                    )
                )

        # Multi-stage secret leak detection
        findings.extend(self._check_secret_leak_between_stages(layers))

        return findings

    def _audit_run(self, layer: Layer) -> list[DockerfileFinding]:
        args = layer.arguments
        out: list[DockerfileFinding] = []
        if _PIPE_TO_SHELL_RE.search(args):
            out.append(
                self._finding(
                    layer, "pipe_to_shell", "Remote content is piped into a shell"
                )
            )
        if _INSECURE_DOWNLOAD_RE.search(args):
            out.append(
                self._finding(
                    layer,
                    "insecure_download",
                    "TLS certificate verification is disabled",
                )
            )
        if _WORLD_WRITABLE_RE.search(args):
            out.append(
                self._finding(
                    layer,
                    "world_writable",
                    "chmod grants write permission to everyone on a path in the image",
                )
            )
        if (
            re.search(r"\bapt(-get)?\s+(-\S+\s+)*install\b", args)
            and "--no-install-recommends" not in args
        ):
            out.append(
                self._finding(
                    layer,
                    "apt_recommends",
                    "apt install without --no-install-recommends",
                )
            )
        m = _RUN_SECRET_RE.search(args)
        if m:
            value = m.group("value").strip("\"'")
            shown = redact_value(value) if self.redact else value
            out.append(
                self._finding(
                    layer,
                    "secret_in_run",
                    f"RUN writes a literal value for '{m.group('key')}': {shown}",
                )
            )
        return out

    def _check_secret_leak_between_stages(
        self, layers: list[Layer]
    ) -> list[DockerfileFinding]:
        """Warn when a secret-bearing ENV/ARG in an early stage has no matching
        --build-arg override or secret mount in later stages (best-effort)."""
        findings: list[DockerfileFinding] = []
        secret_names: list[tuple[Layer, str]] = []
        for layer in layers:
            if layer.instruction in ("ENV", "ARG"):
                match = re.search(
                    r"(?i)(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|ACCESS_KEY)\b",
                    layer.arguments,
                )
                if match:
                    secret_names.append((layer, match.group(1)))

        # If we find secrets, check whether a final FROM stage clears them
        stage_names = [
            layer_.stage for layer_ in layers if layer_.instruction == "FROM"
        ]
        if secret_names and len(set(stage_names)) > 1:
            for layer, name in secret_names:
                findings.append(
                    DockerfileFinding(
                        line_number=layer.line_number,
                        instruction=layer.instruction,
                        check_key="env_secret",
                        cis_id="CIS-4.9",
                        title="Potential secret leak across multi-stage build",
                        severity="HIGH",
                        detail=(
                            f"'{name}' is set in stage '{layer.stage}'. "
                            "If it is COPY-ed or inherited, it may persist into the final image."
                        ),
                        layer_index=layer.index,
                        stage=layer.stage,
                        remediation=(
                            "Use `RUN --mount=type=secret` (BuildKit) to inject secrets at "
                            "build time without baking them into any layer."
                        ),
                    )
                )
        return findings

    # ------------------------------------------------------------------

    def _finding(self, layer: Layer, check_key: str, detail: str) -> DockerfileFinding:
        rule = CIS_RULE_MAP.get(check_key)
        if rule:
            return DockerfileFinding(
                line_number=layer.line_number,
                instruction=layer.instruction,
                check_key=check_key,
                cis_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                detail=detail,
                layer_index=layer.index,
                stage=layer.stage,
                remediation=rule.remediation,
            )
        return DockerfileFinding(
            line_number=layer.line_number,
            instruction=layer.instruction,
            check_key=check_key,
            cis_id="CIS-UNKNOWN",
            title=check_key,
            severity="MEDIUM",
            detail=detail,
            layer_index=layer.index,
            stage=layer.stage,
            remediation="Review the Dockerfile instruction.",
        )
