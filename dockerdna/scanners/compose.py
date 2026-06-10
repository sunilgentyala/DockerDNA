"""
docker-compose.yml security scanner.

DockSec scans only Dockerfiles and pre-built images.
DockerDNA extends analysis to docker-compose files — catching
runtime misconfigurations that never appear in the image itself.

Checks mapped to CIS Docker Benchmark v1.6 Section 5.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from dockerdna.utils.patterns import CIS_RULE_MAP, SENSITIVE_PATHS


@dataclass
class ComposeFinding:
    service: str
    check_key: str
    cis_id: str
    title: str
    severity: str
    detail: str
    line_hint: Optional[int]
    remediation: str

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "check": self.check_key,
            "cis_id": self.cis_id,
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "line_hint": self.line_hint,
            "remediation": self.remediation,
        }


class ComposeScanner:
    """Parse and security-audit docker-compose files."""

    def scan(self, path: str | Path) -> list[ComposeFinding]:
        path = Path(path)
        if not path.exists():
            return []
        if yaml is None:
            return []
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            doc = yaml.safe_load(raw)
        except Exception:
            return []

        if not isinstance(doc, dict):
            return []

        services = doc.get("services", {}) or {}
        findings: list[ComposeFinding] = []
        for svc_name, svc_conf in services.items():
            if not isinstance(svc_conf, dict):
                continue
            findings.extend(self._audit_service(svc_name, svc_conf))
        return findings

    # ------------------------------------------------------------------

    def _audit_service(self, name: str, cfg: dict) -> list[ComposeFinding]:
        findings: list[ComposeFinding] = []

        # CIS-5.4 — privileged
        if cfg.get("privileged") is True:
            findings.append(self._make(name, "privileged", "Privileged mode enabled"))

        # CIS-5.3 — cap_add: [ALL] or dangerous caps
        cap_add = cfg.get("cap_add", []) or []
        dangerous = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"}
        bad_caps = [c for c in cap_add if str(c).upper() in dangerous]
        if bad_caps:
            findings.append(
                self._make(
                    name,
                    "excess_capabilities",
                    f"Dangerous capabilities added: {bad_caps}",
                )
            )

        # CIS-5.13 — Docker socket mount
        volumes = cfg.get("volumes", []) or []
        for vol in volumes:
            src = self._vol_source(vol)
            if src and ("docker.sock" in src):
                findings.append(
                    self._make(name, "docker_socket", f"Docker socket mounted: {src}")
                )

        # CIS-5.5 — sensitive filesystem mounts
        for vol in volumes:
            src = self._vol_source(vol)
            if src and any(
                src.startswith(p)
                for p in SENSITIVE_PATHS
                if p != "/var/run/docker.sock"
            ):
                findings.append(
                    self._make(
                        name, "sensitive_mount", f"Sensitive path mounted: {src}"
                    )
                )

        # CIS-5.9 — host network
        net_mode = cfg.get("network_mode", "") or ""
        if str(net_mode).lower() == "host":
            findings.append(self._make(name, "host_network", "network_mode: host"))

        # CIS-5.10 — memory limit
        deploy = cfg.get("deploy", {}) or {}
        resources = deploy.get("resources", {}) or {}
        limits = resources.get("limits", {}) or {}
        has_mem_deploy = bool(limits.get("memory"))
        has_mem_old = bool(cfg.get("mem_limit"))
        if not has_mem_deploy and not has_mem_old:
            findings.append(
                self._make(name, "no_memory_limit", "No memory limit defined")
            )

        # CIS-5.11 — CPU limit
        has_cpu_deploy = bool(limits.get("cpus"))
        has_cpu_old = bool(cfg.get("cpus") or cfg.get("cpu_shares"))
        if not has_cpu_deploy and not has_cpu_old:
            findings.append(self._make(name, "no_cpu_limit", "No CPU limit defined"))

        # CIS-5.12 — read-only root filesystem
        if not cfg.get("read_only"):
            findings.append(
                self._make(name, "no_readonly_fs", "read_only not set to true")
            )

        # CIS-5.14 — no-new-privileges
        sec_opts = cfg.get("security_opt", []) or []
        has_nnp = any("no-new-privileges" in str(o) for o in sec_opts)
        if not has_nnp:
            findings.append(
                self._make(
                    name, "no_new_privileges", "no-new-privileges not in security_opt"
                )
            )

        # CIS-5.7 — privileged ports (< 1024) published to host
        ports = cfg.get("ports", []) or []
        for port_entry in ports:
            host_port = self._host_port(port_entry)
            if host_port is not None and host_port < 1024:
                findings.append(
                    self._make(
                        name,
                        "privileged_ports",
                        f"Privileged port exposed: {host_port}",
                    )
                )

        # CIS-5.1 — no AppArmor profile
        has_apparmor = any("apparmor" in str(o).lower() for o in sec_opts)
        if not has_apparmor:
            findings.append(
                self._make(name, "no_apparmor", "No AppArmor security profile defined")
            )

        # CIS-4.6 — healthcheck
        if not cfg.get("healthcheck"):
            findings.append(
                self._make(name, "no_healthcheck", "No healthcheck defined")
            )

        # Detect secrets in environment variables
        env = cfg.get("environment", {}) or {}
        if isinstance(env, list):
            env_dict = {}
            for item in env:
                if "=" in item:
                    k, v = item.split("=", 1)
                    env_dict[k] = v
            env = env_dict
        for k, v in env.items():
            if re.search(r"(?i)(password|secret|api_key|token|private_key)", k):
                if v and str(v) not in ("", "${%s}" % k, "$%s" % k):
                    findings.append(
                        ComposeFinding(
                            service=name,
                            check_key="env_secret",
                            cis_id="CIS-4.9",
                            title=(
                                CIS_RULE_MAP.get(
                                    "env_secret",
                                    type(
                                        "",
                                        (),
                                        {"title": "Secret in environment variable"},
                                    )(),
                                ).title
                                if hasattr(
                                    CIS_RULE_MAP.get("env_secret", None), "title"
                                )
                                else "Secret in environment variable"
                            ),
                            severity="CRITICAL",
                            detail=f"Possible secret in env var '{k}'",
                            line_hint=None,
                            remediation=(
                                "Use Docker secrets or a .env file excluded from version control. "
                                "Never hardcode credentials in docker-compose.yml."
                            ),
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make(self, service: str, check_key: str, detail: str) -> ComposeFinding:
        rule = CIS_RULE_MAP.get(check_key)
        if rule:
            return ComposeFinding(
                service=service,
                check_key=check_key,
                cis_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                detail=detail,
                line_hint=None,
                remediation=rule.remediation,
            )
        return ComposeFinding(
            service=service,
            check_key=check_key,
            cis_id="CIS-UNKNOWN",
            title=check_key,
            severity="MEDIUM",
            detail=detail,
            line_hint=None,
            remediation="Review the docker-compose configuration.",
        )

    @staticmethod
    def _vol_source(vol: Any) -> Optional[str]:
        if isinstance(vol, str):
            return vol.split(":")[0] if ":" in vol else None
        if isinstance(vol, dict):
            return vol.get("source") or vol.get("target")
        return None

    @staticmethod
    def _host_port(port_entry: Any) -> Optional[int]:
        """Extract the host-side port number from various compose port formats."""
        entry = str(port_entry)
        # "host:container" or "ip:host:container"
        parts = entry.split(":")
        try:
            if len(parts) >= 2:
                raw = parts[-2].split("/")[0]
                return int(raw)
        except (ValueError, IndexError):
            pass
        return None
