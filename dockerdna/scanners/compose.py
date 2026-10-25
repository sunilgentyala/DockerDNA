"""
docker-compose.yml security scanner.

Audits runtime configuration in docker-compose files - catching
misconfigurations (privileged mode, socket mounts, missing resource
limits, host networking) that never appear in a Dockerfile-only scan.

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
    file: str = ""

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "check": self.check_key,
            "cis_id": self.cis_id,
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "line_hint": self.line_hint,
            "file": self.file,
            "remediation": self.remediation,
        }


# check_key -> compose key the finding points at; checks about a missing
# setting are anchored to the service line instead.
_YAML_KEY = {
    "privileged": "privileged",
    "excess_capabilities": "cap_add",
    "docker_socket": "volumes",
    "sensitive_mount": "volumes",
    "host_network": "network_mode",
    "privileged_ports": "ports",
    "latest_tag": "image",
    "no_user": "user",
    "env_secret": "environment",
}


def _node_text(node: Any) -> str:
    """Flatten a YAML scalar or mapping node to text for needle matching."""
    if isinstance(node, yaml.ScalarNode):
        return str(node.value)
    if isinstance(node, yaml.MappingNode):
        return " ".join(_node_text(n) for pair in node.value for n in pair)
    return ""


_TRUE_STRINGS = {"true", "yes", "on", "1"}


def _truthy(value: Any) -> bool:
    """Compose accepts booleans and their string spellings ("true", "yes", ...)."""
    if isinstance(value, str):
        return value.strip().lower() in _TRUE_STRINGS
    return value is True or value == 1


class ComposeScanner:
    """Parse and security-audit docker-compose files.

    Anything that stops a file from being fully analysed (missing file,
    unreadable, invalid YAML, PyYAML absent) is recorded in ``self.errors``
    rather than silently producing an empty, clean-looking result.
    """

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.images: list[tuple[str, str]] = []  # (service, image ref)
        self.env_files: list[Path] = []  # resolved env_file paths
        self._file = ""
        self._svc_nodes: dict[str, Any] = {}  # service name -> YAML node

    def scan(self, path: str | Path) -> list[ComposeFinding]:
        path = Path(path)
        if not path.exists():
            self.errors.append(f"{path}: compose file not found")
            return []
        if yaml is None:
            self.errors.append(f"{path}: PyYAML is not installed, compose not scanned")
            return []
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            doc = yaml.safe_load(raw)
        except Exception as exc:
            self.errors.append(
                f"{path}: cannot parse compose file ({type(exc).__name__})"
            )
            return []

        if not isinstance(doc, dict):
            self.errors.append(f"{path}: compose file is not a YAML mapping")
            return []

        self._base_dir = path.parent
        self._file = str(path)
        self._svc_nodes = self._service_nodes(raw)
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

        # CIS-5.4 - privileged
        if _truthy(cfg.get("privileged")):
            findings.append(self._make(name, "privileged", "Privileged mode enabled"))

        image = cfg.get("image")
        if isinstance(image, str) and image.strip():
            self.images.append((name, image.strip()))
            ref = image.strip()
            if "@sha256:" not in ref and not ref.startswith("${"):
                last = ref.rsplit("/", 1)[-1]
                if ":" not in last or last.endswith(":latest"):
                    findings.append(
                        self._make(
                            name, "latest_tag", f"Image '{ref}' uses :latest or no tag"
                        )
                    )

        env_file = cfg.get("env_file")
        entries = env_file if isinstance(env_file, list) else [env_file]
        for entry in entries:
            if isinstance(entry, dict):
                entry = entry.get("path")
            if isinstance(entry, str) and entry:
                self.env_files.append(self._base_dir / entry)

        # Service runs as root explicitly
        svc_user = str(cfg.get("user", "") or "").strip().split(":")[0]
        if svc_user in ("root", "0"):
            findings.append(
                self._make(
                    name, "no_user", f"Service runs as root (user: {cfg.get('user')})"
                )
            )

        # CIS-5.3 - cap_add: [ALL] or dangerous caps
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

        # CIS-5.13 - Docker socket mount
        volumes = cfg.get("volumes", []) or []
        for vol in volumes:
            src = self._vol_source(vol)
            if src and ("docker.sock" in src):
                findings.append(
                    self._make(
                        name, "docker_socket", f"Docker socket mounted: {src}", src
                    )
                )

        # CIS-5.5 - sensitive filesystem mounts
        for vol in volumes:
            src = self._vol_source(vol)
            if src and any(
                src.startswith(p)
                for p in SENSITIVE_PATHS
                if p != "/var/run/docker.sock"
            ):
                findings.append(
                    self._make(
                        name, "sensitive_mount", f"Sensitive path mounted: {src}", src
                    )
                )

        # CIS-5.9 - host network
        net_mode = cfg.get("network_mode", "") or ""
        if str(net_mode).lower() == "host":
            findings.append(self._make(name, "host_network", "network_mode: host"))

        # CIS-5.10 - memory limit
        deploy = cfg.get("deploy", {}) or {}
        resources = deploy.get("resources", {}) or {}
        limits = resources.get("limits", {}) or {}
        has_mem_deploy = bool(limits.get("memory"))
        has_mem_old = bool(cfg.get("mem_limit"))
        if not has_mem_deploy and not has_mem_old:
            findings.append(
                self._make(name, "no_memory_limit", "No memory limit defined")
            )

        # CIS-5.11 - CPU limit
        has_cpu_deploy = bool(limits.get("cpus"))
        has_cpu_old = bool(cfg.get("cpus") or cfg.get("cpu_shares"))
        if not has_cpu_deploy and not has_cpu_old:
            findings.append(self._make(name, "no_cpu_limit", "No CPU limit defined"))

        # CIS-5.12 - read-only root filesystem
        if not cfg.get("read_only"):
            findings.append(
                self._make(name, "no_readonly_fs", "read_only not set to true")
            )

        # CIS-5.14 - no-new-privileges
        sec_opts = cfg.get("security_opt", []) or []
        has_nnp = any("no-new-privileges" in str(o) for o in sec_opts)
        if not has_nnp:
            findings.append(
                self._make(
                    name, "no_new_privileges", "no-new-privileges not in security_opt"
                )
            )

        # CIS-5.7 - privileged ports (< 1024) published to host
        ports = cfg.get("ports", []) or []
        for port_entry in ports:
            host_port = self._host_port(port_entry)
            if host_port is not None and host_port < 1024:
                findings.append(
                    self._make(
                        name,
                        "privileged_ports",
                        f"Privileged port exposed: {host_port}",
                        str(port_entry),
                    )
                )

        # CIS-5.1 - no AppArmor profile
        has_apparmor = any("apparmor" in str(o).lower() for o in sec_opts)
        if not has_apparmor:
            findings.append(
                self._make(name, "no_apparmor", "No AppArmor security profile defined")
            )

        # CIS-4.6 - healthcheck
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
                            line_hint=self._line(name, "environment", k),
                            file=self._file,
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

    def _make(
        self,
        service: str,
        check_key: str,
        detail: str,
        needle: Optional[str] = None,
    ) -> ComposeFinding:
        line = self._line(service, _YAML_KEY.get(check_key), needle)
        rule = CIS_RULE_MAP.get(check_key)
        if rule:
            return ComposeFinding(
                service=service,
                check_key=check_key,
                cis_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                detail=detail,
                line_hint=line,
                remediation=rule.remediation,
                file=self._file,
            )
        return ComposeFinding(
            service=service,
            check_key=check_key,
            cis_id="CIS-UNKNOWN",
            title=check_key,
            severity="MEDIUM",
            detail=detail,
            line_hint=line,
            remediation="Review the docker-compose configuration.",
            file=self._file,
        )

    @staticmethod
    def _service_nodes(raw: str) -> dict[str, Any]:
        """Map service name -> YAML node so findings can carry real line numbers."""
        try:
            root = yaml.compose(raw)
        except Exception:
            return {}
        if not isinstance(root, yaml.MappingNode):
            return {}
        for k, v in root.value:
            if getattr(k, "value", None) == "services" and isinstance(
                v, yaml.MappingNode
            ):
                return {
                    sk.value: (sk, sv)
                    for sk, sv in v.value
                    if isinstance(sk, yaml.ScalarNode)
                }
        return {}

    def _line(
        self, service: str, key: Optional[str], needle: Optional[str] = None
    ) -> Optional[int]:
        """1-based line of ``key`` (or of the list item / mapping key matching
        ``needle``) inside ``service``; falls back to the service's own line."""
        entry = self._svc_nodes.get(service)
        if entry is None:
            return None
        svc_key, svc_val = entry
        line = svc_key.start_mark.line + 1
        if key is None or not isinstance(svc_val, yaml.MappingNode):
            return line
        for k, v in svc_val.value:
            if getattr(k, "value", None) != key:
                continue
            line = k.start_mark.line + 1
            if needle is None:
                return line
            if isinstance(v, yaml.SequenceNode):
                # exact entry first, then "needle:..." (volume source), then substring
                for match in (
                    lambda t: t == needle,
                    lambda t: t.startswith(needle + ":"),
                    lambda t: needle in t,
                ):
                    for item in v.value:
                        if match(_node_text(item)):
                            return item.start_mark.line + 1
            elif isinstance(v, yaml.MappingNode):
                for ik, _iv in v.value:
                    if getattr(ik, "value", None) == needle:
                        return ik.start_mark.line + 1
            return line
        return line

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
