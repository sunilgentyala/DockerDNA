"""
Secret patterns, CIS Docker Benchmark rules, and detection utilities.
"""

import math
import string
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Secret patterns (format: name, regex, severity, cis_id)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    # Cloud providers
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "CRITICAL", "CIS-4.10"),
    (
        "AWS Secret Access Key",
        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "CRITICAL",
        "CIS-4.10",
    ),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "CRITICAL", "CIS-4.10"),
    ("Google OAuth Token", r"ya29\.[0-9A-Za-z\-_]+", "HIGH", "CIS-4.10"),
    (
        "Azure Connection String",
        r"DefaultEndpointsProtocol=https;AccountName=",
        "CRITICAL",
        "CIS-4.10",
    ),
    ("Azure SAS Token", r"sig=[A-Za-z0-9%+/=]{43,}", "CRITICAL", "CIS-4.10"),
    # Auth tokens
    (
        "Generic API Key",
        r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
        "HIGH",
        "CIS-4.10",
    ),
    (
        "Generic Secret",
        r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*()_\-+=]{8,}['\"]?",
        "HIGH",
        "CIS-4.10",
    ),
    (
        "Bearer Token",
        r"[Bb]earer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+",
        "HIGH",
        "CIS-4.10",
    ),
    (
        "JWT Token",
        r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+",
        "HIGH",
        "CIS-4.10",
    ),
    # Private keys
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "CRITICAL", "CIS-4.10"),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "CRITICAL", "CIS-4.10"),
    (
        "OpenSSH Private Key",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "CRITICAL",
        "CIS-4.10",
    ),
    ("PEM Certificate", r"-----BEGIN CERTIFICATE-----", "MEDIUM", "CIS-4.10"),
    # Source control / CI
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9]{36,}", "CRITICAL", "CIS-4.10"),
    ("GitLab Token", r"glpat-[A-Za-z0-9\-_]{20}", "CRITICAL", "CIS-4.10"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}", "HIGH", "CIS-4.10"),
    ("Stripe Key", r"sk_(live|test)_[0-9a-zA-Z]{24}", "CRITICAL", "CIS-4.10"),
    ("Twilio SID", r"AC[a-f0-9]{32}", "HIGH", "CIS-4.10"),
    # Database URIs
    (
        "Database URI",
        r"(?i)(mysql|postgresql|postgres|mongodb|redis|mssql)://[^@\s]+:[^@\s]+@",
        "CRITICAL",
        "CIS-4.10",
    ),
    (
        "Connection String",
        r"(?i)(Server|Data Source)=[^;]+;(User ID|uid)=[^;]+;(Password|pwd)=[^;]+",
        "CRITICAL",
        "CIS-4.10",
    ),
    # Dockerfile-specific
    (
        "Hardcoded ENV Secret",
        r"(?i)^ENV\s+(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*\S+",
        "CRITICAL",
        "CIS-4.9",
    ),
    (
        "ARG Secret",
        r"(?i)^ARG\s+(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*\S+",
        "HIGH",
        "CIS-4.9",
    ),
]

# ---------------------------------------------------------------------------
# High-entropy string detection
# ---------------------------------------------------------------------------

ENTROPY_THRESHOLD = 4.5  # Shannon entropy threshold for secrets
MIN_SECRET_LENGTH = 20
ENTROPY_CHARSET = string.ascii_letters + string.digits + "+/="


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {c: data.count(c) / len(data) for c in set(data)}
    return -sum(p * math.log2(p) for p in freq.values())


def is_high_entropy_secret(token: str) -> bool:
    if len(token) < MIN_SECRET_LENGTH:
        return False
    charset = set(token)
    if not charset.issubset(set(ENTROPY_CHARSET)):
        return False
    return shannon_entropy(token) >= ENTROPY_THRESHOLD


# ---------------------------------------------------------------------------
# CIS Docker Benchmark v1.6 rules
# ---------------------------------------------------------------------------


@dataclass
class CISRule:
    id: str
    title: str
    level: int  # 1 or 2
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    remediation: str
    check_key: str  # internal key used by the compliance scanner


CIS_RULES: list[CISRule] = [
    # Section 4 — Container Images
    CISRule(
        "CIS-4.1",
        "Ensure a user for the container has been created",
        1,
        "HIGH",
        "Containers should not run as root. A non-root USER instruction is required.",
        "Add `USER nonroot` or a specific UID before the final CMD/ENTRYPOINT.",
        "no_user",
    ),
    CISRule(
        "CIS-4.2",
        "Ensure container images do not use the latest tag",
        1,
        "MEDIUM",
        "Using `latest` makes builds non-deterministic and bypasses known-vulnerability pinning.",
        "Pin the base image to a specific digest or version tag.",
        "latest_tag",
    ),
    CISRule(
        "CIS-4.3",
        "Ensure unnecessary packages are not installed",
        1,
        "MEDIUM",
        "Installing debug tools or package managers in production images increases attack surface.",
        "Use multi-stage builds; only copy the final artifact into a minimal base image.",
        "unnecessary_packages",
    ),
    CISRule(
        "CIS-4.4",
        "Ensure images are scanned for vulnerabilities",
        1,
        "HIGH",
        "Images must be scanned with a CVE scanner before deployment.",
        "Integrate Trivy, Grype, or Snyk in the CI pipeline.",
        "no_scan_evidence",
    ),
    CISRule(
        "CIS-4.5",
        "Ensure Content Trust is enabled",
        2,
        "MEDIUM",
        "Docker Content Trust ensures images are signed and verified.",
        "Set DOCKER_CONTENT_TRUST=1 in the build environment.",
        "no_content_trust",
    ),
    CISRule(
        "CIS-4.6",
        "Ensure HEALTHCHECK is defined",
        1,
        "LOW",
        "Without HEALTHCHECK the orchestrator cannot detect a broken container.",
        "Add a HEALTHCHECK instruction to the Dockerfile.",
        "no_healthcheck",
    ),
    CISRule(
        "CIS-4.7",
        "Ensure update instructions are not used alone",
        1,
        "MEDIUM",
        "`apt-get update` without `apt-get install` in the same RUN causes stale cache layers.",
        "Combine update and install in a single RUN instruction.",
        "update_without_install",
    ),
    CISRule(
        "CIS-4.8",
        "Ensure setuid/setgid bits are removed",
        2,
        "HIGH",
        "Binaries with setuid/setgid can allow privilege escalation.",
        "Add `RUN find / -perm /6000 -type f -exec chmod a-s {} +` to the Dockerfile.",
        "setuid_binaries",
    ),
    CISRule(
        "CIS-4.9",
        "Ensure sensitive data is not stored in Dockerfile ENV/ARG",
        1,
        "CRITICAL",
        "Secrets in ENV or ARG are baked into the image layer history.",
        "Use Docker secrets, BuildKit --secret, or external secret managers.",
        "env_secret",
    ),
    CISRule(
        "CIS-4.10",
        "Ensure secrets are not hardcoded in image layers",
        1,
        "CRITICAL",
        "Hardcoded credentials, tokens, or keys in any layer are extractable.",
        "Rotate any exposed credentials; use runtime secret injection.",
        "hardcoded_secret",
    ),
    # Section 5 — Container Runtime
    CISRule(
        "CIS-5.1",
        "Ensure AppArmor Profile is applied",
        1,
        "MEDIUM",
        "Containers should run with an AppArmor profile to restrict syscalls.",
        "Add `--security-opt apparmor=<profile>` to docker run / compose.",
        "no_apparmor",
    ),
    CISRule(
        "CIS-5.2",
        "Ensure SELinux security options are set",
        2,
        "MEDIUM",
        "SELinux labels provide MAC enforcement for containers.",
        "Add `security_opt: ['label:type:container_t']` to the service.",
        "no_selinux",
    ),
    CISRule(
        "CIS-5.3",
        "Ensure Linux Kernel capabilities are restricted",
        1,
        "HIGH",
        "`cap_add: [ALL]` or `--privileged` grants full kernel access.",
        "Drop all capabilities and add only what is needed: `cap_drop: [ALL]`.",
        "excess_capabilities",
    ),
    CISRule(
        "CIS-5.4",
        "Ensure privileged containers are not used",
        1,
        "CRITICAL",
        "Privileged containers have unrestricted access to the host kernel.",
        "Remove `privileged: true`; use specific capabilities instead.",
        "privileged",
    ),
    CISRule(
        "CIS-5.5",
        "Ensure sensitive host filesystem paths are not mounted",
        1,
        "HIGH",
        "Mounting /etc, /proc, or the Docker socket exposes the host.",
        "Remove sensitive bind mounts; use named volumes.",
        "sensitive_mount",
    ),
    CISRule(
        "CIS-5.6",
        "Ensure sshd is not running inside containers",
        1,
        "MEDIUM",
        "SSH inside a container provides a backdoor and blurs security boundaries.",
        "Use `docker exec` for debugging instead.",
        "ssh_in_container",
    ),
    CISRule(
        "CIS-5.7",
        "Ensure privileged ports are not mapped",
        1,
        "MEDIUM",
        "Mapping ports < 1024 from a container requires elevated privileges.",
        "Use ports >= 1024 and reverse-proxy externally.",
        "privileged_ports",
    ),
    CISRule(
        "CIS-5.8",
        "Ensure only needed ports are open",
        1,
        "LOW",
        "Publishing all ports (`-P`) may expose unintended services.",
        "Explicitly list only required ports.",
        "all_ports_open",
    ),
    CISRule(
        "CIS-5.9",
        "Ensure host network mode is not used",
        1,
        "HIGH",
        "`network_mode: host` bypasses network isolation.",
        "Use a user-defined bridge network.",
        "host_network",
    ),
    CISRule(
        "CIS-5.10",
        "Ensure memory is limited",
        1,
        "LOW",
        "No memory limit allows a container to consume all host memory (DoS).",
        "Set `mem_limit` or `resources.limits.memory` in docker-compose.",
        "no_memory_limit",
    ),
    CISRule(
        "CIS-5.11",
        "Ensure CPU priority is set",
        2,
        "LOW",
        "Unlimited CPU can starve other containers.",
        "Set `cpu_shares` or `cpus` in docker-compose.",
        "no_cpu_limit",
    ),
    CISRule(
        "CIS-5.12",
        "Ensure the container root filesystem is mounted as read-only",
        1,
        "MEDIUM",
        "A writable root filesystem allows attackers to persist changes.",
        "Set `read_only: true` in docker-compose.",
        "no_readonly_fs",
    ),
    CISRule(
        "CIS-5.13",
        "Ensure Docker socket is not mounted inside containers",
        1,
        "CRITICAL",
        "The Docker socket gives a container full control over the Docker daemon.",
        "Remove `/var/run/docker.sock` volume mounts.",
        "docker_socket",
    ),
    CISRule(
        "CIS-5.14",
        "Ensure no-new-privileges is set",
        1,
        "HIGH",
        "Without `no-new-privileges`, a setuid binary can escalate privileges.",
        "Add `security_opt: ['no-new-privileges:true']`.",
        "no_new_privileges",
    ),
]

# Lookup by check_key
CIS_RULE_MAP: dict[str, CISRule] = {r.check_key: r for r in CIS_RULES}
CIS_RULE_BY_ID: dict[str, CISRule] = {r.id: r for r in CIS_RULES}

# ---------------------------------------------------------------------------
# Sensitive path patterns for volume-mount analysis
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/root",
    "/home",
    "/boot",
    "/lib/modules",
    "/usr/lib",
    "/bin",
    "/sbin",
]

UNNECESSARY_PACKAGES = [
    "curl",
    "wget",
    "nc",
    "netcat",
    "ncat",
    "nmap",
    "telnet",
    "ftp",
    "vim",
    "nano",
    "emacs",
    "gcc",
    "g++",
    "make",
    "gdb",
    "strace",
    "ltrace",
    "perl",
    "ruby",
    "python2",
    "python2.7",
    "ssh",
    "openssh-server",
    "sshd",
]
