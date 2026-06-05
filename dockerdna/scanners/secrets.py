"""
Secrets detection scanner.

Finds hardcoded secrets, tokens, and credentials in:
  - Dockerfiles
  - docker-compose.yml / docker-compose.yaml
  - .env files
  - Any additional files passed

Uses two complementary strategies:
  1. Regex pattern matching against 20+ known secret formats
  2. Shannon entropy analysis to catch unknown high-entropy tokens

Neither strategy is used by DockSec, Trivy, or Hadolint.
"""

import re
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dockerdna.utils.patterns import (
    SECRET_PATTERNS,
    is_high_entropy_secret,
    ENTROPY_THRESHOLD,
)


@dataclass
class SecretFinding:
    file: str
    line_number: int
    line_content: str
    secret_type: str
    severity: str
    cis_id: str
    matched_value: str
    detection_method: str   # "pattern" | "entropy"
    entropy_score: Optional[float] = None
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line_number,
            "content": self.line_content.rstrip(),
            "type": self.secret_type,
            "severity": self.severity,
            "cis_id": self.cis_id,
            "matched_value": self.matched_value,
            "detection": self.detection_method,
            "entropy": self.entropy_score,
            "remediation": self.remediation,
        }


# Token extractor: grab quoted and unquoted values from assignment-style lines
_ASSIGNMENT_VALUE = re.compile(
    r"(?:=|:\s*)\"?([A-Za-z0-9+/!@#$%^&*()\-_=.]{20,})\"?"
)

_REMEDIATIONS = {
    "pattern": (
        "Remove the secret from the file and rotate it immediately. "
        "Inject at runtime using Docker secrets, BuildKit --secret mounts, "
        "or a vault integration (e.g. HashiCorp Vault, AWS Secrets Manager)."
    ),
    "entropy": (
        "High-entropy string detected - likely a key or token. "
        "Verify whether this is a credential and, if so, rotate and move it "
        "to a runtime secret store."
    ),
}


class SecretsScanner:
    """Scan files for hardcoded secrets using pattern + entropy analysis."""

    def __init__(self, redact: bool = True):
        self.redact = redact
        self._compiled = [
            (name, re.compile(pattern, re.MULTILINE), sev, cis)
            for name, pattern, sev, cis in SECRET_PATTERNS
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, path: str | Path) -> list[SecretFinding]:
        path = Path(path)
        if not path.exists():
            return []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []
        findings: list[SecretFinding] = []
        for lineno, line in enumerate(lines, start=1):
            findings.extend(self._check_line(str(path), lineno, line))
        return findings

    def scan_directory(self, directory: str | Path,
                       extensions: tuple[str, ...] = (
                           "", ".yml", ".yaml", ".env",
                           ".env.example", ".cfg", ".ini", ".conf",
                       )) -> list[SecretFinding]:
        directory = Path(directory)
        findings: list[SecretFinding] = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", "node_modules"}]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in extensions or fname in (
                    "Dockerfile", ".env", ".env.local", ".env.production"
                ):
                    findings.extend(self.scan_file(fpath))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_line(self, filepath: str, lineno: int, line: str) -> list[SecretFinding]:
        results: list[SecretFinding] = []
        stripped = line.strip()

        # Skip obvious false positives
        if stripped.startswith("#") or not stripped:
            return results

        # 1. Pattern matching
        for name, regex, severity, cis_id in self._compiled:
            match = regex.search(line)
            if match:
                raw = match.group(0)
                value = self._redact(raw) if self.redact else raw
                results.append(SecretFinding(
                    file=filepath,
                    line_number=lineno,
                    line_content=line,
                    secret_type=name,
                    severity=severity,
                    cis_id=cis_id,
                    matched_value=value,
                    detection_method="pattern",
                    remediation=_REMEDIATIONS["pattern"],
                ))
                return results   # one finding per line is enough

        # 2. Entropy analysis on assignment RHS values
        for m in _ASSIGNMENT_VALUE.finditer(line):
            token = m.group(1)
            if is_high_entropy_secret(token):
                value = self._redact(token) if self.redact else token
                from dockerdna.utils.patterns import shannon_entropy
                score = round(shannon_entropy(token), 3)
                results.append(SecretFinding(
                    file=filepath,
                    line_number=lineno,
                    line_content=line,
                    secret_type="High-Entropy String",
                    severity="HIGH",
                    cis_id="CIS-4.10",
                    matched_value=value,
                    detection_method="entropy",
                    entropy_score=score,
                    remediation=_REMEDIATIONS["entropy"],
                ))
                break   # one per line

        return results

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 8:
            return "****"
        return value[:4] + "****" + value[-4:]
