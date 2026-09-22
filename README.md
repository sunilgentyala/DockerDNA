# DockerDNA

**Layer-by-Layer Container Security DNA Analysis**

[![CI](https://github.com/sunilgentyala/DockerDNA/actions/workflows/ci.yml/badge.svg)](https://github.com/sunilgentyala/DockerDNA/actions)
[![PyPI](https://img.shields.io/pypi/v/dockerdna.svg)](https://pypi.org/project/dockerdna/)
[![Downloads](https://img.shields.io/pypi/dm/dockerdna.svg)](https://pypi.org/project/dockerdna/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Docker Benchmark](https://img.shields.io/badge/CIS-Docker%20Benchmark%20v1.6-orange)](https://www.cisecurity.org/benchmark/docker)

DockerDNA is an open-source container security scanner focused on **pre-build analysis**: layer-by-layer Dockerfile attribution, docker-compose.yml auditing, CIS-mapped findings, dual-mode secret detection (regex + Shannon entropy), supply-chain risk scoring, SARIF, and CycloneDX output. It's designed to complement tools like OWASP DockSec, Trivy, and Hadolint, not replace them.

---

## What Makes DockerDNA Unique

Verified against each project's public documentation, September 2026. Tools evolve quickly - always
check upstream docs before relying on this. "not documented" means the capability could not be
confirmed either way, not that it's absent.

| Capability | DockerDNA | DockSec | Trivy | Hadolint |
|---|:---:|:---:|:---:|:---:|
| Dockerfile security scan | YES | YES | partial (image/IaC scan) | YES |
| **docker-compose.yml scanner** | **YES** | YES | not documented | NO |
| **Secrets detection** | **YES (regex + entropy)** | YES (via Trivy) | YES (regex, built-in rules) | NO |
| **Entropy detection for unknown secrets** | **YES** | not documented | NO (regex-only) | NO |
| **CIS Docker Benchmark control-ID mapping** | **YES** | not documented | NO | NO |
| **SBOM (CycloneDX)** | **YES** | YES | YES | NO |
| **SARIF output** | **YES** | YES | YES | NO |
| **Supply chain image risk scoring** | **YES** | not documented | partial (CVE-based) | NO |
| **Multi-stage build secret leak detection** | **YES** | not documented | NO | NO |
| **CI/CD threshold gate** | **YES (--threshold)** | YES (--fail-on) | YES | NO |
| AI-powered remediation | YES (Claude) | YES (multi-LLM) | NO | NO |
| Layer-by-layer attribution | YES | not documented | NO | NO |

---

## Core Differentiators

### 1. Secrets Detection (Regex + Shannon Entropy)

DockerDNA scans Dockerfiles, docker-compose.yml, .env files, and any project file for:
- 20+ known secret formats (AWS keys, GitHub tokens, Google API keys, JWT, database URIs, ...)
- **High-entropy string analysis** using Shannon entropy - catches *unknown* credential formats that regex misses

```
[CRITICAL] CIS-4.10 Dockerfile line 5: AWS Access Key ID detected (method: pattern)
[HIGH]     CIS-4.10 .env line 12: High-Entropy String detected (entropy: 5.21, method: entropy)
```

### 2. docker-compose.yml Security Scanner

Audits docker-compose files and maps every finding to a specific CIS Docker Benchmark control ID:

```
[CRITICAL] CIS-5.4  webapp: Privileged mode enabled
[CRITICAL] CIS-5.13 webapp: Docker socket mounted: /var/run/docker.sock
[HIGH]     CIS-5.9  webapp: network_mode: host
[HIGH]     CIS-5.3  webapp: Dangerous capabilities added: ['ALL']
[MEDIUM]   CIS-5.12 webapp: read_only not set to true
```

### 3. CIS Docker Benchmark v1.6 Compliance Report

Every finding is tagged with its CIS control ID. A full scorecard is generated — real output
from `examples/Dockerfile.secure` + `examples/docker-compose.secure.yml`:

```
CIS Controls: 19 passed / 1 failed / 4 not-checked
Compliance Score: 95.0%
```

### 4. Supply Chain Risk Scoring

Each FROM instruction receives a 0-100 risk score based on:
- Registry trust (official vs community vs self-hosted)
- Tag specificity (digest > version > :latest)
- Docker Content Trust status
- Known malicious image name patterns

### 5. SARIF Output for GitHub Security Tab

Findings appear as inline PR annotations in the GitHub Security tab - no additional integration needed.

### 6. CycloneDX SBOM Generation

Parses every package install instruction (`apt-get`, `pip`, `npm`, `apk`, `yum`) to produce a CycloneDX 1.5 SBOM with PURL identifiers and layer attribution.

---

## Quick Start

**[View on PyPI](https://pypi.org/project/dockerdna/)**

```bash
pip install dockerdna

# Scan a Dockerfile
dockerdna Dockerfile

# Scan Dockerfile + docker-compose
dockerdna Dockerfile --compose docker-compose.yml

# Scan entire project directory
dockerdna --dir ./myapp

# All output formats
dockerdna Dockerfile --compose docker-compose.yml --format json html sarif sbom

# CI/CD gate: fail if any HIGH or above
dockerdna Dockerfile --threshold HIGH

# AI-powered remediation (requires ANTHROPIC_API_KEY)
dockerdna Dockerfile --compose docker-compose.yml --ai
```

Output is written to `./dockerdna-results/` by default.

---

## GitHub Actions Integration

```yaml
# .github/workflows/security.yml
name: Container Security

on: [push, pull_request]

jobs:
  dockerdna:
    runs-on: ubuntu-latest
    permissions:
      security-events: write

    steps:
      - uses: actions/checkout@v4
      - run: pip install dockerdna

      - name: Run DockerDNA
        run: |
          dockerdna Dockerfile \
            --compose docker-compose.yml \
            --format sarif json \
            --threshold HIGH \
            --output dockerdna-results

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: dockerdna-results/report.sarif
```

---

## Output Formats

| Format | File | Description |
|--------|------|-------------|
| `json` | `report.json` | Full structured report with all findings, compliance, and SBOM |
| `html` | `report.html` | Interactive dashboard with severity badges and CIS scorecard |
| `sarif` | `report.sarif` | SARIF 2.1.0 for GitHub Advanced Security integration |
| `sbom` | `sbom.cyclonedx.json` | CycloneDX 1.5 Software Bill of Materials |

---

## How It Works

```
┌────────────────────────────────────────────────────────┐
│                     DockerDNA Pipeline                  │
├──────────────┬──────────────┬─────────────┬────────────┤
│  Dockerfile  │   Compose    │   Secrets   │  Supply    │
│  Scanner     │   Scanner    │   Engine    │  Chain     │
│  (CIS 4.x)   │   (CIS 5.x)  │  Regex +    │  Scoring   │
│              │              │  Entropy    │            │
└──────┬───────┴──────┬───────┴──────┬──────┴─────┬──────┘
       │              │              │            │
       └──────────────┴──────────────┴────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  CIS Compliance   │
                    │  Mapper           │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
           JSON/HTML        SARIF           SBOM
           Reports      (GitHub Security)  (CycloneDX)
              │
              ▼ (optional)
        AI Remediation
        (Anthropic Claude)
```

---

## Comparison with OWASP DockSec

DockSec wraps Trivy, Hadolint, and Docker Scout with multi-LLM AI explanations and automated
patching, and (per its current docs, checked September 2026) also covers docker-compose scanning,
SARIF, SBOM, and a `--fail-on` CI gate. DockerDNA focuses specifically on pre-build analysis with a
few things not documented elsewhere:

- **Entropy-based secret detection.** DockSec's secret handling isn't publicly documented beyond
  redaction; Trivy (which DockSec wraps) is regex-only. DockerDNA's dual-mode scanner (pattern +
  Shannon entropy) also catches custom or rotated credentials that match no known pattern.
- **CIS Docker Benchmark control-ID mapping.** Every finding is tagged with its specific CIS v1.6
  control ID and rolled into a pass/fail/not-checked compliance scorecard, not just a severity bucket.
- **Layer-by-layer attribution.** Every finding traces back to the exact instruction and build stage
  that introduced it, including secrets that leak across multi-stage builds.

If you already use DockSec for its AI-powered explanations and automated Dockerfile patching,
DockerDNA is a good complement for pre-build compose/secrets/compliance analysis, not a replacement.

---

## Installation

```bash
# Core (no AI)
pip install dockerdna

# With AI remediation
pip install "dockerdna[ai]"

# Development
git clone https://github.com/sunilgentyala/DockerDNA.git
cd DockerDNA
pip install -e ".[dev]"
pytest
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required for `--ai` flag (AI remediation) |
| `DOCKER_CONTENT_TRUST` | Set to `1` to enable image signing verification |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) to get set up, [CHANGELOG.md](CHANGELOG.md) for what's
changed and what's on the roadmap, and [SECURITY.md](SECURITY.md) to report a vulnerability
(please don't file those as a public issue). This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## License

MIT License. See [LICENSE](LICENSE).

## Author

**Sunil Gentyala, Independent Researcher**
IEEE senior Member | Security Researcher
- IEEE: sunil.gentyala@ieee.org
- GitHub: [@sunilgentyala](https://github.com/sunilgentyala)
