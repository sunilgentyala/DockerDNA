# DockerDNA

**Layer-by-Layer Container Security DNA Analysis**

[![CI](https://github.com/sunilgentyala/DockerDNA/actions/workflows/ci.yml/badge.svg)](https://github.com/sunilgentyala/DockerDNA/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Docker Benchmark](https://img.shields.io/badge/CIS-Docker%20Benchmark%20v1.6-orange)](https://www.cisecurity.org/benchmark/docker)

DockerDNA is an open-source container security scanner that goes beyond static Dockerfile analysis to cover the **security gaps** left by existing tools including [OWASP DockSec](https://github.com/OWASP/DockSec).

---

## What Makes DockerDNA Unique

| Capability | DockerDNA | DockSec | Trivy | Hadolint |
|---|:---:|:---:|:---:|:---:|
| Dockerfile security scan | YES | YES | - | YES |
| **docker-compose.yml scanner** | **YES** | NO | NO | NO |
| **Secrets detection (regex + entropy)** | **YES** | NO | partial | NO |
| **Shannon entropy analysis** | **YES** | NO | NO | NO |
| **CIS Docker Benchmark mapping** | **YES** | NO | NO | NO |
| **SBOM (CycloneDX 1.5)** | **YES** | NO | YES | NO |
| **SARIF output** | **YES** | NO (open issue) | YES | NO |
| **Supply chain risk scoring** | **YES** | NO | NO | NO |
| **Multi-stage build secret leak detection** | **YES** | NO | NO | NO |
| **CI/CD threshold gate (--threshold)** | **YES** | NO (open issue) | YES | NO |
| AI remediation | YES | YES | NO | NO |
| Layer-by-layer attribution | YES | NO | NO | NO |

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

The only tool that systematically audits docker-compose files against CIS Docker Benchmark controls:

```
[CRITICAL] CIS-5.4  webapp: Privileged mode enabled
[CRITICAL] CIS-5.13 webapp: Docker socket mounted: /var/run/docker.sock
[HIGH]     CIS-5.9  webapp: network_mode: host
[HIGH]     CIS-5.3  webapp: Dangerous capabilities added: ['ALL']
[MEDIUM]   CIS-5.12 webapp: read_only not set to true
```

### 3. CIS Docker Benchmark v1.6 Compliance Report

Every finding is tagged with its CIS control ID. A full scorecard is generated:

```
CIS Controls: 14 passed / 8 failed / 2 not-checked
Compliance Score: 63.6%
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

DockSec is an excellent tool for wrapping Trivy + Hadolint with AI explanations. DockerDNA fills the gaps:

- **DockSec** analyzes images that already exist (pull + scan). DockerDNA analyzes the **build definition** - catching issues before an image is ever built.
- **DockSec** has no `docker-compose.yml` scanner. Runtime misconfigs (privileged mode, socket mounts, missing resource limits) are invisible to it.
- **DockSec** relies on Trivy for secret scanning, which covers common cases but misses custom/high-entropy secrets. DockerDNA's dual-mode scanner (pattern + entropy) catches both known and unknown formats.
- **DockSec** produces no SARIF output (open GitHub issue #45). DockerDNA ships SARIF 2.1.0 by default.
- **DockSec** has no CIS benchmark compliance scorecard. DockerDNA maps every finding to a specific CIS Docker Benchmark v1.6 control.

---

## Installation

```bash
# Core (no AI)
pip install dockerdna

# With AI remediation
pip install "dockerdna[ai]"

# Development
pip install "dockerdna[dev]"
pytest
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required for `--ai` flag (AI remediation) |
| `DOCKER_CONTENT_TRUST` | Set to `1` to enable image signing verification |

---

## License

MIT License. See [LICENSE](LICENSE).

## Author

**Sunil Gentyala, Independent Researcher**
IEEE senior Member | Security Researcher
- IEEE: sunil.gentyala@ieee.org
- GitHub: [@sunilgentyala](https://github.com/sunilgentyala)
