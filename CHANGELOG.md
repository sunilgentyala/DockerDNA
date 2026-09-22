# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] — Roadmap

Not yet done — tracked here so contributors have somewhere concrete to start:

- **CIS Docker Benchmark v1.8 mapping.** Current mappings target v1.6, which is what they were
  developed and validated against. Moving the badge requires re-checking every control, not just
  relabeling it — good first project-sized contribution.
- **GitHub Action packaging** (`uses: sunilgentyala/DockerDNA@v1`) so users don't need the
  `pip install` step at all.
- **Official container image** for use in CI without a Python setup step.
- **GitLab CI / Azure DevOps integration examples** (the reusable workflow today is GitHub
  Actions-only).
- **Baseline/waiver support** — suppress a known/accepted finding with a reason and expiry,
  rather than only an all-or-nothing `--threshold`.
- More unit-test fixtures, and more secret-pattern signatures.
- A terminal recording/GIF in the README showing a real scan end to end.

## [1.0.2] — Unreleased at time of writing

### Fixed

- **CI gate did not actually gate.** `dockerdna-action.yml`'s scan step ran
  `dockerdna ... --threshold ... || echo "::warning::..."`, which swallowed DockerDNA's exit
  code — the reusable "Security Gate" workflow reported a warning and continued instead of
  failing the job. Removed the fallback; the scan step now fails (and blocks the PR) exactly
  when `--threshold` is exceeded, as documented. Report/SARIF upload steps still run via
  `if: always()`.
- **The live GitHub Pages site did not describe this project.** The root `index.html` that
  `static.yml` actually deploys had drifted into unrelated, fabricated content (a fictional
  "cryptographic container lineage" framework, false SLSA v1.0 Level 3 / NIST SP 800-190
  compliance claims, invented performance numbers) while a separate, accurate `docs/index.html`
  sat unused. Replaced the live page with the accurate one and removed the stale duplicate so
  there's a single source of truth going forward.
- **Social preview image wasn't deployed.** `static.yml` only copied `index.html` into the
  Pages artifact; `thumbnail.png` and `favicon.svg` were referenced by URL but never actually
  shipped by the workflow (they were only reachable via stale CDN cache from an earlier, since
  overwritten build). Both are now copied into the deployment.
- **Outdated competitor claims.** README, the website, and five module docstrings claimed
  OWASP DockSec and Trivy lack capabilities (compose scanning, SARIF, SBOM, CI gating, secret
  detection) that their current public documentation shows they now have. Verified each claim
  against upstream docs (September 2026) and rewrote the comparison to only assert what's
  confirmed, framing DockerDNA by what it verifiably adds (entropy-based unknown-secret
  detection, CIS control-ID mapping, layer-by-layer attribution) rather than by claiming gaps in
  tools that have moved on.

### Added

- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, and a PR template.

## [1.0.1] — 2026-09-22

### Fixed

- **[GHSA-w535-46vg-vprh](https://github.com/sunilgentyala/DockerDNA/security/advisories/GHSA-w535-46vg-vprh):**
  secret redaction bypass. `redact_secrets=True` (the default) only masked the dedicated
  `matched_value` field; the full raw line — including the secret — still landed in
  `report.json`'s `content` field regardless of the setting, and the bundled GitHub Action
  uploads that report as a 30-day CI artifact. Separately, the Dockerfile ENV/ARG secret check
  had no redaction path at all. Both fixed; regression tests added.
- Install instructions (README, reusable Action, CI example) told users to
  `pip install dockerdna`, which 404s — the package has never been published to PyPI. Switched
  to a working `git+https://` install with a TODO to revert once published.

## [1.0.0] — initial release

Secrets detection (regex + Shannon entropy), docker-compose.yml auditing against CIS Docker
Benchmark Section 5, Dockerfile layer-by-layer scanning against CIS Section 4, supply-chain risk
scoring, CIS compliance scorecard, JSON/HTML/SARIF/CycloneDX SBOM output, optional
Claude-powered remediation, and a CI threshold gate.
