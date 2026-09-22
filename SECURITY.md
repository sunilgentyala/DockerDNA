# Security Policy

## Supported versions

DockerDNA is pre-1.0-stable and released from `main`. Security fixes are made against the
latest release; there is no separate LTS branch at this stage.

| Version | Supported |
|---------|-----------|
| latest (main) | Yes |
| < 1.0.1 | No — see [GHSA-w535-46vg-vprh](https://github.com/sunilgentyala/DockerDNA/security/advisories/GHSA-w535-46vg-vprh) |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Use GitHub's private reporting instead:

1. Go to the [Security tab](https://github.com/sunilgentyala/DockerDNA/security) of this repository.
2. Click **Report a vulnerability** to open a private advisory draft.
3. Include: what you found, the affected file(s)/version, a minimal reproduction, and the
   impact as you see it (what an attacker gains, what data is exposed).

If you'd rather email: **sunil.gentyala@ieee.org**.

### What to expect

- Acknowledgement within a few days.
- If confirmed, a fix is developed against a private branch/advisory, then released together
  with a published GHSA advisory crediting the reporter (unless you ask to stay anonymous).
- If it's not a vulnerability (e.g. a hardening suggestion or a false positive in DockerDNA's
  own findings), it'll be redirected to a regular issue instead.

### Scope

In scope: DockerDNA's own code (`dockerdna/`) — logic bugs that cause it to mishandle secrets
it detects, misreport findings in a security-relevant way, or otherwise behave unsafely when
run as documented.

Out of scope: vulnerabilities in Dockerfiles/compose files DockerDNA is *scanning* (that's the
tool's whole job — please open those as regular findings against your own project, not as a
DockerDNA vulnerability), and vulnerabilities in third-party dependencies (report those
upstream; we'll pick up the fix on the next `pip install --upgrade`).

## Past advisories

- [GHSA-w535-46vg-vprh](https://github.com/sunilgentyala/DockerDNA/security/advisories/GHSA-w535-46vg-vprh) —
  secret redaction bypass, fixed in v1.0.1.
