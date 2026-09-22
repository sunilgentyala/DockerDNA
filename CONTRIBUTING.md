# Contributing to DockerDNA

Thanks for considering a contribution. DockerDNA is a small, single-maintainer project, so the
process is intentionally lightweight.

## Getting set up

```bash
git clone https://github.com/sunilgentyala/DockerDNA.git
cd DockerDNA
pip install -e ".[dev]"
pytest
```

That's the whole environment — pure Python, PyYAML for compose parsing, `anthropic` only if
you're touching the optional `--ai` remediation path.

## Before opening a PR

- Add or update a test for any behavior change. `tests/` mirrors `dockerdna/`'s module layout
  (e.g. `dockerdna/scanners/secrets.py` -> `tests/test_secrets.py`).
- Run `pytest` locally and make sure it's green.
- If you're changing what a scanner detects or reports, run it against
  `examples/Dockerfile.vulnerable` / `examples/docker-compose.vulnerable.yml` and sanity-check
  the output — those files exist specifically as a shared fixture.
- Keep PRs scoped to one change. Easier to review, easier to revert if something's wrong.

## Reporting bugs

Open an issue with: what you ran, what you expected, what you got. If it's a false
positive/negative in a specific scanner, include the Dockerfile/compose snippet that triggers it
(redact anything sensitive first — or better, reduce it to a minimal non-sensitive repro).

## Reporting vulnerabilities

Do not open a public issue — see [SECURITY.md](SECURITY.md).

## Good places to start

Check issues labeled [`good first issue`](https://github.com/sunilgentyala/DockerDNA/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
Common shapes of contribution that are easy to review and merge:

- A new secret pattern signature in `dockerdna/utils/patterns.py` (`SECRET_PATTERNS`), with a
  test case in `tests/test_secrets.py`.
- A new docker-compose check in `dockerdna/scanners/compose.py`, mapped to a CIS Docker
  Benchmark control in `dockerdna/utils/patterns.py` (`CIS_RULES`).
- Additional unit-test fixtures — more edge cases in `examples/` or `tests/`.

## Code style

No enforced formatter/linter yet (contributions to add one, e.g. `ruff`, are welcome). Match the
surrounding file: type hints on public functions, dataclasses for findings, docstrings on new
modules.

## License

By contributing, you agree your contribution is licensed under the project's [MIT License](LICENSE).
