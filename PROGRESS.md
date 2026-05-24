# Progress

A 12-week build plan tracks vectrava from scaffold to public launch.

## Current marker: Week 0

Scaffold and repository foundation.

### Done

- Package structure for the three modules: `dow`, `ipi`, `rag`.
- Authorization gate: scope-file check enforced in code, with tests that prove
  it rejects missing, malformed, and expired scope files.
- BYOK config: target API key is read from the environment and validated, never
  shipped or stored.
- Output writer interfaces: SARIF v2.1.0, HTML, JSON (stubs).
- Tooling: uv, ruff (lint and format), mypy strict, pytest with hypothesis.
- CI matrix across Python 3.11, 3.12, 3.13 on Linux, macOS, and Windows.
- Supply-chain and quality workflows: CodeQL, OpenSSF Scorecard, DCO check,
  secret scanning.
- Standard repository files: README, LICENSE (Apache 2.0), CONTRIBUTING,
  CODE_OF_CONDUCT, SECURITY, MAINTAINERS.

### Not done

- Probe logic for all three modules.
- Output serialization (the writers raise `NotImplementedError`).
- Scope-file signature verification.

## Review checkpoints

- **Week 2:** tooling review. Confirm the CI matrix, linting, typing, and the
  authorization gate hold up as the first probes land.
- **Week 6:** tooling review. Reassess dependencies, output formats, and test
  coverage at the halfway point.

## Visibility

The repository is private during the build and flips to public at the Week 12
launch.
