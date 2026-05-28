# vectrava agent rules

vectrava is an AI application security scanner with three modules: dow
(Denial-of-Wallet), ipi (indirect prompt injection), and rag (RAG pipeline
boundary probes).

## File purpose

This file gives coding agents that look for an `AGENTS.md` the rules and facts
specific to this repository. The companion file `CLAUDE.md` carries the same
content for agents that read that filename instead. Both files are kept in
sync. The duplication exists so any agent finds its expected configuration
filename.

## Inherited rules

Any global agent-instruction file you already load applies to this project as
well, together with the project rules below. They govern:

- Author identity: every artifact is the work of Shivamani Vastrala.
- Forbidden characters: no em dashes and no en dashes anywhere text is written
  and committed. Use an ASCII hyphen, comma, colon, parentheses, or a new
  sentence.
- Forbidden phrases: no AI attribution lines, no machine-authorship footers,
  and no co-author trailers referencing any model.
- Conventional Commits with module scopes, signed off under the DCO.
- Defensive security posture.
- The four coding principles: think before coding, simplicity first, surgical
  changes, goal-driven execution.

Those rules are not repeated in detail here. Inherit them. This file only adds
what is specific to vectrava.

## Project facts (locked)

- License: Apache 2.0, copyright 2026 Shivamani Vastrala. Not MIT. The patent
  grant matters for security tooling.
- Languages: Python 3.11, 3.12, and 3.13, validated as a CI matrix.
- Environment: uv (Astral) for environment and dependency management. No pip,
  no virtualenv, no poetry. Use `uv add`, `uv sync`, `uv run`.
- Runtime libraries: Typer for the CLI, Pydantic v2 for models, httpx for the
  HTTP client, structlog for logging.
- Quality tooling: ruff for lint and format, mypy in strict mode, pytest with
  hypothesis for tests.
- Package layout: three probe modules (`dow`, `ipi`, `rag`) plus `config`
  (scope and BYOK models), `core` (orchestration and the authorization gate),
  and `output` (report writers).
- Output formats: SARIF v2.1.0, HTML, and JSON.
- Distribution: PyPI via Trusted Publishing (OIDC), container images on GHCR as
  the primary registry with a Docker Hub mirror, and a published GitHub Action.

## Architecture invariants (do not violate)

These hold for every change. If a change cannot be made without breaking one of
them, stop and raise it rather than working around it.

- BYOK enforced in code. Every function that calls a target API reads its
  credentials from the environment at run time. Credentials are never bundled,
  hard-coded, or written to disk.
- Scope-file authorization gate. The CLI refuses to run any scan without a
  valid, signed, unexpired scope file. The gate is the single chokepoint. Do
  not add a scan path that bypasses it.
- Defensive posture. vectrava finds and reports failure modes so they can be
  fixed. It does not weaponize. Features ship authorization-gated by default.
- Visibility. The repository is public. Do not change repository visibility.

## Commit scopes

Conventional Commits with a module scope are mandatory. Allowed scopes:

`dow`, `ipi`, `rag`, `cli`, `config`, `core`, `output`, `docs`, `ci`, `test`,
`build`, `release`, `repo`, `scorecard`, `codeql`, `dco`, `secrets`, `workflow`

Example:

```
feat(dow): add cost amplification meter
```

Use a workflow-name scope (`scorecard`, `codeql`, `dco`, `secrets`) for a change
to that single workflow. Use `workflow` for a change that spans several
workflows at once, and `ci` for CI configuration that is not tied to one
specific workflow.

## Where to find more

- `PROGRESS.md`: current state and the running day-close record.
- `CONTRIBUTING.md`: contributor workflow, required checks, and sign-off.
- `SECURITY.md`: how to report a vulnerability.
- `MAINTAINERS.md`: who runs the project.
