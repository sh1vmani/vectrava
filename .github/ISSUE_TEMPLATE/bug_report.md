---
name: Bug report
about: Report unexpected behavior in vectrava
title: ''
labels: bug
assignees: ''
---

## What happened

Describe the actual behavior. If a probe or writer is involved, name it.

## What you expected

Describe what should have happened.

## Steps to reproduce

Minimal steps. If the report involves a scan, include the invocation (redact the
`--api-key-env` value), the scope file (redact the signature and public key),
and the target shape (provider, endpoint). Do not include actual API keys or
real scope files.

## Output

Paste the relevant output. For SARIF, JSON, or HTML report files, attach a
redacted copy if it is small; otherwise paste the relevant snippet.

## Environment

- vectrava version (from `pyproject.toml` or `uv pip show vectrava`):
- Python version (`python --version`):
- OS:
- `uv --version`:

## Additional context

Anything else that helps. Logs, hypotheses, related issues.
