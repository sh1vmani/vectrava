## What this PR does

One or two sentences describing the change. If this PR adds a probe, name it and
its module. If it changes a public API or CLI flag, name what changes.

## Why

The problem this solves, or the design decision behind the change. Link to an
issue if one exists.

## How to verify

Steps a reviewer can take to confirm the change works. Test names, CLI commands,
or expected output. If the change is internal refactoring, note that no behavior
changes and the test suite is the verification.

## Checklist

- [ ] `uv run ruff check .` passes
- [ ] `uv run ruff format --check .` passes
- [ ] `uv run mypy src tests` passes
- [ ] `uv run pytest` passes
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
      using one of the allowed scopes (see [CONTRIBUTING.md](../CONTRIBUTING.md))
- [ ] Every commit is signed off (`git commit -s`)
- [ ] If this changes user-facing behavior, `CHANGELOG.md` is updated under
      `## [Unreleased]`
- [ ] If this adds or changes a probe, the README and the per-module README
      probe table are current
