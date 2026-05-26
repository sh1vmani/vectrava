# Contributing to vectrava

Contributions are welcome. This document covers the workflow and the checks that
must pass before a change can be merged.

## Development setup

vectrava uses [uv](https://docs.astral.sh/uv/). Python 3.11, 3.12, and 3.13 are
supported.

```sh
uv sync
```

## Running a scan in development

Running an actual scan needs a signed scope file and a target API key in the
environment. See the [README](README.md) Quickstart and the template at
[`examples/scope.example.json`](examples/scope.example.json) for the keypair
generation, scope signing, and `VECTRAVA_TRUSTED_KEYS` steps.

## Before you open a pull request

All of the following must pass:

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest
```

New behavior needs tests. Bug fixes should add a test that fails before the fix
and passes after.

User-facing changes should be recorded in [CHANGELOG.md](./CHANGELOG.md) under
the `[Unreleased]` section in the appropriate Keep a Changelog category (Added,
Changed, Deprecated, Removed, Fixed, Security).

## Commit messages

Commits use [Conventional Commits](https://www.conventionalcommits.org/) with a
module scope.

```
<type>(<scope>): <subject>
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `build`,
`ci`, `style`, `revert`.

Scopes: `dow`, `ipi`, `rag`, `cli`, `config`, `core`, `output`, `docs`, `ci`,
`test`, `build`, `release`, `repo`, `scorecard`, `codeql`, `dco`, `secrets`,
`workflow`.

Examples:

```
feat(dow): add cost amplification meter
fix(cli): handle missing scope file gracefully
docs(ipi): document refusal bypass probe
```

## Sign-off (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). Add the
sign-off automatically:

```sh
git commit -s -m "feat(dow): add cost amplification meter"
```

The sign-off line must match the commit author:

```
Signed-off-by: Your Name <your.email@example.com>
```

Pull requests without a sign-off on every commit are blocked by CI.

## Git hooks

The repository ships local git hooks under `.git/hooks/`, committed as part of
the repo so a fresh clone gets them automatically. They inject the DCO
`Signed-off-by` trailer for you, reject a commit whose message uses a scope
outside the list above, and reject any commit message or staged file content
that contains an em dash, an en dash, or an AI-authorship signature phrase. If a
commit is blocked or reformatted locally, that is the hooks keeping history
consistent with the rules in this document.

## Style

Code style is enforced by ruff (lint and format) and mypy in strict mode. Match
the surrounding code. Do not reformat unrelated lines.

Do not use em dashes or en dashes in code, comments, or documentation. Use a
regular hyphen, a comma, a colon, parentheses, or a new sentence.
