# Contributing to vectrava

Contributions are welcome. This document covers the workflow and the checks that
must pass before a change can be merged.

## Development setup

vectrava uses [uv](https://docs.astral.sh/uv/). Python 3.11, 3.12, and 3.13 are
supported.

```sh
uv sync
```

## Before you open a pull request

All of the following must pass:

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy src/
uv run pytest tests/
```

New behavior needs tests. Bug fixes should add a test that fails before the fix
and passes after.

## Commit messages

Commits use [Conventional Commits](https://www.conventionalcommits.org/) with a
module scope.

```
<type>(<scope>): <subject>
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `build`,
`ci`, `style`, `revert`.

Scopes: `dow`, `ipi`, `rag`, `cli`, `config`, `docs`, `ci`, `test`, `build`,
`release`, `repo`.

Examples:

```
feat(dow): add cost amplification meter
fix(cli): handle missing scope file gracefully
docs(ipi): document payload taxonomy
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

## Style

Code style is enforced by ruff (lint and format) and mypy in strict mode. Match
the surrounding code. Do not reformat unrelated lines.

Do not use em dashes or en dashes in code, comments, or documentation. Use a
regular hyphen, a comma, a colon, parentheses, or a new sentence.
