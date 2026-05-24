"""Command line interface for vectrava.

Every scan subcommand passes through the authorization gate first. Without a
valid scope file the CLI refuses to do anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vectrava.core.auth_gate import AuthorizationError, AuthorizationGate

app = typer.Typer(
    name="vectrava",
    help="AI application security scanner. Defensive use only.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command()
def scan(
    scope: Annotated[
        Path,
        typer.Option(help="Path to the signed scope authorization file."),
    ],
    module: Annotated[
        str,
        typer.Option(help="Module to run: dow, ipi, or rag."),
    ],
) -> None:
    """Run a scan after verifying scope authorization.

    The scan refuses to start unless a valid, unexpired scope file is present.
    """
    gate = AuthorizationGate(scope)
    try:
        gate.check()
    except AuthorizationError as exc:
        typer.secho(f"authorization refused: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc

    raise NotImplementedError(f"module {module!r} scanning is not implemented yet")


if __name__ == "__main__":
    app()
