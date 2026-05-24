"""Command line interface for vectrava.

Every scan passes through the authorization gate first, and the requested target
must be listed in the scope file. Without both, the CLI refuses to contact
anything. Probe discovery and cost estimation happen before any API call, so
`--list` and `--dry-run` never touch the target.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import httpx
import structlog
import typer

from vectrava.config.byok import BYOKConfig
from vectrava.core import registry
from vectrava.core.auth_gate import AuthorizationError, AuthorizationGate
from vectrava.core.probe import Probe, ProbeContext, ProbeError
from vectrava.core.result import Finding
from vectrava.output.sarif import write_sarif

# Cost transparency. The rate is a placeholder default; reading it from config is
# a future enhancement.
COST_PROMPT_THRESHOLD_TOKENS = 50_000
USD_PER_1K_TOKENS = 0.01
VALID_FORMATS = ("sarif", "json", "html")
DEFAULT_OUTPUT = Path("findings.sarif")

app = typer.Typer(
    name="vectrava",
    help="AI application security scanner. Defensive use only.",
    no_args_is_help=True,
    add_completion=False,
)
scan_app = typer.Typer(
    help="Run probes against an authorized target.",
    no_args_is_help=True,
)
app.add_typer(scan_app, name="scan")


def _estimated_cost_usd(tokens: int) -> float:
    """Return the estimated USD cost for a token count at the default rate."""
    return (tokens / 1000) * USD_PER_1K_TOKENS


def _load_module_probes(module: str) -> None:
    """Import a module's probe package so its probes register themselves."""
    with contextlib.suppress(ModuleNotFoundError):
        # No probe package for this module yet; nothing to register.
        importlib.import_module(f"vectrava.{module}.probes")


def _fail(message: str) -> typer.Exit:
    """Print an error to stderr and return an Exit with the scan-error code."""
    typer.secho(message, err=True, fg=typer.colors.RED)
    return typer.Exit(code=2)


def _print_probe_list(module: str, probes: list[type[Probe]]) -> None:
    """Print the probes registered for a module, sorted by name."""
    if not probes:
        typer.echo(f"No {module} probes are registered yet.")
        return
    typer.echo(f"{module} probes:")
    for probe in sorted(probes, key=lambda cls: cls.name):
        typer.echo(f"  {probe.name}  [{probe.baseline_severity}]  {probe.description}")


def _select_probes(probes: list[type[Probe]], only: str | None) -> list[type[Probe]]:
    """Filter the probe list to a single named probe when `only` is given."""
    if only is None:
        return probes
    matched = [cls for cls in probes if cls.name == only]
    if not matched:
        names = ", ".join(sorted(cls.name for cls in probes)) or "(none)"
        raise _fail(f"error: probe {only!r} not found in this module. Available: {names}")
    return matched


def _emit_findings(
    findings: list[Finding],
    output: Path,
    output_format: str,
    *,
    started_at: datetime,
    execution_successful: bool,
    exit_code: int,
    arguments: list[str],
) -> None:
    """Write findings to the output path in the requested format.

    SARIF goes through the real writer. JSON and HTML fall back to the interim
    JSON dump until their writers are implemented.
    """
    if output_format == "sarif":
        write_sarif(
            findings,
            output,
            started_at=started_at,
            execution_successful=execution_successful,
            exit_code=exit_code,
            arguments=arguments,
        )
        typer.echo(f"wrote {len(findings)} finding(s) to {output} (format 'sarif')")
        return

    payload = [finding.model_dump(mode="json") for finding in findings]
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    typer.echo(
        f"wrote {len(findings)} finding(s) to {output} "
        f"(format {output_format!r} pending writer implementation)"
    )


def _run_scan(
    module: str,
    *,
    scope: Path | None,
    target: str | None,
    endpoint: str | None,
    api_key_env: str | None,
    only: str | None,
    list_probes: bool,
    dry_run: bool,
    yes: bool,
    output: Path | None,
    output_format: str,
    threshold: float,
    model: str,
) -> None:
    """Drive a scan for one module: discover, authorize, estimate, run, emit."""
    started_at = datetime.now(UTC)
    _load_module_probes(module)
    module_probes = registry.by_module(module)

    # Listing is pure introspection: no scope, no auth, no target contact.
    if list_probes:
        _print_probe_list(module, module_probes)
        raise typer.Exit(code=0)

    if output_format not in VALID_FORMATS:
        choices = ", ".join(VALID_FORMATS)
        raise _fail(f"error: unknown format {output_format!r}. Choose from: {choices}")

    if scope is None or target is None:
        raise _fail("error: --scope and --target are required for a scan run")

    try:
        scope_file = AuthorizationGate(scope).check()
    except AuthorizationError as exc:
        raise _fail(f"authorization refused: {exc}") from exc

    if target not in scope_file.targets:
        authorized = ", ".join(scope_file.targets) or "(none)"
        raise _fail(
            f"error: target {target!r} is not authorized by the scope file. "
            f"Authorized targets: {authorized}"
        )

    selected = _select_probes(module_probes, only)

    total_tokens = sum(probe.estimated_tokens_per_run for probe in selected)
    cost = _estimated_cost_usd(total_tokens)

    if dry_run:
        typer.echo(
            f"dry run: {len(selected)} probe(s), up to {total_tokens} tokens, "
            f"estimated cost ${cost:.2f}. No API calls made."
        )
        raise typer.Exit(code=0)

    if total_tokens > COST_PROMPT_THRESHOLD_TOKENS and not yes:
        proceed = typer.confirm(
            f"This scan will consume up to {total_tokens} tokens "
            f"(estimated cost ${cost:.2f}). Continue?"
        )
        if not proceed:
            typer.echo("aborted")
            raise typer.Exit(code=0)

    credentials: str | None = None
    if any(probe.requires_credentials for probe in selected):
        if api_key_env is None:
            raise _fail(
                "error: --api-key-env is required because a selected probe needs credentials"
            )
        try:
            credentials = BYOKConfig(api_key_env=api_key_env).resolve()
        except ValueError as exc:
            raise _fail(f"error: {exc}") from exc

    logger = structlog.get_logger()
    findings: list[Finding] = []
    scan_error = False
    out_path = output if output is not None else DEFAULT_OUTPUT

    with httpx.Client() as http:
        for probe_cls in selected:
            probe = probe_cls()
            ctx = ProbeContext(
                target=target,
                endpoint=endpoint if endpoint is not None else probe.default_endpoint,
                credentials=credentials if probe.requires_credentials else None,
                scope=scope_file,
                http=http,
                logger=logger.bind(probe=probe.name),
                options={"threshold": threshold, "model": model},
            )
            try:
                findings.extend(probe.run(ctx))
            except ProbeError as exc:
                scan_error = True
                typer.secho(f"probe {probe.name!r} failed: {exc}", err=True, fg=typer.colors.YELLOW)

    exit_code = 2 if scan_error else (1 if findings else 0)
    _emit_findings(
        findings,
        out_path,
        output_format,
        started_at=started_at,
        execution_successful=not scan_error,
        exit_code=exit_code,
        arguments=sys.argv[1:],
    )
    raise typer.Exit(code=exit_code)


@scan_app.command("dow")
def scan_dow(
    scope: Annotated[
        Path | None,
        typer.Option(help="Path to the signed scope authorization file."),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(help="Target base URL. Must be listed in the scope file."),
    ] = None,
    endpoint: Annotated[
        str | None,
        typer.Option(help="Override the probe default endpoint."),
    ] = None,
    api_key_env: Annotated[
        str | None,
        typer.Option("--api-key-env", help="Env var holding the target API key (BYOK)."),
    ] = None,
    only: Annotated[
        str | None,
        typer.Option(help="Run only the named probe."),
    ] = None,
    list_probes: Annotated[
        bool,
        typer.Option("--list", "-l", help="List dow probes and exit. No scope or target needed."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Estimate token cost without making API calls."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip the cost confirmation prompt."),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(help="Output file path. Defaults to findings.sarif."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: sarif, json, or html."),
    ] = "sarif",
    threshold: Annotated[
        float,
        typer.Option(
            "--threshold",
            min=1.0,
            help="Flag when output tokens reach this multiple of input tokens. Default 15.0.",
        ),
    ] = 15.0,
    model: Annotated[
        str,
        typer.Option(
            "--model",
            help="Model identifier sent in the chat-completions request body (e.g. gpt-4o-mini).",
        ),
    ] = "gpt-4o-mini",
) -> None:
    """Run Denial-of-Wallet (dow) probes against an authorized target."""
    _run_scan(
        "dow",
        scope=scope,
        target=target,
        endpoint=endpoint,
        api_key_env=api_key_env,
        only=only,
        list_probes=list_probes,
        dry_run=dry_run,
        yes=yes,
        output=output,
        output_format=output_format,
        threshold=threshold,
        model=model,
    )


if __name__ == "__main__":
    app()
