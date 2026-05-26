"""Command line interface for vectrava.

Every scan passes through the authorization gate first, and the requested target
must be listed in the scope file. Without both, the CLI refuses to contact
anything. Probe discovery and cost estimation happen before any API call, so
`--list` and `--dry-run` never touch the target.
"""

from __future__ import annotations

import contextlib
import getpass
import importlib
import os
import socket
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import httpx
import structlog
import typer

from vectrava import __version__
from vectrava.config.byok import BYOKConfig
from vectrava.core import registry
from vectrava.core.audit import AuditError, AuditWriter
from vectrava.core.auth_gate import AuthorizationError, AuthorizationGate
from vectrava.core.probe import Probe, ProbeContext, ProbeError
from vectrava.core.result import Finding
from vectrava.core.signing import (
    generate_keypair,
    verify_scope,
)
from vectrava.core.signing import (
    sign_scope as sign_scope_file,
)
from vectrava.output.html import write_html
from vectrava.output.json_writer import write_json
from vectrava.output.sarif import write_sarif

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pydantic import JsonValue

# Cost transparency. The token threshold halts a full scan only when the
# estimated worst-case spend is meaningfully large; 150,000 clears the heaviest
# standard module's honest worst case (ipi at ~105k tokens after triangular
# estimation, driven by the two multi-turn probes resending the full transcript
# each turn) with headroom for one more multi-turn probe before re-tripping, so a
# normal full scan does not prompt while a genuinely-runaway custom selection
# (150k+) still does. USD_PER_1K_TOKENS is a placeholder default; reading
# per-model pricing from config is a future enhancement.
COST_PROMPT_THRESHOLD_TOKENS = 150_000
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
scope_app = typer.Typer(
    help="Manage scope-file signing keys and signatures.",
    no_args_is_help=True,
)
app.add_typer(scope_app, name="scope")


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
    target: str,
    execution_successful: bool,
    exit_code: int,
    arguments: list[str],
) -> None:
    """Write findings to the output path in the requested format.

    SARIF, JSON, and HTML each go through their own writer, all fed the same
    run-level metadata.
    """
    if output_format == "sarif":
        write_sarif(
            findings,
            output,
            target=target,
            started_at=started_at,
            execution_successful=execution_successful,
            exit_code=exit_code,
            arguments=arguments,
        )
        typer.echo(f"wrote {len(findings)} finding(s) to {output} (format 'sarif')")
        return

    if output_format == "json":
        write_json(
            findings,
            output,
            started_at=started_at,
            target=target,
            execution_successful=execution_successful,
            exit_code=exit_code,
            arguments=arguments,
        )
        typer.echo(f"wrote {len(findings)} finding(s) to {output} (format 'json')")
        return

    write_html(
        findings,
        output,
        started_at=started_at,
        target=target,
        execution_successful=execution_successful,
        exit_code=exit_code,
        arguments=arguments,
    )
    typer.echo(f"wrote {len(findings)} finding(s) to {output} (format 'html')")


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
    options: Mapping[str, JsonValue],
    audit_log: Path | None,
) -> None:
    """Drive a scan for one module: discover, authorize, estimate, run, emit.

    When audit_log is set, one JSONL record is written for the invocation
    regardless of outcome. The record is flushed in a finally block, so a refused
    or errored scan is recorded too. A --list invocation is pure introspection and
    is not audited.
    """
    started_at = datetime.now(UTC)
    _load_module_probes(module)
    module_probes = registry.by_module(module)

    # Listing is pure introspection: no scope, no auth, no target contact, no audit.
    if list_probes:
        _print_probe_list(module, module_probes)
        raise typer.Exit(code=0)

    audit = AuditWriter(audit_log)
    try:
        audit.preflight()
    except AuditError as exc:
        # Fail closed before any target contact: a dead audit path means no scan.
        raise _fail(f"audit log preflight failed: {exc}") from exc

    audit.set_invocation(
        invocation_id=uuid.uuid4().hex,
        started_at=started_at,
        module=module,
        arguments=sys.argv[1:],
        runner_host=socket.gethostname(),
        runner_user=getpass.getuser(),
        runner_pid=os.getpid(),
        vectrava_version=__version__,
    )

    try:
        if output_format not in VALID_FORMATS:
            choices = ", ".join(VALID_FORMATS)
            audit.set_outcome("invalid_arguments", 2)
            raise _fail(f"error: unknown format {output_format!r}. Choose from: {choices}")

        if scope is None or target is None:
            audit.set_outcome("invalid_arguments", 2)
            raise _fail("error: --scope and --target are required for a scan run")

        try:
            scope_file = AuthorizationGate(scope).check()
        except AuthorizationError as exc:
            audit.set_scope_rejected(exc.scope)
            audit.set_outcome("authorization_rejected", 2)
            raise _fail(f"authorization refused: {exc}") from exc
        audit.set_scope(scope_file)

        if target not in scope_file.targets:
            authorized = ", ".join(scope_file.targets) or "(none)"
            audit.set_outcome("target_not_in_scope", 2)
            raise _fail(
                f"error: target {target!r} is not authorized by the scope file. "
                f"Authorized targets: {authorized}"
            )
        audit.set_target(target)

        try:
            selected = _select_probes(module_probes, only)
        except typer.Exit:
            audit.set_outcome("invalid_arguments", 2)
            raise

        total_tokens = sum(probe.estimated_tokens_per_run for probe in selected)
        cost = _estimated_cost_usd(total_tokens)

        if dry_run:
            typer.echo(
                f"dry run: {len(selected)} probe(s), up to {total_tokens} tokens, "
                f"estimated cost ${cost:.2f}. No API calls made."
            )
            audit.set_outcome("dry_run", 0)
            raise typer.Exit(code=0)

        if total_tokens > COST_PROMPT_THRESHOLD_TOKENS and not yes:
            proceed = typer.confirm(
                f"This scan will consume up to {total_tokens} tokens "
                f"(estimated cost ${cost:.2f}). Continue?"
            )
            if not proceed:
                typer.echo("aborted")
                audit.set_outcome("aborted_by_user", 0)
                raise typer.Exit(code=0)

        credentials: str | None = None
        if any(probe.requires_credentials for probe in selected):
            if api_key_env is None:
                audit.set_outcome("credentials_missing", 2)
                raise _fail(
                    "error: --api-key-env is required because a selected probe needs credentials"
                )
            try:
                credentials = BYOKConfig(api_key_env=api_key_env).resolve()
            except ValueError as exc:
                audit.set_outcome("credentials_missing", 2)
                raise _fail(f"error: {exc}") from exc
            audit.set_credential(env_var=api_key_env, value=credentials)

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
                    options=options,
                )
                try:
                    findings.extend(probe.run(ctx))
                except ProbeError as exc:
                    scan_error = True
                    typer.secho(
                        f"probe {probe.name!r} failed: {exc}", err=True, fg=typer.colors.YELLOW
                    )

        exit_code = 2 if scan_error else (1 if findings else 0)
        _emit_findings(
            findings,
            out_path,
            output_format,
            started_at=started_at,
            target=target,
            execution_successful=not scan_error,
            exit_code=exit_code,
            arguments=sys.argv[1:],
        )
        audit.set_output(out_path)
        audit.set_findings(findings)
        if scan_error:
            audit.set_outcome("probe_error", 2)
        elif findings:
            audit.set_outcome("completed_with_findings", 1)
        else:
            audit.set_outcome("completed_clean", 0)
        raise typer.Exit(code=exit_code)
    except typer.Exit:
        raise
    except Exception:
        audit.set_outcome("internal_error", 1)
        raise
    finally:
        audit.flush()


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
    padding_threshold: Annotated[
        float,
        typer.Option(
            "--padding-threshold",
            min=1.0,
            help=(
                "Flag output_padding findings when the completion-to-ceiling "
                "ratio reaches this value. Default 4.0."
            ),
        ),
    ] = 4.0,
    model: Annotated[
        str,
        typer.Option(
            "--model",
            help="Model identifier sent in the chat-completions request body (e.g. gpt-4o-mini).",
        ),
    ] = "gpt-4o-mini",
    max_requests_per_second: Annotated[
        float,
        typer.Option(
            "--max-requests-per-second",
            min=1.0,
            help=(
                "Cap on outbound request rate per second. Default 10 "
                "is well above typical LLM latency; lower this to be "
                "gentler on a target, raise it for stress testing. "
                "The cap applies across all probes within one scan, "
                "except rate_limit_bypass, which deliberately overpaces "
                "to test target-side rate-limit enforcement."
            ),
        ),
    ] = 10.0,
    audit_log: Annotated[
        Path | None,
        typer.Option(
            "--audit-log",
            help=(
                "Append a JSONL audit record for this scan to this path. Overrides "
                "VECTRAVA_AUDIT_LOG_PATH. Parent directories are created."
            ),
        ),
    ] = None,
) -> None:
    """Run Denial-of-Wallet (dow) probes against an authorized target."""
    options: dict[str, JsonValue] = {
        "threshold": threshold,
        "padding_threshold": padding_threshold,
        "model": model,
        "max_rps": max_requests_per_second,
    }
    resolved_audit = audit_log or (
        Path(env_audit) if (env_audit := os.environ.get("VECTRAVA_AUDIT_LOG_PATH")) else None
    )
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
        options=options,
        audit_log=resolved_audit,
    )


@scan_app.command("ipi")
def scan_ipi(
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
        typer.Option("--list", "-l", help="List ipi probes and exit. No scope or target needed."),
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
    model: Annotated[
        str,
        typer.Option(
            "--model",
            help="Model identifier sent in the chat-completions request body (e.g. gpt-4o-mini).",
        ),
    ] = "gpt-4o-mini",
    max_turns: Annotated[
        int,
        typer.Option(
            "--max-turns",
            min=2,
            help=(
                "Conversation length for the multi_turn_persistence probe. Default 5, "
                "capped at 10. Turn 1 plants a persistence directive; later turns test "
                "whether the injected canary leaks into subsequent replies."
            ),
        ),
    ] = 5,
    max_requests_per_second: Annotated[
        float,
        typer.Option(
            "--max-requests-per-second",
            min=1.0,
            help=(
                "Cap on outbound request rate per second. Default 10 "
                "is well above typical LLM latency; lower this to be "
                "gentler on a target, raise it for stress testing. "
                "The cap applies across all probes within one scan."
            ),
        ),
    ] = 10.0,
    audit_log: Annotated[
        Path | None,
        typer.Option(
            "--audit-log",
            help=(
                "Append a JSONL audit record for this scan to this path. Overrides "
                "VECTRAVA_AUDIT_LOG_PATH. Parent directories are created."
            ),
        ),
    ] = None,
) -> None:
    """Run Indirect Prompt Injection probes against TARGET."""
    options: dict[str, JsonValue] = {
        "model": model,
        "max_turns": max_turns,
        "max_rps": max_requests_per_second,
    }
    resolved_audit = audit_log or (
        Path(env_audit) if (env_audit := os.environ.get("VECTRAVA_AUDIT_LOG_PATH")) else None
    )
    _run_scan(
        "ipi",
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
        options=options,
        audit_log=resolved_audit,
    )


@scan_app.command("rag")
def scan_rag(
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
        typer.Option("--list", "-l", help="List rag probes and exit. No scope or target needed."),
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
    model: Annotated[
        str,
        typer.Option(
            "--model",
            help="Model identifier sent in the chat-completions request body (e.g. gpt-4o-mini).",
        ),
    ] = "gpt-4o-mini",
    num_sources: Annotated[
        int,
        typer.Option(
            "--num-sources",
            min=2,
            help=(
                "Number of retrieved source chunks per injection. Default 3 sends "
                "the canonical injection structure; values above 3 pad with benign "
                "filler chunks interleaved between the attack-pattern chunks to "
                "stress-test robustness to retrieval distractors."
            ),
        ),
    ] = 3,
    max_requests_per_second: Annotated[
        float,
        typer.Option(
            "--max-requests-per-second",
            min=1.0,
            help=(
                "Cap on outbound request rate per second. Default 10 "
                "is well above typical LLM latency; lower this to be "
                "gentler on a target, raise it for stress testing. "
                "The cap applies across all probes within one scan."
            ),
        ),
    ] = 10.0,
    audit_log: Annotated[
        Path | None,
        typer.Option(
            "--audit-log",
            help=(
                "Append a JSONL audit record for this scan to this path. Overrides "
                "VECTRAVA_AUDIT_LOG_PATH. Parent directories are created."
            ),
        ),
    ] = None,
) -> None:
    """Run RAG pipeline boundary probes against TARGET."""
    options: dict[str, JsonValue] = {
        "model": model,
        "num_sources": num_sources,
        "max_rps": max_requests_per_second,
    }
    resolved_audit = audit_log or (
        Path(env_audit) if (env_audit := os.environ.get("VECTRAVA_AUDIT_LOG_PATH")) else None
    )
    _run_scan(
        "rag",
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
        options=options,
        audit_log=resolved_audit,
    )


@scope_app.command("new-key")
def scope_new_key(
    out_dir: Annotated[
        Path,
        typer.Option("--out-dir", help="Directory to write the keypair into."),
    ] = Path("."),
) -> None:
    """Generate an Ed25519 keypair for signing scope files."""
    priv_b64, pub_b64 = generate_keypair()
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path = out_dir / "vectrava_ed25519"
    pub_path = out_dir / "vectrava_ed25519.pub"
    priv_path.write_text(priv_b64, encoding="utf-8")
    # Windows does not support chmod; best effort.
    with contextlib.suppress(NotImplementedError):
        priv_path.chmod(0o600)
    pub_path.write_text(pub_b64, encoding="utf-8")
    typer.echo(f"private key: {priv_path}")
    typer.echo(f"public key:  {pub_path}")
    typer.echo(f"set VECTRAVA_TRUSTED_KEYS={pub_b64} to authorize scans signed with this key")


@scope_app.command("sign")
def scope_sign(
    scope_path: Annotated[Path, typer.Argument(help="Scope file to sign.")],
    key_path: Annotated[
        Path,
        typer.Option("--key", help="Path to the Ed25519 private key file."),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write signed scope here (default: overwrite input)."),
    ] = None,
) -> None:
    """Sign a scope file with an Ed25519 private key."""
    import json as _json

    from vectrava.config.scope import ScopeFile as _ScopeFile

    priv_b64 = key_path.read_text(encoding="utf-8").strip()
    raw = _json.loads(scope_path.read_text(encoding="utf-8"))
    scope = _ScopeFile.model_validate(raw)
    signed = sign_scope_file(scope, priv_b64)
    data = signed.model_dump(mode="json")
    out = output or scope_path
    out.write_text(_json.dumps(data, indent=2), encoding="utf-8")
    typer.echo(f"signed scope written to {out}")


@scope_app.command("verify")
def scope_verify(
    scope_path: Annotated[Path, typer.Argument(help="Scope file to verify.")],
) -> None:
    """Verify the signature on a signed scope file."""
    import json as _json

    from cryptography.exceptions import InvalidSignature

    from vectrava.config.scope import ScopeFile as _ScopeFile

    raw = _json.loads(scope_path.read_text(encoding="utf-8"))
    scope = _ScopeFile.model_validate(raw)
    try:
        verify_scope(scope)
        typer.echo("signature valid")
        typer.echo(f"public key:  {scope.public_key}")
        typer.echo(f"signed by:   {scope.signed_by}")
    except (ValueError, InvalidSignature) as exc:
        typer.secho(f"verification failed: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()
