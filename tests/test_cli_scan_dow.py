"""CLI tests for `vectrava scan dow`."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import JsonValue
from typer.testing import CliRunner

from vectrava.cli import _estimated_cost_usd, app
from vectrava.core import registry
from vectrava.core.pricing import PRICING_TABLE, USD_PER_1K_TOKENS
from vectrava.core.probe import Probe, ProbeContext
from vectrava.core.result import Finding, Severity

runner = CliRunner()

_captured_options: list[Mapping[str, JsonValue]] = []


class _CapturingProbe(Probe):
    """Records the options it receives, so CLI option plumbing can be asserted."""

    name = "capture_probe"
    module = "dow"
    description = "captures ctx.options for assertions"
    baseline_severity = Severity.LOW
    estimated_tokens_per_run = 1
    requires_credentials = False

    def run(self, ctx: ProbeContext) -> list[Finding]:
        _captured_options.append(dict(ctx.options))
        return []


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    registry.clear()
    _captured_options.clear()
    yield
    registry.clear()
    _captured_options.clear()


def _combined(result: Any) -> str:
    text = result.stdout or ""
    with contextlib.suppress(ValueError, AttributeError):
        text += result.stderr or ""
    return text


def _make_dow_probe(name: str, tokens: int) -> type[Probe]:
    return type(
        name,
        (Probe,),
        {
            "name": name,
            "module": "dow",
            "description": "test probe",
            "baseline_severity": Severity.LOW,
            "estimated_tokens_per_run": tokens,
            "requires_credentials": False,
            "run": lambda self, ctx: [],
        },
    )


def test_list_shows_probes_without_scope() -> None:
    result = runner.invoke(app, ["scan", "dow", "--list"])
    assert result.exit_code == 0
    assert "probe" in _combined(result).lower()


def test_scan_without_scope_exits_2() -> None:
    result = runner.invoke(app, ["scan", "dow", "--target", "http://x"])
    assert result.exit_code == 2


def test_scan_with_invalid_scope_exits_2(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    result = runner.invoke(app, ["scan", "dow", "--scope", str(missing), "--target", "http://x"])
    assert result.exit_code == 2


def test_scan_with_target_not_in_scope_exits_2(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    result = runner.invoke(
        app,
        ["scan", "dow", "--scope", str(scope), "--target", "http://not-allowed"],
    )
    assert result.exit_code == 2
    assert "authorized" in _combined(result).lower()


def test_dry_run_does_not_make_api_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_scope_factory: Callable[..., Path],
) -> None:
    registry.register(_make_dow_probe("amp", tokens=100))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])

    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("httpx.Client must not be constructed during a dry run")

    monkeypatch.setattr(httpx, "Client", boom)
    result = runner.invoke(
        app,
        ["scan", "dow", "--scope", str(scope), "--target", "http://allowed", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "dry run" in _combined(result).lower()


def test_dry_run_prints_estimate(tmp_path: Path, signed_scope_factory: Callable[..., Path]) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    result = runner.invoke(
        app,
        ["scan", "dow", "--scope", str(scope), "--target", "http://allowed", "--dry-run"],
    )
    assert result.exit_code == 0
    text = _combined(result)
    assert "2000" in text
    assert "0.0003" in text


def test_padding_threshold_default_reaches_probe(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_CapturingProbe)
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    assert len(_captured_options) == 1
    assert _captured_options[0]["padding_threshold"] == 4.0


def test_padding_threshold_custom_reaches_probe(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_CapturingProbe)
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--padding-threshold",
            "2.5",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    assert _captured_options[0]["padding_threshold"] == 2.5


def test_padding_threshold_below_one_rejected() -> None:
    result = runner.invoke(app, ["scan", "dow", "--padding-threshold", "0.5"])
    # Typer's FloatRange rejection exits 2 via SystemExit, not by raising
    # an unhandled exception. We assert the structural signal (exit code
    # plus no unhandled exception) rather than substring-matching the
    # Rich-formatted error panel, which gets width-truncated under a
    # narrow CI tty and may not contain the flag name.
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_max_requests_per_second_default_reaches_probe(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_CapturingProbe)
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    assert len(_captured_options) == 1
    assert _captured_options[0]["max_rps"] == 10.0


def test_max_requests_per_second_custom_reaches_probe(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_CapturingProbe)
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--max-requests-per-second",
            "5.0",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    assert _captured_options[0]["max_rps"] == 5.0


def test_max_requests_per_second_below_one_rejected() -> None:
    result = runner.invoke(app, ["scan", "dow", "--max-requests-per-second", "0.5"])
    # Mirror test_padding_threshold_below_one_rejected: Typer's FloatRange
    # rejection exits 2 via SystemExit. Assert the structural signal rather
    # than substring-matching the width-truncated Rich error panel.
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)


def _audit_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_audit_log_records_completed_scan(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_CapturingProbe)
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    audit = tmp_path / "audit.jsonl"
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--format",
            "json",
            "--output",
            str(out),
            "--audit-log",
            str(audit),
        ],
    )
    assert result.exit_code == 0
    lines = _audit_lines(audit)
    assert len(lines) == 1
    record: Any = json.loads(lines[0])
    assert record["outcome"] == "completed_clean"
    assert record["module"] == "dow"
    assert record["target"] == "http://allowed"
    assert record["scope_signer_public_key"] is not None
    assert record["findings_summary"]["total"] == 0
    assert record["output_file_sha256"] is not None
    assert record["vectrava_version"] is not None


def test_audit_log_preflight_unwritable_path_exits_2(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_CapturingProbe)
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    # A file where a directory is needed makes the audit parent un-creatable.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    bad_audit = blocker / "sub" / "audit.jsonl"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--audit-log",
            str(bad_audit),
        ],
    )
    assert result.exit_code == 2
    assert "audit" in _combined(result).lower()


def test_audit_log_dry_run_records_outcome(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("amp", tokens=100))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--dry-run",
            "--audit-log",
            str(audit),
        ],
    )
    assert result.exit_code == 0
    record: Any = json.loads(_audit_lines(audit)[0])
    assert record["outcome"] == "dry_run"
    assert record["exit_code"] == 0


def test_audit_log_auth_rejected_records_signer(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    scope = signed_scope_factory(
        tmp_path,
        targets=["https://example.test"],
        authorized_until=datetime.now(UTC) - timedelta(days=1),
    )
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "https://example.test",
            "--audit-log",
            str(audit),
        ],
    )
    assert result.exit_code == 2
    record: Any = json.loads(_audit_lines(audit)[0])
    assert record["outcome"] == "authorization_rejected"
    assert record["scope_signer_public_key"] is not None
    assert record["scope_authorized_until"] is not None


def test_audit_log_env_var_used_when_flag_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_CapturingProbe)
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    env_audit = tmp_path / "env_audit.jsonl"
    monkeypatch.setenv("VECTRAVA_AUDIT_LOG_PATH", str(env_audit))

    base = [
        "scan",
        "dow",
        "--scope",
        str(scope),
        "--target",
        "http://allowed",
        "--format",
        "json",
        "--output",
        str(out),
    ]
    # No --audit-log flag: the env var path is used.
    result = runner.invoke(app, base)
    assert result.exit_code == 0
    assert len(_audit_lines(env_audit)) == 1

    # Flag present: it wins, and the env path is not written again.
    flag_audit = tmp_path / "flag_audit.jsonl"
    result = runner.invoke(app, [*base, "--audit-log", str(flag_audit)])
    assert result.exit_code == 0
    assert len(_audit_lines(flag_audit)) == 1
    assert len(_audit_lines(env_audit)) == 1  # unchanged: env did not receive the second record


def test_cost_info_line_prints_below_threshold(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))  # well below the 150k threshold
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    # No --yes and no input: the prompt must NOT fire below threshold (an unexpected
    # prompt would hang the runner), so the scan completes cleanly.
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    text = _combined(result)
    assert "Estimated cost: 2,000 tokens" in text
    assert "(~$0.0003, model rate)" in text


def test_cost_info_line_prints_above_threshold_then_confirm(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("big", tokens=200_000))  # above the 150k threshold
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--format",
            "json",
            "--output",
            str(out),
        ],
        input="y\n",
    )
    text = _combined(result)
    assert "Estimated cost: 200,000 tokens" in text
    assert "(~$0.0300, model rate)" in text
    # The prompt's wording is unchanged and does not use thousands-separators.
    assert "This scan will consume up to 200000 tokens" in text
    assert result.exit_code in (0, 1)  # confirmed; 0 (no findings) here
    assert "aborted" not in text


def test_cost_info_line_does_not_print_in_dry_run_path(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    result = runner.invoke(
        app,
        ["scan", "dow", "--scope", str(scope), "--target", "http://allowed", "--dry-run"],
    )
    assert result.exit_code == 0
    text = _combined(result)
    assert "dry run:" in text  # the existing dry-run line still prints
    assert "Estimated cost:" not in text  # the info line does not print on the dry-run path


def test_cost_info_line_format_matches_dry_run_numbers(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    # The info line uses thousands-separators for legibility at high token counts;
    # the dry-run line does not. Both paths agree on the numbers (2000 tokens,
    # $0.0003) and the rate source (model rate); only the token formatting differs.
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    actual = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    actual_text = _combined(actual)
    assert "2,000" in actual_text  # info line: comma-separated
    assert "0.0003" in actual_text

    dry = runner.invoke(
        app,
        ["scan", "dow", "--scope", str(scope), "--target", "http://allowed", "--dry-run"],
    )
    dry_text = _combined(dry)
    assert "2000" in dry_text  # dry-run line: no comma
    assert "0.0003" in dry_text


def test_cost_info_line_is_not_colored(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    # CliRunner strips color by default (not a TTY), so this mainly guards against
    # an accidental secho(fg=...) on the cost-gate path; still worth pinning.
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert "\x1b[" not in _combined(result)


def test_audit_log_records_cost_estimate_for_live_scan(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    audit = tmp_path / "audit.jsonl"
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--format",
            "json",
            "--output",
            str(out),
            "--audit-log",
            str(audit),
        ],
    )
    assert result.exit_code == 0
    record: Any = json.loads(_audit_lines(audit)[0])
    assert record["estimated_tokens"] == 2000
    # Default model is gpt-4o-mini; the audit field rounds to 6 decimals.
    expected_cost, _ = _estimated_cost_usd(2000, "gpt-4o-mini")
    assert record["estimated_cost_usd"] == round(expected_cost, 6)


def test_audit_log_records_cost_estimate_for_dry_run(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--dry-run",
            "--audit-log",
            str(audit),
        ],
    )
    assert result.exit_code == 0
    record: Any = json.loads(_audit_lines(audit)[0])
    # Dry-run records the estimate: the figure exists and is the single most
    # useful fact about a dry-run, so it is captured rather than left null.
    assert record["outcome"] == "dry_run"
    assert record["estimated_tokens"] == 2000
    assert record["estimated_cost_usd"] is not None


def test_audit_log_records_cost_estimate_for_declined_scan(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("big", tokens=200_000))  # above the 150k threshold
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--audit-log",
            str(audit),
        ],
        input="n\n",
    )
    assert result.exit_code == 0
    record: Any = json.loads(_audit_lines(audit)[0])
    # The operator saw the cost and declined; the audit record agrees with the
    # figure they were shown.
    assert record["outcome"] == "aborted_by_user"
    assert record["estimated_tokens"] == 200000
    assert record["estimated_cost_usd"] is not None


def test_info_line_shows_model_rate_when_lookup_succeeds(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--model",
            "gpt-4o-mini",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    text = _combined(result)
    assert "model rate" in text
    # A known model uses a real rate, so no fallback warning is emitted.
    assert "fallback" not in text
    assert "warning:" not in text


def test_info_line_shows_fallback_rate_for_unknown_model(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--model",
            "some-fake-model",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0
    text = _combined(result)
    assert "fallback rate" in text
    # The one-time stderr warning names the unknown model so operators can request
    # its addition. CliRunner folds stderr into the combined output.
    assert "warning:" in text
    assert "some-fake-model" in text


def test_audit_field_records_model_rate(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = signed_scope_factory(tmp_path, targets=["http://allowed"])
    audit = tmp_path / "audit.jsonl"
    out = tmp_path / "out.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "http://allowed",
            "--model",
            "gpt-4o-mini",
            "--format",
            "json",
            "--output",
            str(out),
            "--audit-log",
            str(audit),
        ],
    )
    assert result.exit_code == 0
    record: Any = json.loads(_audit_lines(audit)[0])
    rate = PRICING_TABLE["gpt-4o-mini"]
    assert record["estimated_cost_usd"] == round((2000 / 1000) * rate, 6)
    # The recorded cost uses the real model rate, not the old placeholder.
    assert record["estimated_cost_usd"] != round((2000 / 1000) * USD_PER_1K_TOKENS, 6)
