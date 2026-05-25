"""CLI tests for `vectrava scan dow`."""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import JsonValue
from typer.testing import CliRunner

from vectrava.cli import app
from vectrava.core import registry
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
    assert "0.02" in text


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
    assert result.exit_code == 2
    assert "padding-threshold" in _combined(result).lower()
