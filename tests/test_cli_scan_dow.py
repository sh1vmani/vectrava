"""CLI tests for `vectrava scan dow`."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from vectrava.cli import app
from vectrava.core import registry
from vectrava.core.probe import Probe
from vectrava.core.result import Severity

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    registry.clear()
    yield
    registry.clear()


def _combined(result: Any) -> str:
    text = result.stdout or ""
    with contextlib.suppress(ValueError, AttributeError):
        text += result.stderr or ""
    return text


def _write_scope(path: Path, targets: list[str]) -> Path:
    path.write_text(
        json.dumps(
            {
                "targets": targets,
                "authorized_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "signed_by": "Shivamani Vastrala",
            }
        ),
        encoding="utf-8",
    )
    return path


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


def test_scan_with_target_not_in_scope_exits_2(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path / "scope.json", ["http://allowed"])
    result = runner.invoke(
        app,
        ["scan", "dow", "--scope", str(scope), "--target", "http://not-allowed"],
    )
    assert result.exit_code == 2
    assert "authorized" in _combined(result).lower()


def test_dry_run_does_not_make_api_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry.register(_make_dow_probe("amp", tokens=100))
    scope = _write_scope(tmp_path / "scope.json", ["http://allowed"])

    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("httpx.Client must not be constructed during a dry run")

    monkeypatch.setattr(httpx, "Client", boom)
    result = runner.invoke(
        app,
        ["scan", "dow", "--scope", str(scope), "--target", "http://allowed", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "dry run" in _combined(result).lower()


def test_dry_run_prints_estimate(tmp_path: Path) -> None:
    registry.register(_make_dow_probe("amp", tokens=2000))
    scope = _write_scope(tmp_path / "scope.json", ["http://allowed"])
    result = runner.invoke(
        app,
        ["scan", "dow", "--scope", str(scope), "--target", "http://allowed", "--dry-run"],
    )
    assert result.exit_code == 0
    text = _combined(result)
    assert "2000" in text
    assert "0.02" in text
