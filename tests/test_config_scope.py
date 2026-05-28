"""Tests for scope-file target validation.

Targets must be base URLs (scheme, host, optional port, at most a trailing
slash). Probes append the endpoint path, so a target carrying a path would
double it against a live endpoint. The rule is enforced both on scope-file
targets at model-validate time and on the --target CLI value.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from vectrava.cli import app
from vectrava.config.scope import ScopeFile, validate_base_target

runner = CliRunner()


def _combined(result: Any) -> str:
    text = result.stdout or ""
    with contextlib.suppress(ValueError, AttributeError):
        text += result.stderr or ""
    return text


def _scope(target: str) -> ScopeFile:
    return ScopeFile(
        targets=[target],
        authorized_until=datetime.now(UTC) + timedelta(days=1),
        signed_by="Shivamani Vastrala",
    )


def test_scope_rejects_target_with_chat_completions_path() -> None:
    with pytest.raises(ValidationError, match="base URL with no path"):
        _scope("https://api.openai.com/v1/chat/completions")


def test_scope_rejects_target_with_other_path() -> None:
    with pytest.raises(ValidationError, match="base URL with no path"):
        _scope("https://api.openai.com/v1/responses")


def test_scope_rejects_target_without_scheme() -> None:
    with pytest.raises(ValidationError, match="http:// or https://"):
        _scope("api.openai.com")


def test_scope_accepts_bare_base_target() -> None:
    scope = _scope("https://api.openai.com")
    assert scope.targets == ["https://api.openai.com"]


def test_scope_accepts_bare_base_with_trailing_slash() -> None:
    scope = _scope("https://api.openai.com/")
    assert scope.targets == ["https://api.openai.com/"]


def test_validate_base_target_rejects_query_or_fragment() -> None:
    with pytest.raises(ValueError, match="query or fragment"):
        validate_base_target("https://api.openai.com?model=x")


def test_scan_target_with_path_exits_2(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    # The scope itself is a valid bare base, so the failure is isolated to the
    # --target form rather than the scope file.
    scope = signed_scope_factory(tmp_path, targets=["https://api.openai.com"])
    result = runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "https://api.openai.com/v1/chat/completions",
        ],
    )
    assert result.exit_code == 2
    assert "base URL with no path" in _combined(result)
