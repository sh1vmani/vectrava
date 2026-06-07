"""CLI tests for `vtra scope new-key`.

Drives the new-key subcommand through CliRunner and covers the platform branch:
on Windows the command warns that file permissions were not restricted, on POSIX
it does not. No network; each test writes only into its tmp_path out-dir.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from typer.testing import CliRunner

from vectrava.cli import app

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

runner = CliRunner()

_WARNING = "file permissions were not restricted"


def _combined(result: Any) -> str:
    text = result.stdout or ""
    with contextlib.suppress(ValueError, AttributeError):
        text += result.stderr or ""
    return text


def test_new_key_warns_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.platform", "win32")
    result = runner.invoke(app, ["scope", "new-key", "--out-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert _WARNING in _combined(result)
    assert (tmp_path / "vectrava_ed25519").exists()
    assert (tmp_path / "vectrava_ed25519.pub").exists()


def test_new_key_no_warning_on_posix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.platform", "linux")
    result = runner.invoke(app, ["scope", "new-key", "--out-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert _WARNING not in _combined(result)
    assert (tmp_path / "vectrava_ed25519").exists()
    assert (tmp_path / "vectrava_ed25519.pub").exists()
