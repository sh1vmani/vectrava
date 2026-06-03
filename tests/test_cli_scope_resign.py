"""CLI tests for `vtra scope re-sign`.

Drives the re-sign subcommand through CliRunner: signs a scope, reissues it with
a new deadline, and confirms refusal on unsigned or tampered input, a bad
--until value, and that a past deadline supersedes the scope under the gate. No
network and no keys on disk beyond the tmp_path each test writes.
"""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING, Any

import pytest
from typer.testing import CliRunner

from vectrava.cli import app
from vectrava.core.auth_gate import AuthorizationError, AuthorizationGate
from vectrava.core.signing import generate_keypair

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def _combined(result: Any) -> str:
    text = result.stdout or ""
    with contextlib.suppress(ValueError, AttributeError):
        text += result.stderr or ""
    return text


def _make_key(tmp_path: Path) -> tuple[Path, str]:
    """Generate a keypair, write the private key to disk, return its path and pubkey."""
    priv_b64, pub_b64 = generate_keypair()
    key_path = tmp_path / "key"
    key_path.write_text(priv_b64, encoding="utf-8")
    return key_path, pub_b64


def _write_unsigned_scope(path: Path, authorized_until: str) -> None:
    """Write an unsigned scope JSON with the given deadline to path."""
    scope = {
        "targets": ["https://api.openai.com"],
        "authorized_until": authorized_until,
        "signed_by": "tester",
    }
    path.write_text(json.dumps(scope, indent=2), encoding="utf-8")


def test_resign_roundtrip_updates_deadline(tmp_path: Path) -> None:
    key_path, _pub_b64 = _make_key(tmp_path)
    scope = tmp_path / "scope.json"
    _write_unsigned_scope(scope, "2099-12-31T23:59:59Z")

    signed = runner.invoke(app, ["scope", "sign", str(scope), "--key", str(key_path)])
    assert signed.exit_code == 0

    reissued = tmp_path / "reissued.json"
    result = runner.invoke(
        app,
        [
            "scope",
            "re-sign",
            str(scope),
            "--key",
            str(key_path),
            "--until",
            "2026-12-31T00:00:00Z",
            "--output",
            str(reissued),
        ],
    )
    assert result.exit_code == 0

    data = json.loads(reissued.read_text(encoding="utf-8"))
    assert data["authorized_until"] == "2026-12-31T00:00:00Z"
    assert data["targets"] == ["https://api.openai.com"]
    assert data["signed_by"] == "tester"
    assert data["signature"]
    assert data["public_key"]

    verified = runner.invoke(app, ["scope", "verify", str(reissued)])
    assert verified.exit_code == 0
    assert "signature valid" in _combined(verified)


def test_resign_refuses_unsigned_input(tmp_path: Path) -> None:
    key_path, _pub_b64 = _make_key(tmp_path)
    scope = tmp_path / "scope.json"
    _write_unsigned_scope(scope, "2099-12-31T23:59:59Z")  # never signed

    reissued = tmp_path / "reissued.json"
    result = runner.invoke(
        app,
        [
            "scope",
            "re-sign",
            str(scope),
            "--key",
            str(key_path),
            "--until",
            "2026-12-31T00:00:00Z",
            "--output",
            str(reissued),
        ],
    )
    assert result.exit_code == 1
    assert "refusing to reissue" in _combined(result)
    assert not reissued.exists()


def test_resign_refuses_tampered_input(tmp_path: Path) -> None:
    key_path, _pub_b64 = _make_key(tmp_path)
    scope = tmp_path / "scope.json"
    _write_unsigned_scope(scope, "2099-12-31T23:59:59Z")

    signed = runner.invoke(app, ["scope", "sign", str(scope), "--key", str(key_path)])
    assert signed.exit_code == 0

    # Tamper a signed field after signing so the canonical payload no longer matches.
    data = json.loads(scope.read_text(encoding="utf-8"))
    data["signed_by"] = "tampered"
    scope.write_text(json.dumps(data, indent=2), encoding="utf-8")

    reissued = tmp_path / "reissued.json"
    result = runner.invoke(
        app,
        [
            "scope",
            "re-sign",
            str(scope),
            "--key",
            str(key_path),
            "--until",
            "2026-12-31T00:00:00Z",
            "--output",
            str(reissued),
        ],
    )
    assert result.exit_code == 1
    assert "refusing to reissue" in _combined(result)


def test_resign_to_past_deadline_supersedes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path, pub_b64 = _make_key(tmp_path)
    monkeypatch.setenv("VECTRAVA_TRUSTED_KEYS", pub_b64)
    scope = tmp_path / "scope.json"
    _write_unsigned_scope(scope, "2099-12-31T23:59:59Z")

    signed = runner.invoke(app, ["scope", "sign", str(scope), "--key", str(key_path)])
    assert signed.exit_code == 0

    reissued = tmp_path / "reissued.json"
    result = runner.invoke(
        app,
        [
            "scope",
            "re-sign",
            str(scope),
            "--key",
            str(key_path),
            "--until",
            "2020-01-01T00:00:00Z",
            "--output",
            str(reissued),
        ],
    )
    assert result.exit_code == 0
    assert "supersedes the scope" in _combined(result)

    gate = AuthorizationGate(reissued)
    with pytest.raises(AuthorizationError, match="expired"):
        gate.check()


def test_resign_rejects_bad_until(tmp_path: Path) -> None:
    key_path, _pub_b64 = _make_key(tmp_path)
    scope = tmp_path / "scope.json"
    _write_unsigned_scope(scope, "2099-12-31T23:59:59Z")

    signed = runner.invoke(app, ["scope", "sign", str(scope), "--key", str(key_path)])
    assert signed.exit_code == 0

    reissued = tmp_path / "reissued.json"
    result = runner.invoke(
        app,
        [
            "scope",
            "re-sign",
            str(scope),
            "--key",
            str(key_path),
            "--until",
            "not-a-date",
            "--output",
            str(reissued),
        ],
    )
    assert result.exit_code == 1
    assert "invalid --until value" in _combined(result)
