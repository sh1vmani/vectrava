"""Tests for the scan authorization gate."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vectrava.config.scope import ScopeFile
from vectrava.core.auth_gate import AuthorizationError, AuthorizationGate
from vectrava.core.signing import generate_keypair, sign_scope


def test_gate_rejects_when_scope_file_missing(tmp_path: Path) -> None:
    gate = AuthorizationGate(tmp_path / "does-not-exist.json")
    with pytest.raises(AuthorizationError):
        gate.check()


def test_gate_rejects_expired_scope(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    path = signed_scope_factory(tmp_path, authorized_until=datetime.now(UTC) - timedelta(days=1))
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError, match="expired"):
        gate.check()


def test_gate_rejects_malformed_scope(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_text("{not valid json", encoding="utf-8")
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError):
        gate.check()


def test_gate_accepts_valid_scope(valid_scope_file: Path) -> None:
    gate = AuthorizationGate(valid_scope_file)
    scope = gate.check()
    assert scope.signed_by == "Shivamani Vastrala"
    assert scope.targets == ["https://example.test"]


def test_gate_rejects_unsigned_scope(tmp_path: Path) -> None:
    """An unsigned scope file must be rejected with no grace period."""
    scope_data = {
        "targets": ["https://example.test"],
        "authorized_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "signed_by": "Unsigned Operator",
    }
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(scope_data), encoding="utf-8")
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError, match="not signed"):
        gate.check()


def test_gate_rejects_untrusted_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A signed scope whose key is not in VECTRAVA_TRUSTED_KEYS must be rejected."""
    monkeypatch.setenv("VECTRAVA_TRUSTED_KEYS", "")  # explicitly empty
    scope = ScopeFile(
        targets=["https://example.test"],
        authorized_until=datetime.now(UTC) + timedelta(days=1),
        signed_by="Untrusted Operator",
    )
    priv_b64, _ = generate_keypair()
    signed = sign_scope(scope, priv_b64)
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(signed.model_dump(mode="json")), encoding="utf-8")
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError, match="untrusted"):
        gate.check()


def test_scope_present_on_expired_rejection(
    tmp_path: Path, signed_scope_factory: Callable[..., Path]
) -> None:
    """An expired-but-valid scope attaches its parsed contents to the error."""
    deadline = datetime.now(UTC) - timedelta(days=1)
    path = signed_scope_factory(tmp_path, authorized_until=deadline)
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError) as exc_info:
        gate.check()
    assert exc_info.value.scope is not None
    assert exc_info.value.scope.signed_by == "Shivamani Vastrala"
    assert exc_info.value.scope.authorized_until.replace(tzinfo=UTC) == deadline


def test_scope_present_on_unsigned_rejection(tmp_path: Path) -> None:
    scope_data = {
        "targets": ["https://example.test"],
        "authorized_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "signed_by": "Unsigned Operator",
    }
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(scope_data), encoding="utf-8")
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError, match="not signed") as exc_info:
        gate.check()
    assert exc_info.value.scope is not None
    assert exc_info.value.scope.signed_by == "Unsigned Operator"


def test_scope_present_on_untrusted_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VECTRAVA_TRUSTED_KEYS", "")
    scope = ScopeFile(
        targets=["https://example.test"],
        authorized_until=datetime.now(UTC) + timedelta(days=1),
        signed_by="Untrusted Operator",
    )
    priv_b64, _ = generate_keypair()
    signed = sign_scope(scope, priv_b64)
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(signed.model_dump(mode="json")), encoding="utf-8")
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError, match="untrusted") as exc_info:
        gate.check()
    assert exc_info.value.scope is not None
    assert exc_info.value.scope.public_key is not None


def test_gate_rejects_signature_mismatch(
    tmp_path: Path,
    signed_scope_factory: Callable[..., Path],
) -> None:
    # Build a signed, trusted, non-expired scope, then tamper its signed_by after
    # signing. The pubkey and signature still parse and the pubkey is still trusted,
    # so the gate reaches the signature-verify step; verify_scope then fails because
    # the canonical payload no longer matches the signature.
    path = signed_scope_factory(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["signed_by"] = "Tampered Operator"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(AuthorizationError, match="signature verification"):
        AuthorizationGate(path).check()


def test_scope_present_on_signature_mismatch_rejection(
    tmp_path: Path,
    signed_scope_factory: Callable[..., Path],
) -> None:
    # The audit log captures the attacker's claimed scope on signature mismatch, so a
    # forensic reviewer can see what was claimed even though the signature did not
    # verify.
    path = signed_scope_factory(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["signed_by"] = "Tampered Operator"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(AuthorizationError) as exc_info:
        AuthorizationGate(path).check()

    assert exc_info.value.scope is not None
    assert exc_info.value.scope.signed_by == "Tampered Operator"
    assert exc_info.value.scope.signature is not None
    assert exc_info.value.scope.public_key is not None


def test_scope_none_on_missing_file(tmp_path: Path) -> None:
    gate = AuthorizationGate(tmp_path / "does-not-exist.json")
    with pytest.raises(AuthorizationError) as exc_info:
        gate.check()
    assert exc_info.value.scope is None


def test_scope_none_on_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_text("{not valid json", encoding="utf-8")
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError) as exc_info:
        gate.check()
    assert exc_info.value.scope is None
