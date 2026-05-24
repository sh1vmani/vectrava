"""Tests for the scan authorization gate."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vectrava.core.auth_gate import AuthorizationError, AuthorizationGate


def test_gate_rejects_when_scope_file_missing(tmp_path: Path) -> None:
    gate = AuthorizationGate(tmp_path / "does-not-exist.json")
    with pytest.raises(AuthorizationError):
        gate.check()


def test_gate_rejects_expired_scope(tmp_path: Path) -> None:
    path = tmp_path / "expired.json"
    payload = {
        "targets": ["https://example.test"],
        "authorized_until": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        "signed_by": "Shivamani Vastrala",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    gate = AuthorizationGate(path)
    with pytest.raises(AuthorizationError):
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
