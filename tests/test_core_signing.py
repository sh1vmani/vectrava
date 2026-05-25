"""Tests for the Ed25519 scope-file signing module."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.exceptions import InvalidSignature

from vectrava.config.scope import ScopeFile
from vectrava.core.signing import (
    b64url_decode,
    b64url_encode,
    canonical_payload,
    generate_keypair,
    sign_scope,
    trusted_public_keys,
    verify_scope,
)


@pytest.fixture
def scope() -> ScopeFile:
    return ScopeFile(
        targets=["https://example.test"],
        authorized_until=datetime.now(UTC) + timedelta(days=1),
        signed_by="Shivamani Vastrala",
    )


def test_canonical_payload_is_deterministic() -> None:
    until = datetime.now(UTC) + timedelta(days=1)
    first = ScopeFile(targets=["https://example.test"], authorized_until=until, signed_by="X")
    second = ScopeFile(targets=["https://example.test"], authorized_until=until, signed_by="X")
    assert canonical_payload(first) == canonical_payload(second)


def test_canonical_payload_excludes_signature_fields(scope: ScopeFile) -> None:
    signed = scope.model_copy(update={"signature": "sig", "public_key": "key"})
    assert canonical_payload(signed) == canonical_payload(scope)


def test_sign_and_verify_roundtrip(scope: ScopeFile) -> None:
    priv_b64, _pub_b64 = generate_keypair()
    signed = sign_scope(scope, priv_b64)
    verify_scope(signed)  # raises on failure


def test_verify_rejects_tampered_payload(scope: ScopeFile) -> None:
    priv_b64, _pub_b64 = generate_keypair()
    signed = sign_scope(scope, priv_b64)
    tampered = signed.model_copy(update={"targets": ["https://evil.test"]})
    with pytest.raises(InvalidSignature):
        verify_scope(tampered)


def test_verify_raises_on_missing_signature(scope: ScopeFile) -> None:
    with pytest.raises(ValueError, match="no signature"):
        verify_scope(scope)


def test_trusted_public_keys_empty_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VECTRAVA_TRUSTED_KEYS", raising=False)
    assert trusted_public_keys() == frozenset()


def test_trusted_public_keys_parses_comma_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VECTRAVA_TRUSTED_KEYS", "abc,def, ghi ")
    assert trusted_public_keys() == frozenset({"abc", "def", "ghi"})


def test_b64url_roundtrip() -> None:
    for size in (0, 1, 15, 16, 31, 32, 64):
        data = os.urandom(size)
        assert b64url_decode(b64url_encode(data)) == data
