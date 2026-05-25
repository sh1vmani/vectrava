"""Shared pytest fixtures for the vectrava test suite."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vectrava.config.scope import ScopeFile
from vectrava.core.signing import generate_keypair, sign_scope


@pytest.fixture
def signed_scope_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., Path]:
    """Factory that builds a signed scope file and sets VECTRAVA_TRUSTED_KEYS.

    Each call generates a fresh ephemeral Ed25519 keypair, signs the scope
    payload, embeds signature and public_key, writes the JSON, and registers the
    public key in VECTRAVA_TRUSTED_KEYS so the gate accepts it.
    """

    def _make(
        tmp_path: Path,
        *,
        targets: list[str] | None = None,
        authorized_until: datetime | None = None,
        signed_by: str = "Shivamani Vastrala",
        filename: str = "scope.json",
    ) -> Path:
        if targets is None:
            targets = ["https://example.test"]
        if authorized_until is None:
            authorized_until = datetime.now(UTC) + timedelta(days=1)
        scope = ScopeFile(
            targets=targets,
            authorized_until=authorized_until,
            signed_by=signed_by,
        )
        priv_b64, pub_b64 = generate_keypair()
        signed = sign_scope(scope, priv_b64)
        data = signed.model_dump(mode="json")
        path = tmp_path / filename
        path.write_text(json.dumps(data), encoding="utf-8")

        # Register this public key as trusted. If the env var already holds keys
        # from a prior factory call in the same test, append rather than overwrite.
        existing = os.environ.get("VECTRAVA_TRUSTED_KEYS", "")
        keys = [part for part in (raw.strip() for raw in existing.split(",")) if part]
        if pub_b64 not in keys:
            keys.append(pub_b64)
        monkeypatch.setenv("VECTRAVA_TRUSTED_KEYS", ",".join(keys))
        return path

    return _make


@pytest.fixture
def valid_scope_file(tmp_path: Path, signed_scope_factory: Callable[..., Path]) -> Path:
    """Write a valid, unexpired, signed scope file and return its path."""
    return signed_scope_factory(tmp_path)
