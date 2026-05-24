"""Shared pytest fixtures for the vectrava test suite."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


@pytest.fixture
def valid_scope_file(tmp_path: Path) -> Path:
    """Write a valid, unexpired scope file and return its path."""
    path = tmp_path / "scope.json"
    payload = {
        "targets": ["https://example.test"],
        "authorized_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "signed_by": "Shivamani Vastrala",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
