"""Smoke tests that verify the package imports and exposes a version."""

from __future__ import annotations

import vectrava


def test_package_exposes_version() -> None:
    assert vectrava.__version__ == "0.0.1"
