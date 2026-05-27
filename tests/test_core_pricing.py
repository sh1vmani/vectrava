"""Tests for the per-model pricing table and lookup (core/pricing.py)."""

from __future__ import annotations

import pytest

from vectrava.cli import _estimated_cost_usd
from vectrava.core.pricing import PRICING_TABLE, USD_PER_1K_TOKENS, lookup_rate


@pytest.mark.parametrize(("model", "rate"), sorted(PRICING_TABLE.items()))
def test_pricing_lookup_returns_rate_for_known_model(model: str, rate: float) -> None:
    assert lookup_rate(model) == (rate, False)


def test_pricing_lookup_returns_fallback_for_unknown_model() -> None:
    assert lookup_rate("some-fake-model") == (USD_PER_1K_TOKENS, True)


def test_estimated_cost_usd_uses_model_rate() -> None:
    rate = PRICING_TABLE["gpt-4o-mini"]
    cost, is_fallback = _estimated_cost_usd(2000, "gpt-4o-mini")
    assert cost == (2000 / 1000) * rate
    assert is_fallback is False


def test_estimated_cost_usd_falls_back_for_unknown_model() -> None:
    cost, is_fallback = _estimated_cost_usd(2000, "unknown")
    assert cost == (2000 / 1000) * USD_PER_1K_TOKENS
    assert is_fallback is True
