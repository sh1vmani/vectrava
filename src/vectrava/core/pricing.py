"""Per-model USD pricing for scan cost estimation.

vectrava never calls these models itself; it calls the operator's target, which
is whatever they are testing. This table exists so the cost gate can show an
operator an order-of-magnitude estimate of what a scan against a given model
would cost, based on the model passed via --model.

v1 contract:

- Rates are per-1K input tokens, in USD, and are point-in-time accurate as of the
  2026-05-26 release that shipped them. Provider list prices change on a
  weeks-to-months cadence, so this table drifts out of date over time.
- Input rate only. The probes' estimated token counts are worst-case upper bounds
  dominated by input (long prompts, short capped replies), so the input rate
  applied to the whole count is a reasonable approximation; output is priced
  higher but is a small fraction of the total.
- Operators with billing-grade accuracy needs should not depend on this table.
  Treat the figure as an order-of-magnitude estimate, not a billing contract.
- External-config override (per-deployment rate customization) is planned for a
  future release. v1 is a built-in table only.

Lookups are exact-key against the model id string. Model ids that are not in the
table fall back to USD_PER_1K_TOKENS and are flagged so callers can mark the
figure approximate.
"""

from __future__ import annotations

# Fallback placeholder rate, applied to any model not in the table below. Also
# the historical default before per-model pricing existed.
USD_PER_1K_TOKENS = 0.01

# Default model identifier used by the CLI and probe fallbacks when --model is
# not passed. Centralized so the 15+ sites that previously hardcoded the default
# share one source of truth; a future change is a one-line update here.
# Drives the displayed cost estimate and the request body model field when
# --model is omitted. Not a network endpoint default: there is no default target
# host, so --target is always operator-supplied.
DEFAULT_MODEL: str = "gpt-5.4-mini"

# Model id -> per-1K input-token rate in USD. Keys are exact API id strings, not
# display names. Each block records its canonical source and fetch date so future
# updaters know what was verified and when.
PRICING_TABLE: dict[str, float] = {
    # OpenAI. source: https://developers.openai.com/api/docs/pricing, fetched 2026-05-26
    "gpt-5.5": 0.005,
    "gpt-5.4": 0.0025,
    "gpt-5.4-mini": 0.00075,
    "gpt-5.4-nano": 0.0002,
    # gpt-4o-mini is delisted from the canonical OpenAI pricing page; rate from web
    # search corroboration ($0.15 / 1M input). Kept for historical reasons and so
    # cost lookups for this id still resolve after its delisting.
    # source: https://developers.openai.com/api/docs/pricing (delisted), fetched 2026-05-26
    "gpt-4o-mini": 0.00015,
    # Claude. rates: https://platform.claude.com/docs/en/about-claude/pricing, fetched 2026-05-26
    # API ids: https://platform.claude.com/docs/en/about-claude/models/overview, fetched 2026-05-26
    "claude-opus-4-7": 0.005,
    "claude-sonnet-4-6": 0.003,
    "claude-haiku-4-5": 0.001,
    # Gemini. rates: https://ai.google.dev/pricing, fetched 2026-05-26
    # API ids: https://ai.google.dev/gemini-api/docs/models, fetched 2026-05-26
    "gemini-2.5-pro": 0.00125,
    "gemini-2.5-flash": 0.0003,
    "gemini-2.5-flash-lite": 0.0001,
}


def lookup_rate(model: str) -> tuple[float, bool]:
    """Return (rate_per_1k_usd, is_fallback) for a model id.

    Exact-key match against PRICING_TABLE. On a miss, returns the placeholder
    fallback rate and True so the caller can flag the figure as approximate.
    """
    if model in PRICING_TABLE:
        return PRICING_TABLE[model], False
    return USD_PER_1K_TOKENS, True
