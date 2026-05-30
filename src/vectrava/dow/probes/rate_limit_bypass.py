"""Rate-limit bypass probe.

Sends a deterministic burst of identical minimal requests faster than any
reasonable service-level rate limit and checks whether the target enforces HTTP
429 (Too Many Requests). Zero 429s across the burst means the endpoint served
every request unthrottled: rate-limit hardening is absent or set above the tested
rate, leaving the endpoint open to unbounded cost exposure. This is a
Denial-of-Wallet vector by absent infrastructure, distinct from the four
token-accounting dow probes (token_amplification, output_padding,
model_substitution, error_amplification), which measure per-request waste rather
than the absence of an infrastructure-level guardrail.

Detection is deterministic and count-based. No regex matching of model intent and
no LLM judge: the detection signal is the presence or absence of HTTP 429 across
a deterministic burst. The probe sends each request through post_no_retry, not
the retrying client path, because a retry on 429 would mask the very signal the
probe exists to observe.

Two known limitations:
- Strict 429-only detection may miss targets that shed load with HTTP 503/529 or
  by dropping connections; those are rate-limit defenses too, but this probe
  treats only a 429 as evidence of enforcement. Broadening the signal is a future
  enhancement.
- Scan-ordering bleed: a target that enforces per-credential or per-IP limits may
  stay throttled after this burst, which can perturb probes that run later in the
  same scan. Prefer running this probe via --only, or last in a scan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

import httpx

from vectrava.core.http import post_no_retry
from vectrava.core.probe import Probe, ProbeError
from vectrava.core.registry import register
from vectrava.core.result import Severity

if TYPE_CHECKING:
    from pydantic import JsonValue

    from vectrava.core.probe import ProbeContext
    from vectrava.core.result import Finding

_BURST_SIZE: int = 20
PROBE_MAX_TOKENS: int = 1
PROBE_PROMPT: str = "ping"


@register
class RateLimitBypassProbe(Probe):
    """Flags chat-completions endpoints that serve a request burst with no HTTP 429."""

    name: ClassVar[str] = "rate_limit_bypass"
    module: ClassVar[str] = "dow"
    description: ClassVar[str] = (
        "Sends a deterministic burst of minimal requests and flags the endpoint when "
        "none are answered with HTTP 429, indicating absent rate-limit hardening."
    )
    baseline_severity: ClassVar[Severity] = Severity.MEDIUM
    estimated_tokens_per_run: ClassVar[int] = _BURST_SIZE * (30 + PROBE_MAX_TOKENS)
    tags: ClassVar[tuple[str, ...]] = ("dow", "rate-limit", "infrastructure")
    requires_credentials: ClassVar[bool] = True

    def run(self, ctx: ProbeContext) -> list[Finding]:
        """Burst the endpoint and flag the absence of HTTP 429 across the burst."""
        if ctx.credentials is None:
            raise ProbeError(
                "rate_limit_bypass requires credentials but none were provided",
                probe_name=self.name,
            )
        credential = ctx.credentials

        raw_model = ctx.options.get("model")
        if not isinstance(raw_model, str):
            raise ProbeError(
                "rate_limit_bypass requires a model identifier in options",
                probe_name=self.name,
            )
        model = raw_model

        endpoint_path = ctx.endpoint or ctx.adapter.default_endpoint_path
        url, payload, headers = ctx.adapter.build_request(
            target_base=ctx.target,
            model=model,
            messages=[{"role": "user", "content": PROBE_PROMPT}],
            max_tokens=PROBE_MAX_TOKENS,
            credential=credential,
            endpoint_path=endpoint_path,
        )

        # The burst deliberately ignores ctx.options["max_rps"]: its purpose is to
        # overpace, and post_no_retry applies no client-side pacing.
        status_counts: dict[str, int] = {}
        for _ in range(_BURST_SIZE):
            try:
                response = post_no_retry(ctx.http, url, json=payload, headers=headers, timeout=60.0)
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                raise ProbeError(
                    f"transport failure during burst: {exc}",
                    probe_name=self.name,
                    details={"completed_requests": sum(status_counts.values())},
                ) from exc
            code = str(response.status_code)
            status_counts[code] = status_counts.get(code, 0) + 1

        saw_429 = status_counts.get("429", 0) > 0
        if saw_429:
            return []

        evidence: dict[str, JsonValue] = {
            "burst_size": _BURST_SIZE,
            "status_counts": cast("dict[str, JsonValue]", dict(status_counts)),
            "saw_429": saw_429,
            "endpoint": endpoint_path,
        }
        finding = self.make_finding(
            message=(
                f"endpoint served {_BURST_SIZE} consecutive requests with no HTTP 429; "
                "rate-limit hardening is absent or ineffective."
            ),
            target=url,
            evidence=evidence,
            remediation=(
                "configure a rate limit at the gateway (e.g. 20 req/min per credential "
                "or IP) and return HTTP 429 once exceeded; an unprotected "
                "chat-completions endpoint is a cost-exposure surface."
            ),
        )
        return [finding]
