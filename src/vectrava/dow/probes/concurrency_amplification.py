"""Concurrency-induced rate-limit bypass probe.

Many AI APIs implement rate limiting at request-count granularity (requests per
second or per minute) rather than at concurrent-request granularity. An attacker
holding a credential can spike the operator's bill by sending N parallel
requests on the same credential before any rate-limit window has elapsed; each
request consumes tokens and is billed even though the per-window counter has not
yet incremented. This is a distinct attack class from rate_limit_bypass, which
tests sustained over-rate tolerance on a single thread: a target can pass that
sibling (the per-minute limiter catches the 20th sequential request) and still
fail this one (five concurrent requests all complete before the counter ticks).

Detection is deterministic and count-based. The probe dispatches N identical
requests through ThreadPoolExecutor so they are genuinely in flight at the same
time, then tallies their statuses. Any HTTP 429 means the target enforced a
concurrency or rate guardrail; no 429 with N-1-or-more 200s means the operator's
bill scales linearly with N on a single credential. The probe sends each request
through post_no_retry, not the retrying client path, because a retry on 429
would mask the very signal the probe exists to observe. Per-request transport
errors are captured (recorded with status -1) rather than aborting the whole
burst, so a single transient drop does not invalidate the run; only an all-fail
burst raises ProbeError.

Two known limitations:
- Strict 429-only detection may miss targets that shed concurrency load with
  HTTP 503/529 or by dropping connections; those are guardrails too, but this
  probe treats only a 429 as evidence of enforcement. Broadening the signal is
  a future enhancement, coupled with the same broadening on rate_limit_bypass.
- Scan-ordering bleed: a target that enforces per-credential or per-IP limits
  may stay throttled after this burst, which can perturb probes that run later
  in the same scan. Prefer running this probe via --only, or last in a scan.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
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

_CONCURRENCY: int = 5
PROBE_MAX_TOKENS: int = 1
PROBE_PROMPT: str = "ping"


@register
class ConcurrencyAmplificationProbe(Probe):
    """Flags chat-completions endpoints that serve N concurrent requests on one credential."""

    name: ClassVar[str] = "concurrency_amplification"
    module: ClassVar[str] = "dow"
    description: ClassVar[str] = (
        "Dispatches a small burst of identical requests concurrently on one credential and "
        "flags the endpoint when most return 200 and none return HTTP 429, indicating absent "
        "concurrency-level rate limiting."
    )
    baseline_severity: ClassVar[Severity] = Severity.MEDIUM
    estimated_tokens_per_run: ClassVar[int] = _CONCURRENCY * (30 + PROBE_MAX_TOKENS)
    tags: ClassVar[tuple[str, ...]] = ("dow", "rate-limit", "concurrency", "infrastructure")
    requires_credentials: ClassVar[bool] = True
    default_endpoint: ClassVar[str | None] = "/v1/chat/completions"

    def run(self, ctx: ProbeContext) -> list[Finding]:
        """Dispatch N concurrent requests and flag the absence of HTTP 429 across the burst."""
        if ctx.credentials is None:
            raise ProbeError(
                "concurrency_amplification requires credentials but none were provided",
                probe_name=self.name,
            )
        credential = ctx.credentials

        raw_model = ctx.options.get("model")
        if not isinstance(raw_model, str):
            raise ProbeError(
                "concurrency_amplification requires a model identifier in options",
                probe_name=self.name,
            )
        model = raw_model

        endpoint_path = ctx.endpoint or self.default_endpoint or "/v1/chat/completions"
        url, payload, headers = ctx.adapter.build_request(
            target_base=ctx.target,
            model=model,
            messages=[{"role": "user", "content": PROBE_PROMPT}],
            max_tokens=PROBE_MAX_TOKENS,
            credential=credential,
            endpoint_path=endpoint_path,
        )

        def _send_one(index: int) -> tuple[int, int, float]:
            """Send one request; return (index, status, elapsed_ms); -1 on transport failure."""
            start = time.perf_counter()
            try:
                response = post_no_retry(ctx.http, url, json=payload, headers=headers, timeout=60.0)
            except (httpx.TransportError, httpx.TimeoutException):
                return (index, -1, (time.perf_counter() - start) * 1000)
            return (index, response.status_code, (time.perf_counter() - start) * 1000)

        # ThreadPoolExecutor.map preserves the order of the input iterable in its output,
        # so results land in index order without an explicit sort. httpx.Client is
        # thread-safe; the shared ctx.http is safe to use across the N workers.
        with ThreadPoolExecutor(max_workers=_CONCURRENCY) as executor:
            results = list(executor.map(_send_one, range(_CONCURRENCY)))

        if all(status == -1 for _, status, _ in results):
            raise ProbeError(
                f"transport failed for all {_CONCURRENCY} concurrent requests",
                probe_name=self.name,
                details={"results": [{"index": i, "status": s} for i, s, _ in results]},
            )

        status_counts: dict[str, int] = {}
        for _, status, _ in results:
            key = str(status)
            status_counts[key] = status_counts.get(key, 0) + 1

        saw_429 = status_counts.get("429", 0) > 0
        served_200 = status_counts.get("200", 0)

        # Any 429 means the target enforced a concurrency or rate guardrail; otherwise
        # require N-1 served 200s before firing, tolerating a single transient drop.
        if saw_429 or served_200 < _CONCURRENCY - 1:
            return []

        evidence: dict[str, JsonValue] = {
            "concurrency": _CONCURRENCY,
            "results": cast(
                "list[JsonValue]",
                [{"index": i, "status": s, "elapsed_ms": round(e, 1)} for i, s, e in results],
            ),
            "status_counts": cast("dict[str, JsonValue]", dict(status_counts)),
            "saw_429": saw_429,
            "served_200": served_200,
            "endpoint": endpoint_path,
        }
        finding = self.make_finding(
            message=(
                f"endpoint served {served_200} of {_CONCURRENCY} concurrent requests on one "
                "credential with no HTTP 429; concurrency-level rate-limit hardening is "
                "absent or ineffective."
            ),
            target=url,
            evidence=evidence,
            remediation=(
                "configure a per-credential or per-IP concurrency cap at the gateway in "
                "addition to a request-rate limit; an endpoint that throttles sustained "
                "over-rate but not simultaneous in-flight requests still leaks cost on a "
                "compromised or shared credential."
            ),
        )
        return [finding]
