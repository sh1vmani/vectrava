"""HTTP client wrapper for Denial-of-Wallet probes.

A single synchronous helper, `call_completion`, sends one prompt to an
OpenAI-compatible chat-completions endpoint and returns normalized token
accounting. It reads no environment: the caller supplies the already-resolved
BYOK credential. Every failure path raises `ProbeError` so the runner can
isolate the probe and continue. No retries are attempted.
"""

from __future__ import annotations

import time

import httpx
from pydantic import BaseModel, ValidationError

from vectrava.core.probe import ProbeError

_BODY_PREVIEW_CHARS = 500


class TokenUsage(BaseModel):
    """Token accounting parsed from a target completion response."""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class CompletionResult(BaseModel):
    """One target response, normalized for amplification analysis."""

    usage: TokenUsage
    finish_reason: str | None
    latency_ms: float
    http_status: int
    model: str | None


def call_completion(
    http: httpx.Client,
    *,
    url: str,
    credential: str,
    model: str,
    prompt: str,
    max_tokens: int,
    timeout_s: float = 60.0,
) -> CompletionResult:
    """Send one benign prompt to an OpenAI-compatible chat endpoint.

    Reads no environment; `credential` is the resolved BYOK value, never an
    env-var name. Returns normalized token accounting on a 2xx response with
    parseable usage. Raises `ProbeError` on transport failure, timeout, non-2xx
    status, or missing usage. No retry is attempted.

    Args:
        http: Synchronous client supplied by the runner.
        url: Fully resolved POST URL.
        credential: Resolved API key value, sent as a Bearer token.
        model: Model identifier placed in the request body.
        prompt: The single user prompt to send.
        max_tokens: Output cap requested from the target.
        timeout_s: Per-request timeout in seconds.

    Returns:
        A CompletionResult with token usage, finish reason, latency, status,
        and the echoed model.

    Raises:
        ProbeError: on any transport, timeout, status, or schema failure.
    """
    request_body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {credential}"}

    start = time.perf_counter()
    try:
        response = http.post(url, json=request_body, headers=headers, timeout=timeout_s)
    except httpx.TimeoutException as exc:
        raise ProbeError(
            f"target did not respond within {timeout_s}s",
            details={"timeout_s": timeout_s},
        ) from exc
    except httpx.TransportError as exc:
        raise ProbeError(
            f"could not reach target: {exc}",
            details=repr(exc),
        ) from exc
    latency_ms = (time.perf_counter() - start) * 1000

    status = response.status_code
    if status == 429:
        raise ProbeError(
            "target rate-limited the probe (429); no backoff is implemented",
            details={"status": 429, "retry_after": response.headers.get("Retry-After")},
        )
    if status in (401, 403):
        raise ProbeError(
            f"target rejected the credential ({status}); check --api-key-env",
            details={"status": status},
        )
    if not 200 <= status < 300:
        raise ProbeError(
            f"target returned HTTP {status}",
            details={"status": status, "body": response.text[:_BODY_PREVIEW_CHARS]},
        )

    missing_usage = "target response missing token usage; cannot measure amplification"
    try:
        body = response.json()
    except ValueError as exc:
        raise ProbeError(
            missing_usage,
            details={"body": response.text[:_BODY_PREVIEW_CHARS]},
        ) from exc
    if not isinstance(body, dict):
        raise ProbeError(missing_usage, details={"body": response.text[:_BODY_PREVIEW_CHARS]})

    usage_raw = body.get("usage")
    if not isinstance(usage_raw, dict):
        raise ProbeError(missing_usage, details={"body": response.text[:_BODY_PREVIEW_CHARS]})
    try:
        usage = TokenUsage.model_validate(usage_raw)
    except ValidationError as exc:
        raise ProbeError(
            missing_usage,
            details={"body": response.text[:_BODY_PREVIEW_CHARS]},
        ) from exc

    finish_reason: str | None = None
    choices = body.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        raw_reason = choices[0].get("finish_reason")
        if isinstance(raw_reason, str):
            finish_reason = raw_reason

    raw_model = body.get("model")
    model_echo = raw_model if isinstance(raw_model, str) else None

    return CompletionResult(
        usage=usage,
        finish_reason=finish_reason,
        latency_ms=latency_ms,
        http_status=status,
        model=model_echo,
    )
