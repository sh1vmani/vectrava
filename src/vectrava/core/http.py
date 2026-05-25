"""Synchronous HTTP POST with retry and backoff.

`post_with_retry` wraps a single httpx POST in a tenacity retry policy: it retries
transport errors, timeouts, and a fixed set of retryable status codes (429 and
the transient 5xx family), honoring a Retry-After header when present and falling
back to exponential backoff with jitter otherwise. Retries exhausted on a status
return the last response; retries exhausted on an exception re-raise it. The
caller decides how to translate either outcome.
"""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

import httpx
from tenacity import (
    Retrying,
    retry_any,
    retry_if_exception_type,
    retry_if_result,
    stop_after_attempt,
    wait_exponential_jitter,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from tenacity import RetryCallState

_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header into seconds, or None when absent or invalid."""
    if value is None:
        return None
    candidate = value.strip()
    try:
        return max(float(int(candidate)), 0.0)
    except ValueError:
        pass
    try:
        moment = parsedate_to_datetime(candidate)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return max((moment - datetime.now(UTC)).total_seconds(), 0.0)


def post_with_retry(
    client: httpx.Client,
    url: str,
    *,
    json: Mapping[str, object],
    headers: Mapping[str, str],
    timeout: float,
    max_attempts: int = 3,
    wait_initial_s: float = 1.0,
    wait_max_s: float = 30.0,
) -> httpx.Response:
    """POST with retry on transport errors, timeouts, and retryable statuses.

    Retryable statuses are 429, 500, 502, 503, and 504. A Retry-After header on a
    retryable response is honored (numeric seconds or HTTP-date), capped at
    wait_max_s; otherwise the wait is exponential with jitter. When retries are
    exhausted the last response is returned (for a retryable status) or the last
    exception is raised (for a transport error or timeout).

    Args:
        client: Synchronous HTTP client.
        url: POST URL.
        json: Request body serialized as JSON.
        headers: Request headers.
        timeout: Per-request timeout in seconds.
        max_attempts: Total attempts before giving up.
        wait_initial_s: Initial backoff for the exponential-jitter fallback.
        wait_max_s: Maximum backoff, and the cap applied to a Retry-After value.

    Returns:
        The final httpx.Response.

    Raises:
        httpx.TransportError: if every attempt raised a transport error or timeout.
    """

    def _do_post() -> httpx.Response:
        return client.post(url, json=json, headers=headers, timeout=timeout)

    def _is_retryable_status(response: httpx.Response) -> bool:
        return response.status_code in _RETRYABLE_STATUSES

    jitter = wait_exponential_jitter(initial=wait_initial_s, max=wait_max_s)

    def _wait(retry_state: RetryCallState) -> float:
        outcome = retry_state.outcome
        if outcome is not None and not outcome.failed:
            response: httpx.Response = outcome.result()
            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
            if retry_after is not None:
                return min(retry_after, wait_max_s)
        return jitter(retry_state)

    def _on_exhausted(retry_state: RetryCallState) -> httpx.Response:
        outcome = retry_state.outcome
        if outcome is None:
            msg = "retry completed without an outcome"
            raise RuntimeError(msg)
        if outcome.failed:
            exc = outcome.exception()
            if exc is not None:
                raise exc
            msg = "retry failed without an exception"
            raise RuntimeError(msg)
        last: httpx.Response = outcome.result()
        return last

    retrying = Retrying(
        retry=retry_any(
            retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
            retry_if_result(_is_retryable_status),
        ),
        stop=stop_after_attempt(max_attempts),
        wait=_wait,
        retry_error_callback=_on_exhausted,
    )
    result: httpx.Response = retrying(_do_post)
    return result
