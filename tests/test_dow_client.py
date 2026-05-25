"""Tests for the dow HTTP client wrapper.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. Retryable failures (429, 5xx, transport, timeout) are retried
up to _RETRY_MAX_ATTEMPTS (3) times before call_completion translates them; the
_fast_retry fixture collapses the backoff waits to zero so those cases run fast.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from vectrava.core.probe import ProbeError
from vectrava.dow.client import CompletionResult, call_completion

_URL = "https://example.test/v1/chat/completions"
_MAX_ATTEMPTS = 3  # mirrors vectrava.dow.client._RETRY_MAX_ATTEMPTS

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def _fast_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapse retry backoff to zero so retry-touching tests run fast."""
    monkeypatch.setattr("vectrava.dow.client._RETRY_WAIT_INITIAL_S", 0.0)
    monkeypatch.setattr("vectrava.dow.client._RETRY_WAIT_MAX_S", 0.0)


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _call(client: httpx.Client) -> CompletionResult:
    return call_completion(
        client,
        url=_URL,
        credential="test-key",
        model="gpt-4o-mini",
        prompt="hello",
        max_tokens=512,
    )


def test_transport_error_raises_probe_error(_fast_retry: None) -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("no route to host")

    with _client(handler) as client, pytest.raises(ProbeError, match="could not reach target"):
        _call(client)
    assert len(calls) == _MAX_ATTEMPTS


def test_timeout_raises_probe_error_with_timeout_detail(_fast_retry: None) -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.TimeoutException("slow")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "did not respond" in str(exc_info.value)
    assert "timeout_s" in details
    assert len(calls) == _MAX_ATTEMPTS


def test_rate_limit_429_retries_then_raises(_fast_retry: None) -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(429, headers={"Retry-After": "30"}, text="slow down")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "retries were exhausted" in str(exc_info.value)
    assert details["status"] == 429
    assert details["retry_after"] == "30"
    assert len(calls) == _MAX_ATTEMPTS


def test_unauthorized_401_raises_credential_error() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(401, text="unauthorized")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "credential" in str(exc_info.value)
    assert details["status"] == 401
    assert len(calls) == 1


def test_forbidden_403_raises_credential_error() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(403, text="forbidden")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "credential" in str(exc_info.value)
    assert details["status"] == 403
    assert len(calls) == 1


def test_generic_4xx_raises_with_status_and_body() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404, text="not found")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "HTTP 404" in str(exc_info.value)
    assert details["status"] == 404
    assert details["body"] == "not found"
    assert len(calls) == 1


def test_generic_5xx_retries_then_raises_with_status_and_body(_fast_retry: None) -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(500, text="server boom")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "HTTP 500" in str(exc_info.value)
    assert details["status"] == 500
    assert details["body"] == "server boom"
    assert len(calls) == _MAX_ATTEMPTS


def test_2xx_missing_usage_raises_with_body_detail() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop"}]})

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "missing token usage" in str(exc_info.value)
    assert "body" in details
    assert len(calls) == 1


def test_2xx_with_usage_returns_completion_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"finish_reason": "length"}],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 480,
                    "total_tokens": 492,
                },
            },
        )

    with _client(handler) as client:
        result = _call(client)
    assert result.usage.prompt_tokens == 12
    assert result.usage.completion_tokens == 480
    assert result.usage.total_tokens == 492
    assert result.finish_reason == "length"
    assert result.http_status == 200
    assert result.model == "gpt-4o-mini"
    assert result.latency_ms > 0
