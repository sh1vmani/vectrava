"""Tests for the dow HTTP client wrapper.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. One test maps to each failure row of the D5 contract that the
client can produce, plus the 2xx happy path.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from vectrava.core.probe import ProbeError
from vectrava.dow.client import CompletionResult, call_completion

_URL = "https://example.test/v1/chat/completions"

Handler = Callable[[httpx.Request], httpx.Response]


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


def test_transport_error_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    with _client(handler) as client, pytest.raises(ProbeError, match="could not reach target"):
        _call(client)


def test_timeout_raises_probe_error_with_timeout_detail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("slow")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "did not respond" in str(exc_info.value)
    assert "timeout_s" in details


def test_rate_limit_429_raises_with_status_and_retry_after() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "30"}, text="slow down")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "429" in str(exc_info.value)
    assert details["status"] == 429
    assert details["retry_after"] == "30"


def test_unauthorized_401_raises_credential_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "credential" in str(exc_info.value)
    assert details["status"] == 401


def test_forbidden_403_raises_credential_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "credential" in str(exc_info.value)
    assert details["status"] == 403


def test_generic_4xx_raises_with_status_and_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "HTTP 404" in str(exc_info.value)
    assert details["status"] == 404
    assert details["body"] == "not found"


def test_generic_5xx_raises_with_status_and_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server boom")

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "HTTP 500" in str(exc_info.value)
    assert details["status"] == 500
    assert details["body"] == "server boom"


def test_2xx_missing_usage_raises_with_body_detail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop"}]})

    with _client(handler) as client, pytest.raises(ProbeError) as exc_info:
        _call(client)
    details = exc_info.value.details
    assert isinstance(details, dict)
    assert "missing token usage" in str(exc_info.value)
    assert "body" in details


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
