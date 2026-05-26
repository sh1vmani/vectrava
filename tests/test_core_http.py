"""Tests for the synchronous HTTP retry helper.

Every case uses httpx.MockTransport (no network) and zero backoff waits for
speed, except the Retry-After cap test which records the slept duration via a
monkeypatched time.sleep.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import httpx
import pytest

from vectrava.core.http import post_with_retry

_URL = "https://example.test/v1/chat/completions"

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _post(
    client: httpx.Client, *, wait_max_s: float = 0.0, max_attempts: int = 3
) -> httpx.Response:
    return post_with_retry(
        client,
        _URL,
        json={"x": 1},
        headers={},
        timeout=5.0,
        max_attempts=max_attempts,
        wait_initial_s=0.0,
        wait_max_s=wait_max_s,
    )


def test_retry_on_500_then_success() -> None:
    calls: list[int] = []
    responses = iter(
        [httpx.Response(500), httpx.Response(500), httpx.Response(200, json={"ok": True})]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return next(responses)

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 200
    assert len(calls) == 3


def _retry_5xx_then_success(status: int) -> None:
    calls: list[int] = []
    responses = iter([httpx.Response(status), httpx.Response(200, json={"ok": True})])

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return next(responses)

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 200
    assert len(calls) == 2


def test_retry_on_502_503_504() -> None:
    for status in (502, 503, 504):
        _retry_5xx_then_success(status)


def test_retry_on_429_honors_retry_after_numeric() -> None:
    calls: list[int] = []
    responses = iter(
        [httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json={"ok": True})]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return next(responses)

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 200
    assert len(calls) == 2


def test_retry_on_429_honors_retry_after_caps_at_max(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", lambda seconds: slept.append(seconds))
    responses = iter(
        [
            httpx.Response(429, headers={"Retry-After": "999"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    with _client(handler) as client:
        resp = _post(client, wait_max_s=5.0)
    assert resp.status_code == 200
    assert slept == [5.0]


def test_no_retry_on_400() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(400, text="bad")

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 400
    assert len(calls) == 1


def test_no_retry_on_404() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404, text="missing")

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 404
    assert len(calls) == 1


def test_no_retry_on_501() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(501, text="not implemented")

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 501
    assert len(calls) == 1


def test_retry_on_transport_error_then_success() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ConnectError("boom")
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 200
    assert len(calls) == 2


def test_retry_on_timeout_then_success() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            raise httpx.TimeoutException("slow")
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 200
    assert len(calls) == 2


def test_exhausted_retries_on_status_returns_last_response() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(503, text="unavailable")

    with _client(handler) as client:
        resp = _post(client)
    assert resp.status_code == 503
    assert len(calls) == 3


def test_exhausted_retries_on_transport_raises_last_exception() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("down")

    with _client(handler) as client, pytest.raises(httpx.ConnectError):
        _post(client)
    assert len(calls) == 3


def test_exhausted_retries_on_timeout_raises_last_exception() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.TimeoutException("slow")

    with _client(handler) as client, pytest.raises(httpx.TimeoutException):
        _post(client)
    assert len(calls) == 3


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={})


def test_post_with_retry_no_pacing_when_min_delay_zero() -> None:
    with _client(_ok) as client:
        start = time.monotonic()
        post_with_retry(client, _URL, json={"x": 1}, headers={}, timeout=5.0, min_delay_s=0.0)
        post_with_retry(client, _URL, json={"x": 1}, headers={}, timeout=5.0, min_delay_s=0.0)
        elapsed = time.monotonic() - start
    assert elapsed < 0.05


def test_post_with_retry_paces_requests_when_min_delay_positive() -> None:
    with _client(_ok) as client:
        start = time.monotonic()
        post_with_retry(client, _URL, json={"x": 1}, headers={}, timeout=5.0, min_delay_s=0.1)
        post_with_retry(client, _URL, json={"x": 1}, headers={}, timeout=5.0, min_delay_s=0.1)
        elapsed = time.monotonic() - start
    assert elapsed >= 0.1
    assert elapsed < 0.5


def test_post_with_retry_per_client_state_independence() -> None:
    with _client(_ok) as client_a, _client(_ok) as client_b:
        post_with_retry(client_a, _URL, json={"x": 1}, headers={}, timeout=5.0, min_delay_s=1.0)
        start = time.monotonic()
        post_with_retry(client_b, _URL, json={"x": 1}, headers={}, timeout=5.0, min_delay_s=1.0)
        elapsed = time.monotonic() - start
    assert elapsed < 0.1
