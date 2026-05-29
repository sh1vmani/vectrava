"""Tests for local-Ollama autodetection.

Every case injects an httpx.Client built on a MockTransport so no network is
touched. The injected client must never be closed by detect_ollama; the owned
(client=None) path is exercised by the CLI tests through monkeypatching.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from vectrava.core.autodetect import OllamaDetection, detect_ollama

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_hit_returns_detection_with_model_name() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": "llama3.2:1b"}]})

    with _client(handler) as client:
        result = detect_ollama(client=client)

    assert result == OllamaDetection(base_url="http://localhost:11434", models=("llama3.2:1b",))


def test_hit_empty_model_list_is_still_a_hit() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": []})

    with _client(handler) as client:
        result = detect_ollama(client=client)

    assert result is not None
    assert result.models == ()


def test_hit_multiple_models_preserves_order() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": [{"name": "alpha"}, {"name": "beta"}]})

    with _client(handler) as client:
        result = detect_ollama(client=client)

    assert result is not None
    assert result.models == ("alpha", "beta")


def test_miss_on_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with _client(handler) as client:
        assert detect_ollama(client=client) is None


def test_miss_on_connect_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    with _client(handler) as client:
        assert detect_ollama(client=client) is None


def test_miss_on_non_200() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    with _client(handler) as client:
        assert detect_ollama(client=client) is None


def test_miss_on_non_json_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="this is not json")

    with _client(handler) as client:
        assert detect_ollama(client=client) is None


def test_miss_on_missing_models_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"foo": 1})

    with _client(handler) as client:
        assert detect_ollama(client=client) is None


def test_miss_when_models_not_a_list() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": "notalist"})

    with _client(handler) as client:
        assert detect_ollama(client=client) is None


def test_injected_client_is_not_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": []})

    client = _client(handler)
    detect_ollama(client=client)
    # The caller owns an injected client; detect_ollama must leave it open.
    assert client.is_closed is False
    client.close()
