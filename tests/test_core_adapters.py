"""Tests for the vendor adapters.

parse_response is exercised with httpx.Response objects built directly, since it
reads only the response and never touches the network.
"""

from __future__ import annotations

import httpx
from pydantic import JsonValue

from vectrava.core.adapters import ChatCompletionsAdapter, NormalizedResponse


def test_build_request_url_body_headers() -> None:
    url, body, headers = ChatCompletionsAdapter().build_request(
        target_base="https://api.example.test",
        model="gpt-5.4-nano",
        messages=[{"role": "user", "content": "ping"}],
        max_tokens=16,
        credential="secret-value",
    )
    assert url == "https://api.example.test/v1/chat/completions"
    assert body == {
        "model": "gpt-5.4-nano",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 16,
    }
    assert headers["Authorization"] == "Bearer secret-value"
    assert headers["Content-Type"] == "application/json"


def test_build_request_strips_trailing_slash() -> None:
    url, _, _ = ChatCompletionsAdapter().build_request(
        target_base="https://api.example.test/",
        model="m",
        messages=[{"role": "user", "content": "x"}],
        max_tokens=1,
        credential="c",
    )
    assert url == "https://api.example.test/v1/chat/completions"


def test_parse_well_formed_200() -> None:
    body: JsonValue = {
        "model": "gpt-5.4-nano",
        "choices": [{"message": {"content": "hello"}, "finish_reason": "length"}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 480, "total_tokens": 492},
    }
    nr = ChatCompletionsAdapter().parse_response(httpx.Response(200, json=body))
    assert nr == NormalizedResponse(
        status_code=200,
        content="hello",
        prompt_tokens=12,
        completion_tokens=480,
        total_tokens=492,
        finish_reason="length",
        reported_model="gpt-5.4-nano",
        raw=body,
    )


def test_parse_finish_reason_is_identity() -> None:
    nr = ChatCompletionsAdapter().parse_response(
        httpx.Response(200, json={"choices": [{"finish_reason": "stop"}]})
    )
    assert nr.finish_reason == "stop"


def test_parse_non_2xx_does_not_raise() -> None:
    adapter = ChatCompletionsAdapter()
    nr429 = adapter.parse_response(httpx.Response(429, json={"error": "slow down"}))
    assert isinstance(nr429, NormalizedResponse)
    assert nr429.status_code == 429
    nr500 = adapter.parse_response(httpx.Response(500, json={"error": "boom"}))
    assert nr500.status_code == 500


def test_parse_non_json_body() -> None:
    nr = ChatCompletionsAdapter().parse_response(httpx.Response(200, content=b"not json at all"))
    assert nr.status_code == 200
    assert nr.content is None
    assert nr.prompt_tokens is None
    assert nr.completion_tokens is None
    assert nr.total_tokens is None
    assert nr.raw is None


def test_parse_non_dict_body_sets_raw() -> None:
    nr = ChatCompletionsAdapter().parse_response(httpx.Response(200, json=[1, 2, 3]))
    assert nr.content is None
    assert nr.raw == [1, 2, 3]


def test_parse_malformed_structure_missing_choices() -> None:
    nr = ChatCompletionsAdapter().parse_response(
        httpx.Response(
            200,
            json={"usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}},
        )
    )
    assert nr.content is None
    assert nr.total_tokens == 3


def test_parse_non_string_content_is_none() -> None:
    nr = ChatCompletionsAdapter().parse_response(
        httpx.Response(200, json={"choices": [{"message": {"content": 123}}]})
    )
    assert nr.content is None


def test_parse_missing_usage_yields_none_tokens() -> None:
    # The adapter does not decide that absent usage is fatal; the caller does.
    nr = ChatCompletionsAdapter().parse_response(
        httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
    )
    assert nr.content == "hi"
    assert nr.prompt_tokens is None
    assert nr.completion_tokens is None
    assert nr.total_tokens is None
