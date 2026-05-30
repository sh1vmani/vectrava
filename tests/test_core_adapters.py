"""Tests for the vendor adapters.

parse_response is exercised with httpx.Response objects built directly, since it
reads only the response and never touches the network.
"""

from __future__ import annotations

import httpx
from pydantic import JsonValue

from vectrava.core.adapters import (
    ChatCompletionsAdapter,
    MessagesAdapter,
    NormalizedResponse,
    build_url,
)


def test_build_url_appends_path() -> None:
    assert build_url("https://x", "/v1/chat/completions") == "https://x/v1/chat/completions"


def test_build_url_strips_trailing_slash() -> None:
    assert build_url("https://x/", "/p") == "https://x/p"


def test_build_request_honors_custom_endpoint_path() -> None:
    url, _, _ = ChatCompletionsAdapter().build_request(
        target_base="https://x",
        model="m",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=1,
        credential="c",
        endpoint_path="/custom",
    )
    assert url == "https://x/custom"


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


# --- MessagesAdapter (the messages wire format) ----------------------------


def test_messages_build_request_splits_leading_system() -> None:
    _, body, _ = MessagesAdapter().build_request(
        target_base="https://x",
        model="m",
        messages=[
            {"role": "system", "content": "sys text"},
            {"role": "user", "content": "hi"},
        ],
        max_tokens=8,
        credential="c",
    )
    assert body == {
        "model": "m",
        "system": "sys text",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8,
    }
    # The system turn is lifted out of the messages array, not duplicated in it.
    assert list(body) == ["model", "system", "messages", "max_tokens"]


def test_messages_build_request_no_system_omits_field() -> None:
    _, body, _ = MessagesAdapter().build_request(
        target_base="https://x",
        model="m",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=8,
        credential="c",
    )
    assert "system" not in body
    assert body == {
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8,
    }
    assert list(body) == ["model", "messages", "max_tokens"]


def test_messages_build_request_url_default_and_override() -> None:
    adapter = MessagesAdapter()
    url, _, _ = adapter.build_request(
        target_base="https://api.example.test/",
        model="m",
        messages=[{"role": "user", "content": "x"}],
        max_tokens=1,
        credential="c",
    )
    assert url == "https://api.example.test/v1/messages"
    url2, _, _ = adapter.build_request(
        target_base="https://x",
        model="m",
        messages=[{"role": "user", "content": "x"}],
        max_tokens=1,
        credential="c",
        endpoint_path="/custom",
    )
    assert url2 == "https://x/custom"


def test_messages_build_request_headers_use_api_key_not_bearer() -> None:
    _, _, headers = MessagesAdapter().build_request(
        target_base="https://x",
        model="m",
        messages=[{"role": "user", "content": "x"}],
        max_tokens=1,
        credential="secret-value",
    )
    assert headers == {
        "X-Api-Key": "secret-value",
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    # The credential is the raw key, not a Bearer token.
    assert headers["X-Api-Key"] == "secret-value"
    assert not headers["X-Api-Key"].startswith("Bearer ")
    assert "Authorization" not in headers


def test_messages_parse_single_text_block() -> None:
    nr = MessagesAdapter().parse_response(
        httpx.Response(200, json={"content": [{"type": "text", "text": "hello"}]})
    )
    assert nr.content == "hello"


def test_messages_parse_joins_multiple_text_blocks() -> None:
    nr = MessagesAdapter().parse_response(
        httpx.Response(
            200,
            json={"content": [{"type": "text", "text": "foo"}, {"type": "text", "text": "bar"}]},
        )
    )
    assert nr.content == "foobar"


def test_messages_parse_tool_use_only_content_is_none() -> None:
    nr = MessagesAdapter().parse_response(
        httpx.Response(
            200,
            json={"content": [{"type": "tool_use", "id": "t1", "name": "f", "input": {}}]},
        )
    )
    assert nr.content is None


def test_messages_parse_empty_content_is_none() -> None:
    nr = MessagesAdapter().parse_response(httpx.Response(200, json={"content": []}))
    assert nr.content is None


def test_messages_parse_usage_input_output_total_none() -> None:
    nr = MessagesAdapter().parse_response(
        httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "hi"}],
                "usage": {"input_tokens": 11, "output_tokens": 22},
            },
        )
    )
    assert nr.prompt_tokens == 11
    assert nr.completion_tokens == 22
    # The vendor reports no combined total; the adapter does not synthesize one.
    assert nr.total_tokens is None


def test_messages_parse_stop_reason_is_identity() -> None:
    adapter = MessagesAdapter()
    for reason in ("end_turn", "max_tokens"):
        nr = adapter.parse_response(
            httpx.Response(
                200,
                json={"content": [{"type": "text", "text": "x"}], "stop_reason": reason},
            )
        )
        assert nr.finish_reason == reason


def test_messages_parse_reports_echoed_model() -> None:
    nr = MessagesAdapter().parse_response(
        httpx.Response(
            200,
            json={"model": "served-model-9", "content": [{"type": "text", "text": "x"}]},
        )
    )
    assert nr.reported_model == "served-model-9"


def test_messages_parse_non_json_body() -> None:
    nr = MessagesAdapter().parse_response(httpx.Response(200, content=b"not json"))
    assert nr.status_code == 200
    assert nr.content is None
    assert nr.raw is None


def test_messages_parse_non_dict_body_sets_raw() -> None:
    nr = MessagesAdapter().parse_response(httpx.Response(200, json=[1, 2]))
    assert nr.content is None
    assert nr.raw == [1, 2]


def test_messages_parse_non_2xx_does_not_raise() -> None:
    nr = MessagesAdapter().parse_response(
        httpx.Response(
            400,
            json={"type": "error", "error": {"type": "invalid_request_error", "message": "bad"}},
        )
    )
    assert isinstance(nr, NormalizedResponse)
    assert nr.status_code == 400


def test_messages_parse_raw_populated_on_success() -> None:
    body: JsonValue = {
        "model": "served-model-9",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 3, "output_tokens": 4},
    }
    nr = MessagesAdapter().parse_response(httpx.Response(200, json=body))
    assert nr.raw == body
    assert nr == NormalizedResponse(
        status_code=200,
        content="hi",
        prompt_tokens=3,
        completion_tokens=4,
        total_tokens=None,
        finish_reason="end_turn",
        reported_model="served-model-9",
        raw=body,
    )
