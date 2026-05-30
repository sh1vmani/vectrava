"""Tests for core/probe_helpers.

Covers the shared single-turn conversation step exchange_turn (which uses
httpx.MockTransport so no network is touched and no environment variable is
read), plus the content_or_raise and interleave_padding_chunks helpers in this
module.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from vectrava.core.adapters import ChatCompletionsAdapter, NormalizedResponse
from vectrava.core.probe import ProbeError
from vectrava.core.probe_helpers import (
    content_or_raise,
    exchange_turn,
    interleave_padding_chunks,
)

Handler = Callable[[httpx.Request], httpx.Response]


def _resp(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={"model": "gpt-4o-mini", "choices": [{"message": {"content": content}}]},
    )


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _call(client: httpx.Client, messages: list[dict[str, str]], **overrides: object) -> str:
    kwargs: dict[str, object] = {
        "client": client,
        "adapter": ChatCompletionsAdapter(),
        "target_base": "https://example.test",
        "endpoint_path": "/v1/chat/completions",
        "messages": messages,
        "model": "gpt-4o-mini",
        "max_tokens": 256,
        "credential": "test-key",
        "probe_name": "test_probe",
        "label": "case_a",
        "turn_index": 1,
    }
    kwargs.update(overrides)
    return exchange_turn(**kwargs)  # type: ignore[arg-type]


def test_exchange_turn_appends_assistant_and_returns_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("Hello from the model.")

    messages: list[dict[str, str]] = [{"role": "user", "content": "Hi"}]
    with _client(handler) as client:
        content = _call(client, messages)

    assert content == "Hello from the model."
    assert messages[-1] == {"role": "assistant", "content": "Hello from the model."}
    assert len(messages) == 2


def test_exchange_turn_http_error_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    messages: list[dict[str, str]] = [{"role": "user", "content": "Hi"}]
    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="HTTP 400") as exc_info,
    ):
        _call(client, messages, label="case_b", turn_index=3)

    assert exc_info.value.details == {
        "status": 400,
        "injection_label": "case_b",
        "turn": 3,
    }
    # No assistant turn is appended on failure.
    assert len(messages) == 1


def test_exchange_turn_malformed_body_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "gpt-4o-mini"})

    messages: list[dict[str, str]] = [{"role": "user", "content": "Hi"}]
    with _client(handler) as client, pytest.raises(ProbeError, match="assistant message content"):
        _call(client, messages)

    assert len(messages) == 1


def test_exchange_turn_mutates_messages_in_place() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("ok")

    messages: list[dict[str, str]] = [{"role": "user", "content": "Hi"}]
    original_id = id(messages)
    with _client(handler) as client:
        _call(client, messages)

    # Same list object, mutated in place; not replaced.
    assert id(messages) == original_id
    assert len(messages) == 2


def test_exchange_turn_honors_min_delay_s(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(
        "vectrava.core.http.time.sleep",
        lambda duration: sleeps.append(duration),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("ok")

    messages: list[dict[str, str]] = [{"role": "user", "content": "Hi"}]
    with _client(handler) as client:
        _call(client, messages, min_delay_s=0.1)
        _call(client, messages, min_delay_s=0.1)

    # First call: no prior request on this client, so no sleep. Second call: paced.
    # The requested sleep is min_delay_s minus the real time elapsed between the two
    # calls, so it is positive and at most min_delay_s. Asserting a tight lower bound
    # would couple the test to wall-clock overhead and the host timer resolution
    # (Windows monotonic is ~15.6ms), which is exactly what flaked on a CI runner.
    assert len(sleeps) == 1
    assert 0 < sleeps[0] <= 0.1


# --- content_or_raise ------------------------------------------------------


def _normalized(content: str | None) -> NormalizedResponse:
    return NormalizedResponse(
        status_code=200,
        content=content,
        prompt_tokens=None,
        completion_tokens=None,
        total_tokens=None,
        finish_reason=None,
        reported_model=None,
        raw=None,
    )


def test_content_or_raise_returns_string_content() -> None:
    assert content_or_raise(_normalized("hello"), "label", "probe") == "hello"


def test_content_or_raise_raises_on_none_content() -> None:
    with pytest.raises(ProbeError, match="assistant message content"):
        content_or_raise(_normalized(None), "label", "probe")


def test_content_or_raise_error_carries_label_and_probe_name() -> None:
    with pytest.raises(ProbeError) as exc_info:
        content_or_raise(_normalized(None), "case_a", "my_probe")
    assert exc_info.value.probe_name == "my_probe"
    assert exc_info.value.details == {"injection_label": "case_a"}


# --- interleave_padding_chunks ---------------------------------------------


def test_interleave_returns_original_when_at_target_count() -> None:
    chunks = ("a", "b", "c")
    assert interleave_padding_chunks(chunks, ("x", "y"), 3) == chunks


def test_interleave_returns_original_when_above_target_count() -> None:
    chunks = ("a", "b", "c", "d", "e")
    result = interleave_padding_chunks(chunks, ("x", "y"), 3)
    assert result == chunks
    assert len(result) == 5


def test_interleave_pads_with_filler_when_below_target() -> None:
    filler = ("x0", "x1", "x2", "x3", "x4")
    result = interleave_padding_chunks(("c0",), filler, 4)
    assert len(result) == 4
    assert result[0] == "c0"
    assert all(item in filler for item in result[1:])


def test_interleave_cycles_filler_when_filler_shorter_than_pad() -> None:
    result = interleave_padding_chunks(("c0",), ("x", "y"), 6)
    assert len(result) == 6
    # Five padding entries drawn from a two-item pool cycle: x, y, x, y, x.
    assert result == ("c0", "x", "y", "x", "y", "x")


def test_interleave_preserves_chunk_order() -> None:
    # The helper interleaves filler between chunks, so chunks do not all precede
    # filler; what is guaranteed is the chunks' relative order is preserved.
    result = interleave_padding_chunks(("a", "b", "c"), ("x", "y"), 5)
    assert len(result) == 5
    assert result.index("a") < result.index("b") < result.index("c")
    assert result == ("a", "x", "b", "y", "c")


def test_interleave_with_empty_chunks_returns_filler_padding() -> None:
    result = interleave_padding_chunks((), ("x", "y"), 3)
    assert len(result) == 3
    assert all(item in ("x", "y") for item in result)
