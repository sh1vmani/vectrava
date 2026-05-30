"""Adapter-selection seam.

The adapter on ProbeContext is what a probe builds requests through. With the
chat_completions adapter selected (the default and only accepted vendor in this
slice), the request a probe emits must be byte-identical to the pre-seam
chat-completions wire: Bearer auth, the /v1/chat/completions path, and a body of
exactly model/messages/max_tokens. One ipi, one rag, and one dow (the last through
call_completion) probe are covered, since they reach the adapter by three
different routes (inline build site, inline build site, and the dow client helper).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import structlog

from vectrava.config.scope import ScopeFile
from vectrava.core.adapters import ChatCompletionsAdapter, MessagesAdapter, VendorAdapter
from vectrava.core.probe import ProbeContext
from vectrava.dow.probes.token_amplification import TokenAmplificationProbe
from vectrava.ipi.probes.direct_override import DirectOverrideProbe
from vectrava.rag.probes.citation_hijack import CitationHijackProbe

Handler = Callable[[httpx.Request], httpx.Response]

_CREDENTIAL = "secret-value"


def _scope() -> ScopeFile:
    return ScopeFile(
        targets=["https://example.test"],
        authorized_until=datetime.now(UTC) + timedelta(days=1),
        signed_by="Shivamani Vastrala",
    )


def _ctx(client: httpx.Client, *, adapter: VendorAdapter | None = None) -> ProbeContext:
    return ProbeContext(
        target="https://example.test",
        endpoint=None,
        credentials=_CREDENTIAL,
        scope=_scope(),
        http=client,
        logger=structlog.get_logger(),
        adapter=adapter if adapter is not None else ChatCompletionsAdapter(),
        options={
            "model": "gpt-4o-mini",
            "threshold": 15.0,
            "num_sources": 3,
            "max_rps": 10.0,
        },
    )


def _assert_chat_completions_wire(request: httpx.Request) -> None:
    assert request.url.path == "/v1/chat/completions"
    assert request.headers["Authorization"] == f"Bearer {_CREDENTIAL}"
    assert "X-Api-Key" not in request.headers
    body = json.loads(request.content)
    assert set(body) == {"model", "messages", "max_tokens"}
    assert body["model"] == "gpt-4o-mini"


def _text_handler(captured: list[httpx.Request]) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"model": "gpt-4o-mini", "choices": [{"message": {"content": "ok"}}]},
        )

    return handler


def test_seam_ipi_probe_builds_chat_completions_via_ctx_adapter() -> None:
    captured: list[httpx.Request] = []
    with httpx.Client(transport=httpx.MockTransport(_text_handler(captured))) as client:
        DirectOverrideProbe().run(_ctx(client))
    assert captured
    _assert_chat_completions_wire(captured[0])


def test_seam_rag_probe_builds_chat_completions_via_ctx_adapter() -> None:
    captured: list[httpx.Request] = []
    with httpx.Client(transport=httpx.MockTransport(_text_handler(captured))) as client:
        CitationHijackProbe().run(_ctx(client))
    assert captured
    _assert_chat_completions_wire(captured[0])


def test_seam_dow_probe_builds_chat_completions_via_ctx_adapter() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        TokenAmplificationProbe().run(_ctx(client))
    assert captured
    _assert_chat_completions_wire(captured[0])


# --- vendor-aware endpoint defaulting: a messages ctx resolves /v1/messages -


def _assert_messages_wire(request: httpx.Request) -> None:
    assert request.url.path == "/v1/messages"
    assert request.headers["X-Api-Key"] == _CREDENTIAL
    assert "Authorization" not in request.headers


def _messages_handler(captured: list[httpx.Request]) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 5, "output_tokens": 5},
            },
        )

    return handler


def test_seam_ipi_probe_resolves_messages_endpoint() -> None:
    captured: list[httpx.Request] = []
    with httpx.Client(transport=httpx.MockTransport(_messages_handler(captured))) as client:
        DirectOverrideProbe().run(_ctx(client, adapter=MessagesAdapter()))
    assert captured
    _assert_messages_wire(captured[0])


def test_seam_dow_probe_resolves_messages_endpoint() -> None:
    captured: list[httpx.Request] = []
    with httpx.Client(transport=httpx.MockTransport(_messages_handler(captured))) as client:
        TokenAmplificationProbe().run(_ctx(client, adapter=MessagesAdapter()))
    assert captured
    _assert_messages_wire(captured[0])
