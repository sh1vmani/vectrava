"""Tests for the cross_document_injection rag probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. Canaries are generated inside the probe, so handlers
recover them from the request body with a [0-9a-f]{16} match and echo them back.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import structlog
from pydantic import JsonValue

from vectrava.config.scope import ScopeFile
from vectrava.core import registry
from vectrava.core.adapters import ChatCompletionsAdapter
from vectrava.core.probe import ProbeContext, ProbeError
from vectrava.core.result import Severity
from vectrava.rag.probes.cross_document_injection import (
    INJECTION_PROMPTS,
    CrossDocumentInjectionProbe,
)

Handler = Callable[[httpx.Request], httpx.Response]

_HEX16 = re.compile(r"[0-9a-f]{16}")


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    registry.clear()
    yield
    registry.clear()


def _scope() -> ScopeFile:
    return ScopeFile(
        targets=["https://example.test"],
        authorized_until=datetime.now(UTC) + timedelta(days=1),
        signed_by="Shivamani Vastrala",
    )


def _ctx(
    client: httpx.Client,
    *,
    target: str = "https://example.test",
    endpoint: str | None = None,
    credentials: str | None = "test-key",
    options: Mapping[str, JsonValue] | None = None,
) -> ProbeContext:
    return ProbeContext(
        target=target,
        endpoint=endpoint,
        credentials=credentials,
        scope=_scope(),
        http=client,
        logger=structlog.get_logger(),
        adapter=ChatCompletionsAdapter(),
        options=options if options is not None else {"model": "gpt-4o-mini"},
    )


def _canary_in(request: httpx.Request) -> str:
    body = json.loads(request.content)
    content = body["messages"][1]["content"]
    match = _HEX16.search(content)
    return match.group(0) if match else ""


def _echo_response(token: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"content": f"Per the sources: {token}"}}],
        },
    )


def _benign_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"content": "Full time staff get 20 vacation days."}}],
        },
    )


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_canary_in_response_emits_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _echo_response(_canary_in(request))

    with _client(handler) as client:
        findings = CrossDocumentInjectionProbe().run(_ctx(client))

    assert len(findings) == len(INJECTION_PROMPTS)
    for finding in findings:
        assert finding.level == Severity.HIGH
        assert finding.rule_id == "cross_document_injection"
        assert finding.probe == "rag.cross_document_injection"


def test_no_canary_in_response_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with _client(handler) as client:
        findings = CrossDocumentInjectionProbe().run(_ctx(client))

    assert findings == []


def test_each_injection_prompt_can_succeed_independently() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _echo_response(_canary_in(request))
        return _benign_response()

    with _client(handler) as client:
        findings = CrossDocumentInjectionProbe().run(_ctx(client))

    assert len(findings) == 1
    assert findings[0].evidence["injection_label"] == INJECTION_PROMPTS[0][0]


def test_all_injection_prompts_succeed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _echo_response(_canary_in(request))

    with _client(handler) as client:
        findings = CrossDocumentInjectionProbe().run(_ctx(client))

    assert len(findings) == len(INJECTION_PROMPTS)
    assert [f.evidence["injection_label"] for f in findings] == [
        label for label, _ in INJECTION_PROMPTS
    ]


def test_canary_is_fresh_per_run() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(_canary_in(request))
        return _benign_response()

    with _client(handler) as client:
        CrossDocumentInjectionProbe().run(_ctx(client))
        CrossDocumentInjectionProbe().run(_ctx(client))

    assert len(seen) == 2 * len(INJECTION_PROMPTS)
    assert len(set(seen)) == len(seen)


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        CrossDocumentInjectionProbe().run(_ctx(client, credentials=None))


def test_http_4xx_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        CrossDocumentInjectionProbe().run(_ctx(client))


def test_malformed_response_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "gpt-4o-mini"})

    with _client(handler) as client, pytest.raises(ProbeError, match="assistant message content"):
        CrossDocumentInjectionProbe().run(_ctx(client))


def test_required_classvars_set() -> None:
    assert CrossDocumentInjectionProbe.name == "cross_document_injection"
    assert isinstance(CrossDocumentInjectionProbe.name, str)
    assert CrossDocumentInjectionProbe.module == "rag"
    assert isinstance(CrossDocumentInjectionProbe.module, str)
    assert isinstance(CrossDocumentInjectionProbe.description, str)
    assert CrossDocumentInjectionProbe.baseline_severity == Severity.HIGH
    assert isinstance(CrossDocumentInjectionProbe.baseline_severity, Severity)
    assert CrossDocumentInjectionProbe.estimated_tokens_per_run == 3 * 600
    assert isinstance(CrossDocumentInjectionProbe.estimated_tokens_per_run, int)


def test_num_sources_pads_with_filler_when_greater_than_three() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        user_content = body["messages"][1]["content"]
        captured["user_content"] = user_content
        match = _HEX16.search(user_content)
        token = match.group(0) if match else ""
        return _echo_response(token)

    with _client(handler) as client:
        ctx = _ctx(client, options={"model": "gpt-4o-mini", "num_sources": 5})
        CrossDocumentInjectionProbe().run(ctx)

    content = captured["user_content"]
    assert content.count('<source id="') == 5
    assert "Office hours are 9 AM to 5 PM" in content
