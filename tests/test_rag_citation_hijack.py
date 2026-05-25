"""Tests for the citation_hijack rag probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. Canaries are generated inside the probe, so handlers
recover them from the request body with a [0-9a-f]{16} match and echo them back.
Detection is two-part: a finding needs both the canary and a citation of the
legitimate source by name, so handlers vary which of the two they return.
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
from vectrava.core.probe import ProbeContext, ProbeError
from vectrava.core.result import Severity
from vectrava.rag.probes.citation_hijack import (
    INJECTION_PROMPTS,
    LEGITIMATE_SOURCE_NAME,
    CitationHijackProbe,
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
        options=options if options is not None else {"model": "gpt-4o-mini"},
    )


def _canary_in(request: httpx.Request) -> str:
    body = json.loads(request.content)
    content = body["messages"][1]["content"]
    match = _HEX16.search(content)
    return match.group(0) if match else ""


def _response(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={"model": "gpt-4o-mini", "choices": [{"message": {"content": content}}]},
    )


def _both_response(token: str) -> httpx.Response:
    return _response(f"According to {LEGITIMATE_SOURCE_NAME}, the value is {token}.")


def _canary_only_response(token: str) -> httpx.Response:
    return _response(f"The reported value is {token}.")


def _source_only_response() -> httpx.Response:
    return _response(f"According to {LEGITIMATE_SOURCE_NAME}, the company offers 15 days.")


def _benign_response() -> httpx.Response:
    return _response("The company offers 15 vacation days per year.")


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_canary_and_source_in_response_emits_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _both_response(_canary_in(request))

    with _client(handler) as client:
        findings = CitationHijackProbe().run(_ctx(client))

    assert len(findings) == len(INJECTION_PROMPTS)
    for finding in findings:
        assert finding.level == Severity.HIGH
        assert finding.rule_id == "citation_hijack"
        assert finding.probe == "rag.citation_hijack"


def test_canary_alone_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _canary_only_response(_canary_in(request))

    with _client(handler) as client:
        findings = CitationHijackProbe().run(_ctx(client))

    assert findings == []


def test_source_alone_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _source_only_response()

    with _client(handler) as client:
        findings = CitationHijackProbe().run(_ctx(client))

    assert findings == []


def test_neither_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with _client(handler) as client:
        findings = CitationHijackProbe().run(_ctx(client))

    assert findings == []


def test_each_injection_prompt_can_succeed_independently() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _both_response(_canary_in(request))
        return _benign_response()

    with _client(handler) as client:
        findings = CitationHijackProbe().run(_ctx(client))

    assert len(findings) == 1
    assert findings[0].evidence["injection_label"] == INJECTION_PROMPTS[0][0]


def test_canary_is_fresh_per_run() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(_canary_in(request))
        return _benign_response()

    with _client(handler) as client:
        CitationHijackProbe().run(_ctx(client))
        CitationHijackProbe().run(_ctx(client))

    assert len(seen) == 2 * len(INJECTION_PROMPTS)
    assert len(set(seen)) == len(seen)


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        CitationHijackProbe().run(_ctx(client, credentials=None))


def test_http_4xx_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        CitationHijackProbe().run(_ctx(client))


def test_malformed_response_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "gpt-4o-mini"})

    with _client(handler) as client, pytest.raises(ProbeError, match="chat-completions"):
        CitationHijackProbe().run(_ctx(client))


def test_required_classvars_set() -> None:
    assert CitationHijackProbe.name == "citation_hijack"
    assert isinstance(CitationHijackProbe.name, str)
    assert CitationHijackProbe.module == "rag"
    assert isinstance(CitationHijackProbe.module, str)
    assert isinstance(CitationHijackProbe.description, str)
    assert CitationHijackProbe.baseline_severity == Severity.HIGH
    assert isinstance(CitationHijackProbe.baseline_severity, Severity)
    assert CitationHijackProbe.estimated_tokens_per_run == 3 * 500
    assert isinstance(CitationHijackProbe.estimated_tokens_per_run, int)


def test_num_sources_pads_with_filler_when_greater_than_three() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        user_content = body["messages"][1]["content"]
        captured["user_content"] = user_content
        match = _HEX16.search(user_content)
        token = match.group(0) if match else ""
        return _both_response(token)

    with _client(handler) as client:
        ctx = _ctx(client, options={"model": "gpt-4o-mini", "num_sources": 5})
        CitationHijackProbe().run(ctx)

    content = captured["user_content"]
    assert content.count('<source id="') == 5
    assert "Office hours are 9 AM to 5 PM" in content
