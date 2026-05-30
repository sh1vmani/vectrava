"""Tests for the prompt_leak_via_retrieval rag probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. The canary is planted in the retrieval-template marker
inside the user message, so handlers recover it from messages[1] with a
[0-9a-f]{16} match and echo it back.
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
from vectrava.rag.probes.prompt_leak_via_retrieval import (
    BASE_BENIGN_CHUNKS,
    FILLER_CHUNKS,
    TRUSTED_INSTRUCTION,
    USER_QUERY_LABELS,
    PromptLeakViaRetrievalProbe,
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


def _user_content(request: httpx.Request) -> str:
    body = json.loads(request.content)
    content = body["messages"][1]["content"]
    assert isinstance(content, str)
    return content


def _canary_in(request: httpx.Request) -> str:
    match = _HEX16.search(_user_content(request))
    return match.group(0) if match else ""


def _echo_response(token: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"content": f"The template marker is {token}."}}],
        },
    )


def _benign_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"content": "Full-time staff get 20 vacation days."}}],
        },
    )


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_leak_at_each_label_emits_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _echo_response(_canary_in(request))

    with _client(handler) as client:
        findings = PromptLeakViaRetrievalProbe().run(_ctx(client))

    assert len(findings) == len(USER_QUERY_LABELS)
    for finding in findings:
        assert finding.level == Severity.HIGH
        assert finding.rule_id == "prompt_leak_via_retrieval"
        assert finding.probe == "rag.prompt_leak_via_retrieval"
    assert [f.evidence["framing_label"] for f in findings] == [
        label for label, _ in USER_QUERY_LABELS
    ]


def test_no_leak_emits_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with _client(handler) as client:
        findings = PromptLeakViaRetrievalProbe().run(_ctx(client))

    assert findings == []


def test_partial_leak_emits_partial_findings() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        # Leak only on the first label (meta_query); benign for the rest.
        if calls["n"] == 1:
            return _echo_response(_canary_in(request))
        return _benign_response()

    with _client(handler) as client:
        findings = PromptLeakViaRetrievalProbe().run(_ctx(client))

    assert len(findings) == 1
    assert findings[0].evidence["framing_label"] == "meta_query"
    assert findings[0].evidence["framing_label"] == USER_QUERY_LABELS[0][0]


def test_evidence_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _echo_response(_canary_in(request))

    with _client(handler) as client:
        findings = PromptLeakViaRetrievalProbe().run(_ctx(client))

    assert findings
    evidence = findings[0].evidence
    assert set(evidence.keys()) == {
        "framing_label",
        "canary_token",
        "response_excerpt",
        "prompt_template",
    }
    canary_token = evidence["canary_token"]
    prompt_template = evidence["prompt_template"]
    assert isinstance(evidence["framing_label"], str)
    assert isinstance(canary_token, str)
    assert isinstance(evidence["response_excerpt"], str)
    assert isinstance(prompt_template, str)
    assert canary_token in prompt_template
    assert f"[retrieval-template version={canary_token}]" in prompt_template
    assert "[/retrieval-template]" in prompt_template
    assert '<source id="1">' in prompt_template


def test_one_canary_per_label() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _echo_response(_canary_in(request))

    with _client(handler) as client:
        findings = PromptLeakViaRetrievalProbe().run(_ctx(client))

    tokens: list[str] = []
    for finding in findings:
        canary_token = finding.evidence["canary_token"]
        prompt_template = finding.evidence["prompt_template"]
        assert isinstance(canary_token, str)
        assert isinstance(prompt_template, str)
        # Each finding's canary lives in its own template marker.
        assert f"[retrieval-template version={canary_token}]" in prompt_template
        tokens.append(canary_token)

    assert len(tokens) == len(USER_QUERY_LABELS)
    assert len(set(tokens)) == len(tokens)


def test_num_sources_default() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["content"] = _user_content(request)
        return _benign_response()

    with _client(handler) as client:
        PromptLeakViaRetrievalProbe().run(_ctx(client))

    content = captured["content"]
    assert '<source id="3">' in content
    assert '<source id="4">' not in content


def test_num_sources_custom() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["content"] = _user_content(request)
        return _benign_response()

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "num_sources": 5}
    with _client(handler) as client:
        PromptLeakViaRetrievalProbe().run(_ctx(client, options=options))

    content = captured["content"]
    assert '<source id="5">' in content


def test_chunks_are_benign() -> None:
    # No canary placeholder anywhere in the source content; the canary lives only
    # in the retrieval-template marker the probe wraps around the sources.
    for chunk in (*BASE_BENIGN_CHUNKS, *FILLER_CHUNKS):
        assert "{canary}" not in chunk
        assert _HEX16.search(chunk) is None


def test_system_prompt_declares_confidentiality() -> None:
    assert "confidential" in TRUSTED_INSTRUCTION
    assert "never reveal" in TRUSTED_INSTRUCTION


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        PromptLeakViaRetrievalProbe().run(_ctx(client, credentials=None))


def test_http_4xx_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        PromptLeakViaRetrievalProbe().run(_ctx(client))


def test_malformed_response_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "gpt-4o-mini"})

    with _client(handler) as client, pytest.raises(ProbeError, match="assistant message content"):
        PromptLeakViaRetrievalProbe().run(_ctx(client))


def test_required_classvars_set() -> None:
    assert PromptLeakViaRetrievalProbe.name == "prompt_leak_via_retrieval"
    assert isinstance(PromptLeakViaRetrievalProbe.name, str)
    assert PromptLeakViaRetrievalProbe.module == "rag"
    assert isinstance(PromptLeakViaRetrievalProbe.module, str)
    assert isinstance(PromptLeakViaRetrievalProbe.description, str)
    assert PromptLeakViaRetrievalProbe.baseline_severity == Severity.HIGH
    assert isinstance(PromptLeakViaRetrievalProbe.baseline_severity, Severity)
    assert PromptLeakViaRetrievalProbe.estimated_tokens_per_run == 2250
    assert isinstance(PromptLeakViaRetrievalProbe.estimated_tokens_per_run, int)
