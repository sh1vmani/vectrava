"""Tests for the retrieval_permission_leak rag probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a hand-built
ProbeContext. The canary is planted in the tenant-b document inside the user
message, so handlers recover it from messages[1] with a [0-9a-f]{16} match and
echo it back.
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
from vectrava.core.probe import ProbeContext
from vectrava.core.result import Severity
from vectrava.rag.probes.retrieval_permission_leak import (
    ATTACK_LABELS,
    RetrievalPermissionLeakProbe,
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
            "choices": [{"message": {"content": f"The restricted reference is {token}."}}],
        },
    )


def _benign_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"content": "I can only share tenant-a Project Apollo info."}}],
        },
    )


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_required_classvars_set() -> None:
    assert RetrievalPermissionLeakProbe.name == "retrieval_permission_leak"
    assert isinstance(RetrievalPermissionLeakProbe.name, str)
    assert RetrievalPermissionLeakProbe.module == "rag"
    assert isinstance(RetrievalPermissionLeakProbe.module, str)
    assert isinstance(RetrievalPermissionLeakProbe.description, str)
    assert RetrievalPermissionLeakProbe.baseline_severity == Severity.CRITICAL
    assert isinstance(RetrievalPermissionLeakProbe.baseline_severity, Severity)
    assert RetrievalPermissionLeakProbe.estimated_tokens_per_run == 2550
    assert isinstance(RetrievalPermissionLeakProbe.estimated_tokens_per_run, int)


def test_clean_target_produces_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with _client(handler) as client:
        findings = RetrievalPermissionLeakProbe().run(_ctx(client))

    assert findings == []


def test_leaking_target_produces_finding_per_label() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _echo_response(_canary_in(request))

    with _client(handler) as client:
        findings = RetrievalPermissionLeakProbe().run(_ctx(client))

    assert len(findings) == len(ATTACK_LABELS)
    for finding in findings:
        assert finding.level == Severity.CRITICAL
        assert finding.rule_id == "retrieval_permission_leak"
        assert finding.probe == "rag.retrieval_permission_leak"
        canary_token = finding.evidence["canary_token"]
        assert isinstance(canary_token, str)
        assert canary_token != ""
    assert [f.evidence["attack_label"] for f in findings] == [label for label, _ in ATTACK_LABELS]


def test_canary_not_present_in_user_query() -> None:
    # The canary lives only in the tenant-b document body, never in the user
    # query that precedes the Sources block. Statically, no attack query carries
    # a canary placeholder or a hex token; at runtime, the planted canary appears
    # in the sources block but not in the query prefix.
    for _label, query in ATTACK_LABELS:
        assert "{canary}" not in query
        assert _HEX16.search(query) is None

    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(_user_content(request))
        return _benign_response()

    with _client(handler) as client:
        RetrievalPermissionLeakProbe().run(_ctx(client))

    assert len(captured) == len(ATTACK_LABELS)
    for content in captured:
        query_prefix, _, sources_block = content.partition("Sources:")
        match = _HEX16.search(sources_block)
        assert match is not None  # the canary is planted in the tenant-b document
        assert match.group(0) not in query_prefix


def test_padding_chunks_interleaved() -> None:
    # interleave_padding_chunks pads the single tenant-b attack chunk up to
    # num_sources with benign tenant-a fillers. With a single attack chunk the
    # helper is deterministic (the attack chunk leads, fillers follow); the
    # invariant worth pinning is that padding happens and exactly one source
    # carries the mismatched tenant-b tag among num_sources total.
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(_user_content(request))
        return _benign_response()

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "num_sources": 5}
    with _client(handler) as client:
        RetrievalPermissionLeakProbe().run(_ctx(client, options=options))

    assert captured
    for content in captured:
        # Padding to num_sources occurred: one mismatched tenant-b source plus
        # four benign tenant-a fillers, five sources total.
        assert content.count("<source ") == 5
        assert content.count('tag="tenant-b"') == 1
        assert content.count('tag="tenant-a"') == 4


def test_response_excerpt_truncated_to_200_chars() -> None:
    long_tail = " lorem ipsum dolor sit amet" * 20

    def handler(request: httpx.Request) -> httpx.Response:
        token = _canary_in(request)
        content = f"{token}{long_tail}"
        return httpx.Response(
            200,
            json={"model": "gpt-4o-mini", "choices": [{"message": {"content": content}}]},
        )

    with _client(handler) as client:
        findings = RetrievalPermissionLeakProbe().run(_ctx(client))

    assert findings
    for finding in findings:
        excerpt = finding.evidence["response_excerpt"]
        assert isinstance(excerpt, str)
        assert len(excerpt) == 200


def test_mismatched_doc_tag_recorded_in_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _echo_response(_canary_in(request))

    with _client(handler) as client:
        findings = RetrievalPermissionLeakProbe().run(_ctx(client))

    assert findings
    for finding in findings:
        assert finding.evidence["mismatched_doc_tag"] == "tenant-b"
