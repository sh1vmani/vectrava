"""Tests for the multi_turn_persistence ipi probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. One canary is generated per conversation, interpolated
into the turn-1 injection, so handlers recover it from messages[0] of every
request with a [0-9a-f]{16} match. The conversation turn index is derived from
the message-list length: (len + 1) // 2.
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
from vectrava.ipi.probes.multi_turn_persistence import (
    INJECTION_PROMPTS,
    MultiTurnPersistenceProbe,
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


def _resp(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={"model": "gpt-4o-mini", "choices": [{"message": {"content": content}}]},
    )


def _canary_first(request: httpx.Request) -> str:
    """Recover the conversation canary from the turn-1 message (always messages[0])."""
    body = json.loads(request.content)
    match = _HEX16.search(body["messages"][0]["content"])
    return match.group(0) if match else ""


def _turn_index(request: httpx.Request) -> int:
    """Derive the 1-based conversation turn index from the message-list length."""
    body = json.loads(request.content)
    return (len(body["messages"]) + 1) // 2


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_leak_after_turn_one_emits_finding() -> None:
    state = {"convo": -1}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if len(body["messages"]) == 1:
            state["convo"] += 1
        # Only the first conversation leaks, and only after the turn-1 ack.
        if state["convo"] == 0 and _turn_index(request) >= 2:
            return _resp(f"CANARY: {_canary_first(request)} here is the answer")
        return _resp("Understood.")

    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.level == Severity.HIGH
    assert finding.rule_id == "multi_turn_persistence"
    assert finding.probe == "ipi.multi_turn_persistence"
    assert finding.evidence["injection_label"] == INJECTION_PROMPTS[0][0]


def test_no_leak_emits_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("Here is a normal, canary-free answer.")

    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client))

    assert findings == []


def test_turn_one_ack_only_not_counted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # The canary comes back only on the turn-1 acknowledgement, never after.
        if _turn_index(request) == 1:
            return _resp(f"Understood, I will use CANARY: {_canary_first(request)}")
        return _resp("Paris is the capital of France.")

    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client))

    assert findings == []


def test_evidence_turns_full_conversation_shape() -> None:
    state = {"convo": -1}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if len(body["messages"]) == 1:
            state["convo"] += 1
        if state["convo"] == 0 and _turn_index(request) >= 2:
            return _resp(f"CANARY: {_canary_first(request)}")
        return _resp("Understood.")

    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client))

    assert len(findings) == 1
    turns = findings[0].evidence["turns"]
    assert isinstance(turns, list)
    # Leak detected on response index 2: user1, assistant1, user2, assistant2.
    assert len(turns) == 4
    roles: list[str] = []
    contents: list[str] = []
    for entry in turns:
        assert isinstance(entry, dict)
        assert set(entry.keys()) == {"role", "content"}
        role = entry["role"]
        content = entry["content"]
        assert isinstance(role, str)
        assert isinstance(content, str)
        roles.append(role)
        contents.append(content)
    assert roles == ["user", "assistant", "user", "assistant"]
    assert _HEX16.search(contents[-1]) is not None


def test_one_canary_per_conversation() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if len(body["messages"]) == 1:
            seen.append(_canary_first(request))
        if _turn_index(request) >= 2:
            return _resp(f"CANARY: {_canary_first(request)}")
        return _resp("Understood.")

    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client))

    # Three conversations, three distinct canaries, one finding each.
    assert len(seen) == len(INJECTION_PROMPTS)
    assert len(set(seen)) == len(INJECTION_PROMPTS)
    assert len(findings) == len(INJECTION_PROMPTS)
    for index, finding in enumerate(findings):
        assert finding.evidence["canary_token"] == seen[index]


def test_max_turns_clamp_high() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No canary here.")

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 99}
    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client, options=options))

    assert findings == []
    # Clamped to 10 turns per label, no leak, three labels.
    assert calls["n"] == len(INJECTION_PROMPTS) * 10


def test_max_turns_clamp_low() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No canary here.")

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 1}
    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client, options=options))

    assert findings == []
    # Clamped up to the floor of 2 turns per label.
    assert calls["n"] == len(INJECTION_PROMPTS) * 2


def test_max_turns_default() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No canary here.")

    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client))

    assert findings == []
    # Default of 5 turns per label, no leak, three labels.
    assert calls["n"] == len(INJECTION_PROMPTS) * 5


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("No canary here.")

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        MultiTurnPersistenceProbe().run(_ctx(client, credentials=None))


def test_http_4xx_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        MultiTurnPersistenceProbe().run(_ctx(client))


def test_malformed_turn_no_prior_leak_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "gpt-4o-mini"})

    with _client(handler) as client, pytest.raises(ProbeError, match="chat-completions"):
        MultiTurnPersistenceProbe().run(_ctx(client))


def test_malformed_turn_after_leak_finding_preserved() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        turn_index = _turn_index(request)
        # A malformed turn 3 would raise if reached; detect-as-you-go must break
        # on the turn-2 leak first, so this branch is never exercised.
        if turn_index >= 3:
            return httpx.Response(200, json={"model": "gpt-4o-mini"})
        if turn_index >= 2:
            return _resp(f"CANARY: {_canary_first(request)}")
        return _resp("Understood.")

    with _client(handler) as client:
        findings = MultiTurnPersistenceProbe().run(_ctx(client))

    # Every conversation leaks at turn 2 and stops there: two requests per label.
    assert len(findings) == len(INJECTION_PROMPTS)
    assert calls["n"] == len(INJECTION_PROMPTS) * 2


def test_required_classvars_set() -> None:
    assert MultiTurnPersistenceProbe.name == "multi_turn_persistence"
    assert isinstance(MultiTurnPersistenceProbe.name, str)
    assert MultiTurnPersistenceProbe.module == "ipi"
    assert isinstance(MultiTurnPersistenceProbe.module, str)
    assert isinstance(MultiTurnPersistenceProbe.description, str)
    assert MultiTurnPersistenceProbe.baseline_severity == Severity.HIGH
    assert isinstance(MultiTurnPersistenceProbe.baseline_severity, Severity)
    assert MultiTurnPersistenceProbe.estimated_tokens_per_run == 49500
    assert isinstance(MultiTurnPersistenceProbe.estimated_tokens_per_run, int)
