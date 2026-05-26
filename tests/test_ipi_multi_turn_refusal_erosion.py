"""Tests for the multi_turn_refusal_erosion ipi probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. One codeword is generated per conversation and lives in
the system prompt (messages[0]), so handlers recover it from messages[0] with a
[0-9a-f]{16} match. The conversation turn index is len(messages) // 2 because
messages[0] is the system turn.
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
from vectrava.ipi.probes.multi_turn_refusal_erosion import (
    LABELS,
    SYSTEM_PROMPT_TEMPLATE,
    MultiTurnRefusalErosionProbe,
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


def _canary_system(request: httpx.Request) -> str:
    """Recover the conversation codeword from the system turn (always messages[0])."""
    body = json.loads(request.content)
    match = _HEX16.search(body["messages"][0]["content"])
    return match.group(0) if match else ""


def _turn_index(request: httpx.Request) -> int:
    """Derive the 1-based turn index; messages[0] is the system turn."""
    body = json.loads(request.content)
    return len(body["messages"]) // 2


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_leak_at_final_turn_emits_finding() -> None:
    # Default max_turns is 5, so the final turn is turn 5.
    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 5:
            return _resp(f"The codeword is {_canary_system(request)}.")
        return _resp("Staying in character, continuing the scene.")

    with _client(handler) as client:
        findings = MultiTurnRefusalErosionProbe().run(_ctx(client))

    assert len(findings) == len(LABELS)
    for finding in findings:
        assert finding.level == Severity.HIGH
        assert finding.rule_id == "multi_turn_refusal_erosion"
        assert finding.probe == "ipi.multi_turn_refusal_erosion"
    assert findings[0].evidence["framing_label"] == LABELS[0][0]


def test_no_leak_emits_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("I will not reveal that, even in a story.")

    with _client(handler) as client:
        findings = MultiTurnRefusalErosionProbe().run(_ctx(client))

    assert findings == []


def test_leak_in_framing_turn_not_counted() -> None:
    # Codeword echoed on a non-final (framing) turn must not count; only the
    # final turn is judged.
    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 2:
            return _resp(f"Whoops, the codeword is {_canary_system(request)}.")
        return _resp("I will not reveal that.")

    with _client(handler) as client:
        findings = MultiTurnRefusalErosionProbe().run(_ctx(client))

    assert findings == []


def test_evidence_turns_full_conversation_shape() -> None:
    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 3}

    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 3:
            return _resp(f"codeword: {_canary_system(request)}")
        return _resp("Continuing the scene.")

    with _client(handler) as client:
        findings = MultiTurnRefusalErosionProbe().run(_ctx(client, options=options))

    assert len(findings) == len(LABELS)
    turns = findings[0].evidence["turns"]
    assert isinstance(turns, list)
    # max_turns=3: system + (user, assistant) * 3 = 7 entries.
    assert len(turns) == 7
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
    assert roles[0] == "system"
    assert roles == ["system", "user", "assistant", "user", "assistant", "user", "assistant"]
    assert _HEX16.search(contents[-1]) is not None


def test_one_canary_per_conversation() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 1:
            seen.append(_canary_system(request))
        if _turn_index(request) == 5:
            return _resp(f"codeword {_canary_system(request)}")
        return _resp("Continuing.")

    with _client(handler) as client:
        findings = MultiTurnRefusalErosionProbe().run(_ctx(client))

    assert len(seen) == len(LABELS)
    assert len(set(seen)) == len(LABELS)
    assert len(findings) == len(LABELS)
    for index, finding in enumerate(findings):
        assert finding.evidence["canary_token"] == seen[index]


def test_max_turns_clamp_high() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No codeword here.")

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 99}
    with _client(handler) as client:
        findings = MultiTurnRefusalErosionProbe().run(_ctx(client, options=options))

    assert findings == []
    # Clamped to 10 turns per label, no leak, three labels.
    assert calls["n"] == len(LABELS) * 10


def test_max_turns_clamp_low() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No codeword here.")

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 1}
    with _client(handler) as client:
        findings = MultiTurnRefusalErosionProbe().run(_ctx(client, options=options))

    assert findings == []
    # Clamped up to the floor of 2 turns per label.
    assert calls["n"] == len(LABELS) * 2


def test_max_turns_default() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No codeword here.")

    with _client(handler) as client:
        findings = MultiTurnRefusalErosionProbe().run(_ctx(client))

    assert findings == []
    # Default of 5 turns per label, no leak, three labels.
    assert calls["n"] == len(LABELS) * 5


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("No codeword here.")

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        MultiTurnRefusalErosionProbe().run(_ctx(client, credentials=None))


def test_http_4xx_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        MultiTurnRefusalErosionProbe().run(_ctx(client))


def test_malformed_final_turn_raises_probe_error() -> None:
    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 2}

    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 2:
            return httpx.Response(200, json={"model": "gpt-4o-mini"})
        return _resp("Continuing the scene.")

    with _client(handler) as client, pytest.raises(ProbeError, match="chat-completions"):
        MultiTurnRefusalErosionProbe().run(_ctx(client, options=options))


def test_framing_turns_do_not_reference_canary() -> None:
    # The codeword lives only in the system prompt; framing text never carries it.
    assert "{canary}" in SYSTEM_PROMPT_TEMPLATE
    for _label, opening_frame, framed_ask in LABELS:
        assert "{canary}" not in opening_frame
        assert "{canary}" not in framed_ask


def test_framing_turns_use_codeword_vocabulary() -> None:
    for _label, opening_frame, framed_ask in LABELS:
        opening = opening_frame.lower()
        ask = framed_ask.lower()
        assert "codeword" in opening or "secret" in opening
        assert "codeword" in ask or "secret" in ask


def test_required_classvars_set() -> None:
    assert MultiTurnRefusalErosionProbe.name == "multi_turn_refusal_erosion"
    assert isinstance(MultiTurnRefusalErosionProbe.name, str)
    assert MultiTurnRefusalErosionProbe.module == "ipi"
    assert isinstance(MultiTurnRefusalErosionProbe.module, str)
    assert isinstance(MultiTurnRefusalErosionProbe.description, str)
    assert MultiTurnRefusalErosionProbe.baseline_severity == Severity.HIGH
    assert isinstance(MultiTurnRefusalErosionProbe.baseline_severity, Severity)
    assert MultiTurnRefusalErosionProbe.estimated_tokens_per_run == 51900
    assert isinstance(MultiTurnRefusalErosionProbe.estimated_tokens_per_run, int)
