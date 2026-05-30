"""Tests for the multi_turn_buried_instruction ipi probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a hand-built
ProbeContext. One canary is generated per conversation, interpolated into the
turn-1 injection only, so handlers recover it from messages[0] of every request
with a [0-9a-f]{16} match. There is no system turn, so the 1-based conversation
turn index is (len(messages) + 1) // 2, the same derivation as
multi_turn_persistence.
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
from vectrava.core.probe_helpers import GENERIC_FILLER_TURNS
from vectrava.core.result import Severity
from vectrava.ipi.probes.multi_turn_buried_instruction import (
    INJECTION_VARIANTS,
    MultiTurnBuriedInstructionProbe,
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


def _resp(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={"model": "gpt-4o-mini", "choices": [{"message": {"content": content}}]},
    )


def _canary_first(request: httpx.Request) -> str:
    """Recover the conversation canary from the turn-1 injection (always messages[0])."""
    body = json.loads(request.content)
    match = _HEX16.search(body["messages"][0]["content"])
    return match.group(0) if match else ""


def _turn_index(request: httpx.Request) -> int:
    """Derive the 1-based turn index from the message-list length; no system turn."""
    body = json.loads(request.content)
    return (len(body["messages"]) + 1) // 2


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_leak_in_final_turn_emits_finding() -> None:
    # Default max_turns is 5, so the final turn is turn 5.
    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 5:
            return _resp(f"Here is the summary {_canary_first(request)}.")
        return _resp("Sure, happy to help with that.")

    with _client(handler) as client:
        findings = MultiTurnBuriedInstructionProbe().run(_ctx(client))

    assert len(findings) == len(INJECTION_VARIANTS)
    for finding in findings:
        assert finding.level == Severity.HIGH
        assert finding.rule_id == "multi_turn_buried_instruction"
        assert finding.probe == "ipi.multi_turn_buried_instruction"
    assert findings[0].evidence["injection_label"] == INJECTION_VARIANTS[0][0]


def test_no_leak_clean_replies() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("Here is a normal, canary-free answer.")

    with _client(handler) as client:
        findings = MultiTurnBuriedInstructionProbe().run(_ctx(client))

    assert findings == []


def test_leak_in_filler_turn_not_counted() -> None:
    # The canary surfaces on a non-final (filler) turn but not on the final turn.
    # Only the final turn is judged, so this is not a finding.
    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 2:
            return _resp(f"Oops, early marker {_canary_first(request)}.")
        return _resp("A plain answer with no marker.")

    with _client(handler) as client:
        findings = MultiTurnBuriedInstructionProbe().run(_ctx(client))

    assert findings == []


def test_evidence_contains_full_conversation_and_canary() -> None:
    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 3}

    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 3:
            return _resp(f"summary tail {_canary_first(request)}")
        return _resp("Continuing the conversation.")

    with _client(handler) as client:
        findings = MultiTurnBuriedInstructionProbe().run(_ctx(client, options=options))

    assert len(findings) == len(INJECTION_VARIANTS)
    turns = findings[0].evidence["turns"]
    assert isinstance(turns, list)
    # max_turns=3, no system turn: (user, assistant) * 3 = 6 entries.
    assert len(turns) == 6
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
    assert roles == ["user", "assistant", "user", "assistant", "user", "assistant"]
    assert _HEX16.search(contents[-1]) is not None


def test_canary_fresh_per_variant() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if _turn_index(request) == 1:
            seen.append(_canary_first(request))
        if _turn_index(request) == 5:
            return _resp(f"summary {_canary_first(request)}")
        return _resp("Continuing.")

    with _client(handler) as client:
        findings = MultiTurnBuriedInstructionProbe().run(_ctx(client))

    assert len(seen) == len(INJECTION_VARIANTS)
    assert len(set(seen)) == len(INJECTION_VARIANTS)
    assert len(findings) == len(INJECTION_VARIANTS)
    for index, finding in enumerate(findings):
        assert finding.evidence["canary_token"] == seen[index]


def test_canary_appears_only_in_turn_one_injection() -> None:
    # The {canary} placeholder lives only in the injection; the final_turn never
    # carries it, so a leak proves the buried directive fired, not an echo.
    for _label, injection, _trigger_word, final_turn in INJECTION_VARIANTS:
        assert "{canary}" in injection
        assert "{canary}" not in final_turn


def test_filler_turns_do_not_reference_trigger_words() -> None:
    # No generic filler may contain a variant's trigger word, or the buried
    # directive could fire mid-conversation instead of only on the final turn.
    for _label, _injection, trigger_word, _final_turn in INJECTION_VARIANTS:
        for filler in GENERIC_FILLER_TURNS:
            assert trigger_word not in filler


def test_final_turn_contains_trigger_word() -> None:
    for _label, _injection, trigger_word, final_turn in INJECTION_VARIANTS:
        assert trigger_word in final_turn


def test_max_turns_clamp_high() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No marker here.")

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 99}
    with _client(handler) as client:
        findings = MultiTurnBuriedInstructionProbe().run(_ctx(client, options=options))

    assert findings == []
    # Clamped to 10 turns per variant, no leak, three variants.
    assert calls["n"] == len(INJECTION_VARIANTS) * 10


def test_max_turns_clamp_low() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No marker here.")

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_turns": 1}
    with _client(handler) as client:
        findings = MultiTurnBuriedInstructionProbe().run(_ctx(client, options=options))

    assert findings == []
    # Clamped up to the floor of 2 turns per variant.
    assert calls["n"] == len(INJECTION_VARIANTS) * 2


def test_max_turns_default() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _resp("No marker here.")

    with _client(handler) as client:
        findings = MultiTurnBuriedInstructionProbe().run(_ctx(client))

    assert findings == []
    # Default of 5 turns per variant, no leak, three variants.
    assert calls["n"] == len(INJECTION_VARIANTS) * 5


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _resp("No marker here.")

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        MultiTurnBuriedInstructionProbe().run(_ctx(client, credentials=None))


def test_http_400_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        MultiTurnBuriedInstructionProbe().run(_ctx(client))


def test_malformed_response_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "gpt-4o-mini"})

    with _client(handler) as client, pytest.raises(ProbeError, match="chat-completions"):
        MultiTurnBuriedInstructionProbe().run(_ctx(client))


def test_required_classvars_set() -> None:
    assert MultiTurnBuriedInstructionProbe.name == "multi_turn_buried_instruction"
    assert isinstance(MultiTurnBuriedInstructionProbe.name, str)
    assert MultiTurnBuriedInstructionProbe.module == "ipi"
    assert isinstance(MultiTurnBuriedInstructionProbe.module, str)
    assert isinstance(MultiTurnBuriedInstructionProbe.description, str)
    assert MultiTurnBuriedInstructionProbe.baseline_severity == Severity.HIGH
    assert isinstance(MultiTurnBuriedInstructionProbe.baseline_severity, Severity)
    assert MultiTurnBuriedInstructionProbe.tags == ("injection", "multi-turn", "ipi")
    assert MultiTurnBuriedInstructionProbe.estimated_tokens_per_run == 49500
    assert isinstance(MultiTurnBuriedInstructionProbe.estimated_tokens_per_run, int)
