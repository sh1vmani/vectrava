"""Tests for the token_amplification dow probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import structlog
from pydantic import JsonValue

from vectrava.config.scope import ScopeFile
from vectrava.core import registry
from vectrava.core.probe import ProbeContext, ProbeError
from vectrava.core.registry import register
from vectrava.dow.probes.token_amplification import (
    PROMPTS,
    TokenAmplificationProbe,
)

Handler = Callable[[httpx.Request], httpx.Response]

_EVIDENCE_KEYS = {
    "amplification_factor",
    "threshold",
    "prompt_category",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "max_tokens_requested",
    "finish_reason",
    "sample_prompt",
    "model",
    "latency_ms",
    "endpoint",
}


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
    options: Mapping[str, JsonValue] | None = None,
) -> ProbeContext:
    return ProbeContext(
        target=target,
        endpoint=endpoint,
        credentials="test-key",
        scope=_scope(),
        http=client,
        logger=structlog.get_logger(),
        options=options if options is not None else {"model": "gpt-4o-mini"},
    )


def _response(prompt_tokens: int, completion_tokens: int) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"finish_reason": "length"}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        },
    )


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_probe_is_registered_under_dow() -> None:
    register(TokenAmplificationProbe)
    probes = registry.by_module("dow")
    assert TokenAmplificationProbe in probes
    assert any(cls.name == "token_amplification" for cls in probes)


def test_high_ratio_yields_one_finding_per_category() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(prompt_tokens=10, completion_tokens=500)

    with _client(handler) as client:
        findings = TokenAmplificationProbe().run(_ctx(client))

    assert len(findings) == len(PROMPTS)
    assert [f.evidence["prompt_category"] for f in findings] == [c for c, _ in PROMPTS]
    for finding in findings:
        assert set(finding.evidence) == _EVIDENCE_KEYS
        assert finding.evidence["amplification_factor"] == 50.0
        assert finding.evidence["max_tokens_requested"] == 512


def test_below_threshold_yields_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(prompt_tokens=10, completion_tokens=20)

    with _client(handler) as client:
        findings = TokenAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_threshold_override_changes_cutoff() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(prompt_tokens=10, completion_tokens=500)

    options: dict[str, JsonValue] = {"model": "gpt-4o-mini", "threshold": 100.0}
    with _client(handler) as client:
        findings = TokenAmplificationProbe().run(_ctx(client, options=options))

    assert findings == []


def test_model_option_is_sent_in_request_body() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body["model"])
        return _response(prompt_tokens=10, completion_tokens=20)

    options = {"model": "custom-model"}
    with _client(handler) as client:
        TokenAmplificationProbe().run(_ctx(client, options=options))

    assert seen == ["custom-model"] * len(PROMPTS)


def test_probe_error_on_first_prompt_propagates_and_halts() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["messages"][0]["content"])
        return httpx.Response(400, text="boom")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        TokenAmplificationProbe().run(_ctx(client))

    assert seen == [PROMPTS[0][1]]


def test_endpoint_override_is_used_for_url() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return _response(prompt_tokens=10, completion_tokens=20)

    with _client(handler) as client:
        TokenAmplificationProbe().run(_ctx(client, endpoint="/custom/llm"))

    assert set(seen) == {"/custom/llm"}
