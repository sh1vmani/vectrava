"""Tests for the output_padding dow probe.

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
from vectrava.core.result import Severity
from vectrava.dow.probes.output_padding import PROMPTS, OutputPaddingProbe

Handler = Callable[[httpx.Request], httpx.Response]

_EVIDENCE_KEYS = {
    "padding_ratio",
    "threshold",
    "expected_max_content_tokens",
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


def test_probe_registers() -> None:
    register(OutputPaddingProbe)
    probes = registry.by_module("dow")
    assert OutputPaddingProbe in probes
    assert any(cls.name == "output_padding" for cls in probes)


def test_high_ratio_emits_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(prompt_tokens=10, completion_tokens=256)

    with _client(handler) as client:
        findings = OutputPaddingProbe().run(_ctx(client))

    assert len(findings) == len(PROMPTS)
    assert {f.evidence["prompt_category"] for f in findings} == {c for c, _, _ in PROMPTS}
    for finding in findings:
        assert finding.rule_id == "output_padding"
        ratio = finding.evidence["padding_ratio"]
        assert isinstance(ratio, float)
        assert ratio >= 4.0


def test_below_threshold_emits_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(prompt_tokens=10, completion_tokens=4)

    with _client(handler) as client:
        findings = OutputPaddingProbe().run(_ctx(client))

    assert findings == []


def test_threshold_override() -> None:
    options: dict[str, JsonValue] = {"padding_threshold": 0.1, "model": "gpt-4o-mini"}

    def handler(request: httpx.Request) -> httpx.Response:
        return _response(prompt_tokens=10, completion_tokens=4)

    with _client(handler) as client:
        findings = OutputPaddingProbe().run(_ctx(client, options=options))

    assert len(findings) == len(PROMPTS)


def test_model_option_propagated() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["model"])
        return _response(prompt_tokens=10, completion_tokens=4)

    options = {"model": "custom-model"}
    with _client(handler) as client:
        OutputPaddingProbe().run(_ctx(client, options=options))

    assert seen == ["custom-model"] * len(PROMPTS)


def test_endpoint_override() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return _response(prompt_tokens=10, completion_tokens=4)

    with _client(handler) as client:
        OutputPaddingProbe().run(_ctx(client, endpoint="/custom/v1/chat/completions"))

    assert set(seen) == {"/custom/v1/chat/completions"}


def test_probe_error_propagates() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["messages"][0]["content"])
        return httpx.Response(400, text="server error")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        OutputPaddingProbe().run(_ctx(client))

    assert seen == [PROMPTS[0][1]]


def test_evidence_keys_present() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(prompt_tokens=10, completion_tokens=256)

    with _client(handler) as client:
        findings = OutputPaddingProbe().run(_ctx(client))

    finding = findings[0]
    assert set(finding.evidence) == _EVIDENCE_KEYS
    assert isinstance(finding.evidence["padding_ratio"], float)
    assert isinstance(finding.evidence["expected_max_content_tokens"], int)
    assert isinstance(finding.evidence["prompt_category"], str)
    assert isinstance(finding.evidence["endpoint"], str)


def test_required_classvars_set() -> None:
    assert OutputPaddingProbe.name == "output_padding"
    assert isinstance(OutputPaddingProbe.name, str)
    assert OutputPaddingProbe.module == "dow"
    assert isinstance(OutputPaddingProbe.module, str)
    assert isinstance(OutputPaddingProbe.description, str)
    assert OutputPaddingProbe.baseline_severity == Severity.MEDIUM
    assert isinstance(OutputPaddingProbe.baseline_severity, Severity)
    assert OutputPaddingProbe.estimated_tokens_per_run == 4 * (30 + 256)
    assert isinstance(OutputPaddingProbe.estimated_tokens_per_run, int)
