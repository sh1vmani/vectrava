"""Tests for the model_substitution dow probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is single-shot, so it emits at most one finding.
"""

from __future__ import annotations

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
from vectrava.dow.probes.model_substitution import ModelSubstitutionProbe

Handler = Callable[[httpx.Request], httpx.Response]

_EVIDENCE_KEYS = {
    "requested_model",
    "reported_model",
    "model_matched",
    "match_status",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "max_tokens_requested",
    "finish_reason",
    "sample_prompt",
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


def _response(model: str | None) -> httpx.Response:
    body: dict[str, JsonValue] = {
        "choices": [{"finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }
    if model is not None:
        body["model"] = model
    return httpx.Response(200, json=body)


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_probe_registers() -> None:
    register(ModelSubstitutionProbe)
    probes = registry.by_module("dow")
    assert ModelSubstitutionProbe in probes
    assert any(cls.name == "model_substitution" for cls in probes)


def test_exact_match_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response("gpt-4o-mini")

    with _client(handler) as client:
        findings = ModelSubstitutionProbe().run(_ctx(client))

    assert findings == []


def test_mismatch_emits_medium_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response("gpt-4o")

    with _client(handler) as client:
        findings = ModelSubstitutionProbe().run(_ctx(client))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.level is Severity.MEDIUM
    assert finding.rule_id == "model_substitution"
    assert finding.evidence["match_status"] == "mismatch"
    assert finding.evidence["requested_model"] == "gpt-4o-mini"
    assert finding.evidence["reported_model"] == "gpt-4o"
    assert finding.evidence["model_matched"] is False


def test_null_model_emits_informational_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(None)

    with _client(handler) as client:
        findings = ModelSubstitutionProbe().run(_ctx(client))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.level is Severity.INFORMATIONAL
    assert finding.evidence["match_status"] == "unreported"
    assert finding.evidence["reported_model"] is None


def test_missing_model_option_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response("gpt-4o-mini")

    with _client(handler) as client, pytest.raises(ProbeError):
        ModelSubstitutionProbe().run(_ctx(client, options={}))


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response("gpt-4o-mini")

    with _client(handler) as client, pytest.raises(ProbeError):
        ModelSubstitutionProbe().run(_ctx(client, credentials=None))


def test_evidence_keys_present() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response("gpt-4o")

    with _client(handler) as client:
        findings = ModelSubstitutionProbe().run(_ctx(client))

    evidence = findings[0].evidence
    assert set(evidence) == _EVIDENCE_KEYS
    assert isinstance(evidence["requested_model"], str)
    assert evidence["reported_model"] == "gpt-4o"
    assert isinstance(evidence["model_matched"], bool)
    assert isinstance(evidence["match_status"], str)
    assert isinstance(evidence["endpoint"], str)


def test_endpoint_override() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return _response("gpt-4o-mini")

    with _client(handler) as client:
        ModelSubstitutionProbe().run(_ctx(client, endpoint="/custom/endpoint"))

    assert seen == ["/custom/endpoint"]


def test_probe_error_propagates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server error")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 500"):
        ModelSubstitutionProbe().run(_ctx(client))
