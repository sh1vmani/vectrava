"""Tests for the error_amplification dow probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. Handlers dispatch on the request body to return a
per-shape canned response (some error bodies carry a usage block, some do not).
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
from vectrava.core.adapters import ChatCompletionsAdapter
from vectrava.core.probe import ProbeContext, ProbeError
from vectrava.core.registry import register
from vectrava.core.result import Severity
from vectrava.dow.probes.error_amplification import SENTINEL_MODEL, ErrorAmplificationProbe

Handler = Callable[[httpx.Request], httpx.Response]


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


def _shape_of(request: httpx.Request) -> str:
    """Identify which probe shape a request came from, for per-shape responses."""
    body = json.loads(request.content)
    if body.get("model") == SENTINEL_MODEL:
        return "invalid_model"
    if isinstance(body["messages"][0]["content"], int):
        return "malformed_messages"
    return "oversized_prompt"


def _error_response(status: int, body: object) -> httpx.Response:
    return httpx.Response(status, json=body)


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_probe_is_registered_under_dow() -> None:
    register(ErrorAmplificationProbe)
    probes = registry.by_module("dow")
    assert ErrorAmplificationProbe in probes
    assert any(cls.name == "error_amplification" for cls in probes)


def test_error_response_with_usage_emits_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _shape_of(request) == "oversized_prompt":
            return _error_response(
                400,
                {
                    "error": {
                        "message": "context length exceeded",
                        "type": "invalid_request_error",
                        "code": "context_length_exceeded",
                    },
                    "usage": {"prompt_tokens": 31, "completion_tokens": 16, "total_tokens": 47},
                },
            )
        return _error_response(
            400, {"error": {"message": "rejected", "type": "invalid_request_error"}}
        )

    with _client(handler) as client:
        findings = ErrorAmplificationProbe().run(_ctx(client))

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence["shape_label"] == "oversized_prompt"
    assert evidence["total_tokens"] == 47
    assert evidence["http_status"] == 400
    assert evidence["error_code"] == "context_length_exceeded"


def test_error_response_without_usage_emits_nothing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _error_response(
            400, {"error": {"message": "rejected", "type": "invalid_request_error"}}
        )

    with _client(handler) as client:
        findings = ErrorAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_non_json_error_body_does_not_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="Bad Request")

    with _client(handler) as client:
        findings = ErrorAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_2xx_response_emits_nothing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _error_response(
            200,
            {
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
            },
        )

    with _client(handler) as client:
        findings = ErrorAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_multiple_shapes_fire_independently() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _shape_of(request) == "oversized_prompt":
            return _error_response(
                400,
                {
                    "error": {"code": "context_length_exceeded"},
                    "usage": {
                        "prompt_tokens": 90000,
                        "completion_tokens": 0,
                        "total_tokens": 90000,
                    },
                },
            )
        return _error_response(400, {"error": {"message": "rejected"}})

    with _client(handler) as client:
        findings = ErrorAmplificationProbe().run(_ctx(client))

    assert len(findings) == 1
    assert findings[0].evidence["shape_label"] == "oversized_prompt"


def test_missing_model_option_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _error_response(400, {"error": {}})

    with _client(handler) as client, pytest.raises(ProbeError, match="model"):
        ErrorAmplificationProbe().run(_ctx(client, options={}))


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _error_response(400, {"error": {}})

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        ErrorAmplificationProbe().run(_ctx(client, credentials=None))


def test_required_classvars_set() -> None:
    assert ErrorAmplificationProbe.name == "error_amplification"
    assert isinstance(ErrorAmplificationProbe.name, str)
    assert ErrorAmplificationProbe.module == "dow"
    assert isinstance(ErrorAmplificationProbe.module, str)
    assert isinstance(ErrorAmplificationProbe.description, str)
    assert ErrorAmplificationProbe.baseline_severity == Severity.MEDIUM
    assert isinstance(ErrorAmplificationProbe.baseline_severity, Severity)
    assert ErrorAmplificationProbe.estimated_tokens_per_run == 50_000 + 3 * (30 + 16)
    assert isinstance(ErrorAmplificationProbe.estimated_tokens_per_run, int)
