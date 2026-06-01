"""Tests for the rate_limit_bypass dow probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. Handlers return arbitrary status codes to model a
target that does or does not enforce HTTP 429 across the burst.
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
from vectrava.core.adapters import ChatCompletionsAdapter
from vectrava.core.probe import ProbeContext, ProbeError
from vectrava.core.result import Severity
from vectrava.dow.probes.rate_limit_bypass import (
    _BURST_SIZE,
    RateLimitBypassProbe,
)

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


def _client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_all_200s_emits_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = RateLimitBypassProbe().run(_ctx(client))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.level == Severity.MEDIUM
    assert finding.rule_id == "rate_limit_bypass"
    assert finding.probe == "dow.rate_limit_bypass"
    assert finding.evidence["saw_enforcement"] is False
    assert finding.evidence["status_counts"] == {"200": _BURST_SIZE}


def test_one_429_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="too many requests")

    with _client(handler) as client:
        findings = RateLimitBypassProbe().run(_ctx(client))

    assert findings == []


def test_mixed_statuses_with_429_emits_no_finding() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        # One 429 mid-burst, the rest served 200. Any 429 means the target enforced.
        if calls["n"] == 5:
            return httpx.Response(429, text="slow down")
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = RateLimitBypassProbe().run(_ctx(client))

    assert findings == []


def test_all_503_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="service unavailable")

    with _client(handler) as client:
        findings = RateLimitBypassProbe().run(_ctx(client))

    assert findings == []


def test_all_529_emits_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(529, text="overloaded")

    with _client(handler) as client:
        findings = RateLimitBypassProbe().run(_ctx(client))

    assert findings == []


def test_one_503_among_200s_emits_no_finding() -> None:
    # The burst is single-threaded (post_no_retry), so a plain counter is safe. One
    # of the twenty requests returns 503 and the rest serve 200. Under the old
    # 429-only predicate this fired a finding (no 429 seen); now the 503 counts as
    # enforcement and suppresses it.
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 5:
            return httpx.Response(503, text="service unavailable")
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = RateLimitBypassProbe().run(_ctx(client))

    assert findings == []


def test_burst_issues_exactly_burst_size_requests() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        RateLimitBypassProbe().run(_ctx(client))

    assert calls["n"] == _BURST_SIZE


def test_429_is_not_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, text="too many requests")

    with _client(handler) as client:
        findings = RateLimitBypassProbe().run(_ctx(client))

    # Each of the _BURST_SIZE logical requests is exactly one HTTP call; a 429 is
    # not retried. With post_with_retry this would be up to 3x the calls.
    assert calls["n"] == _BURST_SIZE
    assert findings == []


def test_evidence_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = RateLimitBypassProbe().run(_ctx(client))

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence["burst_size"] == _BURST_SIZE
    status_counts = evidence["status_counts"]
    assert isinstance(status_counts, dict)
    assert status_counts
    assert isinstance(evidence["saw_enforcement"], bool)
    endpoint = evidence["endpoint"]
    assert isinstance(endpoint, str)
    assert "/v1/chat/completions" in endpoint


def test_overpaces_ignoring_max_rps(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(
        "vectrava.core.http.time.sleep",
        lambda duration: sleeps.append(duration),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    options: Mapping[str, JsonValue] = {"model": "gpt-4o-mini", "max_rps": 1}
    with _client(handler) as client:
        RateLimitBypassProbe().run(_ctx(client, options=options))

    # The probe overpaces deliberately: no client-side pacing sleep is ever issued.
    assert sleeps == []


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        RateLimitBypassProbe().run(_ctx(client, credentials=None))


def test_required_classvars_set() -> None:
    assert RateLimitBypassProbe.name == "rate_limit_bypass"
    assert isinstance(RateLimitBypassProbe.name, str)
    assert RateLimitBypassProbe.module == "dow"
    assert isinstance(RateLimitBypassProbe.module, str)
    assert isinstance(RateLimitBypassProbe.description, str)
    assert RateLimitBypassProbe.baseline_severity == Severity.MEDIUM
    assert isinstance(RateLimitBypassProbe.baseline_severity, Severity)
    assert RateLimitBypassProbe.estimated_tokens_per_run == 620
    assert isinstance(RateLimitBypassProbe.estimated_tokens_per_run, int)
