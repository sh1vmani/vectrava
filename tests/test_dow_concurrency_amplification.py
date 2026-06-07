"""Tests for the concurrency_amplification dow probe.

Every case uses httpx.MockTransport so no network is touched and no environment
variable is read. The probe is exercised directly through `run` with a
hand-built ProbeContext. The mock handler is invoked concurrently across N
worker threads, so any test that mutates shared state (e.g. a call counter)
guards the mutation with a threading.Lock.
"""

from __future__ import annotations

import threading
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
from vectrava.dow.probes.concurrency_amplification import (
    _CONCURRENCY,
    ConcurrencyAmplificationProbe,
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


def test_all_succeed_emits_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.level == Severity.MEDIUM
    assert finding.rule_id == "concurrency_amplification"
    assert finding.probe == "dow.concurrency_amplification"
    assert finding.evidence["concurrency"] == _CONCURRENCY
    assert finding.evidence["status_counts"] == {"200": _CONCURRENCY}
    assert finding.evidence["enforcement_observed"] is False
    assert finding.evidence["served_200"] == _CONCURRENCY


def test_any_429_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="too many requests")

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_429_among_200s_no_finding() -> None:
    # Exactly one of the N concurrent requests returns 429; the others return 200.
    # The mock counter is locked because handlers run on multiple worker threads.
    state = {"n": 0}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            state["n"] += 1
            is_target = state["n"] == 3
        if is_target:
            return httpx.Response(429, text="slow down")
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_all_503_no_finding() -> None:
    # A burst of 503s is the target shedding load. The old logic suppressed this only
    # because served_200 was 0; now it suppresses for the right reason: 503 counts as
    # an enforcement status.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="service unavailable")

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_503_among_200s_no_finding() -> None:
    # One of the N concurrent requests returns 503, the rest return 200, so served_200
    # is N-1. The old 429-only predicate would have fired (no 429, served_200 >= N-1);
    # the 503 now counts as enforcement and suppresses the finding. The mock counter is
    # locked because handlers run on multiple worker threads.
    state = {"n": 0}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            state["n"] += 1
            is_target = state["n"] == 3
        if is_target:
            return httpx.Response(503, text="service unavailable")
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_529_among_200s_no_finding() -> None:
    # Same discriminating shape as the 503 case but with a 529 overload response:
    # served_200 is N-1, the old logic would have fired, the 529 now suppresses it.
    state = {"n": 0}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            state["n"] += 1
            is_target = state["n"] == 3
        if is_target:
            return httpx.Response(529, text="overloaded")
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    assert findings == []


def test_one_transport_error_still_emits_finding() -> None:
    # Exactly one of the N concurrent requests raises a transport error; the
    # other four return 200. The probe's N-1 floor tolerates a single drop.
    state = {"n": 0}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            state["n"] += 1
            is_target = state["n"] == 1
        if is_target:
            raise httpx.ConnectError("simulated transport drop", request=request)
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence["served_200"] == _CONCURRENCY - 1
    status_counts = evidence["status_counts"]
    assert isinstance(status_counts, dict)
    assert status_counts.get("200") == _CONCURRENCY - 1
    assert status_counts.get("-1") == 1


def test_all_transport_errors_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated transport drop", request=request)

    with _client(handler) as client, pytest.raises(ProbeError, match="transport failed for all"):
        ConcurrencyAmplificationProbe().run(_ctx(client))


def test_exactly_n_requests_dispatched() -> None:
    state = {"n": 0}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            state["n"] += 1
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        ConcurrencyAmplificationProbe().run(_ctx(client))

    assert state["n"] == _CONCURRENCY


def test_concurrent_dispatch_uses_pool() -> None:
    # The probe must dispatch the burst concurrently, not serially. A barrier sized
    # to the burst width releases only once all _CONCURRENCY requests are in flight
    # at the same time; serial dispatch would block the first request at the barrier
    # until the 5.0s timeout, raising BrokenBarrierError and failing the test. This
    # proves true concurrency deterministically, with no wall-clock bound. The party
    # size matches the probe's ThreadPoolExecutor max_workers (_CONCURRENCY).
    barrier = threading.Barrier(_CONCURRENCY, timeout=5.0)

    def handler(request: httpx.Request) -> httpx.Response:
        barrier.wait()  # releases only when all _CONCURRENCY requests are concurrent
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    # Reaching this assertion proves the barrier released, i.e. the burst was
    # genuinely concurrent. All requests returned 200 with no 429, so a finding fires.
    assert len(findings) == 1


def test_429_not_retried() -> None:
    state = {"n": 0}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            state["n"] += 1
        return httpx.Response(429, text="too many requests")

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    # Each of the N logical requests is exactly one HTTP call; a 429 is not retried.
    assert state["n"] == _CONCURRENCY
    assert findings == []


def test_evidence_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        findings = ConcurrencyAmplificationProbe().run(_ctx(client))

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence["concurrency"] == _CONCURRENCY
    results = evidence["results"]
    assert isinstance(results, list)
    assert len(results) == _CONCURRENCY
    for entry in results:
        assert isinstance(entry, dict)
        assert set(entry.keys()) == {"index", "status", "elapsed_ms"}
    status_counts = evidence["status_counts"]
    assert isinstance(status_counts, dict)
    assert isinstance(evidence["enforcement_observed"], bool)
    assert isinstance(evidence["served_200"], int)
    endpoint = evidence["endpoint"]
    assert isinstance(endpoint, str)
    assert "/v1/chat/completions" in endpoint


def test_missing_credentials_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="requires credentials"),
    ):
        ConcurrencyAmplificationProbe().run(_ctx(client, credentials=None))


def test_missing_model_raises_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    with (
        _client(handler) as client,
        pytest.raises(ProbeError, match="model identifier"),
    ):
        ConcurrencyAmplificationProbe().run(_ctx(client, options={}))


def test_required_classvars_set() -> None:
    assert ConcurrencyAmplificationProbe.name == "concurrency_amplification"
    assert isinstance(ConcurrencyAmplificationProbe.name, str)
    assert ConcurrencyAmplificationProbe.module == "dow"
    assert isinstance(ConcurrencyAmplificationProbe.module, str)
    assert isinstance(ConcurrencyAmplificationProbe.description, str)
    assert ConcurrencyAmplificationProbe.baseline_severity == Severity.MEDIUM
    assert isinstance(ConcurrencyAmplificationProbe.baseline_severity, Severity)
    assert ConcurrencyAmplificationProbe.tags == (
        "dow",
        "rate-limit",
        "concurrency",
        "infrastructure",
    )
    assert ConcurrencyAmplificationProbe.estimated_tokens_per_run == 155
    assert isinstance(ConcurrencyAmplificationProbe.estimated_tokens_per_run, int)
