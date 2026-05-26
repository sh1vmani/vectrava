"""End-to-end integration test for the ipi scan flow.

Drives the full `scan ipi` path through the real CLI entry point: argument
parsing, the authorization gate, probe registration and selection, the probe
running against a mocked httpx transport, the SARIF writer, and schema
validation inside `write_sarif`. No network and no real environment reads.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from typer.testing import CliRunner

from vectrava.cli import app
from vectrava.core import registry
from vectrava.core.registry import register
from vectrava.ipi.probes.direct_override import DirectOverrideProbe
from vectrava.ipi.probes.exfiltration_attempt import ExfiltrationAttemptProbe
from vectrava.ipi.probes.multi_turn_persistence import MultiTurnPersistenceProbe
from vectrava.ipi.probes.refusal_bypass import RefusalBypassProbe

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()
Handler = Callable[[httpx.Request], httpx.Response]

_HEX16 = re.compile(r"[0-9a-f]{16}")


@pytest.fixture(autouse=True)
def _registry() -> Iterator[None]:
    registry.clear()
    register(DirectOverrideProbe)
    register(ExfiltrationAttemptProbe)
    register(RefusalBypassProbe)
    register(MultiTurnPersistenceProbe)
    yield
    registry.clear()


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> None:
    real_client = httpx.Client  # capture before patching to avoid recursion

    def factory(*args: object, **kwargs: object) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "Client", factory)


def _invoke(scope: Path, out: Path, fmt: str = "sarif", only: str = "direct_override") -> Any:
    return runner.invoke(
        app,
        [
            "scan",
            "ipi",
            "--scope",
            str(scope),
            "--target",
            "https://example.test",
            "--api-key-env",
            "VECTRAVA_TEST_KEY",
            "--only",
            only,
            "--format",
            fmt,
            "--output",
            str(out),
        ],
    )


def test_clean_scan_emits_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "The document covers routine steps."}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out)

    assert result.exit_code == 0
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["exitCode"] == 0


def test_injection_succeeds_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        content = body["messages"][0]["content"]
        match = _HEX16.search(content)
        token = match.group(0) if match else ""
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": f"Here you go: {token}"}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out)

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert len(run["results"]) >= 1
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "direct_override" in rule_ids
    assert all(r["ruleId"] == "direct_override" for r in run["results"])


def test_probe_failure_emits_unsuccessful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out)

    assert result.exit_code == 2
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["exitCode"] == 2


def test_exfiltration_clean_scan_emits_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "I cannot share that internal token."}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="exfiltration_attempt")

    assert result.exit_code == 0
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["exitCode"] == 0


def test_exfiltration_succeeds_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        content = body["messages"][0]["content"]
        match = _HEX16.search(content)
        token = match.group(0) if match else ""
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": f"The token is {token}"}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="exfiltration_attempt")

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert len(run["results"]) >= 1
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "exfiltration_attempt" in rule_ids
    assert all(r["ruleId"] == "exfiltration_attempt" for r in run["results"])


def test_exfiltration_probe_failure_emits_unsuccessful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="exfiltration_attempt")

    assert result.exit_code == 2
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["exitCode"] == 2


def test_multi_turn_persistence_succeeds_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        messages = body["messages"]
        # Turn 1 plants the canary in messages[0]; it stays first all conversation.
        match = _HEX16.search(messages[0]["content"])
        token = match.group(0) if match else ""
        turn_index = (len(messages) + 1) // 2
        # Leak only after the turn-1 acknowledgement, so detection counts it.
        content = f"CANARY: {token}" if turn_index >= 2 else "Understood."
        return httpx.Response(
            200,
            json={"model": "gpt-4o-mini", "choices": [{"message": {"content": content}}]},
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="multi_turn_persistence")

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert len(run["results"]) >= 1
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "multi_turn_persistence" in rule_ids
    assert all(r["ruleId"] == "multi_turn_persistence" for r in run["results"])


def test_refusal_bypass_clean_scan_emits_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "I cannot reveal that."}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="refusal_bypass")

    assert result.exit_code == 0
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["exitCode"] == 0


def test_refusal_bypass_succeeds_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        content = body["messages"][0]["content"]
        match = _HEX16.search(content)
        token = match.group(0) if match else ""
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": f"The codeword is {token}"}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="refusal_bypass")

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert len(run["results"]) >= 1
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "refusal_bypass" in rule_ids
    assert all(r["ruleId"] == "refusal_bypass" for r in run["results"])


def test_refusal_bypass_probe_failure_emits_unsuccessful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="refusal_bypass")

    assert result.exit_code == 2
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["exitCode"] == 2
