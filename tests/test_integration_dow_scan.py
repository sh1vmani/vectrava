"""End-to-end integration test for the dow scan flow.

Drives the full `scan dow` path through the real CLI entry point: argument
parsing, the authorization gate, probe registration and selection, the probe
running against a mocked httpx transport, the SARIF writer, and schema
validation inside `write_sarif`. No network and no real environment reads.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from typer.testing import CliRunner

from vectrava.cli import app
from vectrava.core import registry
from vectrava.core.registry import register
from vectrava.dow.probes.error_amplification import ErrorAmplificationProbe
from vectrava.dow.probes.model_substitution import ModelSubstitutionProbe
from vectrava.dow.probes.output_padding import OutputPaddingProbe
from vectrava.dow.probes.rate_limit_bypass import RateLimitBypassProbe
from vectrava.dow.probes.token_amplification import TokenAmplificationProbe

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()
Handler = Callable[[httpx.Request], httpx.Response]

_PINNED_MODEL = "gpt-5.4-nano"


@pytest.fixture(autouse=True)
def _registry() -> Iterator[None]:
    registry.clear()
    register(TokenAmplificationProbe)
    register(OutputPaddingProbe)
    register(ModelSubstitutionProbe)
    register(ErrorAmplificationProbe)
    register(RateLimitBypassProbe)
    yield
    registry.clear()


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> None:
    real_client = httpx.Client  # capture before patching to avoid recursion

    def factory(*args: object, **kwargs: object) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "Client", factory)


def _invoke(scope: Path, out: Path, fmt: str = "sarif", only: str = "token_amplification") -> Any:
    return runner.invoke(
        app,
        [
            "scan",
            "dow",
            "--scope",
            str(scope),
            "--target",
            "https://example.test",
            "--api-key-env",
            "VECTRAVA_TEST_KEY",
            "--model",
            _PINNED_MODEL,
            "--only",
            only,
            "--yes",
            "--format",
            fmt,
            "--output",
            str(out),
        ],
    )


def test_clean_scan_emits_zero_finding_sarif(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
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
    assert run["tool"]["driver"]["rules"] == []
    assert len(run["artifacts"]) == 0
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["exitCode"] == 0


def test_findings_scan_emits_results_sarif(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"finish_reason": "length"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 500, "total_tokens": 510},
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out)

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    results = run["results"]
    assert len(results) == 5
    assert all(r["ruleId"] == "token_amplification" for r in results)
    assert all(r["ruleIndex"] == 0 for r in results)
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["artifacts"]) == 1
    assert all(
        r["locations"][0]["physicalLocation"]["artifactLocation"]["index"] == 0 for r in results
    )
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["exitCode"] == 1


def test_rate_limit_bypass_succeeds_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        # Every burst request served with 200 and no 429: rate limit absent.
        return httpx.Response(200, json={"ok": True})

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="rate_limit_bypass")

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert len(run["results"]) >= 1
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "rate_limit_bypass" in rule_ids
    assert all(r["ruleId"] == "rate_limit_bypass" for r in run["results"])


def test_probe_failure_emits_invocation_unsuccessful_sarif(
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


def test_clean_scan_emits_zero_finding_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.json"
    result = _invoke(valid_scope_file, out, "json")

    assert result.exit_code == 0
    assert out.exists()
    report: Any = json.loads(out.read_text(encoding="utf-8"))
    assert report["findings"] == []
    assert report["execution_successful"] is True
    assert report["exit_code"] == 0


def test_findings_scan_emits_results_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"finish_reason": "length"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 500, "total_tokens": 510},
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.json"
    result = _invoke(valid_scope_file, out, "json")

    assert result.exit_code == 1
    report: Any = json.loads(out.read_text(encoding="utf-8"))
    findings = report["findings"]
    assert len(findings) == 5
    assert all(f["rule_id"] == "token_amplification" for f in findings)
    assert all(f["probe"] == "dow.token_amplification" for f in findings)
    assert all(f["level"] == "medium" for f in findings)
    assert report["execution_successful"] is True
    assert report["exit_code"] == 1


def test_probe_failure_emits_unsuccessful_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.json"
    result = _invoke(valid_scope_file, out, "json")

    assert result.exit_code == 2
    report: Any = json.loads(out.read_text(encoding="utf-8"))
    assert report["findings"] == []
    assert report["execution_successful"] is False
    assert report["exit_code"] == 2


def test_clean_scan_emits_zero_finding_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.html"
    result = _invoke(valid_scope_file, out, "html")

    assert result.exit_code == 0
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "Scan completed successfully" in text
    assert "No findings reported." in text


def test_findings_scan_emits_results_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"finish_reason": "length"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 500, "total_tokens": 510},
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.html"
    result = _invoke(valid_scope_file, out, "html")

    assert result.exit_code == 1
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "Scan completed successfully" in text
    assert '<table class="findings"' in text
    assert "token_amplification" in text


def test_probe_failure_emits_unsuccessful_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.html"
    result = _invoke(valid_scope_file, out, "html")

    assert result.exit_code == 2
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "Scan failed" in text
    assert '<table class="findings"' not in text


def test_scan_dow_error_amplification_finds_when_usage_in_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        # Only the oversized_prompt shape (operator model, string content) returns
        # usage on its rejection; the other shapes reject without a usage block.
        oversized = body.get("model") == _PINNED_MODEL and isinstance(
            body["messages"][0]["content"], str
        )
        if oversized:
            return httpx.Response(
                400,
                json={
                    "error": {"code": "context_length_exceeded", "type": "invalid_request_error"},
                    "usage": {
                        "prompt_tokens": 90000,
                        "completion_tokens": 0,
                        "total_tokens": 90000,
                    },
                },
            )
        return httpx.Response(400, json={"error": {"message": "rejected"}})

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="error_amplification")

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "error_amplification" in rule_ids
    results = run["results"]
    assert all(r["ruleId"] == "error_amplification" for r in results)
    assert results[0]["properties"]["total_tokens"] == 90000
