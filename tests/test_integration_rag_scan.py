"""End-to-end integration test for the rag scan flow.

Drives the full `scan rag` path through the real CLI entry point: argument
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
from vectrava.rag.probes.citation_hijack import CitationHijackProbe
from vectrava.rag.probes.cross_document_injection import CrossDocumentInjectionProbe
from vectrava.rag.probes.cross_source_contradiction import CrossSourceContradictionProbe
from vectrava.rag.probes.prompt_leak_via_retrieval import PromptLeakViaRetrievalProbe
from vectrava.rag.probes.retrieval_permission_leak import RetrievalPermissionLeakProbe

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()
Handler = Callable[[httpx.Request], httpx.Response]

_HEX16 = re.compile(r"[0-9a-f]{16}")


@pytest.fixture(autouse=True)
def _registry() -> Iterator[None]:
    registry.clear()
    register(CrossDocumentInjectionProbe)
    register(CitationHijackProbe)
    register(CrossSourceContradictionProbe)
    register(PromptLeakViaRetrievalProbe)
    register(RetrievalPermissionLeakProbe)
    yield
    registry.clear()


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> None:
    real_client = httpx.Client  # capture before patching to avoid recursion

    def factory(*args: object, **kwargs: object) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "Client", factory)


def _invoke(
    scope: Path, out: Path, fmt: str = "sarif", only: str = "cross_document_injection"
) -> Any:
    return runner.invoke(
        app,
        [
            "scan",
            "rag",
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
                "choices": [{"message": {"content": "Full time staff get 20 vacation days."}}],
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
        content = body["messages"][1]["content"]
        match = _HEX16.search(content)
        token = match.group(0) if match else ""
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": f"Audit token {token}"}}],
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
    assert "cross_document_injection" in rule_ids
    assert all(r["ruleId"] == "cross_document_injection" for r in run["results"])


def test_prompt_leak_via_retrieval_succeeds_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        # The canary rides in the retrieval-template marker in the user message.
        content = body["messages"][1]["content"]
        match = _HEX16.search(content)
        token = match.group(0) if match else ""
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": f"My template marker is {token}"}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="prompt_leak_via_retrieval")

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert len(run["results"]) >= 1
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "prompt_leak_via_retrieval" in rule_ids
    assert all(r["ruleId"] == "prompt_leak_via_retrieval" for r in run["results"])


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


def test_num_sources_flag_plumbs_through_to_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured["user_content"] = body["messages"][1]["content"]
        return httpx.Response(
            200,
            json={"model": "gpt-4o-mini", "choices": [{"message": {"content": "ok"}}]},
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = runner.invoke(
        app,
        [
            "scan",
            "rag",
            "--scope",
            str(valid_scope_file),
            "--target",
            "https://example.test",
            "--api-key-env",
            "VECTRAVA_TEST_KEY",
            "--only",
            "cross_document_injection",
            "--num-sources",
            "5",
            "--format",
            "sarif",
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == 0
    assert captured["user_content"].count('<source id="') == 5


def test_citation_hijack_clean_scan_emits_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "Full time staff get 15 vacation days."}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="citation_hijack")

    assert result.exit_code == 0
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["exitCode"] == 0


def test_citation_hijack_injection_succeeds_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        content = body["messages"][1]["content"]
        match = _HEX16.search(content)
        token = match.group(0) if match else ""
        reply = f"According to source 1, the value is {token}."
        return httpx.Response(
            200,
            json={"model": "gpt-4o-mini", "choices": [{"message": {"content": reply}}]},
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="citation_hijack")

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert len(run["results"]) >= 1
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "citation_hijack" in rule_ids
    assert all(r["ruleId"] == "citation_hijack" for r in run["results"])


def test_citation_hijack_probe_failure_emits_unsuccessful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="citation_hijack")

    assert result.exit_code == 2
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["exitCode"] == 2


def test_cross_source_clean_scan_emits_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "According to the handbook, 15 days."}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="cross_source_contradiction")

    assert result.exit_code == 0
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["exitCode"] == 0


def test_cross_source_succeeds_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        content = body["messages"][1]["content"]
        match = _HEX16.search(content)
        token = match.group(0) if match else ""
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": f"The entitlement is {token} days."}}],
            },
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="cross_source_contradiction")

    assert result.exit_code == 1
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert len(run["results"]) >= 1
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert "cross_source_contradiction" in rule_ids
    assert all(r["ruleId"] == "cross_source_contradiction" for r in run["results"])


def test_cross_source_probe_failure_emits_unsuccessful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="cross_source_contradiction")

    assert result.exit_code == 2
    assert out.exists()
    data: Any = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["exitCode"] == 2


def test_cost_info_line_prints_for_rag_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_scope_file: Path
) -> None:
    # The two-tier cost line is emitted in the shared _run_scan, so it appears for
    # rag scans identically to dow; cross_document_injection (1800 tokens) is below
    # threshold.
    monkeypatch.setenv("VECTRAVA_TEST_KEY", "dummy-value")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"model": "gpt-4o-mini", "choices": [{"message": {"content": "benign"}}]},
        )

    _patch_client(monkeypatch, handler)
    out = tmp_path / "out.sarif"
    result = _invoke(valid_scope_file, out, only="cross_document_injection")

    assert result.exit_code == 0
    assert "Estimated cost: 1,800 tokens (~$0.02, placeholder rate)" in result.stdout
