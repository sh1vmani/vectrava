"""Tests for the JSON output writer."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from vectrava.core.result import Finding, Severity
from vectrava.output.json_writer import build_json_report, write_json

if TYPE_CHECKING:
    from pathlib import Path

_STARTED = datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC)


def _finding(
    *,
    rule_id: str = "token_amplification",
    probe: str = "dow.token_amplification",
    level: Severity = Severity.MEDIUM,
    message: str = "output/input token ratio 50.0x",
    target: str = "https://api.example.test/v1/chat/completions",
) -> Finding:
    return Finding(rule_id=rule_id, probe=probe, level=level, message=message, target=target)


def _report(
    findings: list[Finding],
    *,
    execution_successful: bool = True,
    exit_code: int = 0,
    arguments: list[str] | None = None,
) -> Any:
    return build_json_report(
        findings,
        started_at=_STARTED,
        execution_successful=execution_successful,
        exit_code=exit_code,
        arguments=arguments if arguments is not None else ["scan", "dow"],
    )


def test_build_json_report_envelope_shape() -> None:
    report = _report([_finding()])
    assert set(report) == {
        "schema_version",
        "started_at",
        "execution_successful",
        "exit_code",
        "arguments",
        "findings",
    }
    assert isinstance(report["schema_version"], str)
    assert isinstance(report["started_at"], str)
    assert isinstance(report["execution_successful"], bool)
    assert isinstance(report["exit_code"], int)
    assert isinstance(report["arguments"], list)
    assert isinstance(report["findings"], list)


def test_build_json_report_findings_round_trip() -> None:
    finding = _finding(
        rule_id="output_padding",
        probe="dow.output_padding",
        level=Severity.LOW,
        message="padded answer",
        target="https://t.test/v1/chat/completions",
    )
    report = _report([finding])
    dumped = report["findings"]
    assert len(dumped) == 1
    restored = Finding.model_validate(dumped[0])
    assert restored.rule_id == finding.rule_id
    assert restored.probe == finding.probe
    assert restored.level == finding.level
    assert restored.message == finding.message
    assert restored.target == finding.target


def test_build_json_report_empty_findings() -> None:
    report = _report([], execution_successful=False, exit_code=2)
    assert report["findings"] == []
    assert report["execution_successful"] is False


def test_build_json_report_schema_version_is_string() -> None:
    report = _report([])
    assert report["schema_version"] == "1"
    assert isinstance(report["schema_version"], str)


def test_write_json_writes_utf8_with_trailing_newline(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    write_json(
        [_finding()],
        out,
        started_at=_STARTED,
        execution_successful=True,
        exit_code=1,
        arguments=["scan", "dow"],
    )
    text = out.read_text(encoding="utf-8")
    assert text.endswith("\n")
    data = json.loads(text)
    assert data["exit_code"] == 1


def test_write_json_preserves_key_order(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    write_json(
        [_finding()],
        out,
        started_at=_STARTED,
        execution_successful=True,
        exit_code=0,
        arguments=[],
    )
    text = out.read_text(encoding="utf-8")
    pairs = json.loads(text, object_pairs_hook=list)
    assert pairs[0][0] == "schema_version"
