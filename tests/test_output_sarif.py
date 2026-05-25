"""Tests for the SARIF v2.1.0 writer.

Every case is offline: no network, no environment reads, and file IO only under
tmp_path. Assembled logs are validated against the vendored schema.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import JsonValue

from vectrava.core import registry
from vectrava.core.registry import register
from vectrava.core.result import Finding, Severity
from vectrava.dow.probes.token_amplification import TokenAmplificationProbe
from vectrava.output.sarif import (
    SarifValidationError,
    _validate,
    build_sarif_log,
    write_sarif,
)

if TYPE_CHECKING:
    from pathlib import Path

_TARGET = "https://api.example.test/v1/chat/completions"


@pytest.fixture(autouse=True)
def _registry() -> Iterator[None]:
    registry.clear()
    register(TokenAmplificationProbe)
    yield
    registry.clear()


def _finding(
    *,
    rule_id: str = "token_amplification",
    target: str = _TARGET,
    level: Severity = Severity.MEDIUM,
    category: str = "enumeration",
    evidence: dict[str, JsonValue] | None = None,
) -> Finding:
    ev: dict[str, JsonValue] = (
        evidence
        if evidence is not None
        else {"prompt_category": category, "amplification_factor": 50.0}
    )
    return Finding(
        rule_id=rule_id,
        probe=f"dow.{rule_id}",
        level=level,
        message="output/input token ratio 50.0x meets threshold 15.0",
        target=target,
        evidence=ev,
    )


def test_zero_findings_produces_valid_log() -> None:
    log: Any = build_sarif_log([])
    _validate(log)
    run = log["runs"][0]
    assert run["results"] == []
    assert len(run["invocations"]) == 1
    assert run["invocations"][0]["executionSuccessful"] is True


def test_single_finding_includes_rule_and_artifact() -> None:
    log: Any = build_sarif_log([_finding()])
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "token_amplification"
    assert len(run["artifacts"]) == 1
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleIndex"] == 0
    location = result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location["index"] == 0
    assert location["uri"] == _TARGET
    _validate(log)


def test_severity_to_level_mapping() -> None:
    expected = {
        Severity.INFORMATIONAL: "note",
        Severity.LOW: "note",
        Severity.MEDIUM: "warning",
        Severity.HIGH: "error",
        Severity.CRITICAL: "error",
    }
    for severity, level in expected.items():
        log: Any = build_sarif_log([_finding(level=severity)])
        assert log["runs"][0]["results"][0]["level"] == level


def test_partial_fingerprints_are_stable() -> None:
    finding = _finding(category="enumeration")
    first: Any = build_sarif_log([finding])
    second: Any = build_sarif_log([finding])
    fp_first = first["runs"][0]["results"][0]["partialFingerprints"]["vectrava/v1"]
    fp_second = second["runs"][0]["results"][0]["partialFingerprints"]["vectrava/v1"]
    assert fp_first == fp_second
    assert len(fp_first) == 16
    int(fp_first, 16)  # raises if not hex

    other: Any = build_sarif_log([_finding(category="bounded_repetition")])
    fp_other = other["runs"][0]["results"][0]["partialFingerprints"]["vectrava/v1"]
    assert fp_other != fp_first


def test_arguments_omitted_when_none() -> None:
    log: Any = build_sarif_log([], arguments=None)
    invocation = log["runs"][0]["invocations"][0]
    assert "arguments" not in invocation


def test_arguments_emitted_when_provided() -> None:
    args = ["scan", "dow", "--api-key-env", "[REDACTED]"]
    log: Any = build_sarif_log([], arguments=args)
    invocation = log["runs"][0]["invocations"][0]
    assert invocation["arguments"] == args


def test_dedup_artifacts() -> None:
    target_b = "https://b.example.test/v1/chat/completions"
    target_a = "https://a.example.test/v1/chat/completions"
    findings = [
        _finding(target=target_b),
        _finding(target=target_b),
        _finding(target=target_a),
    ]
    log: Any = build_sarif_log(findings)
    artifacts = log["runs"][0]["artifacts"]
    assert len(artifacts) == 2
    uris = [artifact["location"]["uri"] for artifact in artifacts]
    assert uris == sorted([target_b, target_a])


def test_unregistered_rule_id_synthesizes_fallback_rule() -> None:
    finding = _finding(rule_id="ghost_probe", level=Severity.HIGH)
    log: Any = build_sarif_log([finding])
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "ghost_probe"
    assert rules[0]["defaultConfiguration"]["level"] == "error"
    _validate(log)


def test_write_sarif_writes_file_and_validates(tmp_path: Path) -> None:
    output = tmp_path / "out.sarif"
    write_sarif([_finding()], output)
    assert output.exists()
    data: Any = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    _validate(data)


def test_write_sarif_emits_trailing_newline(tmp_path: Path) -> None:
    output = tmp_path / "out.sarif"
    write_sarif([_finding()], output)
    raw = output.read_bytes()
    assert raw.endswith(b"\n")
    assert not raw.endswith(b"\n\n")
    assert not raw.startswith(b"\xef\xbb\xbf")
    text = output.read_text(encoding="utf-8")
    assert json.loads(text)["version"] == "2.1.0"


def test_write_sarif_validation_failure_raises_and_does_not_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "bad.sarif"
    monkeypatch.setattr(
        "vectrava.output.sarif._schema",
        lambda: {"type": "object", "required": ["__definitely_missing__"]},
    )
    with pytest.raises(SarifValidationError):
        write_sarif([_finding()], output)
    assert not output.exists()


def test_security_severity_numeric_emitted_on_rule_properties() -> None:
    log: Any = build_sarif_log([_finding(level=Severity.MEDIUM)])
    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "5.0"


def test_evidence_preserved_in_result_properties() -> None:
    evidence: dict[str, JsonValue] = {
        "prompt_category": "enumeration",
        "amplification_factor": 50.0,
        "latency_ms": 12.3,
    }
    log: Any = build_sarif_log([_finding(evidence=evidence, level=Severity.MEDIUM)])
    properties = log["runs"][0]["results"][0]["properties"]
    assert properties["amplification_factor"] == 50.0
    assert properties["prompt_category"] == "enumeration"
    assert properties["severity"] == "MEDIUM"
