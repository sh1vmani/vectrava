"""Tests for the shared Finding model and Severity scheme."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from pydantic import JsonValue

from vectrava.core.result import Finding, Severity


def test_finding_has_required_fields() -> None:
    finding = Finding(
        rule_id="token-amplification",
        probe="dow.token-amplification",
        level=Severity.HIGH,
        message="amplification observed",
        target="http://localhost:11434/v1/chat",
    )
    assert finding.rule_id == "token-amplification"
    assert finding.probe == "dow.token-amplification"
    assert finding.level is Severity.HIGH
    assert finding.evidence == {}
    assert finding.remediation is None


def test_severity_has_five_levels() -> None:
    assert len(Severity) == 5
    assert {s.value for s in Severity} == {
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    }


def test_finding_serializes_to_json() -> None:
    finding = Finding(
        rule_id="r",
        probe="dow.r",
        level=Severity.LOW,
        message="m",
        target="http://t",
        evidence={"baseline_tokens": 12, "amplified_tokens": 8400},
    )
    data = json.loads(finding.model_dump_json())
    assert data["level"] == "low"
    assert data["evidence"]["amplified_tokens"] == 8400


def test_evidence_accepts_json_compatible_values() -> None:
    evidence: dict[str, JsonValue] = {
        "count": 1,
        "name": "x",
        "list": [1, 2, 3],
        "nested": {"ok": True},
    }
    finding = Finding(
        rule_id="r",
        probe="dow.r",
        level=Severity.MEDIUM,
        message="m",
        target="http://t",
        evidence=evidence,
    )
    assert finding.evidence["nested"] == {"ok": True}
    assert finding.evidence["list"] == [1, 2, 3]


def test_observed_at_defaults_to_utc_now() -> None:
    before = datetime.now(UTC)
    finding = Finding(
        rule_id="r",
        probe="dow.r",
        level=Severity.INFORMATIONAL,
        message="m",
        target="http://t",
    )
    assert finding.observed_at.tzinfo is not None
    assert finding.observed_at >= before
