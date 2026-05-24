"""Finding data model and severity scheme shared across all probe modules.

A Finding is the unit every probe emits and every output writer consumes. The
severity scheme maps to SARIF v2.1.0 as follows. SARIF uses a coarse `level`
({none, note, warning, error}); GitHub code scanning reads a finer numeric
`security-severity` property in the range 0.0 to 10.0. Each Severity maps to
both:

    Severity        SARIF level    security-severity
    INFORMATIONAL   note           0.0
    LOW             note           2.0
    MEDIUM          warning        5.0
    HIGH            error          7.5
    CRITICAL        error          9.0

The output writers in `vectrava.output` perform this mapping when serializing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, JsonValue


class Severity(StrEnum):
    """Security severity of a finding, ordered lowest to highest."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A single result emitted by a probe.

    Root fields are universal across the dow, ipi, and rag modules. Module or
    probe specific signals (for example a cost amplification factor) belong in
    `evidence`, never as root fields, so the model stays clean for every module.

    Attributes:
        rule_id: Stable identifier for the rule that produced the finding, equal
            to the probe name. Maps to SARIF result.ruleId.
        probe: Fully qualified probe identifier, "<module>.<name>".
        level: Security severity. Maps to SARIF level plus security-severity.
        message: Human readable description. Maps to SARIF result.message.text.
        target: The endpoint URL that was probed.
        evidence: Structured proof for the finding. Serialized into SARIF
            result.properties. Holds the module specific signals.
        remediation: Optional guidance on how to fix or mitigate.
        observed_at: UTC timestamp of when the finding was produced.
    """

    rule_id: str
    probe: str
    level: Severity
    message: str
    target: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    remediation: str | None = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
