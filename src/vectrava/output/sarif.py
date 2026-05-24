"""SARIF v2.1.0 report writer.

Serializes scan findings into a SARIF v2.1.0 log with Standard feature coverage:
a tool driver with rules, results with locations and a properties bag,
invocations, artifacts, and partial fingerprints. Emitted documents validate
against the vendored OASIS SARIF v2.1.0 schema.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from typing import TYPE_CHECKING, cast

import jsonschema
from pydantic import JsonValue

from vectrava import __version__
from vectrava.core import registry
from vectrava.core.result import Finding, Severity

if TYPE_CHECKING:
    from pathlib import Path

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "vectrava"
TOOL_INFORMATION_URI = "https://github.com/sh1vmani/vectrava"
FINGERPRINT_KEY = "vectrava/v1"
_FINGERPRINT_LEN = 16

SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.INFORMATIONAL: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

SECURITY_SEVERITY_NUMERIC: dict[Severity, str] = {
    Severity.INFORMATIONAL: "0.0",
    Severity.LOW: "2.0",
    Severity.MEDIUM: "5.0",
    Severity.HIGH: "7.5",
    Severity.CRITICAL: "9.0",
}


class SarifValidationError(Exception):
    """Raised when an assembled SARIF log fails schema validation."""


def map_level(severity: Severity) -> str:
    """Map a five-level Severity to a SARIF result level."""
    return SEVERITY_TO_LEVEL[severity]


@lru_cache(maxsize=1)
def _schema() -> dict[str, JsonValue]:
    """Load and cache the vendored SARIF v2.1.0 JSON schema."""
    schema_file = resources.files("vectrava.output.schemas").joinpath("sarif-2.1.0.json")
    loaded: dict[str, JsonValue] = json.loads(schema_file.read_text(encoding="utf-8"))
    return loaded


def _validate(log: dict[str, JsonValue]) -> None:
    """Validate a SARIF log against the vendored schema.

    Raises:
        SarifValidationError: if the log does not conform, wrapping the
            underlying jsonschema error and its JSON pointer path.
    """
    try:
        jsonschema.validate(instance=log, schema=_schema())
    except jsonschema.ValidationError as exc:
        path = "/".join(str(part) for part in exc.absolute_path) or "(root)"
        raise SarifValidationError(f"SARIF validation failed at {path}: {exc.message}") from exc


def _pascal_case(name: str) -> str:
    """Turn a snake_case probe name into a PascalCase rule name."""
    return "".join(part.capitalize() for part in name.split("_"))


def _fingerprint(finding: Finding) -> str:
    """Return a stable partial fingerprint for a finding.

    Built from the rule id, the probed target, and the prompt category drawn
    from evidence when present. Volatile signals (ratios, latency) are excluded
    so the fingerprint is stable across scans.
    """
    category = finding.evidence.get("prompt_category", "")
    if not isinstance(category, str):
        category = ""
    raw = f"{finding.rule_id}|{finding.target}|{category}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:_FINGERPRINT_LEN]


def _build_artifacts(findings: list[Finding]) -> tuple[list[JsonValue], dict[str, int]]:
    """Deduplicate finding targets into a sorted artifacts array.

    Returns the artifacts array and a map from target URI to its array index.
    """
    uris = sorted({finding.target for finding in findings})
    artifacts: list[JsonValue] = [{"location": {"uri": uri}} for uri in uris]
    index = {uri: position for position, uri in enumerate(uris)}
    return artifacts, index


def _rule_entry(rule_id: str, fallback_level: Severity) -> dict[str, JsonValue]:
    """Assemble one tool.driver.rules entry.

    Reads metadata from the registered Probe subclass. For an unregistered rule
    id, synthesizes a minimal entry from the rule id and a fallback level.
    """
    try:
        probe_cls = registry.get(rule_id)
    except KeyError:
        return {
            "id": rule_id,
            "defaultConfiguration": {"level": map_level(fallback_level)},
        }
    return {
        "id": probe_cls.name,
        "name": _pascal_case(probe_cls.name),
        "shortDescription": {"text": probe_cls.description},
        "defaultConfiguration": {"level": map_level(probe_cls.baseline_severity)},
        "properties": {
            "tags": cast("list[JsonValue]", list(probe_cls.tags)),
            "security-severity": SECURITY_SEVERITY_NUMERIC[probe_cls.baseline_severity],
        },
    }


def _build_rules(findings: list[Finding]) -> tuple[list[JsonValue], dict[str, int]]:
    """Assemble tool.driver.rules from the distinct rule ids in the findings.

    Returns the rules array and a map from rule id to its array index.
    """
    rule_ids = sorted({finding.rule_id for finding in findings})
    fallback_level = {finding.rule_id: finding.level for finding in findings}
    rules: list[JsonValue] = []
    index: dict[str, int] = {}
    for position, rule_id in enumerate(rule_ids):
        rules.append(_rule_entry(rule_id, fallback_level[rule_id]))
        index[rule_id] = position
    return rules, index


def _build_result(
    finding: Finding,
    uri_to_index: dict[str, int],
    rule_id_to_index: dict[str, int],
) -> dict[str, JsonValue]:
    """Assemble a single SARIF result from a finding."""
    properties: dict[str, JsonValue] = dict(finding.evidence)
    properties["severity"] = finding.level.name
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_id_to_index[finding.rule_id],
        "level": map_level(finding.level),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.target,
                        "index": uri_to_index[finding.target],
                    }
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: _fingerprint(finding)},
        "properties": properties,
    }


def _iso_z(moment: datetime) -> str:
    """Return an ISO 8601 timestamp with a Z suffix for a UTC-aware datetime."""
    return moment.isoformat().replace("+00:00", "Z")


def build_sarif_log(
    findings: list[Finding],
    *,
    tool_version: str = __version__,
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
    arguments: list[str] | None = None,
    execution_successful: bool = True,
    exit_code: int | None = None,
) -> dict[str, JsonValue]:
    """Assemble a SARIF v2.1.0 log document. Pure: no IO, no validation.

    Args:
        findings: Scan findings to serialize.
        tool_version: Version reported in tool.driver.version.
        started_at: Scan start; emitted as startTimeUtc when provided.
        ended_at: Scan end; defaults to the current UTC instant.
        arguments: Invocation arguments; omitted entirely when None.
        execution_successful: Whether the scan completed without error.
        exit_code: Process exit code; emitted when provided.

    Returns:
        A SARIF log as a JSON-serializable dict.
    """
    artifacts, uri_to_index = _build_artifacts(findings)
    rules, rule_id_to_index = _build_rules(findings)
    results: list[JsonValue] = [
        _build_result(finding, uri_to_index, rule_id_to_index) for finding in findings
    ]

    invocation: dict[str, JsonValue] = {"executionSuccessful": execution_successful}
    if exit_code is not None:
        invocation["exitCode"] = exit_code
    if started_at is not None:
        invocation["startTimeUtc"] = _iso_z(started_at)
    invocation["endTimeUtc"] = _iso_z(ended_at if ended_at is not None else datetime.now(UTC))
    if arguments is not None:
        invocation["arguments"] = cast("list[JsonValue]", list(arguments))

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "artifacts": artifacts,
                "results": results,
            }
        ],
    }


def write_sarif(
    findings: list[Finding],
    output_path: Path,
    *,
    started_at: datetime | None = None,
    execution_successful: bool = True,
    exit_code: int | None = None,
    arguments: list[str] | None = None,
    validate: bool = True,
) -> None:
    """Build, validate, and write a SARIF v2.1.0 log to disk.

    Validation runs before any write, so a non-conformant log raises and leaves
    no file behind.

    Raises:
        SarifValidationError: if validation is enabled and the log does not
            conform to the vendored schema.
    """
    log = build_sarif_log(
        findings,
        started_at=started_at,
        ended_at=None,
        arguments=arguments,
        execution_successful=execution_successful,
        exit_code=exit_code,
    )
    if validate:
        _validate(log)
    output_path.write_text(json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8")
