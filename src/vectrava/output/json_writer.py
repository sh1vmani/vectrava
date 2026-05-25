"""JSON output writer.

Emits a dict-typed report whose schema is the Finding Pydantic model verbatim
under the 'findings' key, plus run-level metadata. schema_version is a string to
allow non-integer revisions later.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from pathlib import Path

    from pydantic import JsonValue

    from vectrava.core.result import Finding


def build_json_report(
    findings: Sequence[Finding],
    *,
    started_at: datetime,
    execution_successful: bool,
    exit_code: int,
    arguments: Sequence[str],
) -> dict[str, JsonValue]:
    """Assemble the JSON report envelope. Pure: no IO.

    Args:
        findings: Scan findings to serialize.
        started_at: Scan start timestamp.
        execution_successful: Whether the scan completed without error.
        exit_code: Process exit code.
        arguments: Invocation arguments.

    Returns:
        The report as a JSON-serializable dict.
    """
    findings_json: list[JsonValue] = [finding.model_dump(mode="json") for finding in findings]
    report: dict[str, JsonValue] = {
        "schema_version": "1",
        "started_at": started_at.isoformat(),
        "execution_successful": execution_successful,
        "exit_code": exit_code,
        "arguments": cast("list[JsonValue]", list(arguments)),
        "findings": findings_json,
    }
    return report


def write_json(
    findings: Sequence[Finding],
    path: Path,
    *,
    started_at: datetime,
    execution_successful: bool,
    exit_code: int,
    arguments: Sequence[str],
) -> None:
    """Build the JSON report and write it to disk with a trailing newline."""
    report = build_json_report(
        findings,
        started_at=started_at,
        execution_successful=execution_successful,
        exit_code=exit_code,
        arguments=arguments,
    )
    path.write_text(
        json.dumps(report, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
