"""SARIF v2.1.0 report writer."""

from __future__ import annotations

from pathlib import Path

Finding = dict[str, object]


def write_sarif(findings: list[Finding], output_path: Path) -> None:
    """Write findings as a SARIF v2.1.0 log.

    Args:
        findings: Scan findings to serialize.
        output_path: Destination file path.

    Raises:
        NotImplementedError: serialization is not implemented yet.
    """
    raise NotImplementedError("SARIF output is not implemented yet")
