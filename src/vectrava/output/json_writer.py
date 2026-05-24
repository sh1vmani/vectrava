"""JSON report writer."""

from __future__ import annotations

from pathlib import Path

Finding = dict[str, object]


def write_json(findings: list[Finding], output_path: Path) -> None:
    """Write findings as a JSON document.

    Args:
        findings: Scan findings to serialize.
        output_path: Destination file path.

    Raises:
        NotImplementedError: serialization is not implemented yet.
    """
    raise NotImplementedError("JSON output is not implemented yet")
