"""HTML report writer."""

from __future__ import annotations

from pathlib import Path

Finding = dict[str, object]


def write_html(findings: list[Finding], output_path: Path) -> None:
    """Write findings as a self-contained HTML report.

    Args:
        findings: Scan findings to serialize.
        output_path: Destination file path.

    Raises:
        NotImplementedError: serialization is not implemented yet.
    """
    raise NotImplementedError("HTML output is not implemented yet")
