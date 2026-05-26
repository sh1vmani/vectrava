"""HTML report writer.

Renders a self-contained HTML document: inline CSS only, no JavaScript, no
external assets, no remote fonts or stylesheets. Every interpolation of probe
or target data passes through _h before it reaches the output.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from vectrava.output.sarif import map_level

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from vectrava.core.result import Finding

_STYLE = """<style>
:root { color-scheme: light; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica,
    Arial, sans-serif;
  margin: 2rem; color: #1b1b1b; line-height: 1.5;
}
h1 { font-size: 1.4rem; margin: 0 0 0.2rem; }
.subtitle { color: #555; margin: 0 0 1.5rem; }
table.meta { border-collapse: collapse; margin-bottom: 1.5rem; }
table.meta th { text-align: left; padding: 0.15rem 1rem 0.15rem 0; color: #555;
  font-weight: 600; vertical-align: top; }
table.meta td { padding: 0.15rem 0; font-family: ui-monospace, Consolas, monospace; }
.banner { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1.5rem;
  font-weight: 600; }
.banner-success { background: #e6f4ea; color: #1e6b34; border: 1px solid #b7dfc4; }
.banner-failure { background: #fce8e6; color: #a61b1b; border: 1px solid #f3b7b2; }
table.findings { border-collapse: collapse; width: 100%; }
table.findings th, table.findings td { border: 1px solid #ddd; padding: 0.4rem 0.6rem;
  text-align: left; vertical-align: top; }
table.findings th { background: #f3f3f3; }
td.sev-error { background: #fce8e6; }
td.sev-warning { background: #fef7e0; }
td.sev-note { background: #e8f0fe; }
.empty { color: #555; font-style: italic; }
footer { margin-top: 2rem; color: #777; font-size: 0.85rem;
  border-top: 1px solid #eee; padding-top: 0.75rem; }
</style>"""


def _h(s: str) -> str:
    """Escape a string for safe HTML interpolation, quote characters included."""
    return html.escape(s, quote=True)


def _iso_z(moment: datetime) -> str:
    """Return an ISO 8601 timestamp with a Z suffix, normalizing to UTC."""
    aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")


def build_html_report(
    findings: Sequence[Finding],
    *,
    started_at: datetime,
    target: str,
    execution_successful: bool,
    exit_code: int,
    arguments: Sequence[str],
) -> str:
    """Render findings and run metadata as a self-contained HTML document.

    The returned string carries no trailing newline; write_html appends one.
    All probe and target data is escaped through _h before interpolation. No
    JavaScript and no external assets are emitted.

    Args:
        findings: Scan findings to render.
        started_at: Scan start timestamp.
        target: The scan target URL, rendered in the metadata block.
        execution_successful: Whether the scan completed without error.
        exit_code: Process exit code, mirroring SARIF invocation semantics.
        arguments: Invocation arguments. Accepted to match the writer interface;
            not rendered in the document body.

    Returns:
        A complete HTML document as a single string.
    """
    del arguments  # part of the writer interface; not surfaced in the report

    generated_at = datetime.now(UTC)
    start = started_at if started_at.tzinfo is not None else started_at.replace(tzinfo=UTC)
    elapsed = (generated_at - start).total_seconds()
    duration = f"{elapsed:.3f}s" if elapsed >= 0 else "n/a"
    target_display = _h(target)

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>vectrava scan report</title>",
        _STYLE,
        "</head>",
        "<body>",
        "<h1>vectrava</h1>",
        '<p class="subtitle">Scan report</p>',
        '<table class="meta">',
        f"<tr><th>Target</th><td>{target_display}</td></tr>",
        f"<tr><th>Started</th><td>{_h(_iso_z(start))}</td></tr>",
        f"<tr><th>Finished</th><td>{_h(_iso_z(generated_at))}</td></tr>",
        f"<tr><th>Duration</th><td>{_h(duration)}</td></tr>",
        "</table>",
    ]

    if execution_successful:
        parts.append('<div class="banner banner-success">Scan completed successfully</div>')
    else:
        parts.append(
            f'<div class="banner banner-failure">Scan failed (exit code {exit_code})</div>'
        )

    if execution_successful and findings:
        parts.append('<table class="findings">')
        parts.append(
            "<tr><th>Severity</th><th>Rule ID</th><th>Probe</th>"
            "<th>Message</th><th>Location</th></tr>"
        )
        for finding in findings:
            level_class = f"sev-{map_level(finding.level)}"
            parts.append(
                f'<tr><td class="{level_class}">{_h(finding.level.value)}</td>'
                f"<td>{_h(finding.rule_id)}</td>"
                f"<td>{_h(finding.probe)}</td>"
                f"<td>{_h(finding.message)}</td>"
                f"<td>{_h(finding.target)}</td></tr>"
            )
        parts.append("</table>")
    elif execution_successful:
        parts.append('<p class="empty">No findings reported.</p>')

    parts.append(f"<footer>Report generated at {_h(_iso_z(generated_at))}</footer>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


def write_html(
    findings: Sequence[Finding],
    path: Path,
    *,
    started_at: datetime,
    target: str,
    execution_successful: bool,
    exit_code: int,
    arguments: Sequence[str],
) -> None:
    """Build the HTML report and write it to disk as utf-8 with a trailing newline."""
    document = build_html_report(
        findings,
        started_at=started_at,
        target=target,
        execution_successful=execution_successful,
        exit_code=exit_code,
        arguments=arguments,
    )
    path.write_text(document + "\n", encoding="utf-8")
