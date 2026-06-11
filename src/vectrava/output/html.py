"""HTML report writer.

Renders a self-contained HTML document: inline CSS only, no JavaScript, no
external assets, no remote fonts or stylesheets. Every interpolation of probe
or target data passes through _h before it reaches the output.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from vectrava.core.result import Severity
from vectrava.output.sarif import map_level

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from pydantic import JsonValue

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
.banner-finding-error { background: #fce8e6; color: #a61b1b; border: 1px solid #f3b7b2; }
.banner-finding-warning { background: #fef7e0; color: #7a5e00; border: 1px solid #f0e3a8; }
.banner-finding-note { background: #e8f0fe; color: #1a3a6b; border: 1px solid #c2d5f5; }
table.findings { border-collapse: collapse; width: 100%; }
table.findings th, table.findings td { border: 1px solid #ddd; padding: 0.4rem 0.6rem;
  text-align: left; vertical-align: top; }
table.findings th { background: #f3f3f3; }
td.sev-error { background: #fce8e6; }
td.sev-warning { background: #fef7e0; }
td.sev-note { background: #e8f0fe; }
.empty { color: #555; font-style: italic; }
.conversation { display: flex; flex-direction: column; gap: 0.5rem; margin: 0.5rem 0 0.25rem; }
.turn { border-left: 4px solid #bbb; padding: 0.35rem 0.6rem; background: #fafafa; }
.turn-system { border-left-color: #9aa0a6; background: #f1f3f4; font-style: italic; }
.turn-user { border-left-color: #4285f4; background: #e8f0fe; }
.turn-assistant { border-left-color: #34a853; background: #e6f4ea; }
.role-label { font-weight: 700; text-transform: uppercase; font-size: 0.7rem;
  letter-spacing: 0.05em; color: #555; margin-bottom: 0.2rem; }
.turn-content, .evidence-value { white-space: pre-wrap; word-break: break-word;
  max-height: 20rem; overflow-y: auto; font-family: ui-monospace, Consolas, monospace;
  font-size: 0.85rem; }
.evidence { display: flex; flex-direction: column; gap: 0.3rem; margin: 0.5rem 0 0.25rem; }
.evidence-pair { display: flex; gap: 0.6rem; align-items: baseline; }
.evidence-key { flex: 0 0 12rem; font-weight: 700; font-family: ui-monospace, Consolas,
  monospace; font-size: 0.75rem; color: #555; word-break: break-word; }
.evidence-table { border-collapse: collapse; font-size: 0.8rem; }
.evidence-table td { border: 1px solid #ddd; padding: 0.1rem 0.4rem;
  font-family: ui-monospace, Consolas, monospace; }
.evidence-table th { border: 1px solid #ddd; padding: 0.1rem 0.4rem;
  font-family: ui-monospace, Consolas, monospace; text-align: left; background: #f3f3f3; }
footer { margin-top: 2rem; color: #777; font-size: 0.85rem;
  border-top: 1px solid #eee; padding-top: 0.75rem; }
</style>"""

_CONVERSATION_ROLES = frozenset({"system", "user", "assistant"})


def _h(s: str) -> str:
    """Escape a string for safe HTML interpolation, quote characters included."""
    return html.escape(s, quote=True)


def _iso_z(moment: datetime) -> str:
    """Return an ISO 8601 timestamp with a Z suffix, normalizing to UTC."""
    aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _render_conversation(turns: JsonValue) -> str | None:
    """Render an evidence "turns" list as a conversation sub-row, or None.

    Returns None (so the caller emits no extra row) when turns is not a non-empty
    list of dicts each carrying string "role" and "content". When well-formed,
    returns a single colspan'd table row whose cell holds an expandable, default-
    open chat transcript. Role and content are escaped through _h; the per-role
    CSS class is only applied for the known roles, never a value from the data.
    """
    if not isinstance(turns, list) or not turns:
        return None
    blocks: list[str] = []
    for entry in turns:
        if not isinstance(entry, dict):
            return None
        role = entry.get("role")
        content = entry.get("content")
        if not isinstance(role, str) or not isinstance(content, str):
            return None
        turn_class = f"turn turn-{role}" if role in _CONVERSATION_ROLES else "turn"
        blocks.append(
            f'<div class="{turn_class}">'
            f'<div class="role-label">{_h(role)}</div>'
            f'<div class="turn-content">{_h(content)}</div>'
            "</div>"
        )
    body = "".join(blocks)
    # colspan must equal the findings-table column count: Severity, Rule ID, Probe,
    # Message, Location = 5. If a column is added or removed, update this literal.
    return (
        '<tr class="conversation-row"><td colspan="5">'
        f"<details open><summary>Conversation ({len(turns)} turns)</summary>"
        f'<div class="conversation">{body}</div></details>'
        "</td></tr>"
    )


def _format_float(value: float) -> str:
    """Format a float evidence value to trimmed fixed precision.

    Three decimal places, then trailing zeros and any bare trailing dot are
    removed, so 1596.3774909999984 becomes 1596.377, 4.0 becomes 4, and 4.12 is
    unchanged.
    """
    text = f"{value:.3f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _scalar_html(value: JsonValue) -> str:
    """Render a scalar evidence value, with floats passing through _format_float.

    Handles bool, None, float, int, and str. Bool is checked before int because
    bool is an int subclass. Any non-scalar falls back to its str form, so this is
    safe to reuse for dict-cell values.
    """
    if isinstance(value, bool):
        return _h(str(value))
    if value is None:
        return "(not reported)"
    if isinstance(value, float):
        return _h(_format_float(value))
    if isinstance(value, (int, str)):
        return _h(str(value))
    return _h(str(value))


def _scalar_dict_table_html(rows: Sequence[JsonValue]) -> str | None:
    """Render a non-empty list of uniform scalar-valued dicts as a table.

    Returns table HTML when rows is a non-empty list whose entries are all dicts
    that share one key order and carry only scalar values (str, int, float, bool,
    None). Returns None for any other shape, so the caller can fall back to JSON.
    """
    if not rows:
        return None
    first = rows[0]
    if not isinstance(first, dict):
        return None
    headers = list(first.keys())
    if not headers:
        return None
    body_rows: list[str] = []
    for entry in rows:
        if not isinstance(entry, dict) or list(entry.keys()) != headers:
            return None
        cells: list[str] = []
        for key in headers:
            cell = entry[key]
            if not isinstance(cell, (bool, int, float, str)) and cell is not None:
                return None
            cells.append(f"<td>{_scalar_html(cell)}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    head = "".join(f"<th>{_h(str(k))}</th>" for k in headers)
    return f'<table class="evidence-table"><tr>{head}</tr>{"".join(body_rows)}</table>'


def _render_evidence_pair(key: str, value: JsonValue) -> str:
    """Render one evidence key/value as a pair div, dispatching on the value type.

    Scalars render inline, with floats passing through _format_float. A dict renders
    as a small key/value table. A list of uniform scalar-valued dicts renders as a
    table. Any other shape (a ragged or nested list) renders as indented JSON inside
    the value box, so no real evidence is hidden behind a placeholder.
    """
    key_html = _h(key)
    if isinstance(value, dict):
        rows = "".join(
            f"<tr><td>{_h(str(k))}</td><td>{_scalar_html(v)}</td></tr>" for k, v in value.items()
        )
        return (
            f'<div class="evidence-pair"><span class="evidence-key">{key_html}</span>'
            f'<table class="evidence-table">{rows}</table></div>'
        )
    if isinstance(value, list):
        table = _scalar_dict_table_html(value)
        if table is not None:
            return (
                f'<div class="evidence-pair"><span class="evidence-key">{key_html}</span>'
                f"{table}</div>"
            )
        value_html = _h(json.dumps(value, indent=2))
    elif isinstance(value, (bool, int, float, str)) or value is None:
        value_html = _scalar_html(value)
    else:
        value_html = _h(json.dumps(value, indent=2))
    return (
        f'<div class="evidence-pair"><span class="evidence-key">{key_html}</span>'
        f'<span class="evidence-value">{value_html}</span></div>'
    )


def _render_evidence(evidence: Mapping[str, JsonValue]) -> str | None:
    """Render a finding's evidence (every key except "turns") as a sub-row, or None.

    "turns" is rendered separately by _render_conversation; it is skipped here by
    name. Each remaining key becomes a key/value pair (dict values become a small
    inline table); keys and values are escaped through _h. Returns None when there
    are no non-turns keys to show.
    """
    pairs = [_render_evidence_pair(key, value) for key, value in evidence.items() if key != "turns"]
    if not pairs:
        return None
    body = "".join(pairs)
    # colspan must equal the findings-table column count: Severity, Rule ID, Probe,
    # Message, Location = 5. If a column is added or removed, update this literal.
    return (
        '<tr class="evidence-row"><td colspan="5">'
        f"<details open><summary>Evidence ({len(pairs)} fields)</summary>"
        f'<div class="evidence">{body}</div></details>'
        "</td></tr>"
    )


_SEVERITY_DISPLAY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
)


def _findings_banner(findings: Sequence[Finding]) -> str:
    """Build the findings banner: severity-colored by the highest level present.

    Counts findings by Severity and renders a summary highest first, listing only
    levels with a nonzero count. The banner color follows the table's map_level
    bucket of the highest severity present, so the banner and rows share one
    palette.
    """
    counts = Counter(finding.level for finding in findings)
    present = [level for level in _SEVERITY_DISPLAY_ORDER if counts[level]]
    highest = present[0]
    bucket = map_level(highest)
    summary = ", ".join(f"{counts[level]} {level.value}" for level in present)
    return (
        f'<div class="banner banner-finding-{bucket}">Scan completed with findings: {summary}</div>'
    )


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

    if not execution_successful:
        parts.append(
            f'<div class="banner banner-failure">Scan failed (exit code {exit_code})</div>'
        )
    elif findings:
        parts.append(_findings_banner(findings))
    else:
        parts.append('<div class="banner banner-success">Scan completed, no findings</div>')

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
            evidence_row = _render_evidence(finding.evidence)
            if evidence_row is not None:
                parts.append(evidence_row)
            conversation_row = _render_conversation(finding.evidence.get("turns"))
            if conversation_row is not None:
                parts.append(conversation_row)
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
