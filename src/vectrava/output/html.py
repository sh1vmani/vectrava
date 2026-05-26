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


def _render_evidence_pair(key: str, value: JsonValue) -> str:
    """Render one evidence key/value as a pair div, dispatching on the value type."""
    key_html = _h(key)
    if isinstance(value, bool):
        value_html = _h(str(value))
    elif value is None:
        value_html = "(not reported)"
    elif isinstance(value, str):
        value_html = _h(value)
    elif isinstance(value, (int, float)):
        value_html = _h(str(value))
    elif isinstance(value, dict):
        rows = "".join(
            f"<tr><td>{_h(str(k))}</td><td>{_h(str(v))}</td></tr>" for k, v in value.items()
        )
        return (
            f'<div class="evidence-pair"><span class="evidence-key">{key_html}</span>'
            f'<table class="evidence-table">{rows}</table></div>'
        )
    else:
        # Lists other than "turns" (already handled) and any nested shape: no such
        # evidence exists today, so this is a defensive fallback, not a real path.
        value_html = "(complex value)"
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
