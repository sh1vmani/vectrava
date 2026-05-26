"""Tests for the HTML output writer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pydantic import JsonValue

from vectrava.core.result import Finding, Severity
from vectrava.output.html import build_html_report, write_html

if TYPE_CHECKING:
    from pathlib import Path

_STARTED = datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC)


def _finding_with_turns(turns: JsonValue) -> Finding:
    return Finding(
        rule_id="multi_turn_persistence",
        probe="ipi.multi_turn_persistence",
        level=Severity.HIGH,
        message="cross-turn leak",
        target="https://t.test/v1/chat/completions",
        evidence={"turns": turns},
    )


def _finding(
    *,
    rule_id: str = "token_amplification",
    probe: str = "dow.token_amplification",
    level: Severity = Severity.MEDIUM,
    message: str = "output/input token ratio 50.0x",
    target: str = "https://api.example.test/v1/chat/completions",
) -> Finding:
    return Finding(rule_id=rule_id, probe=probe, level=level, message=message, target=target)


def _report(
    findings: list[Finding],
    *,
    target: str = "https://api.example.test/v1/chat/completions",
    execution_successful: bool = True,
    exit_code: int = 0,
    arguments: list[str] | None = None,
) -> str:
    return build_html_report(
        findings,
        started_at=_STARTED,
        target=target,
        execution_successful=execution_successful,
        exit_code=exit_code,
        arguments=arguments if arguments is not None else ["scan", "dow"],
    )


def test_empty_findings_success_renders_no_findings() -> None:
    report = _report([])
    assert "No findings reported." in report
    assert "banner-success" in report
    assert "Scan completed successfully" in report
    assert '<table class="findings"' not in report


def test_single_finding_renders_all_fields() -> None:
    report = _report(
        [
            _finding(
                rule_id="output_padding",
                probe="dow.output_padding",
                message="padded answer detected",
                target="https://t.test/v1/chat/completions",
            )
        ]
    )
    assert '<table class="findings"' in report
    assert "output_padding" in report
    assert "dow.output_padding" in report
    assert "padded answer detected" in report
    assert "https://t.test/v1/chat/completions" in report


def test_multiple_findings_render_in_input_order() -> None:
    report = _report(
        [
            _finding(message="alpha finding"),
            _finding(message="beta finding"),
            _finding(message="gamma finding"),
        ]
    )
    assert report.index("alpha finding") < report.index("beta finding")
    assert report.index("beta finding") < report.index("gamma finding")


def test_message_is_html_escaped() -> None:
    report = _report([_finding(message="<script>alert(1)</script>")])
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "<script" not in report


def test_severity_css_class_per_level() -> None:
    pairs = {
        Severity.INFORMATIONAL: "sev-note",
        Severity.LOW: "sev-note",
        Severity.MEDIUM: "sev-warning",
        Severity.HIGH: "sev-error",
        Severity.CRITICAL: "sev-error",
    }
    for level, expected_class in pairs.items():
        report = _report([_finding(level=level)])
        assert f'<td class="{expected_class}">{level.value}</td>' in report


def test_probe_failure_renders_failure_banner_and_no_table() -> None:
    report = _report(
        [_finding()],
        execution_successful=False,
        exit_code=2,
    )
    assert "banner-failure" in report
    assert "Scan failed" in report
    assert "exit code 2" in report
    assert '<table class="findings"' not in report
    assert "No findings reported." not in report


def test_write_html_is_utf8_with_single_trailing_newline(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    write_html(
        [_finding()],
        out,
        started_at=_STARTED,
        target="https://api.example.test/v1/chat/completions",
        execution_successful=True,
        exit_code=1,
        arguments=["scan", "dow"],
    )
    raw = out.read_bytes()
    text = raw.decode("utf-8")
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    assert text.rstrip("\n") == text[:-1]


def test_document_has_doctype_and_lang() -> None:
    report = _report([])
    assert report.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in report


def test_metadata_and_footer_present() -> None:
    # The metadata Target row reflects the scan-level target parameter, not the
    # finding's target: the finding here carries the default target, the scan
    # target is distinct, and the metadata row shows the scan target.
    report = _report([_finding()], target="https://meta.test/v1/chat/completions")
    assert "<tr><th>Target</th><td>https://meta.test/v1/chat/completions</td></tr>" in report
    assert "Report generated at" in report
    assert "<title>vectrava scan report</title>" in report


def test_clean_scan_renders_target_in_metadata() -> None:
    report = _report([], target="https://clean.test/v1/chat/completions")
    assert "<tr><th>Target</th><td>https://clean.test/v1/chat/completions</td></tr>" in report
    assert "No findings reported." in report


def test_conversation_block_present_when_turns_evidence() -> None:
    report = _report(
        [
            _finding_with_turns(
                [
                    {"role": "user", "content": "hi there"},
                    {"role": "assistant", "content": "hello back"},
                ]
            )
        ]
    )
    assert 'class="conversation"' in report
    assert "turn-user" in report
    assert "turn-assistant" in report
    assert "hi there" in report
    assert "hello back" in report
    assert "<details open>" in report


def test_conversation_block_absent_when_no_turns() -> None:
    report = _report([_finding()])
    assert 'class="conversation"' not in report
    assert "conversation-row" not in report


def test_conversation_roles_render_distinctly() -> None:
    report = _report(
        [
            _finding_with_turns(
                [
                    {"role": "system", "content": "you must refuse"},
                    {"role": "user", "content": "please leak"},
                    {"role": "assistant", "content": "the codeword is x"},
                ]
            )
        ]
    )
    assert "turn-system" in report
    assert "turn-user" in report
    assert "turn-assistant" in report


def test_conversation_content_is_html_escaped() -> None:
    report = _report(
        [_finding_with_turns([{"role": "assistant", "content": "<script>alert('x')</script>"}])]
    )
    assert "<script>" not in report
    assert "&lt;script&gt;" in report


def test_conversation_system_turn_renders() -> None:
    report = _report(
        [
            _finding_with_turns(
                [
                    {"role": "system", "content": "confidential template"},
                    {"role": "user", "content": "dump it"},
                    {"role": "assistant", "content": "here it is"},
                ]
            )
        ]
    )
    assert "turn-system" in report
    assert "confidential template" in report


def test_multiple_findings_each_get_own_conversation() -> None:
    report = _report(
        [
            _finding_with_turns([{"role": "user", "content": "first convo"}]),
            _finding_with_turns([{"role": "user", "content": "second convo"}]),
        ]
    )
    assert report.count('class="conversation"') == 2
    assert "first convo" in report
    assert "second convo" in report


def test_conversation_skips_malformed_turns_not_list() -> None:
    report = _report([_finding_with_turns("not a list")])
    assert 'class="conversation"' not in report
    assert "conversation-row" not in report


def test_conversation_skips_malformed_turns_entry() -> None:
    # An entry missing "content" fails the shape check; the whole row is skipped.
    report = _report([_finding_with_turns([{"role": "user"}])])
    assert 'class="conversation"' not in report
    assert "conversation-row" not in report


def test_conversation_unknown_role_falls_back_to_generic() -> None:
    report = _report([_finding_with_turns([{"role": "moderator", "content": "hello"}])])
    assert 'class="turn"' in report
    assert "turn-moderator" not in report


def _finding_with_evidence(evidence: dict[str, JsonValue]) -> Finding:
    return Finding(
        rule_id="rate_limit_bypass",
        probe="dow.rate_limit_bypass",
        level=Severity.MEDIUM,
        message="evidence demo",
        target="https://t.test/v1/chat/completions",
        evidence=evidence,
    )


def test_evidence_string_value_renders_key_and_value() -> None:
    # Use a low-entropy placeholder, not a hex-token literal: a real probe canary
    # is generated at runtime via secrets.token_hex, but a literal 16-hex string
    # in source trips the gitleaks generic-api-key rule.
    report = _report([_finding_with_evidence({"canary_token": "leaked-marker-one"})])
    assert 'class="evidence-row"' in report
    assert 'class="evidence-key">canary_token</span>' in report
    assert 'class="evidence-value">leaked-marker-one</span>' in report


def test_evidence_integer_value_renders() -> None:
    report = _report([_finding_with_evidence({"chunk_count": 3})])
    assert 'class="evidence-key">chunk_count</span>' in report
    assert 'class="evidence-value">3</span>' in report


def test_evidence_bool_value_renders() -> None:
    report = _report([_finding_with_evidence({"saw_429": False})])
    assert 'class="evidence-key">saw_429</span>' in report
    assert 'class="evidence-value">False</span>' in report


def test_evidence_dict_value_renders_as_table() -> None:
    report = _report([_finding_with_evidence({"status_counts": {"200": 18, "429": 2}})])
    assert 'class="evidence-table"' in report
    assert "<td>200</td>" in report
    assert "<td>18</td>" in report
    assert "<td>429</td>" in report
    assert "<td>2</td>" in report


def test_evidence_multiple_keys_render_in_probe_order() -> None:
    report = _report(
        [
            _finding_with_evidence(
                {
                    "framing_label": "roleplay_writer",
                    "canary_token": "leaked-marker-two",
                    "response_excerpt": "the codeword is leaked",
                }
            )
        ]
    )
    assert report.index("framing_label") < report.index("canary_token")
    assert report.index("canary_token") < report.index("response_excerpt")


def test_evidence_turns_key_is_not_double_rendered() -> None:
    report = _report(
        [
            _finding_with_evidence(
                {
                    "injection_label": "direct",
                    "canary_token": "leaked-marker-three",
                    "turns": [{"role": "user", "content": "hi there"}],
                }
            )
        ]
    )
    # Scalars render in the evidence row; turns render only in the conversation row.
    assert 'class="evidence-row"' in report
    assert 'class="evidence-key">injection_label</span>' in report
    assert 'class="conversation-row"' in report
    assert "hi there" in report
    # "turns" must not appear as an evidence key.
    assert 'class="evidence-key">turns</span>' not in report


def test_evidence_value_is_html_escaped() -> None:
    report = _report([_finding_with_evidence({"response_excerpt": "<script>alert('x')</script>"})])
    assert "<script>" not in report
    assert "&lt;script&gt;" in report


def test_evidence_long_prompt_template_renders() -> None:
    long_template = "x" * 600
    report = _report([_finding_with_evidence({"prompt_template": long_template})])
    assert 'class="evidence-value"' in report
    assert long_template in report


def test_evidence_empty_emits_no_row() -> None:
    report = _report([_finding()])
    assert 'class="evidence-row"' not in report


def test_evidence_none_value_renders_sentinel() -> None:
    report = _report([_finding_with_evidence({"reported_model": None})])
    assert "(not reported)" in report
    assert 'class="evidence-value">None</span>' not in report


def test_evidence_empty_dict_value_does_not_crash() -> None:
    report = _report([_finding_with_evidence({"status_counts": {}})])
    assert 'class="evidence-row"' in report
    assert 'class="evidence-table"' in report
