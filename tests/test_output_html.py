"""Tests for the HTML output writer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from vectrava.core.result import Finding, Severity
from vectrava.output.html import build_html_report, write_html

if TYPE_CHECKING:
    from pathlib import Path

_STARTED = datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC)


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
