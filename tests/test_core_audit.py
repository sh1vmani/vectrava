"""Tests for the scan-invocation audit log (core/audit.py).

No network, no environment reads. Every case writes to a tmp_path JSONL file or
exercises the pure hashing helpers directly.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from vectrava.config.scope import ScopeFile
from vectrava.core.audit import (
    AuditError,
    AuditWriter,
    credential_fingerprint,
    file_sha256,
    signature_fingerprint,
)
from vectrava.core.result import Finding, Severity

if TYPE_CHECKING:
    from pathlib import Path


def _scope() -> ScopeFile:
    return ScopeFile(
        targets=["https://example.test"],
        authorized_until=datetime.now(UTC) + timedelta(days=1),
        signed_by="Shivamani Vastrala",
        signature="fake-signature-b64url",
        public_key="fake-public-key-b64url",
    )


def _finding(level: Severity, rule_id: str = "demo_probe") -> Finding:
    return Finding(
        rule_id=rule_id,
        probe=f"dow.{rule_id}",
        level=level,
        message="demo",
        target="https://example.test",
    )


def _stamp(writer: AuditWriter) -> None:
    writer.set_invocation(
        invocation_id="abc123",
        started_at=datetime.now(UTC),
        module="dow",
        arguments=["scan", "dow", "--target", "https://example.test"],
        runner_host="test-host",
        runner_user="test-user",
        runner_pid=4242,
        vectrava_version="0.0.1",
    )


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_disabled_writer_flush_writes_nothing(tmp_path: Path) -> None:
    writer = AuditWriter(None)
    _stamp(writer)
    writer.set_outcome("completed_clean", 0)
    # No path: preflight and flush are no-ops and must not raise or create files.
    writer.preflight()
    writer.flush()
    writer.flush()
    assert list(tmp_path.iterdir()) == []


def test_enabled_writer_flush_writes_one_jsonl_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_outcome("completed_clean", 0)
    writer.flush()

    lines = _read_lines(path)
    assert len(lines) == 1
    record: Any = json.loads(lines[0])
    assert record["outcome"] == "completed_clean"
    assert record["exit_code"] == 0
    assert record["schema_version"] == "1"


def test_preflight_raises_audit_error_on_unwritable_dir(tmp_path: Path) -> None:
    # A file where a directory is needed makes mkdir(parents=True) fail on every OS.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    bad_path = blocker / "sub" / "audit.jsonl"
    writer = AuditWriter(bad_path)
    with pytest.raises(AuditError, match="cannot write audit log"):
        writer.preflight()


def test_preflight_auto_creates_parent_directory(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "audit.jsonl"
    writer = AuditWriter(nested)
    writer.preflight()
    assert nested.parent.is_dir()


def test_flush_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_outcome("completed_clean", 0)
    writer.flush()
    writer.flush()
    assert len(_read_lines(path)) == 1


def test_record_schema_required_fields_present(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_scope(_scope())
    writer.set_target("https://example.test")
    writer.set_credential(env_var="VECTRAVA_TEST_KEY", value="super-secret-value")
    writer.set_findings([_finding(Severity.HIGH), _finding(Severity.MEDIUM)])
    output = tmp_path / "out.sarif"
    output.write_text("{}", encoding="utf-8")
    writer.set_output(output)
    writer.set_outcome("completed_with_findings", 1)
    writer.flush()

    record: Any = json.loads(_read_lines(path)[0])
    assert record["invocation_id"] == "abc123"
    assert record["module"] == "dow"
    assert record["target"] == "https://example.test"
    assert record["scope_signer_public_key"] == "fake-public-key-b64url"
    assert record["scope_signed_by"] == "Shivamani Vastrala"
    assert isinstance(record["scope_authorized_until"], str)
    assert isinstance(record["scope_signature_sha256"], str)
    assert record["credential_env_var"] == "VECTRAVA_TEST_KEY"
    assert isinstance(record["credential_sha256_prefix"], str)
    # The credential value must never appear in the record.
    assert "super-secret-value" not in _read_lines(path)[0]
    assert record["findings_summary"]["total"] == 2
    assert record["findings_summary"]["by_severity"]["high"] == 1
    assert record["findings_summary"]["by_severity"]["medium"] == 1
    assert record["output_file_sha256"] == file_sha256(output)
    assert isinstance(record["started_at"], str)
    assert isinstance(record["ended_at"], str)
    assert record["runner_host"] == "test-host"
    assert record["runner_pid"] == 4242


def test_credential_fingerprint_stable_for_same_value() -> None:
    assert credential_fingerprint("key-value") == credential_fingerprint("key-value")
    assert len(credential_fingerprint("key-value")) == 12


def test_credential_fingerprint_differs_for_different_values() -> None:
    assert credential_fingerprint("key-a") != credential_fingerprint("key-b")


def test_signature_fingerprint_same_property() -> None:
    assert signature_fingerprint("sig-x") == signature_fingerprint("sig-x")
    assert signature_fingerprint("sig-x") != signature_fingerprint("sig-y")
    assert len(signature_fingerprint("sig-x")) == 16


def test_file_sha256_matches_hashlib(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    payload = b"vectrava audit blob \x00\x01\x02"
    target.write_bytes(payload)
    assert file_sha256(target) == hashlib.sha256(payload).hexdigest()


def test_record_with_newline_in_field_stays_one_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.preflight()
    writer.set_invocation(
        invocation_id="abc123",
        started_at=datetime.now(UTC),
        module="dow",
        arguments=["scan", "dow", "line1\nline2"],
        runner_host="test-host",
        runner_user="test-user",
        runner_pid=4242,
        vectrava_version="0.0.1",
    )
    writer.set_outcome("completed_clean", 0)
    writer.flush()

    raw = path.read_text(encoding="utf-8")
    # Exactly one physical line: the embedded newline was JSON-escaped, not literal.
    assert raw.count("\n") == 1
    record: Any = json.loads(raw)
    assert record["arguments"] == ["scan", "dow", "line1\nline2"]
