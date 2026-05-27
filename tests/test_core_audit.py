"""Tests for the scan-invocation audit log (core/audit.py).

No network, no environment reads. Every case writes to a tmp_path JSONL file or
exercises the pure hashing helpers directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from vectrava.config.scope import ScopeFile
from vectrava.core.audit import (
    _CHAIN_SENTINEL,
    AuditError,
    AuditWriter,
    _acquire_lock,
    _read_tail_line,
    _release_lock,
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


def test_set_cost_estimate_populates_both_fields(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_cost_estimate(total_tokens=12345, cost_usd=0.12)
    writer.set_outcome("completed_clean", 0)
    writer.flush()

    record: Any = json.loads(_read_lines(path)[0])
    assert record["estimated_tokens"] == 12345
    assert record["estimated_cost_usd"] == 0.12


def test_set_cost_estimate_rounds_usd_to_six_decimals(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    noisy = 0.020000000000000004
    writer.set_cost_estimate(total_tokens=2000, cost_usd=noisy)
    writer.set_outcome("completed_clean", 0)
    writer.flush()

    record: Any = json.loads(_read_lines(path)[0])
    assert record["estimated_cost_usd"] == round(noisy, 6)


def test_set_cost_estimate_serializes_usd_as_float(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_cost_estimate(total_tokens=2000, cost_usd=0.02)
    writer.set_outcome("completed_clean", 0)
    writer.flush()

    record: Any = json.loads(_read_lines(path)[0])
    # json.dumps(default=str) renders a native float as a JSON number, not a
    # stringified value; parsing it back yields a float.
    assert isinstance(record["estimated_cost_usd"], float)


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


# --- hash chaining ---------------------------------------------------------


def test_flush_first_record_uses_sentinel_prev_hash(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_outcome("completed_clean", 0)
    writer.flush()

    record: Any = json.loads(_read_lines(path)[0])
    assert record["prev_hash"] == _CHAIN_SENTINEL


def test_flush_subsequent_record_chains_to_prior_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = AuditWriter(path)
    first.preflight()
    _stamp(first)
    first.set_outcome("completed_clean", 0)
    first.flush()
    line_a = _read_lines(path)[0]

    second = AuditWriter(path)
    second.preflight()
    _stamp(second)
    second.set_outcome("completed_clean", 0)
    second.flush()

    record_a: Any = json.loads(_read_lines(path)[0])
    record_b: Any = json.loads(_read_lines(path)[1])
    assert record_a["prev_hash"] == _CHAIN_SENTINEL
    assert record_b["prev_hash"] == hashlib.sha256(line_a.encode("utf-8")).hexdigest()


def test_flush_chains_after_legacy_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    # A pre-change record: no prev_hash field.
    legacy_line = json.dumps(
        {"schema_version": "1", "outcome": "completed_clean"}, separators=(",", ":")
    )
    path.write_text(legacy_line + "\n", encoding="utf-8", newline="\n")

    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_outcome("completed_clean", 0)
    writer.flush()

    new_record: Any = json.loads(_read_lines(path)[1])
    assert new_record["prev_hash"] == hashlib.sha256(legacy_line.encode("utf-8")).hexdigest()


def test_legacy_record_chains_through_cost_field_transition(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    # A pre-change record with neither cost key present.
    legacy_line = json.dumps(
        {"schema_version": "1", "outcome": "completed_clean"}, separators=(",", ":")
    )
    path.write_text(legacy_line + "\n", encoding="utf-8", newline="\n")

    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_cost_estimate(total_tokens=2000, cost_usd=0.02)
    writer.set_outcome("completed_clean", 0)
    writer.flush()

    new_record: Any = json.loads(_read_lines(path)[1])
    # The new record carries the cost keys; the chain still anchors to the
    # legacy line's bytes, so a no-cost-field to cost-field transition verifies.
    assert new_record["estimated_tokens"] == 2000
    assert new_record["prev_hash"] == hashlib.sha256(legacy_line.encode("utf-8")).hexdigest()


def test_read_tail_line_returns_none_for_missing_file(tmp_path: Path) -> None:
    assert _read_tail_line(tmp_path / "does-not-exist.jsonl") is None


def test_read_tail_line_returns_none_for_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    assert _read_tail_line(path) is None


def test_read_tail_line_returns_last_line_no_trailing_newline(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("line1\nline2", encoding="utf-8")  # no trailing newline
    assert _read_tail_line(path) == b"line2"


# --- file locking ----------------------------------------------------------


def _flush_record(path: Path) -> None:
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_outcome("completed_clean", 0)
    writer.flush()


def test_flush_acquires_and_releases_lock(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    # Two sequential flushes in one process must not self-deadlock: each opens its
    # own fd, locks, and releases on close before the next runs.
    _flush_record(path)
    _flush_record(path)
    lines = _read_lines(path)
    assert len(lines) == 2
    record_b = json.loads(lines[1])
    assert record_b["prev_hash"] == hashlib.sha256(lines[0].encode("utf-8")).hexdigest()


def test_flush_blocks_concurrent_writer_then_proceeds(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _flush_record(path)  # seed one record so the file exists and is non-empty

    holder_locked = threading.Event()

    def holder() -> None:
        fd = os.open(str(path), os.O_RDWR)
        try:
            _acquire_lock(fd)
            holder_locked.set()
            time.sleep(0.2)  # hold briefly, then release in finally
        finally:
            _release_lock(fd)
            os.close(fd)

    thread = threading.Thread(target=holder)
    thread.start()
    assert holder_locked.wait(timeout=5)
    # flush() polls until the holder releases (~0.2s), then appends.
    _flush_record(path)
    thread.join()

    lines = _read_lines(path)
    assert len(lines) == 2
    record_b = json.loads(lines[1])
    assert record_b["prev_hash"] == hashlib.sha256(lines[0].encode("utf-8")).hexdigest()


def test_flush_raises_audit_error_on_lock_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    _flush_record(path)
    monkeypatch.setattr("vectrava.core.audit._LOCK_TIMEOUT_S", 0.2)

    holder_locked = threading.Event()
    release = threading.Event()

    def holder() -> None:
        fd = os.open(str(path), os.O_RDWR)
        try:
            _acquire_lock(fd)
            holder_locked.set()
            release.wait(timeout=5)
        finally:
            _release_lock(fd)
            os.close(fd)

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert holder_locked.wait(timeout=5)
        writer = AuditWriter(path)
        _stamp(writer)
        writer.set_outcome("completed_clean", 0)
        with pytest.raises(AuditError, match="could not acquire") as exc_info:
            writer.flush()
        assert str(path) in str(exc_info.value)
    finally:
        release.set()
        thread.join()


def test_disabled_writer_does_not_acquire_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        msg = "lock must not be acquired for a disabled writer"
        raise RuntimeError(msg)

    monkeypatch.setattr("vectrava.core.audit._acquire_lock", boom)
    writer = AuditWriter(None)
    writer.preflight()
    _stamp(writer)
    writer.set_outcome("completed_clean", 0)
    writer.flush()  # returns before any open/lock; boom is never called


def test_lock_released_on_exception_during_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"

    def boom(handle: object) -> bytes | None:
        msg = "boom during tail read"
        raise ValueError(msg)

    monkeypatch.setattr("vectrava.core.audit._read_tail_from_fd", boom)
    writer = AuditWriter(path)
    writer.preflight()
    _stamp(writer)
    writer.set_outcome("completed_clean", 0)
    with pytest.raises(ValueError, match="boom"):
        writer.flush()

    # The with-block closed the fd, releasing the lock. A fresh flush must succeed.
    monkeypatch.undo()
    _flush_record(path)
    assert len(_read_lines(path)) == 1
