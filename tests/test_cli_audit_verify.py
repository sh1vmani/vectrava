"""CLI tests for `vtra audit verify`.

Builds chained audit logs with AuditWriter (which sets prev_hash correctly),
then tampers with the file on disk and confirms the verifier walks the hash
chain and exits non-zero, naming the offending line. No network, no env reads.
"""

from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from typer.testing import CliRunner

from vectrava.cli import app
from vectrava.core.audit import _CHAIN_SENTINEL, AuditWriter

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def _combined(result: Any) -> str:
    text = result.stdout or ""
    with contextlib.suppress(ValueError, AttributeError):
        text += result.stderr or ""
    return text


def _write_record(path: Path, invocation_id: str) -> None:
    writer = AuditWriter(path)
    writer.preflight()
    writer.set_invocation(
        invocation_id=invocation_id,
        started_at=datetime.now(UTC),
        module="dow",
        arguments=["scan", "dow"],
        runner_host="test-host",
        runner_user="test-user",
        runner_pid=1,
        vectrava_version="0.0.1",
    )
    writer.set_outcome("completed_clean", 0)
    writer.flush()


def _write_chain(path: Path, n: int) -> None:
    for i in range(n):
        _write_record(path, f"id-{i}")


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _rewrite(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _verify(path: Path) -> Any:
    return runner.invoke(app, ["audit", "verify", str(path)])


def test_verify_empty_file_exits_zero(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    result = _verify(path)
    assert result.exit_code == 0
    assert "0 records" in _combined(result)


def test_verify_single_sentinel_record_exits_zero(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 1)
    result = _verify(path)
    assert result.exit_code == 0
    assert "intact" in _combined(result)


def test_verify_two_chained_records_exits_zero(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 2)
    result = _verify(path)
    assert result.exit_code == 0
    assert "2 records" in _combined(result)


def test_verify_legacy_only_log_exits_zero(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    legacy = [
        json.dumps({"schema_version": "1", "outcome": "completed_clean"}, separators=(",", ":")),
        json.dumps(
            {"schema_version": "1", "outcome": "completed_with_findings"}, separators=(",", ":")
        ),
    ]
    _rewrite(path, legacy)
    result = _verify(path)
    assert result.exit_code == 0
    assert "2 records" in _combined(result)


def test_verify_mixed_mode_log_exits_zero(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    legacy = json.dumps(
        {"schema_version": "1", "outcome": "completed_clean"}, separators=(",", ":")
    )
    path.write_text(legacy + "\n", encoding="utf-8", newline="\n")
    # A chained record appended to a legacy log anchors to the legacy tail's hash.
    _write_record(path, "chained-after-legacy")
    result = _verify(path)
    assert result.exit_code == 0
    assert "2 records" in _combined(result)


def test_verify_detects_modification(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 3)
    lines = _lines(path)
    # Tamper with record 2's content; record 3's prev_hash no longer matches.
    record = json.loads(lines[1])
    record["outcome"] = "tampered"
    lines[1] = json.dumps(record, separators=(",", ":"))
    _rewrite(path, lines)
    result = _verify(path)
    assert result.exit_code == 1
    assert "line 3" in _combined(result)


def test_verify_detects_deletion(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 3)
    lines = _lines(path)
    del lines[1]  # remove record 2; surviving line 2 (was record 3) has a stale prev_hash
    _rewrite(path, lines)
    result = _verify(path)
    assert result.exit_code == 1
    assert "line 2" in _combined(result)


def test_verify_detects_insertion(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 3)
    lines = _lines(path)
    forged = json.dumps(
        {"schema_version": "1", "prev_hash": _CHAIN_SENTINEL, "outcome": "forged"},
        separators=(",", ":"),
    )
    lines.insert(1, forged)  # between record 1 and record 2
    _rewrite(path, lines)
    result = _verify(path)
    assert result.exit_code == 1


def test_verify_detects_adjacent_reorder(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 3)
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]  # swap records 2 and 3
    _rewrite(path, lines)
    result = _verify(path)
    assert result.exit_code == 1


def test_verify_detects_head_truncation(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_chain(path, 3)
    lines = _lines(path)
    del lines[0]  # remove the chain root; surviving first record has a non-sentinel prev_hash
    _rewrite(path, lines)
    result = _verify(path)
    assert result.exit_code == 1
    assert "sentinel" in _combined(result)


def test_verify_detects_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("this is not json{\n", encoding="utf-8", newline="\n")
    result = _verify(path)
    assert result.exit_code == 1
    assert "malformed JSON" in _combined(result)
