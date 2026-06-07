"""Tests for the response-capture JSONL sink (output/response_capture.py).

No network, no environment reads. Every case writes to a tmp_path JSONL file or
exercises the disabled no-op recorder.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from vectrava.output.response_capture import ResponseCapture

if TYPE_CHECKING:
    from pathlib import Path


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_capture_writes_one_line_per_record(tmp_path: Path) -> None:
    path = tmp_path / "responses.jsonl"
    capture = ResponseCapture(path)
    capture.record(probe="dow.token_amplification", index=None, label="verbose", content="alpha")
    capture.record(probe="ipi.direct_override", index=None, label="direct", content="beta")
    capture.record(probe="ipi.multi_turn_persistence", index=2, label="prepend", content="gamma")
    capture.close()

    lines = _read_lines(path)
    assert len(lines) == 3
    records: list[Any] = [json.loads(line) for line in lines]
    for record in records:
        assert set(record) == {"probe", "index", "content", "label", "captured_at"}
    assert records[0]["probe"] == "dow.token_amplification"
    assert records[0]["label"] == "verbose"
    assert records[0]["content"] == "alpha"
    assert records[0]["index"] is None
    assert records[2]["index"] == 2
    assert records[2]["content"] == "gamma"

    # LF-only: the raw bytes carry b"\n" separators and no carriage return.
    raw = path.read_bytes()
    assert b"\r" not in raw
    assert raw.count(b"\n") == 3


def test_capture_records_none_content_and_none_label(tmp_path: Path) -> None:
    path = tmp_path / "responses.jsonl"
    capture = ResponseCapture(path)
    # A single unlabeled request with no text content, like model_substitution.
    capture.record(probe="dow.model_substitution", index=None, content=None)
    capture.close()

    lines = _read_lines(path)
    assert len(lines) == 1
    record: Any = json.loads(lines[0])
    assert record["probe"] == "dow.model_substitution"
    assert record["content"] is None
    assert record["label"] is None
    assert record["index"] is None


def test_disabled_capture_writes_nothing(tmp_path: Path) -> None:
    capture = ResponseCapture(None)
    capture.record(probe="dow.token_amplification", index=None, label="verbose", content="x")
    capture.close()
    # No path: record and close are no-ops and must not create any file.
    assert list(tmp_path.iterdir()) == []


def test_enabled_but_never_recorded_creates_no_file(tmp_path: Path) -> None:
    path = tmp_path / "out.jsonl"
    capture = ResponseCapture(path)
    capture.close()
    # Lazy open: a recorder that never records leaves no artifact on disk.
    assert not path.exists()
