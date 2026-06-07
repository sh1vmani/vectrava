"""Optional JSONL sink that captures every probe model response.

When a capture path is set, each probe response is appended as one JSON line,
whether or not it produced a finding, so a no-finding run is auditable after the
fact. Disabled by default: a recorder built with path None is a no-op, so probes
call record(...) without a None check at every site.

The sink is append-only JSONL, written LF-only so the artifact bytes are stable
across platforms, matching the audit log's byte discipline. It is deliberately
not hash-chained: this is a diagnostic capture, not an integrity log.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType
    from typing import TextIO


@dataclass(kw_only=True)
class ResponseRecord:
    """One captured probe response.

    Attributes:
        probe: The probe name that issued the request.
        index: The per-probe iteration or conversation-turn index, or None when
            the probe issues a single unindexed request.
        content: The model response text, or None when the response carried no
            text content.
        label: The attack-variant label for this request, or None when the probe
            issues a single unlabeled request.
        captured_at: UTC capture time in ISO 8601.
    """

    probe: str
    index: int | None
    content: str | None
    label: str | None = None
    captured_at: str


class ResponseCapture:
    """Append-only JSONL sink for probe responses.

    A capture built with path None is disabled: record() is a no-op and no file
    is opened, so callers never branch on whether capture is enabled. When a path
    is set, the file handle opens lazily on the first record and stays open until
    close(); use the object as a context manager to close the handle reliably.

    Writes are LF-only (newline set to a single line feed) so the artifact bytes
    are stable across platforms.
    """

    def __init__(self, path: Path | None) -> None:
        """Store the target path (None disables the sink). Never does IO."""
        self._path = path
        self._handle: TextIO | None = None

    def record(
        self, *, probe: str, index: int | None, content: str | None, label: str | None = None
    ) -> None:
        """Append one response record as a JSON line. No-op when disabled."""
        if self._path is None:
            return
        if self._handle is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self._path.open("a", encoding="utf-8", newline="\n")
        record = ResponseRecord(
            probe=probe,
            index=index,
            content=content,
            label=label,
            captured_at=datetime.now(UTC).isoformat(),
        )
        line = json.dumps(asdict(record), default=str, separators=(",", ":"))
        self._handle.write(line + "\n")

    def close(self) -> None:
        """Close the file handle if open. Idempotent and safe when disabled."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> ResponseCapture:
        """Enter a context; the handle opens lazily on the first record."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the handle on context exit."""
        self.close()
