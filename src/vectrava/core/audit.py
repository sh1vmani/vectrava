"""Opt-in audit log of scan invocations.

Records one JSONL line per scan invocation so an operator in a regulated
environment can prove what was scanned, when, by whom, against which scope, and
with what outcome. The log is opt-in (a path must be supplied) and records both
successful and refused scans, since a refusal (an expired scope, say) is itself
evidence.

What is never recorded: the credential value. Only a SHA-256 fingerprint of the
credential and the environment-variable name appear, so an auditor can correlate
which key slot was used without the secret ever touching the log. The scope
signature is likewise reduced to a fingerprint, not stored verbatim.

The writer is a stateful object: build it once, populate fields as the scan
progresses, and flush exactly once in a finally block. Flush is idempotent and a
disabled writer (no path) is a no-op, so callers never branch on whether auditing
is enabled. Tamper-evidence (per-record signing or hash-chaining) and concurrent
multi-writer safety are out of scope; v1 assumes a single writer per path and
relies on the operator's filesystem controls and log-shipping tooling.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

from vectrava.core.result import Severity

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path
    from typing import BinaryIO

    from pydantic import JsonValue

    from vectrava.config.scope import ScopeFile
    from vectrava.core.result import Finding

_CREDENTIAL_FINGERPRINT_LEN = 12
_SIGNATURE_FINGERPRINT_LEN = 16
# 64-char sentinel meaning "no predecessor"; a valid SHA-256 hex shape that
# reads obviously as the chain root.
_CHAIN_SENTINEL = "0" * 64
# File-lock tuning. The lock is held for milliseconds per flush; poll a
# non-blocking acquire against a monotonic deadline rather than blocking
# unboundedly or using signals (which interact badly with threads/async).
_LOCK_TIMEOUT_S = 5.0
_LOCK_POLL_INTERVAL_S = 0.05
# Windows locks a byte range from the current position; lock a single byte at a
# high offset that record data never reaches, so the lock never overlaps content
# and works on empty files. The Unix (fcntl.flock, whole-file) branch ignores it.
_WINDOWS_LOCK_OFFSET = 2**40


class AuditError(Exception):
    """Raised when an enabled audit log cannot be written (fail-closed)."""


def _acquire_lock(fd: int, timeout: float = _LOCK_TIMEOUT_S) -> None:
    """Take an exclusive advisory lock on an open file descriptor.

    Polls a non-blocking acquire every _LOCK_POLL_INTERVAL_S against a monotonic
    deadline; raises TimeoutError if the lock is still held after `timeout`
    seconds. This primitive stays path-agnostic so the caller (flush) can name the
    path in its AuditError and so tests can drive it on their own fd to simulate a
    competing holder. Unix locks the whole file (fcntl.flock); Windows locks one
    byte at a high sentinel offset (msvcrt.locking).
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            if sys.platform == "win32":
                os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if time.monotonic() >= deadline:
                msg = f"audit log lock not acquired within {timeout}s"
                raise TimeoutError(msg) from exc
            time.sleep(_LOCK_POLL_INTERVAL_S)
        else:
            return


def _release_lock(fd: int) -> None:
    """Release the advisory lock taken by _acquire_lock on this descriptor."""
    if sys.platform == "win32":
        os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


def credential_fingerprint(value: str) -> str:
    """Return a short one-way fingerprint of a credential value.

    SHA-256 truncated to 12 hex chars. Lets an auditor confirm the same key was
    used across scans without the value ever appearing in the log.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:_CREDENTIAL_FINGERPRINT_LEN]


def signature_fingerprint(signature: str) -> str:
    """Return a short fingerprint of a scope signature (SHA-256, 16 hex chars).

    Binds an audit record to the exact authorization instance without storing the
    signature artifact itself.
    """
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()[:_SIGNATURE_FINGERPRINT_LEN]


def file_sha256(path: Path) -> str:
    """Return the full SHA-256 hex digest of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_tail_from_fd(handle: BinaryIO) -> bytes | None:
    """Return the last line's bytes (without the trailing newline), or None.

    Operates on an already-open binary file object so the caller can hold a lock
    on it across the read and a subsequent append. Returns None for an empty file.
    Seeks from the end and scans backward in small chunks to the previous newline,
    so the read is O(1) in the log size rather than O(n) per append. The
    no-final-newline case is handled defensively: the whole last line is returned
    even without a terminator.
    """
    handle.seek(0, 2)
    file_size = handle.tell()
    if file_size == 0:
        return None
    chunk = 4096
    pos = file_size
    buf = b""
    while pos > 0:
        step = min(chunk, pos)
        pos -= step
        handle.seek(pos)
        buf = handle.read(step) + buf
        # Strip a single trailing newline (the record terminator), then look for
        # the boundary that starts the last line.
        trimmed = buf[:-1] if buf.endswith(b"\n") else buf
        idx = trimmed.rfind(b"\n")
        if idx != -1:
            return trimmed[idx + 1 :]
    return buf[:-1] if buf.endswith(b"\n") else buf


def _read_tail_line(path: Path) -> bytes | None:
    """Open a file read-only and return its last line's bytes, or None.

    Thin wrapper over _read_tail_from_fd for the no-lock path; returns None if the
    file does not exist or cannot be read.
    """
    try:
        with path.open("rb") as handle:
            return _read_tail_from_fd(handle)
    except OSError:
        return None


@dataclass
class AuditRecord:
    """One audit-log record. Every field but schema_version is optional.

    Fields populate incrementally as a scan progresses; an early refusal leaves
    the later fields None, which is itself meaningful (the scan never reached
    them).
    """

    schema_version: str = "1"
    invocation_id: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    outcome: str | None = None
    module: str | None = None
    target: str | None = None
    exit_code: int | None = None
    scope_signer_public_key: str | None = None
    scope_signed_by: str | None = None
    scope_authorized_until: str | None = None
    scope_signature_sha256: str | None = None
    credential_env_var: str | None = None
    credential_sha256_prefix: str | None = None
    findings_summary: dict[str, JsonValue] | None = None
    output_file: str | None = None
    output_file_sha256: str | None = None
    # Cost estimate at scan invocation; populated by set_cost_estimate in
    # _run_scan when the cost gate computes them. None on paths that exit before
    # cost estimation. cost_rate_source records the provenance of the per-1K rate:
    # "model" when it came from the pricing table, "fallback" when the placeholder
    # rate was used. None when cost was never estimated.
    estimated_tokens: int | None = None
    estimated_cost_usd: float | None = None
    cost_rate_source: str | None = None
    arguments: list[str] | None = None
    vectrava_version: str | None = None
    runner_host: str | None = None
    runner_user: str | None = None
    runner_pid: int | None = None
    # SHA-256 hex of the prior record's on-disk line bytes, or the sentinel for
    # the chain root. Set by flush(); optional so records built directly in tests
    # without flushing remain valid.
    prev_hash: str | None = None


class AuditWriter:
    """Builds and flushes a single audit record for one scan invocation.

    A writer with path None is disabled: every method runs but preflight and
    flush are no-ops, so callers need not branch on whether auditing is enabled.

    Records are hash-chained: each flush sets prev_hash to the SHA-256 of the
    prior record's on-disk line bytes (or the sentinel for the first record), so
    `vtra audit verify` can detect post-scan tampering. Concurrent writers
    serialize via an exclusive OS file lock (fcntl on Linux/macOS, msvcrt on
    Windows) held across the tail read and the append, so the chain cannot fork; a
    flush that cannot acquire the lock within _LOCK_TIMEOUT_S seconds raises
    AuditError.
    """

    def __init__(self, path: Path | None) -> None:
        """Store the target path (None disables the writer). Never does IO."""
        self._path = path
        self._record = AuditRecord()
        self._flushed = False

    def preflight(self) -> None:
        """Fail closed: confirm the audit path is writable before the scan runs.

        Creates parent directories and test-opens the file in append mode. Raises
        AuditError on any filesystem failure so the caller can refuse the scan
        before contacting the target. No-op when disabled.

        Raises:
            AuditError: if the audit log path cannot be written.
        """
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8"):
                pass
        except OSError as exc:
            msg = f"cannot write audit log at {self._path}: {exc}"
            raise AuditError(msg) from exc

    def set_invocation(
        self,
        *,
        invocation_id: str,
        started_at: datetime,
        module: str,
        arguments: Sequence[str],
        runner_host: str,
        runner_user: str,
        runner_pid: int,
        vectrava_version: str,
    ) -> None:
        """Record the invocation-level fields known at scan entry."""
        self._record.invocation_id = invocation_id
        self._record.started_at = started_at.isoformat()
        self._record.module = module
        self._record.arguments = list(arguments)
        self._record.runner_host = runner_host
        self._record.runner_user = runner_user
        self._record.runner_pid = runner_pid
        self._record.vectrava_version = vectrava_version

    def set_scope(self, scope: ScopeFile) -> None:
        """Record the authorizing scope's signer identity and window."""
        self._record.scope_signer_public_key = scope.public_key
        self._record.scope_signed_by = scope.signed_by
        self._record.scope_authorized_until = scope.authorized_until.isoformat()
        if scope.signature is not None:
            self._record.scope_signature_sha256 = signature_fingerprint(scope.signature)

    def set_scope_rejected(self, scope: ScopeFile | None) -> None:
        """Record scope details from a refused authorization, when recoverable."""
        if scope is not None:
            self.set_scope(scope)

    def set_target(self, target: str) -> None:
        """Record the resolved target that was scanned."""
        self._record.target = target

    def set_credential(self, *, env_var: str, value: str) -> None:
        """Record the credential env-var name and a fingerprint. Never the value."""
        self._record.credential_env_var = env_var
        self._record.credential_sha256_prefix = credential_fingerprint(value)

    def set_findings(self, findings: Sequence[Finding]) -> None:
        """Record a severity-count summary and the rule ids, not the findings."""
        by_severity: dict[str, int] = {level.value: 0 for level in Severity}
        for finding in findings:
            by_severity[finding.level.value] += 1
        summary: dict[str, JsonValue] = {
            "by_severity": cast("dict[str, JsonValue]", by_severity),
            "total": len(findings),
            "rule_ids": cast("list[JsonValue]", [finding.rule_id for finding in findings]),
        }
        self._record.findings_summary = summary

    def set_output(self, path: Path | None) -> None:
        """Record the output file path and its full SHA-256, if it was written."""
        if path is None:
            return
        self._record.output_file = str(path)
        if path.exists():
            self._record.output_file_sha256 = file_sha256(path)

    def set_cost_estimate(self, *, total_tokens: int, cost_usd: float, is_fallback: bool) -> None:
        """Record the token and USD cost estimate computed by the cost gate.

        Keyword-only because two same-typed numeric args are transposition-prone.
        The USD figure is rounded to six decimals: sub-microcent precision is
        below USD significance and avoids noisy float reprs in the stored JSON.
        is_fallback records rate provenance: False maps to cost_rate_source
        "model" (a per-model rate from the pricing table), True maps to "fallback"
        (the placeholder rate was used because the model was not in the table).
        """
        self._record.estimated_tokens = total_tokens
        self._record.estimated_cost_usd = round(cost_usd, 6)
        self._record.cost_rate_source = "fallback" if is_fallback else "model"

    def set_outcome(self, outcome: str, exit_code: int) -> None:
        """Record the terminal outcome string and process exit code."""
        self._record.outcome = outcome
        self._record.exit_code = exit_code

    def flush(self) -> None:
        """Write the record as one JSONL line. Idempotent; no-op when disabled.

        Stamps ended_at if unset, then takes an exclusive OS file lock spanning the
        tail read and the append so concurrent flushes cannot read the same tail
        and both chain from it. The lock is released when the file closes (after
        the buffered write is flushed), so the bytes land before any other writer
        can acquire the lock. Echoes the resolved absolute path to stderr.

        Raises:
            AuditError: if the lock cannot be acquired within _LOCK_TIMEOUT_S.
        """
        if self._path is None or self._flushed:
            return
        if self._record.ended_at is None:
            self._record.ended_at = datetime.now(UTC).isoformat()
        # Binary append+read: append writes go to EOF regardless of the read seek,
        # and binary keeps the log LF-only (the hash chain depends on stable bytes).
        with self._path.open("a+b") as handle:
            try:
                _acquire_lock(handle.fileno(), timeout=_LOCK_TIMEOUT_S)
            except TimeoutError as exc:
                raise AuditError(
                    f"could not acquire audit log lock within {_LOCK_TIMEOUT_S}s "
                    f"(path: {self._path})"
                ) from exc
            # Chain link: hash the prior record's on-disk bytes under the lock, or
            # the sentinel for the first record. flush() owns this field.
            tail = _read_tail_from_fd(handle)
            self._record.prev_hash = (
                _CHAIN_SENTINEL if tail is None else hashlib.sha256(tail).hexdigest()
            )
            line = json.dumps(asdict(self._record), default=str, separators=(",", ":"))
            handle.write((line + "\n").encode("utf-8"))
        self._flushed = True
        print(f"audit record written to {self._path.resolve()}", file=sys.stderr)
