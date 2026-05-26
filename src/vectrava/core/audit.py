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
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from vectrava.core.result import Severity

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from pydantic import JsonValue

    from vectrava.config.scope import ScopeFile
    from vectrava.core.result import Finding

_CREDENTIAL_FINGERPRINT_LEN = 12
_SIGNATURE_FINGERPRINT_LEN = 16
# 64-char sentinel meaning "no predecessor"; a valid SHA-256 hex shape that
# reads obviously as the chain root.
_CHAIN_SENTINEL = "0" * 64


class AuditError(Exception):
    """Raised when an enabled audit log cannot be written (fail-closed)."""


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


def _read_tail_line(path: Path) -> bytes | None:
    """Return the last line's bytes (without the trailing newline), or None.

    Returns None when the file does not exist or is empty. Seeks from the end and
    scans backward in small chunks to the previous newline, so the read is O(1) in
    the log size rather than O(n) per append. The no-final-newline case is handled
    defensively: the whole last line is returned even without a terminator.
    """
    try:
        with path.open("rb") as handle:
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
                # Strip a single trailing newline (the record terminator), then
                # look for the boundary that starts the last line.
                trimmed = buf[:-1] if buf.endswith(b"\n") else buf
                idx = trimmed.rfind(b"\n")
                if idx != -1:
                    return trimmed[idx + 1 :]
            return buf[:-1] if buf.endswith(b"\n") else buf
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
    `vtra audit verify` can detect post-scan tampering. Single-writer-per-path is
    required for chain integrity: concurrent writers to one path each read the
    same tail and both append, producing a forked chain that fails verification.
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

    def set_outcome(self, outcome: str, exit_code: int) -> None:
        """Record the terminal outcome string and process exit code."""
        self._record.outcome = outcome
        self._record.exit_code = exit_code

    def flush(self) -> None:
        """Write the record as one JSONL line. Idempotent; no-op when disabled.

        Stamps ended_at if unset. Uses compact json.dumps so embedded newlines in
        any field are escaped and the record stays a single physical line. Echoes
        the resolved absolute path to stderr so a typo-misplaced log is visible.
        """
        if self._path is None or self._flushed:
            return
        if self._record.ended_at is None:
            self._record.ended_at = datetime.now(UTC).isoformat()
        # Chain link: hash the prior record's on-disk bytes, or the sentinel for
        # the first record. flush() owns this field regardless of any prior value.
        tail = _read_tail_line(self._path)
        self._record.prev_hash = (
            _CHAIN_SENTINEL if tail is None else hashlib.sha256(tail).hexdigest()
        )
        line = json.dumps(asdict(self._record), default=str, separators=(",", ":"))
        # newline="\n" disables platform newline translation so the log is LF-only
        # and byte-identical across platforms; the hash chain depends on stable bytes.
        with self._path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
        self._flushed = True
        print(f"audit record written to {self._path.resolve()}", file=sys.stderr)
