"""Authorization gate enforced before any scan.

The gate is the single chokepoint every scan passes through. It refuses to let a
run start unless a scope file exists, parses, validates, carries a valid
signature from a trusted key, and is still within its authorization window.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from vectrava.config.scope import ScopeFile
from vectrava.core.signing import trusted_public_keys, verify_scope


class AuthorizationError(Exception):
    """Raised when scan authorization is missing, malformed, or expired.

    When the scope file parsed far enough to recover its contents (it was
    unsigned, signed by an untrusted key, or expired), the parsed `ScopeFile` is
    attached as `scope` so an audit record can name the claimed signer and
    authorization window. For a missing or malformed file, `scope` is None.
    """

    def __init__(self, message: str, *, scope: ScopeFile | None = None) -> None:
        """Build the error, optionally carrying the parsed scope for audit.

        Args:
            message: Human readable description of the refusal.
            scope: The parsed scope file, when it was recovered before refusal.
        """
        super().__init__(message)
        self.scope = scope


class AuthorizationGate:
    """Refuses to run a scan without valid scope authorization.

    Threat model:

    1. Missing file. A run invoked with no scope file has presented no authorization.
    The gate refuses rather than treating an absent file as permission, so the
    fail-closed default holds and nothing runs on the strength of a missing file.

    2. Malformed or invalid file. A scope file that does not parse as JSON or fails
    model validation cannot be trusted to mean what its bytes appear to say. The gate
    refuses rather than acting on a partially read or schema-violating authorization,
    so a corrupt or hand-edited file cannot slip through with unverified fields.

    3. Unsigned. An attacker who can write to the operator's filesystem could otherwise
    drop a plain JSON scope granting access to arbitrary targets. The gate requires
    both a signature and a public key, so an unsigned file is rejected before any
    signer or window is considered.

    4. Untrusted key. An attacker can generate their own Ed25519 keypair and produce a
    valid self-signed scope. The gate accepts a signature only from a key the operator
    placed in VECTRAVA_TRUSTED_KEYS, so a signature from an unrecognized key is
    rejected even though it verifies against its own public key.

    5. Signature mismatch. An attacker who edits a scope that was signed by a trusted
    key, widening its targets or pushing out its deadline, breaks the signature over
    the canonical payload. The gate re-verifies the signature against the trusted
    public key, so any change made after signing is caught.

    6. Expired. A scope signed for a past engagement stays cryptographically valid
    indefinitely, so a leaked or reused old scope could authorize a scan long after
    permission lapsed. The gate refuses once the current time passes
    authorized_until, bounding authorization in time as well as in target set.
    """

    def __init__(self, scope_path: Path) -> None:
        """Store the path to the scope authorization file.

        Args:
            scope_path: Filesystem path to the JSON scope file.
        """
        self.scope_path = scope_path

    def check(self) -> ScopeFile:
        """Validate the scope file and return the parsed authorization.

        Returns:
            The validated scope file.

        Raises:
            AuthorizationError: if the file is absent, cannot be parsed, fails
                validation, is unsigned, is signed by an untrusted key, fails
                signature verification, or the authorization window has elapsed.
        """
        if not self.scope_path.exists():
            msg = f"scope file not found: {self.scope_path}"
            raise AuthorizationError(msg)

        try:
            raw = json.loads(self.scope_path.read_text(encoding="utf-8"))
            scope = ScopeFile.model_validate(raw)
        except (ValueError, ValidationError) as exc:
            msg = f"invalid scope file {self.scope_path}: {exc}"
            raise AuthorizationError(msg) from exc

        if scope.signature is None or scope.public_key is None:
            msg = (
                "scope file is not signed; sign with vtra scope sign or set "
                "VECTRAVA_TRUSTED_KEYS for the signing key"
            )
            raise AuthorizationError(msg, scope=scope)

        if scope.public_key not in trusted_public_keys():
            msg = (
                "scope signed by an untrusted key; add the key to "
                "VECTRAVA_TRUSTED_KEYS or sign with a trusted key"
            )
            raise AuthorizationError(msg, scope=scope)

        try:
            verify_scope(scope)
        except InvalidSignature as exc:
            msg = "scope signature verification failed"
            raise AuthorizationError(msg) from exc

        deadline = scope.authorized_until
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        if deadline < datetime.now(UTC):
            msg = f"scope authorization expired at {deadline.isoformat()}"
            raise AuthorizationError(msg, scope=scope)

        return scope
