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
    """Raised when scan authorization is missing, malformed, or expired."""


class AuthorizationGate:
    """Refuses to run a scan without valid scope authorization."""

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
            raise AuthorizationError(msg)

        if scope.public_key not in trusted_public_keys():
            msg = (
                "scope signed by an untrusted key; add the key to "
                "VECTRAVA_TRUSTED_KEYS or sign with a trusted key"
            )
            raise AuthorizationError(msg)

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
            raise AuthorizationError(msg)

        return scope
