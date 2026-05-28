"""Scope authorization file model.

A scope file is the written authorization that permits a vectrava run. It names
the targets that may be probed, the deadline after which authorization lapses,
and the party who signed off. No scan proceeds without one.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


def validate_base_target(value: str) -> str:
    """Validate that a target is a base URL with no path, query, or fragment.

    A base target is scheme plus host plus optional port, with at most a single
    trailing slash. Probes append the endpoint path (for example
    /v1/chat/completions) to the target, so a target that already carries a path
    would produce a doubled path against a live endpoint.

    Args:
        value: The target URL to validate.

    Returns:
        The value unchanged when it is a valid base URL. This is a validator, not
        a normalizer: it never rewrites the value.

    Raises:
        ValueError: if the scheme is not http or https, or the URL carries a path
            beyond root, a query, or a fragment.
    """
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        msg = (
            f"target must start with http:// or https://; got {value!r} with "
            f"scheme {parsed.scheme!r}"
        )
        raise ValueError(msg)
    if parsed.path not in ("", "/"):
        msg = (
            f"target must be a base URL with no path; drop the '{parsed.path}' "
            "suffix and pass only scheme, host, and optional port"
        )
        raise ValueError(msg)
    if parsed.query or parsed.fragment:
        msg = "target must be a base URL with no query or fragment"
        raise ValueError(msg)
    return value


class ScopeFile(BaseModel):
    """Authorization scope for a vectrava run.

    Attributes:
        targets: Hosts or endpoints the run is permitted to probe.
        authorized_until: Instant after which the authorization is no longer
            valid. A run started after this point must be refused.
        signed_by: Identity of the party who authorized the run.
    """

    targets: list[str] = Field(min_length=1)
    authorized_until: datetime
    signed_by: str = Field(min_length=1)
    # base64url-encoded Ed25519 signature over the canonical payload
    signature: str | None = None
    # base64url-encoded raw Ed25519 public key
    public_key: str | None = None

    @field_validator("targets")
    @classmethod
    def _targets_are_base_urls(cls, value: list[str]) -> list[str]:
        """Reject any target that is not a base URL. Runs at model_validate time."""
        for target in value:
            validate_base_target(target)
        return value
