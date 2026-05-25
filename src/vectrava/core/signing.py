"""Ed25519 signing and verification for scope authorization files.

A scope file is signed over a canonical payload: the compact, key-sorted JSON of
its fields with the signature and public_key fields removed, so the signature is
stable regardless of on-disk formatting. Signatures and keys are carried as raw
bytes, base64url-encoded. Verification trust is governed by the
VECTRAVA_TRUSTED_KEYS environment variable, a comma-separated list of base64url
public keys the gate is willing to accept; this module exposes the parsed set,
and an empty set means nothing is trusted (fail-closed).
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vectrava.config.scope import ScopeFile

__all__ = [
    "InvalidSignature",
    "b64url_decode",
    "b64url_encode",
    "canonical_payload",
    "generate_keypair",
    "sign_scope",
    "trusted_public_keys",
    "verify_scope",
]


def b64url_encode(data: bytes) -> str:
    """Return the base64url encoding of raw bytes."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decode a base64url string, restoring stripped padding."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical_payload(scope: ScopeFile) -> bytes:
    """Return the deterministic byte payload that a scope signature covers.

    The payload is the scope's fields minus signature and public_key, dumped as
    compact key-sorted JSON, so it does not depend on file formatting.
    """
    data = scope.model_dump(mode="json")
    data.pop("signature", None)
    data.pop("public_key", None)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair.

    Returns:
        A tuple of (private_key_b64url, public_key_b64url) over the raw key bytes.
    """
    priv = Ed25519PrivateKey.generate()
    priv_b64 = b64url_encode(priv.private_bytes_raw())
    pub_b64 = b64url_encode(priv.public_key().public_bytes_raw())
    return priv_b64, pub_b64


def sign_scope(scope: ScopeFile, private_key_b64: str) -> ScopeFile:
    """Return a copy of the scope with signature and public_key populated."""
    priv = Ed25519PrivateKey.from_private_bytes(b64url_decode(private_key_b64))
    sig_b64 = b64url_encode(priv.sign(canonical_payload(scope)))
    pub_b64 = b64url_encode(priv.public_key().public_bytes_raw())
    return scope.model_copy(update={"signature": sig_b64, "public_key": pub_b64})


def verify_scope(scope: ScopeFile) -> None:
    """Verify the Ed25519 signature on a scope file.

    Raises:
        ValueError: if the signature or public_key field is missing.
        InvalidSignature: if the signature does not match the payload and key.
    """
    if scope.signature is None or scope.public_key is None:
        raise ValueError("scope file has no signature")
    pub = Ed25519PublicKey.from_public_bytes(b64url_decode(scope.public_key))
    pub.verify(b64url_decode(scope.signature), canonical_payload(scope))


def trusted_public_keys() -> frozenset[str]:
    """Return the base64url public keys trusted via VECTRAVA_TRUSTED_KEYS.

    Returns an empty frozenset when the variable is unset or empty, so the gate
    trusts nothing by default (fail-closed).
    """
    raw = os.environ.get("VECTRAVA_TRUSTED_KEYS", "")
    return frozenset(k.strip() for k in raw.split(",") if k.strip())
