"""Scope authorization file model.

A scope file is the written authorization that permits a vectrava run. It names
the targets that may be probed, the deadline after which authorization lapses,
and the party who signed off. No scan proceeds without one.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


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
