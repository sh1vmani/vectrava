"""Bring-your-own-key configuration and validation.

vectrava never ships, bundles, or stores credentials for any target. The
operator supplies their own key through the environment. This module validates
that the named environment variable is actually present before any call is
attempted.
"""

from __future__ import annotations

import os
from typing import Self

from pydantic import BaseModel, Field


class BYOKConfig(BaseModel):
    """Validates that the operator supplied their own API key.

    Attributes:
        api_key_env: Name of the environment variable expected to hold the
            target API key.
    """

    api_key_env: str = Field(min_length=1)

    def resolve(self) -> str:
        """Return the key value from the environment.

        Raises:
            ValueError: if the named environment variable is unset or empty.
        """
        value = os.environ.get(self.api_key_env)
        if not value:
            msg = f"required API key environment variable {self.api_key_env!r} is not set"
            raise ValueError(msg)
        return value

    @classmethod
    def require(cls, api_key_env: str) -> Self:
        """Build a config and confirm the key is present in the environment.

        Raises:
            ValueError: if the named environment variable is unset or empty.
        """
        config = cls(api_key_env=api_key_env)
        config.resolve()
        return config
