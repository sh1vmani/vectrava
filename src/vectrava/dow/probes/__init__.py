"""dow probe implementations.

Importing this package registers every dow probe through its `@register`
decorator. Each probe module is imported here so registration runs on package
import.
"""

from vectrava.dow.probes import token_amplification as _token_amplification  # noqa: F401
