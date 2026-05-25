"""ipi probe implementations.

Importing this package registers every ipi probe through its `@register`
decorator. Each probe module is imported here so registration runs on package
import.
"""

from vectrava.ipi.probes import direct_override as _direct_override  # noqa: F401
