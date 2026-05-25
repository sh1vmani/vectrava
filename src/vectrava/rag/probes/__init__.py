"""rag probe implementations.

Importing this package registers every rag probe through its `@register`
decorator. Each probe module is imported here so registration runs on package
import.
"""

from vectrava.rag.probes import cross_document_injection as _cross_document_injection  # noqa: F401
