"""rag probe implementations.

Importing this package registers every rag probe through its `@register`
decorator. Each probe module is imported here so registration runs on package
import.
"""

from vectrava.rag.probes import citation_hijack as _citation_hijack  # noqa: F401
from vectrava.rag.probes import cross_document_injection as _cross_document_injection  # noqa: F401
from vectrava.rag.probes import (
    cross_source_contradiction as _cross_source_contradiction,  # noqa: F401
)
from vectrava.rag.probes import exfiltration_sink as _exfiltration_sink  # noqa: F401
from vectrava.rag.probes import (
    prompt_leak_via_retrieval as _prompt_leak_via_retrieval,  # noqa: F401
)
from vectrava.rag.probes import (
    retrieval_permission_leak as _retrieval_permission_leak,  # noqa: F401
)
