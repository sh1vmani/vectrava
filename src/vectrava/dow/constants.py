"""Shared constants for Denial-of-Wallet infrastructure probes.

The rate_limit_bypass and concurrency_amplification probes both treat the same
set of HTTP responses as evidence that the target pushed back on a request burst
rather than serving it. Defining the set once keeps the two probes from drifting
apart.
"""

from __future__ import annotations

# HTTP statuses that signal the target enforced a rate or concurrency guardrail
# instead of serving the request: 429 Too Many Requests (explicit throttle), 503
# Service Unavailable (load shedding), and 529 (overloaded, used by some
# providers). Any of these across a burst counts as enforcement.
ENFORCEMENT_STATUSES: frozenset[int] = frozenset({429, 503, 529})
