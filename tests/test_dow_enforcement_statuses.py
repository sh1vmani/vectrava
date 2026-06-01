"""Coupling guard for the shared Denial-of-Wallet enforcement-status set.

rate_limit_bypass and concurrency_amplification must classify the same HTTP
statuses as enforcement. Both import the single ENFORCEMENT_STATUSES constant;
this test fails if either probe stops referencing that shared object, so the two
detection predicates cannot silently drift apart.
"""

from __future__ import annotations

from vectrava.dow import constants
from vectrava.dow.probes import concurrency_amplification, rate_limit_bypass


def test_enforcement_statuses_value() -> None:
    assert frozenset({429, 503, 529}) == constants.ENFORCEMENT_STATUSES


def test_both_probes_share_one_enforcement_set() -> None:
    # Read the name bound in each probe module, not a re-exported attribute, so the
    # check proves both probes point at the one shared frozenset object.
    assert vars(rate_limit_bypass)["ENFORCEMENT_STATUSES"] is constants.ENFORCEMENT_STATUSES
    assert vars(concurrency_amplification)["ENFORCEMENT_STATUSES"] is constants.ENFORCEMENT_STATUSES
