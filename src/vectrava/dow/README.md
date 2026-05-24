# dow: Denial-of-Wallet probes

Cost amplification probes for AI applications. The dow module measures how
small, well-formed inputs can drive disproportionate downstream cost in an AI
system: token amplification, retry storms, expensive tool chains, and runaway
context growth.

## Status

Early development. No probes are implemented yet. The package exists to fix the
module boundary and its public surface.

## Posture

Defensive only. dow exists to quantify cost-amplification exposure so it can be
budgeted and capped before an attacker finds it. It runs only against targets
named in a signed scope file, and only with a key the operator supplies.
