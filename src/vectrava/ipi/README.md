# ipi: Indirect prompt injection payloads

Generators for indirect prompt injection test payloads. The ipi module produces
structured payloads that probe whether untrusted content reaching a model
(documents, web pages, tool output) can override the model's instructions.

## Status

Early development. No generators are implemented yet.

## Posture

Defensive only. Payloads are for testing systems you are authorized to test. ipi
runs only against targets named in a signed scope file. It does not target
third-party systems and refuses to run without authorization.
