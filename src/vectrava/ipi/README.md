# ipi - Indirect prompt injection probes

Indirect prompt injection probes for AI applications. The `ipi` module tests
whether untrusted content reaching a model (documents, tool output, or a crafted
user turn) can override the operator's instructions, extract confidential
context, or talk the model past its refusal behavior. Each probe plants a fresh
random canary token and reports a finding only when that exact token comes back
in the response. Probes run only against targets named in a signed scope file.

| Probe | Severity | What it tests |
| ----- | -------- | ------------- |
| `direct_override` | HIGH | Resistance to a direct instruction-override payload smuggled in untrusted document content. |
| `exfiltration_attempt` | CRITICAL | Whether an injected user message extracts a confidential token from the system prompt. |
| `refusal_bypass` | HIGH | Whether jailbreak framings (hypothetical scenario, educational pretext, roleplay override) defeat the model's refusal. |

See the top-level [README](../../../README.md) for installation, scope signing,
and running.
