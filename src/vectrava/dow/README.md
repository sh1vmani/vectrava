# dow - Denial-of-Wallet probes

Cost-amplification probes for AI applications. The `dow` module measures how
small, well-formed inputs can drive disproportionate downstream cost, so the
exposure can be budgeted and capped before an attacker finds it. Probes run only
against targets named in a signed scope file, using a key the operator supplies.

| Probe | Severity | What it tests |
| ----- | -------- | ------------- |
| `token_amplification` | MEDIUM | Short prompts that elicit large, costly outputs, measured as the output-to-input token ratio. |
| `output_padding` | MEDIUM | Whether short-answer prompts get responses padded beyond their natural length. |
| `model_substitution` | MEDIUM | Whether the target silently serves a different model than the one requested. |
| `error_amplification` | MEDIUM | Whether failed requests still report token usage, indicating billing at the validation layer. |

See the top-level [README](../../../README.md) for installation, scope signing,
and running.
