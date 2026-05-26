# vectrava

AI application security scanner. Denial-of-Wallet, indirect prompt injection,
and RAG boundary probes.

## What it is

vectrava is a defensive scanner for AI applications. It runs only against
targets you are authorized to test: every scan is gated on an Ed25519-signed
scope file that names the authorized targets and a deadline, and target
credentials are read from environment variables at run time (BYOK), never
bundled with the tool or written to config. The probe payloads are working
exploits and are visible in source under `src/vectrava/{dow,ipi,rag}/probes/`;
the rationale for publishing them is documented in the dual-use section of
[SECURITY.md](SECURITY.md).

## What it tests

vectrava ships three probe modules.

`dow` (Denial-of-Wallet) measures how small or malformed inputs can drive
disproportionate downstream cost: large outputs from short prompts, padded
short answers, silent model substitution, and billing on requests that should
have been rejected at the validation layer.

`ipi` (indirect prompt injection) tests whether untrusted content reaching the
model can override the operator's instructions, extract confidential context,
or talk the model past its refusal behavior.

`rag` (retrieval-augmented generation boundary) tests how the model handles
adversarial retrieved content: instructions split across chunks, fabricated
citations, and contradictions between sources.

| Module | Probe | Severity | Attack class |
| ------ | ----- | -------- | ------------ |
| `dow` | `token_amplification` | MEDIUM | Short prompts that elicit large, costly outputs (output-to-input token ratio). |
| `dow` | `output_padding` | MEDIUM | Short-answer prompts whose responses are padded beyond their natural length. |
| `dow` | `model_substitution` | MEDIUM | Target silently serves a different model than the one requested. |
| `dow` | `error_amplification` | MEDIUM | Failed requests still report token usage, indicating billing on validation-rejected inputs. |
| `ipi` | `direct_override` | HIGH | Instruction-override payload smuggled in untrusted data overrides the trusted task. |
| `ipi` | `exfiltration_attempt` | CRITICAL | Injected user message extracts confidential content from the system prompt. |
| `ipi` | `refusal_bypass` | HIGH | Jailbreak framings (hypothetical, educational pretext, roleplay) talk the model past its refusal. |
| `rag` | `cross_document_injection` | HIGH | An instruction split across retrieved chunks is assembled and followed. |
| `rag` | `citation_hijack` | HIGH | Adversarial chunk makes the model attribute a fabricated value to a legitimate source. |
| `rag` | `cross_source_contradiction` | HIGH | Model prefers an adversarial value when retrieved sources contradict each other. |

Severity convention: HIGH marks a demonstrated capability whose real-world
impact depends on what the target was protecting. CRITICAL is reserved for
outcomes that are high-impact regardless of context; currently only
`exfiltration_attempt`, where any system-prompt leak is damaging no matter what
the prompt held.

## Install

Requires Python `>=3.11,<3.14` and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/sh1vmani/vectrava
cd vectrava
uv sync
```

## Quickstart

End to end, from a fresh checkout to a scan.

Generate an Ed25519 signing keypair. This writes `vectrava_ed25519` (private)
and `vectrava_ed25519.pub` (public) into the chosen directory.

```sh
uv run vtra scope new-key --out-dir .
```

Trust the public key. `VECTRAVA_TRUSTED_KEYS` is a comma-separated list of
base64url public keys; the gate trusts nothing by default.

```sh
export VECTRAVA_TRUSTED_KEYS="$(cat ./vectrava_ed25519.pub)"
```

Copy the template under [`examples/scope.example.json`](examples/scope.example.json)
and edit it: set `targets` to URLs in your authorized scope and
`authorized_until` to a future timestamp. The shape is:

```json
{
  "targets": ["https://api.openai.com/v1/chat/completions"],
  "authorized_until": "2026-12-31T23:59:59Z",
  "signed_by": "Your Name"
}
```

Sign it with the private key.

```sh
uv run vtra scope sign ./scope.json --key ./vectrava_ed25519 --output ./scope.signed.json
```

Set the target API key in the environment. vectrava reads the variable you name
with `--api-key-env`; it is never passed on the command line.

```sh
export OPENAI_API_KEY=sk-...
```

Run a scan.

```sh
uv run vtra scan dow --scope ./scope.signed.json \
  --target https://api.openai.com/v1/chat/completions \
  --api-key-env OPENAI_API_KEY
```

Flags shared across `scan dow`, `scan ipi`, and `scan rag`: `--list` enumerates
a module's probes without scope or target, `--only` runs a single named probe,
`--dry-run` previews token cost without making API calls, `--format` selects the
report format (`sarif`, `json`, or `html`), `--output` sets the report path, and
`--max-requests-per-second` caps the outbound request rate. `scan dow` adds
`--threshold` and `--padding-threshold` to tune its cost-amplification cutoffs.
`scan rag` adds `--num-sources` to set how many retrieved chunks each injection
spans.

## Authorization model

A scope file declares which target URLs are authorized and the instant after
which authorization lapses. A scope file is honored only when it is signed by a
key whose public half is listed in `VECTRAVA_TRUSTED_KEYS`. Scans against
unsigned, expired, or untrusted-key-signed scopes are refused before any network
call is made.

## Audit log

For regulated environments, every scan invocation can be recorded to a local
JSONL audit log. It is opt-in: pass `--audit-log <path>` to a `scan` command, or
set `VECTRAVA_AUDIT_LOG_PATH` for the session (the flag wins over the env var). A
scan without either configured behaves exactly as before.

One JSON object is appended per invocation, recording the outcome of both
successful and refused scans (a refusal because of an expired scope is itself
evidence). Each record carries an invocation id, start and end times, the
outcome, the scanned target, the scope signer and authorization deadline, a
finding-severity summary, and runner host/user. Credentials are never recorded:
only a SHA-256 fingerprint of the credential and the environment-variable name
appear. If the audit path is configured but not writable, the scan refuses to run
before any network call (fail-closed). Parent directories are created as needed.

A single writer per audit-log path is assumed; run concurrent scans against
distinct paths or front them with a log shipper. Tamper-evidence (signing or hash
chaining of records) is left to the operator's log-shipping and filesystem
controls.

## BYOK

Target credentials are read from an environment variable named by
`--api-key-env` at scan time. No credentials live in config files, and none are
bundled with the tool.

## Output formats

Findings are written as SARIF v2.1.0 (the default), JSON, or HTML, selected with
`--format`.

## Security

To report a vulnerability and to read the dual-use disclosure, see
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
