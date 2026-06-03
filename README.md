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

Release history and notable changes are tracked in
[CHANGELOG.md](./CHANGELOG.md).

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
| `dow` | `concurrency_amplification` | MEDIUM | Dispatches a small burst of identical requests concurrently on one credential and flags the endpoint when most return 200 and none return HTTP 429, indicating absent concurrency-level rate limiting. |
| `dow` | `error_amplification` | MEDIUM | Failed requests still report token usage, indicating billing on validation-rejected inputs. |
| `dow` | `model_substitution` | MEDIUM | Target silently serves a different model than the one requested. |
| `dow` | `output_padding` | MEDIUM | Short-answer prompts whose responses are padded beyond their natural length. |
| `dow` | `rate_limit_bypass` | MEDIUM | Sends a deterministic burst of minimal requests and flags the endpoint when none are answered with HTTP 429, indicating absent rate-limit hardening. |
| `dow` | `token_amplification` | MEDIUM | Short prompts that elicit large, costly outputs (output-to-input token ratio). |
| `ipi` | `direct_override` | HIGH | Instruction-override payload smuggled in untrusted data overrides the trusted task. |
| `ipi` | `exfiltration_attempt` | CRITICAL | Injected user message extracts confidential content from the system prompt. |
| `ipi` | `multi_turn_buried_instruction` | HIGH | Tests whether an instruction planted once in the first user turn and left unreinforced still binds the model when a later turn springs it after several benign filler turns. |
| `ipi` | `multi_turn_persistence` | HIGH | Tests whether a directive injected in the first user turn persists across later turns, leaking a canary token into replies after the injection turn. |
| `ipi` | `multi_turn_refusal_erosion` | HIGH | Tests whether a benign frame built over several turns erodes the target's refusal posture, leaking a protected system-prompt codeword on the final turn. |
| `ipi` | `refusal_bypass` | HIGH | Jailbreak framings (hypothetical, educational pretext, roleplay) talk the model past its refusal. |
| `rag` | `citation_hijack` | HIGH | Adversarial chunk makes the model attribute a fabricated value to a legitimate source. |
| `rag` | `cross_document_injection` | HIGH | An instruction split across retrieved chunks is assembled and followed. |
| `rag` | `cross_source_contradiction` | HIGH | Model prefers an adversarial value when retrieved sources contradict each other. |
| `rag` | `exfiltration_sink` | CRITICAL | Retrieved chunk induces the model to embed marker data inside a markdown image or link URL, an exfiltration channel a rendering client auto-fetches. |
| `rag` | `prompt_leak_via_retrieval` | HIGH | Tests whether a crafted user query makes the target reveal the retrieval template and scaffolding that wraps retrieved sources. |
| `rag` | `retrieval_permission_leak` | CRITICAL | Tests whether the target's RAG pipeline enforces per-query permission boundaries on retrieved documents. |

Severity convention: HIGH marks a demonstrated capability whose real-world
impact depends on what the target was protecting. CRITICAL is reserved for
outcomes that are high-impact regardless of context: `exfiltration_attempt`,
where any system-prompt leak is damaging no matter what the prompt held,
`retrieval_permission_leak`, where serving a retrieved document across a
permission boundary is a breach regardless of what the document held, and
`exfiltration_sink`, where embedding data into an auto-fetched URL leaks it
out of band regardless of what the data was.

## Install

Requires Python `>=3.11,<3.14` and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/sh1vmani/vectrava
cd vectrava
uv sync
```

## Quickstart with Ollama (no paid API required)

The fastest way to try vectrava end to end, against a local model, with no paid
API account. Ollama serves an OpenAI-compatible endpoint on localhost, so the
same scan flow works against it.

Step 1: Install Ollama. See [ollama.com](https://ollama.com) for the current
install command for your platform.

Step 2: Pull a small model.

```sh
ollama pull llama3.2:1b
```

Step 3: Generate an Ed25519 signing keypair. This writes `vectrava_ed25519`
(private) and `vectrava_ed25519.pub` (public) into the current directory.

```sh
uv run vtra scope new-key --out-dir .
```

Step 4: Trust the public key. `VECTRAVA_TRUSTED_KEYS` is a comma-separated list
of base64url public keys; the gate trusts nothing by default.

```sh
export VECTRAVA_TRUSTED_KEYS="$(cat ./vectrava_ed25519.pub)"
```

Step 5: Sign the Ollama scope template. It already targets the local Ollama
endpoint, so it runs without edits; adjust `signed_by` if you like. Signing
overwrites the file in place with the signed version.

```sh
cp examples/scope.example.ollama.json ./scope.json
uv run vtra scope sign ./scope.json --key ./vectrava_ed25519
```

Step 6: Run a scan.

```sh
export OLLAMA_KEY=ollama
uv run vtra scan dow --scope ./scope.json --api-key-env OLLAMA_KEY
```

With no `--target`, vectrava probes a local Ollama at `http://localhost:11434`
and prints a note that it detected and is using it; with no `--model`, it selects
a pulled model, preferring `llama3.2:1b`. To pin the model or scan a non-default
host, pass them explicitly:

```sh
uv run vtra scan dow --scope ./scope.json --api-key-env OLLAMA_KEY \
  --target http://localhost:11434 --model llama3.2:1b
```

A note on `OLLAMA_KEY`: vectrava's authorization gate requires a credential
environment variable per its BYOK design, so the tool refuses to run without an
explicit key declaration. Ollama itself ignores the Bearer header vectrava
sends, so any non-empty placeholder works for local inference.

A note on the pricing warning: the tool prints a one-time warning that
`llama3.2:1b` is not in its per-model pricing table, and falls back to a
placeholder rate. This is expected for local models, and the resulting USD cost
figures in the dry-run and audit log are not meaningful for local inference,
where the actual cost is zero.

## Quickstart with a paid API

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
  "targets": ["https://api.openai.com"],
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
  --target https://api.openai.com \
  --api-key-env OPENAI_API_KEY
```

Flags shared across `scan dow`, `scan ipi`, and `scan rag`: `--scope` points at
the signed scope file, `--target` names the base URL to probe (omit it to
autodetect a local Ollama), `--api-key-env` names the environment variable
holding the credential, `--endpoint` overrides the request path appended to the
target, `--model` sets the model id sent in the request body (when omitted it is
resolved from an autodetected local Ollama or the built-in default), `--only`
runs a single named probe, `--list` enumerates a module's probes without scope or
target, `--dry-run` previews token cost without making API calls, `--yes` skips
the cost confirmation prompt that fires above the confirmation threshold,
`--format` selects the report format (`sarif`, `json`, or `html`), `--output`
sets the report path, `--max-requests-per-second` caps the outbound request rate,
`--audit-log` sets the path for the append-only audit record, and `--vendor`
selects the target API protocol and accepts `chat_completions` (the default) or
`messages`. A `messages` scan needs a `--model` valid for that protocol; the
default model id is a chat-completions label, so a `messages` scan with no
`--model` override returns HTTP 400.
`scan dow` adds
`--threshold` and `--padding-threshold` to tune its cost-amplification cutoffs,
`scan ipi` adds `--max-turns` to set the multi-turn conversation length, and
`scan rag` adds `--num-sources` to set how many retrieved chunks each injection
spans.

## Authorization model

A scope file declares which target URLs are authorized and the instant after
which authorization lapses. A scope file is honored only when it is signed by a
key whose public half is listed in `VECTRAVA_TRUSTED_KEYS`. Scans against
unsigned, expired, or untrusted-key-signed scopes are refused before any network
call is made.

Authorization is bounded in time by the deadline, so prefer short windows
(hours or days) over long ones. To extend an engagement, reissue the scope
with a later deadline using `vtra scope re-sign <scope> --key <key> --until
<deadline>`, which keeps the targets and signer and re-signs with a fresh
deadline. To revoke a scope before its deadline, reissue it with a past or
near-term `--until`: the gate refuses the original on expiry. Revocation
rides the deadline check rather than a separate list, so it cannot be
defeated by deleting a file.

## Audit log

For regulated environments, every scan invocation can be recorded to a local
JSONL audit log. It is opt-in: pass `--audit-log <path>` to a `scan` command, or
set `VECTRAVA_AUDIT_LOG_PATH` for the session (the flag wins over the env var). A
scan without either configured behaves exactly as before.

One JSON object is appended per invocation, recording the outcome of both
successful and refused scans (a refusal because of an expired scope is itself
evidence). Each record carries an invocation id, start and end times, the
outcome, the scanned target, the scope signer and authorization deadline, a
finding-severity summary, a SHA-256 digest of the written output report, the
estimated token count and USD cost estimate together with the rate source used
to compute it (`cost_rate_source`, either `model` from the per-model pricing
table or `fallback` when a placeholder rate was applied), and runner host/user.
Credentials are never recorded:
only a SHA-256 fingerprint of the credential and the environment-variable name
appear. If the audit path is configured but not writable, the scan refuses to run
before any network call (fail-closed). Parent directories are created as needed.

Records are hash-chained for tamper-evidence: each record stores a `prev_hash`
field holding the SHA-256 of the previous record's on-disk bytes, so any later
modification, deletion, reordering, or insertion breaks the chain. Concurrent
writers serialize through an exclusive OS file lock held across the tail read
and the append, so records cannot interleave and the chain cannot fork. Run
`vtra audit verify <path>` to walk the chain and report the first record whose
link does not match. The chain detects tampering after the fact; it does not
prevent a write to the file on disk, so pair it with the filesystem and
log-shipping controls appropriate to the environment.

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
