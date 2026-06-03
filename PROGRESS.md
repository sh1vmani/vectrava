# Progress

## Current state

vectrava is feature-shaped. The three scanner modules are live, the three
output writers are live, the authorization gate is signed-scope with audit
logging. The day-close sections below carry the running record. For shipped
capability, see the most recent "State at end of Day N" block. For what is
open, see the most recent "Carry-forward still pending" block.

### Done

- Package structure for the three modules: `dow`, `ipi`, `rag`.
- Authorization gate: scope-file check enforced in code, with tests that prove
  it rejects missing, malformed, and expired scope files.
- BYOK config: target API key is read from the environment and validated, never
  shipped or stored.
- Output writer interfaces: SARIF v2.1.0, HTML, JSON (stubs).
- Tooling: uv, ruff (lint and format), mypy strict, pytest with hypothesis.
- CI matrix across Python 3.11, 3.12, 3.13 on Linux, macOS, and Windows.
- Supply-chain and quality workflows: CodeQL, OpenSSF Scorecard, DCO check,
  secret scanning. Scorecard is pinned to a specific release tag (v2.4.3).
  Both run on every push to main and on a weekly schedule; CodeQL also runs
  on pull requests.
- Standard repository files: README, LICENSE (Apache 2.0), CONTRIBUTING,
  CODE_OF_CONDUCT, SECURITY, MAINTAINERS.
- Expanded allowed Conventional Commits scopes to include workflow-name scopes.
  Added scope enforcement to the commit-msg hook to prevent future drift. The
  hook now rejects malformed format or unlisted scopes at commit time.
- Probe architecture: a `Probe` ABC, a `Finding` model with a five-level
  `Severity` scheme, and a probe registry, all in `core/` so the ipi and rag
  modules reuse them. New CLI surface `vtra scan dow` with `--list`, `--only`,
  `--dry-run`, and a cost confirmation prompt above 50,000 estimated tokens.
  Added the `vtra` entry point alongside `vectrava`. No dow probes yet.

### Day 2 close (2026-05-24)

Day 2 delivered the commit-scope governance fix and the dow module architecture
(`core/result.py`, `core/probe.py`, `core/registry.py`, plus the new CLI
surface). 29 tests passing. Next: Part 3, the token amplification probe, which
is the first concrete dow probe.

### Day 3 close (2026-05-24)

Parts 3 and 4 landed the first concrete dow probe and its HTTP client, in two
commits in order:

- `d528461` fix(test): repair pre-existing mypy strict violations in core
  tests.
- `e908b11` feat(dow): add token amplification probe.

New artifacts:

- `src/vectrava/dow/client.py`: a synchronous httpx wrapper. A single
  `call_completion` free function builds an OpenAI-compatible chat-completions
  request and returns the `TokenUsage` and `CompletionResult` Pydantic models.
  It enforces the full `ProbeError` contract across seven failure modes:
  transport error, timeout, 429, 401 and 403, generic 4xx, generic 5xx, and
  2xx with missing usage.
- `src/vectrava/dow/probes/token_amplification.py`: the first concrete dow
  probe. It sends five benign volume-eliciting prompt categories
  (enumeration, long_form_generation, bounded_repetition, format_expansion,
  verbose_explanation), compares output tokens to input tokens, and emits a
  finding when the ratio meets the threshold. Default threshold 15.0, a
  probe-imposed 512-token output cap, and a `Severity.MEDIUM` baseline.
- `tests/test_dow_client.py` (9 tests) and
  `tests/test_dow_token_amplification.py` (7 tests). All use
  `httpx.MockTransport`, with no network and no environment reads.

Changes to existing code:

- `src/vectrava/cli.py`: added `--threshold` (default 15.0, minimum 1.0) and
  `--model` (default gpt-4o-mini) options to `scan dow`, plumbed through
  `ctx.options` as a JsonValue map.
- `src/vectrava/dow/probes/__init__.py`: imports `token_amplification` so the
  `@register` decorator runs on package import.
- `tests/test_core_probe.py` and `tests/test_core_result.py`: added missing
  type annotations to satisfy mypy strict on tests. These were pre-existing
  violations, not introduced by Part 3.

Verification gates expanded:

- mypy strict now runs on `src tests`, not just `src`. This caught seven
  pre-existing test-side type holes that landed in commit `d528461`.
- 45 tests passing, up from 29 at Day 3 start (16 from the two new test
  files).
- All four gates clean on HEAD `e908b11`: ruff check, ruff format --check,
  mypy src tests, and pytest.
- CI green (1m29s) and No Secrets green (8s). CodeQL and Scorecard correctly
  skipped under the private-repo gate.

Design decisions, recorded so the reasoning survives:

- Synchronous over async. `Probe.run` is synchronous per the documented Probe
  ABC contract. Async would touch `probe.py`, the `cli.py` runner loop, and
  the test harness at once for no benefit on a sequential probe.
- Free function over a client class. The runner owns the `httpx.Client`
  lifetime through a `with` block, so a stateful wrapper would duplicate
  ownership.
- Credential resolved at scan time, not in the client wrapper.
  `BYOKConfig.resolve()` already runs in `_run_scan`; the wrapper takes a
  resolved string and never an env-var name.
- No client-side token estimation when usage is missing. Estimating would
  inject error into the headline signal, so missing usage raises `ProbeError`.
- No retries on Day 3. tenacity is deferred. A 429 raises `ProbeError` rather
  than producing a finding; a rate-limiting-present finding is a future
  enhancement gated behind the retry work.
- Probe-imposed 512-token cap. Defensive posture: the probe measures
  asymmetry and must not become a cost generator itself. A `finish_reason` of
  "length" under that cap shows the target has no smaller server-side budget.
- Threshold 15.0 rather than 20.0, so the default fires reliably against the
  512-token self-cap on the short Day 3 prompts.

Open items carried forward:

- Output writers (`src/vectrava/output/sarif.py`, `html.py`,
  `json_writer.py`) still raise `NotImplementedError`. SARIF is the Day 3
  evening or Day 4 target.
- tenacity retry and backoff for transient HTTP failures: deferred.
- `--model` is per-scan; there is no model-list discovery against target
  endpoints.
- The Week 12 gate-removal task on `codeql.yml` and `scorecard.yml` remains
  open.

Part 5 added the SARIF v2.1.0 output writer, in two further commits in order:

- `817f9e8` chore(build): vendor SARIF v2.1.0 schema and add jsonschema
  dependencies.
- `d5deb10` feat(output): implement SARIF v2.1.0 writer and wire into CLI.

New artifacts:

- `src/vectrava/output/schemas/sarif-2.1.0.json`: the OASIS SARIF v2.1.0
  schema, vendored byte-for-byte from the oasis-tcs/sarif-spec `main` branch
  (`sarif-2.1/schema/sarif-schema-2.1.0.json`). SHA-256
  `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`.
- `src/vectrava/output/schemas/__init__.py`: package marker so
  `importlib.resources` can locate the vendored schema.
- `src/vectrava/output/sarif.py`: a full rewrite of the `NotImplementedError`
  stub. `build_sarif_log` is a pure assembler that returns the SARIF dict;
  `write_sarif` validates against the vendored schema and writes to disk. Free
  functions, no class.
- `tests/test_output_sarif.py`: 12 tests, all offline, no network and no
  environment reads.

Changes to existing code:

- `pyproject.toml`: `jsonschema>=4` as a runtime dependency and
  `types-jsonschema>=4` as a dev dependency.
- `uv.lock`: regenerated with jsonschema 4.26.0 plus its transitives (`attrs`,
  `jsonschema-specifications`, `referencing`, `rpds-py`) and
  types-jsonschema 4.26.0.20260518 in the dev group.
- `src/vectrava/cli.py`: `_emit_findings` dispatches to `write_sarif` when the
  format is `sarif`; the `json` and `html` paths are preserved as the interim
  JSON dump. `_run_scan` records `started_at` and computes `exit_code` before
  calling `_emit_findings`, then passes the invocation context (`started_at`,
  `execution_successful`, `exit_code`, `arguments=sys.argv[1:]`) to the writer.

SARIF feature coverage (Standard, not Maximal):

- `runs[0].tool.driver` with `name`, `version`, `informationUri`, and `rules`.
- `runs[0].results[]` with `ruleId`, `ruleIndex`, `level`, `message`,
  `locations[].physicalLocation.artifactLocation`,
  `partialFingerprints["vectrava/v1"]`, and a properties bag carrying the
  original `Finding.evidence` plus a `severity` key holding the five-level
  Severity name for consumers that want it.
- `runs[0].invocations[]` with `executionSuccessful`, `exitCode`,
  `startTimeUtc`, `endTimeUtc`, and `arguments` when provided.
- `runs[0].artifacts[]` deduplicated by URI and sorted by URI for
  deterministic output.
- Excluded: taxonomies, code flows, graphs, conversions, fixes, suppressions.

Design decisions, recorded so the reasoning survives:

- Severity to SARIF level follows the existing docstring table in
  `src/vectrava/core/result.py`: INFORMATIONAL and LOW map to `note`, MEDIUM
  to `warning`, HIGH and CRITICAL to `error`. I initially locked a different
  mapping (LOW to `warning`) and reversed it after the implementation pass
  surfaced the conflict against `result.py`'s existing convention.
- The `security-severity` numeric values also come from that table: 0.0, 2.0,
  5.0, 7.5, 9.0.
- Partial fingerprint inputs are `sha256(rule_id|target|category)` truncated
  to 16 hex chars, keyed under `partialFingerprints["vectrava/v1"]`. Volatile
  signals (the ratio, latency) are excluded so fingerprints stay stable across
  scans.
- The `arguments` parameter on `build_sarif_log` defaults to None and is
  omitted from the SARIF document when None. The CLI passes `sys.argv[1:]`
  explicitly; the writer never auto-collects argv, so test calls do not
  silently capture pytest's argv.
- The emitted `$schema` field uses the GitHub raw URL (matching modern
  emitters such as checkov), not the schema's internal `docs.oasis-open.org`
  id, since that host has had reachability issues historically.
- Schema validation defaults to on in production `write_sarif` calls and fails
  closed: a non-conformant log raises `SarifValidationError` and no file is
  written. A `validate=False` escape hatch exists only for local builder
  debugging.
- Argument scrubbing in `invocations[].arguments` is the CLI's responsibility,
  not the writer's. The writer emits whatever list it is passed; the
  `--api-key-env` value redaction lives in the CLI.

Tests added (12, all offline):

- `test_zero_findings_produces_valid_log`
- `test_single_finding_includes_rule_and_artifact`
- `test_severity_to_level_mapping` (covers all five severities)
- `test_partial_fingerprints_are_stable`
- `test_arguments_omitted_when_none`
- `test_arguments_emitted_when_provided`
- `test_dedup_artifacts`
- `test_unregistered_rule_id_synthesizes_fallback_rule`
- `test_write_sarif_writes_file_and_validates`
- `test_write_sarif_validation_failure_raises_and_does_not_write`
- `test_security_severity_numeric_emitted_on_rule_properties`
- `test_evidence_preserved_in_result_properties`

Verification gates, scope expanded this session:

- 57 tests passing on HEAD `d5deb10`, up from 45 earlier this session and 29
  at Day 3 start.
- mypy strict still clean across 32 source files.
- CI green on HEAD (58s) and No Secrets green (9s). CodeQL and Scorecard
  correctly skipped under the private-repo gate.

Open items carried forward, revised after Part 5:

- Output writers: SARIF is now implemented. `json_writer.py` and `html.py`
  still raise `NotImplementedError`, and the CLI falls back to the interim
  JSON dump for both. These remain open.
- tenacity retry and backoff for transient HTTP failures: still deferred.
- Scope-file signature verification: still open, listed under Not done, and
  will need its own focused session.
- The Week 12 gate-removal task on `codeql.yml` and `scorecard.yml`: still
  open.
- No end-to-end smoke test yet that drives `_run_scan` against a mock target
  and validates the SARIF output through the real flow. Each piece (probe,
  client, writer) is unit-tested in isolation today. This is the next item on
  the Day 3 evening plan.

Step B added an end-to-end integration test, closing the integration gap, in
one commit:

- `8e0c886` test(test): add end-to-end integration tests for dow scan and SARIF
  output.

New artifact:

- `tests/test_integration_dow_scan.py`: 152 lines, three tests. Drives the full
  `scan dow` path through the real CLI entry point: argument parsing, the
  authorization gate, probe registration and selection, the probe running
  against a mocked httpx transport, the SARIF writer, and schema validation
  inside `write_sarif`. No network and no real environment reads.

Test cases:

- `test_clean_scan_emits_zero_finding_sarif`: exit 0, empty results,
  `invocations[0].executionSuccessful` true.
- `test_findings_scan_emits_results_sarif`: exit 1, five findings, every
  `ruleId` is `token_amplification`, correct SARIF structure.
- `test_probe_failure_emits_invocation_unsuccessful_sarif`: exit 2,
  `executionSuccessful` false.

Each piece (probe, client, writer) was unit-tested in isolation before this
commit; the integration test exercises the wiring between them through the real
CLI entry.

Design notes:

- `httpx.Client` is monkeypatched to inject `MockTransport`, the established
  precedent from `test_cli_scan_dow.py`.
- The registry is cleared and re-registered per test, because the
  `_load_module_probes` cached import is a no-op after the first call and does
  not re-trigger `@register`.

Step C added the second concrete dow probe, in one commit:

- `dcf3134` feat(dow): add output padding probe.

New artifacts:

- `src/vectrava/dow/probes/output_padding.py`: 121 lines. Measures whether the
  target inflates responses to short-answer prompts far beyond the natural
  answer length. A response that burns many tokens for a one-word answer wastes
  cost on every call, a Denial-of-Wallet vector distinct from the large-output
  amplification measured by `token_amplification`.
- `tests/test_dow_output_padding.py`: 193 lines, eight tests.

Changes to existing code:

- `src/vectrava/dow/probes/__init__.py`: added the `output_padding` side-effect
  import so the `@register` decorator runs on package import.

Probe design:

- Four short-answer categories with per-category expected-content ceilings:
  arithmetic (12), single_fact (16), yes_no (8), boolean_classification (8).
- `PROMPTS` is a tuple of three-tuples `(category, prompt,
  expected_max_content_tokens)`, a deliberate divergence from
  `token_amplification`'s two-tuple because the per-category ceiling is the
  signal.
- `padding_ratio = completion_tokens / expected_max_content_tokens`. The probe
  reads `ctx.options.get("padding_threshold", 4.0)` and does not consume the
  amplification `threshold` key, since the two metrics are incompatible on a
  single scale. A dedicated `--padding-threshold` CLI flag is deferred.
- Reuses `call_completion` with no client changes. `PROBE_MAX_TOKENS` is 256,
  smaller than `token_amplification`'s 512, since short answers need no
  headroom. Baseline severity MEDIUM, tags `dow`, `cost`, `padding`.

Decisions deferred:

- Fingerprint: `prompt_category` is in evidence, so the existing `_fingerprint`
  in `sarif.py` is correct and collision-free. The D19
  `fingerprint_discriminator` ClassVar design (option b) was pre-specified for
  the first probe lacking `prompt_category` but deferred on YAGNI grounds; the
  ipi and rag probes are the real trigger.
- ABC extension: deferred. No new ClassVars, no change to `core/probe.py`.

Verification after Step C:

- 68 tests passing (60 after the integration test, plus 8 new output_padding
  tests).
- Both probes listed by `vtra scan dow --list`: `output_padding` and
  `token_amplification`, both medium severity.
- mypy strict clean across 35 source files.
- CI green on HEAD `dcf3134` (1m5s), No Secrets green (16s). CodeQL and
  Scorecard skipped under the private-repo gate.

Open items carried forward, revised after Step C:

- The integration gap is now closed.
- The dow module now has two concrete probes. A third probe (model substitution
  detection) is the planned next step.
- The `padding_threshold` CLI flag is still deferred.
- `json_writer.py` and `html.py` still raise `NotImplementedError`, tenacity
  retry and backoff is still deferred, scope-file signature verification is
  still open, and the Week 12 gate-removal task on `codeql.yml` and
  `scorecard.yml` remains open.

Step D added the third concrete dow probe, in one commit:

- `2859e4a` feat(dow): add model substitution probe.

New artifacts:

- `src/vectrava/dow/probes/model_substitution.py`: 112 lines. Measures whether
  the target serves the model the operator requested. Single-shot: one request
  with a 16-token output cap, comparing `CompletionResult.model` to the model
  in `ctx.options["model"]`.
- `tests/test_dow_model_substitution.py`: 188 lines, nine tests.

Changes to existing code:

- `src/vectrava/dow/probes/__init__.py`: added the `model_substitution`
  import in alphabetical order.

Probe design:

- Single-shot, no `PROMPTS` loop. One request, at most one finding per scan.
  `PROBE_MAX_TOKENS` is 16, since only the response envelope is needed, not the
  output content.
- Consumes only `ctx.options["model"]`. Reads no threshold key of any kind, and
  adds no CLI flag.
- Three outcomes: an exact match emits no finding; a non-null mismatch emits a
  MEDIUM finding with `match_status` `mismatch`; a null reported model emits an
  INFORMATIONAL finding with `match_status` `unreported`.
- Per-finding level override: the unreported case calls
  `make_finding(level=Severity.INFORMATIONAL)`, so the mismatch and unreported
  findings carry different SARIF levels while the rule's
  `defaultConfiguration.level` uses the MEDIUM baseline.
- String comparison only. The probe cannot resolve a deployment alias to a
  canonical model name and cannot rank model cost direction, so a mismatch is
  flagged for human triage rather than judged an upgrade or a downgrade. The
  raw `requested_model` and `reported_model` strings are in evidence for triage.

Decisions deferred:

- Exit code: an INFORMATIONAL finding (unreported model) still drives the scan
  to exit 1 under the existing exit-code logic. Accepted for Day 3; targets like
  Azure deployments that do not echo the model name will exit 1 even though no
  cost manipulation is confirmed. A severity-threshold exit-code option is
  deferred.
- Fingerprint: the probe emits at most one finding per target, so the
  empty-string discriminator fallback is safe per D9's own safety condition. No
  `fingerprint_discriminator` ClassVar, and the D9/D19 deferral still holds.
- ABC extension: deferred. No new ClassVars, no change to `core/probe.py`.

Verification after Step D:

- 77 tests passing.
- All three dow probes listed by `vtra scan dow --list`: `model_substitution`,
  `output_padding`, and `token_amplification`, all medium severity.
- mypy strict clean across 37 source files.
- CI green on HEAD `2859e4a` (1m1s), No Secrets green (10s). CodeQL and
  Scorecard skipped under the private-repo gate.

Open items carried forward, revised after Step D:

- The dow module now has three concrete probes covering three distinct
  Denial-of-Wallet vectors. A fourth probe is under consideration but not yet
  planned; Step E will assess remaining time and whether to go deeper on dow or
  pivot to scope-file signature verification, the first ipi probe, or the JSON
  and HTML output writers.
- All other open items from the Step C carry-forward remain open: the
  `padding_threshold` CLI flag, the `json_writer.py` and `html.py` stubs,
  tenacity retry and backoff, scope-file signature verification, and the Week 12
  gate-removal task on `codeql.yml` and `scorecard.yml`.

Step E hardened the authorization gate to require signed scope files, in two
commits:

- `5b0315b` feat(cli): add scope signing infrastructure and vtra scope commands.
- `a737b5f` feat(core): require signed scope files for authorization.

New artifacts:

- `src/vectrava/core/signing.py` provides the Ed25519 signing path:
  `b64url_encode` and `b64url_decode` for the wire format, `canonical_payload`
  (Pydantic `model_dump` with the two signature fields stripped, then
  `json.dumps` with `sort_keys=True` and compact separators) so the bytes
  signed are stable across reformatting, `generate_keypair`, `sign_scope`,
  `verify_scope`, and `trusted_public_keys` which reads `VECTRAVA_TRUSTED_KEYS`
  (comma separated base64url public keys) and fails closed on an empty
  environment.
- `vtra scope` subcommand group: `new-key` prints a fresh Ed25519 keypair,
  `sign` writes `signature` and `public_key` into a scope JSON in place,
  `verify` checks a scope file against the current `VECTRAVA_TRUSTED_KEYS`.
- `tests/test_core_signing.py` covers the 8 round-trip and tamper cases for the
  signing primitives.
- `tests/conftest.signed_scope_factory` generates a fresh ephemeral Ed25519
  keypair per call, signs the scope, embeds `signature` and `public_key`,
  writes the JSON, and registers the public key in `VECTRAVA_TRUSTED_KEYS` via
  `monkeypatch.setenv` so tests do not bleed keys.

Changes to existing code:

- `ScopeFile` gains optional `signature: str | None` and
  `public_key: str | None` fields, both defaulting to `None`. The defaults
  preserve the direct `ScopeFile(...)` construction sites in the three
  `test_dow_*.py` files, which build models in process and never invoke the
  gate.
- `AuthorizationGate.check()` now requires both fields to be present, requires
  the embedded public key to appear in `VECTRAVA_TRUSTED_KEYS`, verifies the
  Ed25519 signature, and only then evaluates the expiry window. Unsigned
  scopes, untrusted keys, and invalid signatures each raise `AuthorizationError`
  with a distinct message.
- `tests/conftest.valid_scope_file` delegates to `signed_scope_factory`, so
  `tests/test_integration_dow_scan.py` and any other consumer get a signed
  scope without further changes.
- `tests/test_auth_gate.py` migrated the expired-scope test to a
  signed-but-expired scope (matched on `expired`) and added
  `test_gate_rejects_unsigned_scope` and `test_gate_rejects_untrusted_key`.
- `tests/test_cli_scan_dow.py` dropped its local `_write_scope` helper in favor
  of `signed_scope_factory`, and pruned the now-unused `json` and `datetime`
  imports.

Design decisions:

- Full non-repudiation, not integrity-only. The gate refuses to run unless the
  embedded public key is listed in `VECTRAVA_TRUSTED_KEYS` at scan time, so a
  passing scan is provably authorized by an operator whose key the running
  environment already trusted. An integrity-only path (verify against the
  embedded key with no trust root) was considered and rejected: it would only
  catch tampering, not unauthorized signers.
- Ed25519, not RSA or ECDSA. Keys and signatures are short, the primitive is
  misuse-resistant, and `cryptography` ships it directly.
- Canonical payload via `model_dump(mode='json')` with the two signature fields
  removed, then `json.dumps(..., sort_keys=True, separators=(',', ':'))`. The
  same byte sequence is signed by `sign_scope` and verified by `verify_scope`,
  so a scope JSON that gets reformatted in transit (whitespace, key order) still
  verifies.
- Phase split. Phase 1 landed the signing primitives, the CLI commands, and the
  optional `ScopeFile` fields without touching the gate, so the suite stayed
  green at `5b0315b`. Phase 2 flipped the gate and migrated every gate-facing
  fixture in a single atomic commit at `a737b5f`, so the suite was green on both
  sides of the cutover.

Verification after Step E:

- 87 tests passing. The 8 `test_core_signing.py` tests landed with Phase 1 and
  were part of the 85 baseline; Phase 2 added two `test_auth_gate.py` rejection
  tests, taking the count to 87. The expired-scope test was migrated, not added.
- mypy strict clean across 39 source files.
- CI green on HEAD `a737b5f` (59s), No Secrets green (9s). CodeQL and Scorecard
  skipped under the private-repo gate.

Open items carried forward, revised after Step E:

- Scope-file signature verification is done. The gate refuses unsigned scopes,
  untrusted keys, and invalid signatures, and the `vtra scope` commands give
  operators a way to mint keys and sign scope files.
- All other open items from the Step D carry-forward remain open: the
  `padding_threshold` CLI flag, the `json_writer.py` and `html.py` stubs,
  tenacity retry and backoff, and the Week 12 gate-removal task on `codeql.yml`
  and `scorecard.yml`.
- Day 3 has run long. The next session decides whether to push further on dow
  (a fourth probe, or the `padding_threshold` flag), start the JSON or HTML
  writers, begin the ipi module, or close out the tenacity work.

Step F shipped three runtime and output improvements plus one CI fix,
in four commits:

- `43e5e40` feat(core): add tenacity retry and backoff for httpx calls.
- `ff332ba` feat(output): implement JSON writer.
- `8bf623a` feat(cli): add padding_threshold flag for output_padding
  probe.
- `0833173` fix(test): make padding_threshold rejection assertion
  CI-portable.

New artifacts:

- `src/vectrava/core/http.py` exposes a single sync primitive,
  `post_with_retry`, that wraps an `httpx.Client.post` in a
  `tenacity.Retrying` policy. It retries `httpx.TransportError`,
  `httpx.TimeoutException`, and the retryable status set
  {429, 500, 502, 503, 504}; other 4xx and 501 pass through
  unchanged. Retry-After is honored when present, parsed as numeric
  seconds first and HTTP-date second (via
  `email.utils.parsedate_to_datetime`), capped at `wait_max_s`, with
  `tenacity.wait_exponential_jitter` as the fallback when the header
  is absent or unparseable. Retries exhausted on a status return the
  last response; retries exhausted on an exception re-raise. The
  caller decides translation.
- `tests/test_core_http.py` covers retry-then-success on each
  retryable status, Retry-After honoring on 429, no-retry on
  non-retryable statuses (400, 404, 501), transport and timeout
  retry-then-success, and the three exhaustion paths.
- `src/vectrava/output/json_writer.py` is rewritten from a
  `NotImplementedError` stub into a real writer with the same shape
  as the SARIF writer: `build_json_report` is a pure assembler
  returning a dict envelope, `write_json` builds and writes. The
  envelope has six top-level keys: `schema_version` (string `"1"`),
  `started_at`, `execution_successful`, `exit_code`, `arguments`,
  and `findings`. Findings are emitted as
  `Finding.model_dump(mode='json')`. The Pydantic model is the
  contract; no external schema validation, because there is no
  external spec (unlike SARIF).
- `tests/test_output_json_writer.py` covers the envelope shape, the
  finding round-trip via `Finding.model_validate`, the empty-findings
  case, the `schema_version` string type, trailing newline and utf-8
  encoding, and key-order preservation.
- A `_CapturingProbe` test class in `tests/test_cli_scan_dow.py`
  records `ctx.options` so the new CLI flag tests can assert the
  flag value reaches the probe.

Changes to existing code:

- `src/vectrava/dow/client.py` keeps `call_completion`'s public
  signature and `ProbeError` translation but now delegates the HTTP
  call to `post_with_retry` through three module-level tunables
  (`_RETRY_MAX_ATTEMPTS`, `_RETRY_WAIT_INITIAL_S`,
  `_RETRY_WAIT_MAX_S`) that tests monkeypatch to zero for speed.
  The 429 `ProbeError` message drops "no backoff is implemented"
  (false now) and reads "target rate-limited the probe (429) and
  retries were exhausted"; the details dict still carries `status`
  and `retry_after`.
- `tests/test_dow_client.py` gains a `_fast_retry` fixture and
  call-count assertions: retryable-path tests expect three handler
  invocations, non-retryable-path tests expect one.
- The three probe-level error-propagation tests in
  `tests/test_dow_token_amplification.py`,
  `tests/test_dow_output_padding.py`, and
  `tests/test_dow_model_substitution.py` flipped their fail-fast
  trigger from HTTP 500 to HTTP 400. The original 500 became
  retryable once tenacity landed, which would have caused those
  probe-layer tests to wait three retries plus assert three handler
  calls instead of one. 400 preserves the test intent (a ProbeError
  on the first prompt halts the probe before later prompts) without
  coupling probe-layer tests to client-layer retry semantics. The
  probe source files were not touched.
- `src/vectrava/cli.py` gains a top-level `write_json` import; the
  `_emit_findings` JSON branch now calls `write_json` with the same
  run-level metadata SARIF receives, replacing the interim inline
  `json.dumps` placeholder. The HTML branch is unchanged. A new
  `--padding-threshold` option is added to `scan_dow` with default
  4.0 and `min=1.0`, threaded through `_run_scan` into
  `ProbeContext.options` as the `padding_threshold` key.
  `src/vectrava/dow/probes/output_padding.py` already read that key
  with an in-probe default, so the probe source was not touched.
- `tests/test_integration_dow_scan.py` gains an `fmt` parameter on
  `_invoke` and three end-to-end JSON cases mirroring the SARIF
  clean/findings/failure shape. The pre-existing SARIF probe-failure
  test flipped its handler from HTTP 500 to HTTP 400 to avoid the
  ~3s of real retry backoff the live tenacity policy introduced;
  test intent (probe-failure-as-exit-2,
  `executionSuccessful=False`) is unchanged.

Design decisions:

- One retry primitive, one consumer. `post_with_retry` is a generic
  sync HTTP helper that knows nothing about completions, chat, or
  dow. `call_completion` is the first consumer and the only one
  today; ipi and rag will use it when they land. A per-module retry
  pattern was considered and rejected: same code three times invites
  three subtly different bugs.
- `tenacity.Retrying` with `retry_any` of `retry_if_exception_type`
  and `retry_if_result`, plus a `retry_error_callback` that inspects
  `retry_state.outcome.failed` to choose raise-vs-return. A manual
  retry loop was considered and rejected: tenacity's policy
  composition (stop, wait, retry predicates, callbacks) is exactly
  the shape this needs, and writing it by hand would reimplement
  tenacity less well.
- JSON envelope as a dict, not a bare findings array. Mirrors SARIF's
  run-level metadata (started_at, execution_successful, exit_code,
  arguments) so a consumer can compare formats apples-to-apples and
  so a JSON-only consumer still gets the same context. The
  `schema_version` key is a string (`"1"`) so a later revision can
  be `"1.1"` or `"2"` without a type change.
- Test-status flips over retry-aware probe tests. Both flips
  (probe-level error tests, SARIF probe-failure integration test)
  preserve the test's actual intent (a ProbeError on the first
  prompt halts the probe; the CLI surfaces probe failure as exit
  code 2 with `executionSuccessful=False`) and decouple the test
  from a behavior it was never meant to assert (retry semantics,
  which have their own dedicated tests in `test_core_http.py` and
  `test_dow_client.py`).
- `--padding-threshold` lives on `scan dow`, not on the `scan`
  group. The flag is probe-specific. When ipi or rag land their own
  threshold knobs, those get their own probe-specific flags. A
  unified namespaced-options system was considered and rejected as
  premature; the second probe-specific flag is the right time to
  reconsider.

Verification after Step F:

- 111 tests passing. +12 from `test_core_http.py`, +6 from
  `test_output_json_writer.py`, +3 JSON integration cases, +3 CLI
  padding-threshold cases, modifications elsewhere.
- Full suite back to 0.71s after the SARIF probe-failure test flip
  reclaimed the ~3s of real retry backoff that landed with tenacity.
- mypy strict clean across 42 source files. tenacity is typed (no
  `import-untyped`).
- CI green on HEAD `0833173` across all nine matrix jobs (Python
  3.11/3.12/3.13 on ubuntu/macos/windows). No Secrets green; CodeQL
  and Scorecard skipped under the private-repo gate.
- One CI failure occurred at HEAD `8bf623a`: the new
  `test_padding_threshold_below_one_rejected` asserted a substring
  of typer's Rich-formatted error panel, which is rendered at the
  detected terminal width. Locally the wider terminal kept the
  flag name in the error text; under CI's narrow non-tty runners
  the panel truncated the line, removing the flag name and
  breaking the substring assertion. All nine matrix jobs failed
  identically; the rejection itself (exit code 2) worked
  everywhere. The fix (`0833173`) replaced the substring check
  with a structural one (exit code 2 plus `result.exception` is
  None or a `SystemExit`), which is what the test was actually
  trying to verify.

Open items carried forward, revised after Step F:

- tenacity retry and backoff is done. The dow client retries
  transient failures (429, 5xx, transport, timeout) with capped
  exponential jitter, honors Retry-After, and translates final
  exhaustion into the same `ProbeError` shape `call_completion`
  always produced.
- The JSON writer is done. `vtra scan dow --format json` emits a
  dict envelope with run-level metadata plus the Pydantic Finding
  list. The HTML writer is still a `NotImplementedError` stub and
  is the only output format still pending.
- The `padding_threshold` CLI flag is done. `--padding-threshold`
  threads through `_run_scan` into `ProbeContext.options` with
  default 4.0 and `min=1.0`.
- Surviving open items: the `html.py` writer stub, and the
  Week 12 gate-removal task on `codeql.yml` and `scorecard.yml`
  (deferred until repo visibility flips public).
- One small inconsistency on the open list: `write_json` emits a
  trailing newline, `write_sarif` does not. A small `fix(output)`
  follow-up can align SARIF if it matters.
- Day 3 ends here. Day 4 picks from: the HTML writer (closes the
  third output format), the first ipi probe (opens the second
  scanner module), or further dow work (a fourth probe, threshold
  tuning). The HTML writer is the natural next step if Day 4
  starts with "finish what we have"; the first ipi probe is the
  natural next step if Day 4 starts with "open the next surface".

### Day 4 close (2026-05-25)

Closed the output triad and opened the second scanner module. Three commits,
all CI-green, mypy strict clean across 47 source files, 136 tests passing (was
111 at end of Day 3, +25).

Commits, in order:

- `d791997` feat(output): implement HTML report writer and wire into CLI.
- `8a0edc8` fix(output): align SARIF writer trailing newline with JSON writer.
- `2efff8a` feat(ipi): activate ipi module and add direct override injection
  probe.

What shipped:

HTML writer (`src/vectrava/output/html.py`). Third and final output format.
stdlib only, no new dependencies. Every probe-controlled or target-controlled
interpolation passes through an `html.escape` wrapper before reaching the
output, making the report safe to open in any browser without CSP concerns.
Inline CSS, no JavaScript, no external assets or remote fonts. Renders a
metadata block (target, started_at, finished_at, duration), an invocation
outcome banner (green/red), and a severity-coded findings table. Severity to
CSS class mapping reuses `sarif.map_level` so both writers stay aligned without
duplicating the mapping. Probe-failure scans render the failure banner with no
findings table, mirroring SARIF's invocation_successful and exit_code
semantics.

SARIF trailing-newline alignment. Closed the Day 3 carry-forward: `write_sarif`
now appends a single trailing newline, matching `write_json`. Both writers now
produce POSIX-clean files. One-line writer change, one targeted regression test
(asserts single trailing newline, no double newline, no UTF-8 BOM, utf-8
round-trip parses).

ipi module activation. Second scanner module live, opens the indirect prompt
injection attack surface. `DirectOverrideProbe` tests resistance to direct
instruction-override injection smuggled into untrusted document content. Three
injection phrasings (direct, authority_claim, role_hijack), each embedding a
fresh `secrets.token_hex(8)` canary. Detection is exact-substring match on
response text. HIGH severity (one notch above dow's MEDIUM baseline; CRITICAL
reserved for future probes demonstrating exfiltration or tool-call hijacking).
Probe calls `core.http.post_with_retry` directly rather than introducing an
ipi-local client wrapper (Rule of Three: shared HTTP abstractions wait until
rag arrives and three users justify the shape).

CLI gains `vtra scan ipi` mirroring `scan dow` minus the dow-specific
`--threshold` and `--padding-threshold` flags. `_run_scan` is module-agnostic
by construction (`importlib.import_module(f"vectrava.{module}.probes")` plus
`registry.by_module`) so no `_run_scan` changes were needed.

Carry-forward to Day 5+:

- `_run_scan`'s `options` dict is hardcoded to `{"threshold", "model",
  "padding_threshold"}`, the dow-shaped key set. `scan_ipi` passes dow defaults
  through and the ipi probe ignores those keys. Friction will grow when rag
  arrives; right fix is a module-generic options grammar once a third module
  gives evidence for the shape.
- `src/vectrava/rag/__init__.py` likely carries a stale scaffold-era docstring
  (mirrors what we found and aligned in `src/vectrava/ipi/__init__.py` this
  day). Trivial to fix when Day 5/6 opens rag.
- Writer interface does not thread `target` through. HTML writer derives target
  from `findings[0].target` when findings exist and renders `n/a` on clean
  scans. A clean (no-finding) HTML report should still name what was scanned.
  Cross-writer interface change, deferred.
- Week 12 gate-removal task on `codeql.yml` and `scorecard.yml` (carried from
  Day 3, still deferred until repo visibility flips public).

State at end of Day 4:

- HEAD: 2efff8a on main
- Total commits: 22 (was 19 at end of Day 3, +3)
- Tests: 136 passing (was 124 at midday, was 111 at end of Day 3)
- mypy strict: clean across 47 source files (was 42)
- All workflows green-or-correctly-skipped on every Day 4 commit (CI ~1m14s to
  1m47s, No Secrets ~10s, CodeQL + Scorecard skipped under the private-repo
  gate)

### Day 5 close (2026-05-25)

Brought the scanner from one-and-a-half modules to three complete modules and
hardened the repository for the Week 12 public flip. 21 commits, all CI-green.
Tests grew 136 to 223, mypy stayed clean across 47 to 62 source files. The rag
module went live with its full probe set, ipi reached three probes, dow gained
a fourth, the CLI options grammar became module-agnostic, the HTTP layer gained
rate limiting, scan-level target now threads through every writer, and the
contributor-facing docs (README, per-module READMEs, CHANGELOG, SECURITY,
CONTRIBUTING, examples, issue and PR templates) were rewritten or added.

Commits, in order:

- `0114b8a` docs(repo): record day 4 progress.
- `c37b423` docs(repo): refresh stale not-done entries.
- `99924e0` feat(rag): activate rag module and add cross-document injection
  probe.
- `bc3d12d` refactor(cli): make _run_scan options grammar module-agnostic.
- `e22bad4` feat(rag): add citation hijack probe and update integration
  scaffold.
- `db136c7` feat(ipi): add exfiltration attempt probe and update integration
  scaffold.
- `bd49f2b` refactor(core): extract chat completion content helper to
  core/probe_helpers.
- `7c372c6` feat(cli): add --num-sources flag to scan rag for retrieval
  distractor testing.
- `155a571` feat(rag): add cross source contradiction probe and extract padding
  helper.
- `2b3b9d1` feat(core): add per-client rate limiting to post_with_retry with CLI
  flag.
- `f82d421` fix(test): replace wall-clock pacing assertion with monkeypatched
  sleep capture.
- `ede8e45` docs(repo): add response time and dual use sections to SECURITY.md.
- `c937a89` feat(ipi): add refusal bypass probe and bring ipi to three probes.
- `79ec915` docs(repo): rewrite README and per-module READMEs for current state.
- `3b4c2e5` feat(output): thread scan-level target through writers.
- `c24df5b` docs(repo): add examples directory with sample scope file.
- `937a13c` feat(dow): add error amplification probe.
- `18a6ebd` test(dow): pin required ClassVars across dow probes.
- `ef76911` docs(repo): refresh CONTRIBUTING and re-sync CLAUDE module sentence.
- `119a64c` docs(repo): add CHANGELOG seeded from project history.
- `4601f58` docs(repo): add GitHub issue and PR templates.

What shipped:

rag module activation and full probe set. The third scanner module went from an
empty scaffold to three probes in one day, in sequence:
`cross_document_injection` first (the activation commit, which opened the
retrieval-boundary attack surface), then `citation_hijack`, then
`cross_source_contradiction`. The third probe is what triggered extraction of
the chunk-padding helper: `cross_document_injection` and `citation_hijack` each
had their own inline padding logic, and when `cross_source_contradiction` needed
the same shape it became the third user, so `interleave_padding_chunks` was
lifted into `core/probe_helpers.py` and all three rag probes now consume it.

ipi module completion to three probes. `direct_override` already existed from
Day 4. This day added `exfiltration_attempt` and `refusal_bypass`.
`exfiltration_attempt` is the only CRITICAL probe in the catalog. Every other
probe tops out at HIGH. The reason is impact: a system-prompt or instruction
leak is high-impact regardless of the surrounding context, because it hands an
attacker the model's hidden configuration and any secrets embedded in it, so it
sits one notch above the override and bypass probes. `refusal_bypass` is HIGH,
matching the rest of the ipi surface.

Module-agnostic `_run_scan` options grammar. The scan runner previously
hardcoded a dow-shaped options dict (`threshold`, `model`, `padding_threshold`)
that ipi had to pass through and ignore. The refactor inverts that: each
`scan_X` command builds its own options dict and the runner stays neutral. The
new grammar was validated end-to-end twice, once with the rag-specific
`--num-sources` flag and once with the cross-cutting
`--max-requests-per-second` flag, so both a module-local option and a shared
option exercise the path.

Shared helper extraction on the Rule of Three trigger. Two helpers moved into
`core/probe_helpers.py` once a third caller justified the shape.
`extract_chat_completion_content` is used by all five injection probes (three
ipi, two of the rag set that read response content), and
`interleave_padding_chunks` is used by all three rag probes. The rule that
landed during the third rag probe: a new probe is written to consume the shared
helper from the start rather than carrying its own copy that gets lifted later.

Per-client rate limiting in `core/http.py`. `post_with_retry` gained a
`min_delay_s` keyword that paces requests per HTTP client, with the per-client
state keyed through a weakref so clients can be garbage collected without
leaking pacing entries. The CLI sets the default pacing at the command layer
(10 requests per second) rather than baking a delay into every probe, so probes
stay pacing-agnostic. The test suite pays no pacing tax: the default in tests is
no delay, and the one pacing test monkeypatches `sleep` rather than measuring
wall-clock time.

dow module diversification. `error_amplification` is the fourth dow probe and it
diverges structurally from the first three. Where `token_amplification`,
`output_padding`, and `model_substitution` go through
`dow.client.call_completion`, `error_amplification` calls `post_with_retry`
directly, because it has to inspect non-2xx response bodies for a usage block:
some providers bill for and report token usage even on error responses, and
`call_completion` raises before that body is reachable. This deliberately breaks
the tidy 3-3-3 probe-count symmetry across modules. Correctness of the probe
beats a cosmetic invariant.

Writer interface target threading. Scan-level target is now a first-class field
through all three writers. The HTML clean-scan path no longer renders `n/a` for
the target when there are zero findings, and SARIF and JSON gained a scan-level
target field they did not previously carry. In SARIF the target lands on
`runs[0].invocations[0].properties.target`, keeping it within the schema rather
than inventing a top-level extension.

SARIF trailing-newline fix. `write_sarif` now emits a single trailing newline to
match `write_json`, closing the Day 3 carry-forward so both writers produce
POSIX-clean files.

dow severity correction. The three pre-existing dow rows in the top-level README
and the dow per-module README were documented as HIGH, but the code sets them
MEDIUM. The code was correct and the docs overstated severity. Fixed in the same
commit that added the fourth dow probe so the table reflects all four rows at
their true severity.

Doc rewrite for Week 12 readiness. `README.md` was rewritten with a probe table
(nine probes, then ten after `error_amplification`), a Quickstart using the real
CLI, and an authorization-model section. The per-module READMEs gained probe
inventory tables. `examples/scope.example.json` and `examples/README.md` were
added as an operator quickstart template for the keypair, signing, and
`VECTRAVA_TRUSTED_KEYS` workflow. `SECURITY.md` gained response-time and
dual-use disclosure sections. `CONTRIBUTING.md` was refreshed to the corrected
18-scope list, the real gate commands, a git-hooks paragraph, and a
dev-scan pointer. `CLAUDE.md` was re-synced with `AGENTS.md` so the module
sentence is byte-identical between them.

CHANGELOG.md added. Seeded from project history in the Keep a Changelog 1.1.0
format with a single `[Unreleased]` section.

GitHub templates added. Two issue templates (bug report and feature request) and
one pull request template under `.github/`, carrying redaction guidance for
credentials and scope files and a checklist mirroring the CONTRIBUTING gates.

Test discipline. `test_required_classvars_set` was backfilled across all four
dow probes so dow now matches the ClassVar pinning that ipi and rag already had.
The writer changes added a clean-scan test per writer covering the zero-findings
target-rendering path.

Process meta. Two of the 21 commits are PROGRESS housekeeping: `0114b8a` wrote
the Day 4 close section itself, and `c37b423` refreshed the then-stale Not-done
bullet. That bullet has since drifted again (it predates the rag module landing
30 minutes later) and is rewritten in this commit.

Carry-forward to Day 6:

- Week 12 gate-removal on `codeql.yml` and `scorecard.yml` is still pending the
  repository public flip, carried since Day 3.
- Scope file revocation: there is no mid-deadline revocation mechanism, a future
  feature.
- Audit log of scan invocations is not implemented, a future feature for
  regulated-environment deployments.
- Multi-turn probe infrastructure (conversational state for probes that need it)
  is a multi-session lift not yet started.
- `README.md` and `CONTRIBUTING.md` do not yet link to `CHANGELOG.md`, a small
  follow-on.
- Environmental observation: pytest occasionally exits 139 on Windows mid-suite,
  a native access violation inside jsonschema's recursive `$ref` descent during
  SARIF schema validation. It is transient, re-runs pass, and it is not a code
  defect, but it is worth knowing.

State at end of Day 5:

- HEAD before this commit: 4601f58
- Total commits: 52 (51 before this commit)
- Tests: 223 passing
- mypy: clean across 62 source files
- Probe inventory: dow 4, ipi 3, rag 3 (10 total)
- Modules active: dow, ipi, rag
- Output writers: SARIF v2.1.0, JSON, HTML
- Workflows: CI green, No Secrets green, CodeQL skipped (private gate), Scorecard
  skipped (private gate)

### Day 6 close (2026-05-26)

Closed the audit-log arc (tamper-evidence, file locking, cost recording), shipped
two-tier cost display, completed HTML evidence rendering, and rebalanced rag to
five probes for a 5-5-5 split across the three modules. Seven commits landed. The
session also completed recon for per-model USD pricing; implementation is deferred
to the next session, with a resume prompt captured in the session transcript.

Landed commits, in order:

- `7a72747` feat(output): render non-turns evidence keys in HTML reports.
- History rewrite: a gitleaks false-positive (a 16-hex test literal that tripped
  the generic-api-key rule) was cleared from history via `reset --soft` plus
  `commit -C 5f1c93a`, then force-pushed with `--force-with-lease`. The rewritten
  commit carries low-entropy placeholders from the start.
- `5382d29` feat(core): hash-chain audit log records for tamper-evidence.
- `19fa07a` feat(core): serialize audit log flushes via OS file lock.
- `f7e6e0d` feat(cli): two-tier cost display for scan commands.
- `4975b2d` feat(core): record per-invocation cost estimate in audit log.
- `29992b4` feat(rag): probe for retrieval permission leakage.

State at end of Day 6:

- Total commits: 70
- Tests: 379 passing
- Probe inventory: dow 5, ipi 5, rag 5 (15 total), a 5-5-5 split
- CRITICAL probes: 2 (`ipi.exfiltration_attempt`, `rag.retrieval_permission_leak`);
  CRITICAL severity now spans two modules
- Audit-log arc complete: tamper-evidence (hash chain), concurrent-writer safety
  (OS file lock), and per-invocation cost recording

Carry-forward closed:

- HTML evidence rendering for non-turns keys.
- Gitleaks false-positive cleared from history.
- Tamper-evidence for the audit log via hash chain.
- Concurrent multi-writer safety for the audit log.
- Two-tier cost display.
- Audit log cost-field capture.
- rag module balance (rag went from 4 to the 5-5-5 split).
- `FILLER_TURNS` lifted to a shared pool when the third multi-turn ipi probe landed.
- Per-model USD pricing table shipped, replacing the `USD_PER_1K_TOKENS` placeholder
  as the default rate; the placeholder remains as the fallback for models absent
  from the table.
- AuthorizationGate class docstring documents the threat model for all six rejection
  paths.
- Audit log records `cost_rate_source` ("model" or "fallback") alongside the existing
  cost fields.
- Workflow visibility gates removed from `codeql.yml` and `scorecard.yml` after the
  repository flipped public.
- PROGRESS.md reconciliation pass aligned the carry-forward lists with shipped state.
- Default model migrated from `gpt-4o-mini` (delisted) to `gpt-5.4-mini`, with
  `DEFAULT_MODEL` centralized in `pricing.py` and consumed by `cli.py` and all 11
  probe fallbacks. An Ollama quickstart, a sample Ollama-targeted scope template, and
  a retitled paid-API quickstart were added so vectrava can be evaluated without
  paying any API costs.
- AuthorizationGate signature-mismatch rejection now attaches the parsed scope to its
  `AuthorizationError`, so a tampered-but-parseable scope produces an audit record that
  captures the claimed signer (`scope_signed_by`), the claimed authorization window
  (`scope_authorized_until`), the claimed public key (`scope_signer_public_key`), and a
  fingerprint of the invalid signature (`scope_signature_sha256`). Two new gate-level
  tests (`test_gate_rejects_signature_mismatch` and
  `test_scope_present_on_signature_mismatch_rejection`) cover the rejection and the
  scope attachment.
- New dow probe `concurrency_amplification` added, testing whether a target serves N
  parallel requests on a single credential without triggering its rate-limit
  guardrails. Severity MEDIUM, matching the dow catalog convention. Sibling to
  `rate_limit_bypass`; the two probes test distinct guardrails (temporal vs
  concurrent), and a target can pass one and fail the other. dow catalog now 6 probes,
  total 17, split 6-6-5.
- pyproject Development Status classifier bumped from "2 - Pre-Alpha" to "3 - Alpha"
  to reflect the project's actual state: feature-shaped with 17 probes, audit-log
  forensics, signed-scope authorization, and a documented quickstart, with breaking
  changes still possible as outstanding carry-forwards (default-endpoint review,
  integration-test hardening) land.

Carry-forward still pending (actionable):

- README shared-flags paragraph omits `--model` and `--yes`. Both flags are real and
  surface in `vtra scan dow --help`; the paragraph should list them.
- PROGRESS.md stale-prose cleanup: the `## Current` marker still says "Week 0," the
  Visibility section still describes a private build flipping at Week 12, the Launch
  tasks (Week 12) section describes completed tasks, and the Done (Week 0) block
  claims CodeQL and Scorecard are gated. Coordinated rewrite needs design recon on
  what replaces "Week N" as the canonical state marker now that the project is
  post-flip and capability-driven.
- Standing convention: test fixtures avoid hex-token literals; use low-entropy
  placeholders (for example `leaked-marker-one`) instead. Recorded after the
  mid-Day-6 gitleaks false-positive.
- Default-endpoint review: vectrava ships an OpenAI-shaped default endpoint
  (`/v1/chat/completions`). Revisiting whether that is the right default would unlock
  non-OpenAI default-model options like `gemini-2.5-flash-lite` ($0.0001/1K, the
  cheapest currently-priced option).
- Integration-test hardening: the integration tests in
  `tests/test_integration_{dow,ipi,rag}_scan.py` rely on the default model rather than
  passing `--model` explicitly. Decoupling them would make a future default change a
  one-line constant flip with zero test fallout.
- Ollama autodetection: when `--target` is omitted, probe `localhost:11434` and use it
  as the default endpoint if reachable. Makes the Ollama quickstart shorter and gives
  vectrava a working zero-config first-run experience when Ollama is installed.

Carry-forward still pending (not actionable):

- Windows pytest exit-139 in jsonschema's recursive `$ref` descent during SARIF
  schema validation. Transient, re-runs pass, not a code defect.
- Broaden `rate_limit_bypass` detection to 503/529 response codes (depends on operator
  reports of false-negative cases in the wild).
- Future scope-schema rps/burst cap fields (coupled to operator schema evolution;
  needs operator-side signal before adding fields).

### Day 7 close (2026-05-28)

Twelve commits this session: the eleven below plus this day-close. Closed every
actionable carry-forward from the session start, fixed three latent defects the
recon step surfaced that were not on the carry-forward, and shipped the first two
units of the vendor-abstraction arc.

Landed commits, in order:

- `1a47bcb` docs(repo): align state docs with post-flip public reality.
- `296083e` test(test): pin explicit model in integration scans.
- `f3b0f7c` docs(core): clarify default model scope and fix stale default comments.
- `348db98` fix(config): require base-URL scope targets to stop path doubling.
- `7c64706` feat(core): autodetect a local Ollama when no target is given.
- `b661a80` feat(cli): resolve an Ollama model for zero-config scans.
- `1cc7198` docs(repo): document shared flags and a zero-config Ollama quickstart.
- `67b6452` fix(test): replace concurrency timing bound with a barrier.
- `a57ebd6` test(test): pin explicit model in cli scan cost tests.
- `a645471` refactor(core): add a vendor adapter and route response parsing through it.
- `b2f304e` refactor(dow): route dow request building through the vendor adapter.

What shipped:

Documentation truth-up. PROGRESS, CLAUDE.md, and AGENTS.md were aligned to the
post-flip public state: the Week-N marker was replaced with a capability-
delegating Current state block that points at the latest day-close. The README
shared-flags paragraph was completed (it had omitted several flags shared across
all three scan commands) and a zero-config Ollama quickstart was added. The Ollama
quickstart command was corrected: it exported a placeholder credential but never
passed the credential-env flag, so it could not run as written. The
default-endpoint review closed as a documentation correction after it found the
model default is a cost-estimate label and request-body field, not a network
endpoint default: there is no default target host, so the target is always
operator-supplied.

Defects fixed. Scope targets must now be base URLs: probes append the endpoint
path, so a full-URL target doubled the path against a live server, and the suite
never caught it because mock transports answer any path. The concurrency probe
test replaced its flaky wall-clock bound with a threading barrier that proves
concurrent dispatch deterministically, after the bound overshot by 1.1ms on a busy
CI runner.

Test decoupling. The three integration files and the cli scan test file no longer
rely on the implicit default model for their cost assertions, so a future default
change is zero-fallout across the suite. The one exception is a single audit-cost
test that intentionally tracks the default through the imported constant.

Zero-config local scanning. Omitting the target flag autodetects a local Ollama at
its default port and resolves a model from its tag list, preferring a known small
id, with an actionable failure when none is reachable or no model is pulled.
Authorization is unchanged: the resolved target still passes the base-URL
validator, the gate, and the exact-string scope membership check.

Vendor-abstraction arc, units 1 and 2a. A VendorAdapter protocol, a normalized
response type, and a chat-completions adapter were added; the dow request path now
builds URLs, bodies, and headers through the adapter, with the custom-endpoint
override preserved and every dow request byte-identical on the wire. Neither unit
changed behavior.

State at end of this session:

- Total commits: 100 (after this carry-forward update lands)
- Tests: 496 passing
- Probe inventory: dow 6, ipi 5, rag 5 (17 total), 6-6-5 split
- CRITICAL probes: 2 (`ipi.exfiltration_attempt`, `rag.retrieval_permission_leak`)
- Repository public; four workflows (CI, No Secrets, CodeQL, Scorecard) green
- Vendor-abstraction arc units 1, 2a, 2b, 2c, 3, and 4 (slice 1) done; HEAD before
  this update is 62a18cb. All three modules build requests through the selected
  adapter; parsing is not migrated (`extract_chat_completion_content` stays final).

Carry-forward closed:

- README shared-flags paragraph (was missing flags).
- PROGRESS, CLAUDE, and AGENTS stale post-flip prose.
- Default-endpoint review (closed as a documentation correction; the goal of a
  cheaper default model from another vendor requires the vendor-abstraction arc,
  scoped below).
- Integration-test implicit-default coupling.
- cli scan implicit-default coupling.
- Ollama autodetection (host probe and model resolution).
- Target-form path-doubling defect (recon-surfaced, not previously listed).
- Ollama quickstart missing the credential flag (recon-surfaced).
- Concurrency-probe wall-clock test flake (recon-surfaced).

Carry-forward still pending:

- Vendor-abstraction arc (Option C). Units 1, 2a, 2b, 2c, 3, and 4 (slice 1) are
  done: a `VendorAdapter` `typing.Protocol`, a `NormalizedResponse` type, a
  `ChatCompletionsAdapter` and a `MessagesAdapter`, and a `--vendor` flag that
  selects the adapter once per scan and threads it on `ProbeContext.adapter`. All
  three modules (dow, ipi, rag) plus the `exchange_turn` and `call_completion`
  helpers build requests through the selected adapter. `NormalizedResponse` carries
  content, prompt/completion/total tokens, finish_reason, reported_model,
  status_code, and raw (the escape hatch `error_amplification` and
  `model_substitution` reasoning depend on); the adapter identifier names the
  protocol, not a provider; finish_reason is identity for chat-completions.
  Locked facts from this arc:
  - `extract_chat_completion_content` stays final. Request building was migrated
    onto the adapter, but parsing was not: ipi, rag, and `exchange_turn` still parse
    chat-completions responses through that helper, and only dow's `call_completion`
    parses via the adapter's `parse_response`.
  - At this close the `--vendor` flag shipped `chat_completions`-only as the
    default, so every existing scope and invocation was byte-identical on the
    wire, and `messages` was a built adapter that was not yet a selectable
    vendor. That gate has since flipped; see the Day 8 close (2026-05-31) below.
    The per-target scope-schema vendor field stays deferred (vendor is a protocol
    property, not an authorization property); scope files carry no vendor field.
  - `model_substitution` reads the echoed request model, so a vendor that does not
    echo the model makes the probe not-applicable. The messages protocol echoes the
    model, so it is applicable there in principle. This nuance lives here in the
    roadmap until a vendor-support matrix exists; it is not in user docs.
  - The pre-commit and commit-msg AI-signature scan was narrowed to attribution
    contexts (Co-Authored-By, Generated with, the noreply email, the code-tool URL)
    so the `anthropic-version` protocol header passes content scanning. The hooks
    are untracked (`.git/hooks` plus the global template, kept byte-identical). New
    md5 baseline: pre-commit `63bfdbc131b8467a4ea4e9ba550a4171`, commit-msg
    `125e78981f109daafa58946a22bca136`, prepare-commit-msg unchanged at
    `323e9495c315b10084387a52a4be358a`.
  This enable-messages work is now complete; see the Day 8 close (2026-05-31)
  below for the five items recorded as closed and mapped to their commits.
- Test-fixture hex-token-literal sweep: standing convention to use low-entropy
  placeholders; an optional one-time sweep, not a closeable task.

Intersperse note for the next session: this session took three same-character
adjacencies deliberately, all read as staged work within the rule's spirit: two
feat commits (autodetect host, then model), a fix-test then test-test pair, and a
refactor run across the adapter units. The refactor run is the one to watch: it is
two deep now (Unit 1 core, 2a dow), and units 2b and 2c, if they land as
refactor(ipi) and refactor(rag), extend it to four or five consecutive refactor
commits. That is accepted as one staged migration but is the project's longest
same-character stretch; the alternative, interleaving artificial non-refactor
commits, is worse.

### Day 8 close (2026-05-31)

The enable-messages arc is complete. `messages` is now a selectable vendor:
`--vendor messages` runs every probe through the messages adapter. The five
items the Day 7 close listed as next scoped work all landed:

- ipi, rag, and `exchange_turn` parsing migrated off
  `extract_chat_completion_content` onto vendor-neutral parsing, and the dow
  request and parse paths were rewired through the selected adapter -> `6ca9c61`.
- dow `total_tokens` now sums the prompt and completion components when the
  vendor reports no combined total -> `ff44c56`.
- `error_amplification` is skipped as not applicable for non-chat-completions
  vendors -> `1cb736d`.
- vendor-aware endpoint defaulting: the default endpoint is resolved from the
  selected adapter, and the missing-content error was made protocol-neutral
  -> `e17d622`, `e4730b8`.
- the gate flipped so `messages` is a selectable vendor -> `51d3b54`.

Reference state before this docs commit: HEAD `51d3b54`, 500 tests passing.

Carry-forward still pending (deferred cosmetics, not behavior):

- `dow/client.py` `call_completion`: the `"/v1/chat/completions"` parameter
  default is overridden explicitly by all three production probes, but the
  `test_dow_client.py` `_call` helper relies on it, so retiring the default is a
  scoped test change and stays deferred.
- `probe_helpers.py` `exchange_turn` and `dow/client.py` `call_completion`: the
  "sent as a Bearer token" docstrings are inaccurate for `messages`, which
  authenticates with an `X-Api-Key` header.
- `probe_helpers.py` `exchange_turn` summary docstring still says
  "chat-completions turn"; the primitive is protocol-general now.

Documented `messages` behaviors (not bugs):

- `DEFAULT_MODEL` is a chat-flavored id, so a `messages` scan with no `--model`
  returns HTTP 400. Pass a `--model` valid for the messages protocol.
- The pricing table carries no messages models, so a `messages` cost estimate
  uses the placeholder-rate fallback with its existing stderr warning.

### Day 9 close (2026-06-03)

Carry-forward closed:

- 503/529 enforcement broadening (rate_limit_bypass, concurrency_amplification): 503 and 529 now join 429 as enforcement statuses in both burst probes. Shipped in 128ad1d via the shared ENFORCEMENT_STATUSES frozenset in dow/constants.py, with a coupling test (tests/test_dow_enforcement_statuses.py) proving both probes read the same set. CHANGELOG and this entry recorded in the docs commit that opens Day 9.
- Scope file revocation: addressed by short-window operation plus re-sign supersession, closing the long-standing "future feature" carry-forward. The vtra scope re-sign command reissues a signed scope with a new deadline, keeping targets and signer; reissuing to a past or near-term deadline supersedes the original, since the gate refuses on expiry. Shipped in 4368a30 (the re-sign command) and 21341b3 (CLI tests, including a supersession test that drives the gate). This docs commit ships near-term example scopes and documents the renewal and revocation path in README and CHANGELOG; the stale pending bullet is removed.
- Probe catalog: rag exfiltration_sink added (CRITICAL), bringing the inventory to dow 6, ipi 5, rag 6 (18 total), a 6-6-6 split. CRITICAL probes now 3: ipi.exfiltration_attempt, rag.retrieval_permission_leak, rag.exfiltration_sink. Shipped in 86350d3 (probe) and 9daecb0 (tests).

### Not done

Carry-forward items live in the most recent day-close section's "Carry-forward"
bullets to avoid two sources of truth. See the current Day close above.

## Review checkpoints

Periodically reassess the CI matrix, linting, typing, and the authorization
gate as the probe catalog grows. Revisit dependencies, output formats, and
test coverage when the catalog or the writer set changes shape.

## Visibility

The repository is public. Supply-chain and quality workflows run on pushes,
pull requests, and a weekly schedule depending on the workflow.
