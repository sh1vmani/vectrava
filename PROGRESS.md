# Progress

A 12-week build plan tracks vectrava from scaffold to public launch.

## Current marker: Week 0

Scaffold and repository foundation.

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
  CodeQL and Scorecard are gated to run only when the repository is public,
  because both require GitHub Advanced Security to run on a private repo.
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

### Not done

- Probe logic for all three modules.
- HTML output writer (`html.py` raises `NotImplementedError`;
  SARIF and JSON writers are implemented).

## Review checkpoints

- **Week 2:** tooling review. Confirm the CI matrix, linting, typing, and the
  authorization gate hold up as the first probes land.
- **Week 6:** tooling review. Reassess dependencies, output formats, and test
  coverage at the halfway point.

## Visibility

The repository is private during the build and flips to public at the Week 12
launch.

### Launch tasks (Week 12)

- Remove the `if: github.event.repository.visibility == 'public'` gate from
  `.github/workflows/codeql.yml` and `.github/workflows/scorecard.yml`. The gate
  exists only to skip these jobs while the repo is private, since both require
  GitHub Advanced Security to run on a private repo. Once public the gate is
  unnecessary, and leaving it would skip the weekly scheduled Scorecard run
  because scheduled events do not populate `github.event.repository`.
