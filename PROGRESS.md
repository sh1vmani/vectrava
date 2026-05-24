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

### Not done

- Probe logic for all three modules.
- Output serialization (the writers raise `NotImplementedError`).
- Scope-file signature verification.

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
