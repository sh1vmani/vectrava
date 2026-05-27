# Changelog

All notable changes to vectrava are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Audit log records now capture per-invocation cost estimates:
  `estimated_tokens` and `estimated_cost_usd` fields are populated on every scan
  path that reaches the cost gate, including dry-run, threshold-confirmed,
  declined-by-operator, and proceed-to-scan. Legacy logs (records without these
  fields) continue to verify cleanly under the existing hash chain. The USD
  value is rounded to six decimals to avoid noisy float reprs in stored JSON
  without losing meaningful precision.
- Three probe modules: `dow` (Denial-of-Wallet cost-amplification probes), `ipi`
  (indirect prompt injection probes), and `rag` (retrieval-augmented generation
  boundary probes).
- `dow` probes: `token_amplification`, `output_padding`, `model_substitution`,
  `error_amplification`, and `rate_limit_bypass`.
- `ipi` probes: `direct_override`, `exfiltration_attempt`, `refusal_bypass`,
  `multi_turn_persistence`, and `multi_turn_refusal_erosion`.
- `rag` probes: `cross_document_injection`, `citation_hijack`,
  `cross_source_contradiction`, and `prompt_leak_via_retrieval`.
- Ed25519-signed scope-file authorization gate. Every scan refuses to run until
  the scope file is signed by a key trusted via the `VECTRAVA_TRUSTED_KEYS`
  environment variable, names the target URL, and has not passed its
  `authorized_until` deadline.
- `vtra scope` command group: `new-key` (generate an Ed25519 keypair), `sign`
  (sign a scope file), and `verify` (verify a signed scope file).
- BYOK credential handling. The target API key is read from an environment
  variable named at scan time by `--api-key-env`; credentials are never bundled
  with the tool or written to config.
- Output writers in three formats: SARIF v2.1.0 (default, schema-validated
  against the OASIS-published schema), JSON, and HTML. All three render
  scan-level metadata (target, started_at, arguments, exit code) alongside
  per-finding records.
- CLI per-module scan subcommands (`vtra scan dow`, `vtra scan ipi`,
  `vtra scan rag`) with shared flags `--scope`, `--target`, `--api-key-env`,
  `--endpoint`, `--only`, `--list`, `--dry-run`, `--yes`, `--output`,
  `--format`, and `--max-requests-per-second`.
- `dow`-specific tuning flags `--threshold` and `--padding-threshold`.
- `rag`-specific flag `--num-sources` for retrieval-distractor testing.
- `ipi`-specific flag `--max-turns` controlling the `multi_turn_persistence`
  probe's conversation length (default 5, capped at 10).
- Per-client rate limiting in the HTTP layer, configured by
  `--max-requests-per-second`.
- Opt-in audit log of scan invocations (`--audit-log <path>` or
  `VECTRAVA_AUDIT_LOG_PATH`). One JSONL record per invocation captures the
  outcome of both successful and refused scans, with the scope signer,
  authorization deadline, a finding-severity summary, runner identity, and a
  SHA-256 credential fingerprint (never the credential value). Fail-closed when
  the path is unwritable.
- HTML report now renders `evidence['turns']` as an expandable conversation
  transcript for multi-turn findings.
- HTML reports now render finding evidence beyond the conversation transcript:
  probe-emitted scalar fields, status counts, and other evidence keys appear in
  an expandable Evidence block per finding.
- `AuditWriter` chains records via a SHA-256 `prev_hash` field, and the new
  `vtra audit verify <path>` walks the chain to detect post-scan tampering
  (insertion, deletion, reordering, modification). Mixed-mode logs (legacy
  records followed by chained ones) verify cleanly; the first chained record
  after legacy ones anchors to the prior line's hash. The audit log is now
  written LF-only regardless of platform so the chain bytes are stable;
  pre-existing Windows logs with CRLF line endings still verify correctly. The
  chain cannot detect a fully-truncated log without an external anchor, which is
  a documented v1 limitation. Concurrent writers to one audit-log path break
  chain integrity, not just record ordering; single-writer-per-path is the
  required deployment model until file locking is added.
- `examples/scope.example.json` template and accompanying `examples/README.md`
  documenting the copy / edit / sign workflow.

### Changed

- Scan commands now print the estimated token count and USD cost on every
  actual-scan invocation, not only when the threshold prompt fires. The
  confirmation prompt above 150,000 tokens is unchanged. Dry-run output is
  unchanged. The USD figure remains a placeholder estimate at $0.01/1K tokens;
  reading per-model pricing from config is a planned enhancement.
- `AuditWriter` now serializes concurrent flushes to one audit log path via an
  OS file lock (`fcntl.flock` on Linux and macOS, `msvcrt.locking` on Windows),
  enforcing at the OS level the single-writer-per-path invariant the hash chain
  requires for integrity. A flush that cannot acquire the lock within 5 seconds
  raises `AuditError`. The verifier (`vtra audit verify`) remains lock-free; run
  it when scans are not actively writing the log to avoid transient mismatch
  reports.
- Multi-turn probes now estimate tokens triangularly (the full transcript is
  resent each turn), so worst-case costs reflect reality.
  `COST_PROMPT_THRESHOLD_TOKENS` rises to 150,000 to absorb the honest estimates
  without re-tripping the cost prompt for routine full-module scans.
- `_run_scan` options grammar is now module-agnostic, letting each `scan_X`
  command build its own options dict without changes to the scan runner.
- Scan-level target is now threaded through every writer's public API. HTML
  clean-scan output (zero findings) renders the actual target instead of `n/a`,
  and SARIF and JSON gain a scan-level target field they did not previously
  carry.

### Fixed

- SARIF writer now emits a trailing newline on the written file, matching the
  convention other tools expect when concatenating or diffing SARIF output.

### Security

- Probe payloads ship as working exploits visible in source under
  `src/vectrava/{dow,ipi,rag}/probes/`. The rationale and the threat model are
  documented in [SECURITY.md](SECURITY.md#dual-use-disclosure).
