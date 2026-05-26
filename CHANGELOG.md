# Changelog

All notable changes to vectrava are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Three probe modules: `dow` (Denial-of-Wallet cost-amplification probes), `ipi`
  (indirect prompt injection probes), and `rag` (retrieval-augmented generation
  boundary probes).
- `dow` probes: `token_amplification`, `output_padding`, `model_substitution`,
  and `error_amplification`.
- `ipi` probes: `direct_override`, `exfiltration_attempt`, `refusal_bypass`, and
  `multi_turn_persistence`.
- `rag` probes: `cross_document_injection`, `citation_hijack`, and
  `cross_source_contradiction`.
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
- `examples/scope.example.json` template and accompanying `examples/README.md`
  documenting the copy / edit / sign workflow.

### Changed

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
