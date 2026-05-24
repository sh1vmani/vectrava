# vectrava

AI application security scanner. vectrava probes the failure modes that show up
specifically in AI systems and reports them so they can be fixed.

It ships three modules:

- **dow** (Denial-of-Wallet): cost amplification probes. Measures how small
  inputs can drive disproportionate downstream cost.
- **ipi** (Indirect Prompt Injection): payload generators that test whether
  untrusted content reaching a model can override its instructions.
- **rag** (RAG boundary): probes for the trust boundaries of a
  retrieval-augmented generation pipeline.

## Status

Early development. The package structure, authorization gate, and output writer
interfaces are in place. The probe logic is not implemented yet. Interfaces and
output formats may change before the first tagged release.

## Defensive posture

vectrava is a defensive tool. It exists to audit, find, and report failure modes
so they can be fixed, not to attack systems you do not control. Two guards are
enforced in code, not just documented:

1. **Scope-file authorization.** vectrava refuses to run without a signed scope
   file that names the targets and an authorization deadline. A run started
   after the deadline is refused.
2. **Bring your own key (BYOK).** vectrava never ships or stores credentials.
   The target API key is supplied by the operator through the environment and
   read at run time.

Use vectrava only against systems you own or are explicitly authorized to test.

## Install

vectrava uses [uv](https://docs.astral.sh/uv/) for environment and dependency
management.

```sh
git clone https://github.com/sh1vmani/vectrava.git
cd vectrava
uv sync
```

## Usage

A scan requires two things: a scope file and the target API key in the
environment.

```sh
# The target key is supplied by you, never by vectrava.
export TARGET_API_KEY="..."

# Run a scan against the targets named in scope.json.
uv run vectrava scan --scope ./scope.json --module dow
```

A scope file is JSON:

```json
{
  "targets": ["https://api.example.test"],
  "authorized_until": "2026-12-31T23:59:59Z",
  "signed_by": "Your Name"
}
```

If the scope file is missing, malformed, or past its deadline, the run is
refused before any request is made.

## Output formats

Findings are written as SARIF v2.1.0, HTML, or JSON.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Do not open a public
issue for security reports.

## License

Apache License 2.0. See [LICENSE](LICENSE).
