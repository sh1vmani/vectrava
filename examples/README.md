# examples

Operator-facing sample files for vectrava.

## scope.example.json

An unsigned scope-file template. Copy it, edit `targets` to URLs in
your authorized scope, set `authorized_until` to a future timestamp,
and set `signed_by` to your name or your organization. Then sign it
with the private key produced by `vtra scope new-key`:

```sh
cp examples/scope.example.json ./scope.json
# edit ./scope.json
uv run vtra scope sign ./scope.json --key ./vectrava_ed25519 --output ./scope.signed.json
```

The signed file is what `vtra scan` accepts via `--scope`. See the
top-level [README](../README.md) for the full Quickstart, including
keypair generation and the `VECTRAVA_TRUSTED_KEYS` environment
variable.
