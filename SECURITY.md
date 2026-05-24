# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide a description, reproduction steps, and impact.

Do not open a public issue for a security report. You will receive an
acknowledgement, and the fix will be coordinated privately before disclosure.

## Supported versions

vectrava is in early development. Until the first tagged release, only the
default branch is supported.

## Scope and intended use

vectrava is a defensive tool. It is built to audit, find, and report failure
modes in AI applications so they can be fixed. Two controls are enforced in
code:

- **Scope-file authorization.** vectrava refuses to run without a signed scope
  file that names the authorized targets and an authorization deadline. Runs
  outside that scope or after the deadline are refused.
- **Bring your own key (BYOK).** vectrava does not ship or store credentials.
  The target API key is supplied by the operator through the environment.

Run vectrava only against systems you own or are explicitly authorized to test.
Using it against systems without authorization is outside the project's intended
use and may be illegal.

## Reporting misuse

If you believe vectrava is being used to attack systems without authorization,
report it through the same private channel above.
