# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide a description, reproduction steps, and impact.

Do not open a public issue for a security report. You will receive an
acknowledgement, and the fix will be coordinated privately before disclosure.

## Response time

Vectrava has a sole maintainer (see MAINTAINERS.md). Realistic
response commitments:

- Acknowledgement of receipt within 5 business days.
- Initial assessment within 14 days.
- Coordinated disclosure timeline negotiable per issue,
  typically 30 to 90 days from initial assessment depending
  on severity and complexity.

These are floors, not ceilings; most reports get faster
responses. The commitments exist so reporters know what to
expect when no response has arrived.

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

## Dual-use disclosure

Vectrava's probe modules contain working prompt-injection
payloads visible in source under
`src/vectrava/{ipi,rag}/probes/`. These are necessary for the
tool to function as a scanner: a probe that tests whether a
target is vulnerable to direct instruction override must, by
definition, contain a direct-instruction-override payload.

The same concern applies to any published security tool that
tests for specific vulnerability classes (OWASP example
libraries, MITRE ATT&CK technique references, Burp Suite
payload collections, published CVE proof-of-concept code).
The defender's case for publication is well-established:
defenders need to know what attackers can do, and concealment
does not make attacks go away; it makes defenders less
prepared.

Vectrava's specific mitigations against misuse:

- The probes are demonstrative, not optimized for evasion.
  A sophisticated attacker writing real injection attacks
  will iterate against their actual target, not crib from
  a defensive scanner's source.
- The canary-token methodology makes the probes useless as
  actual exfiltration tools: the "secret" being extracted
  is a fresh random token vectrava generated itself, not a
  real secret.
- Authorization is enforced in code: vectrava refuses to
  scan a target without a signed scope file naming that
  target (see "Scope and intended use" above).

Operators must have written authorization from the target
system's owner before running vectrava against it.
Unauthorized scanning is illegal under computer-fraud laws
in most jurisdictions. The signed scope file is a technical
control; legal authorization is a separate operator
responsibility.

## Reporting misuse

If you believe vectrava is being used to attack systems without authorization,
report it through the same private channel above.
