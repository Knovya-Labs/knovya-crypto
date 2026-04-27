# Security Policy

The Knovya team takes the security of this reference implementation seriously.
If you believe you have found a vulnerability in the cryptographic code
published here, please follow the coordinated disclosure process described
below. Thank you for helping keep our users — and the broader end-to-end
encryption community — safe.

## Scope

In scope for disclosure:

- Code in `crypto/` (frontend and backend encryption surface).
- Protocol flaws documented in [docs/whitepaper/knovya-e2e-encryption-v1.md](./docs/whitepaper/knovya-e2e-encryption-v1.md).
- Test vectors, CI workflows, and tooling in `.github/workflows/`.
- Documentation inaccuracies that could mislead an implementer (e.g. a
  mis-stated IV length, an incorrect AAD string, a missing invariant).

Out of scope:

- Non-cryptographic issues in the rest of the Knovya platform
  (billing, quotas, UI bugs, rate limiting). Report these via the
  in-product **Support** form at <https://knovya.com/support>.
- Findings that require a malicious browser extension (attacker profile
  **T4**, documented as out-of-scope in the threat model).
- Denial-of-service that does not compromise confidentiality or integrity.
- Social-engineering attacks against Knovya staff or support channels.
- Reports from automated scanners without a demonstrated impact.

## How to report

Email **`security@knovya.com`** with:

- A clear description of the vulnerability and its impact.
- Reproduction steps, a proof-of-concept, or a test vector where relevant.
- Affected version, commit hash, or deployment URL.
- Your preferred name for acknowledgement (or pseudonym, or `anonymous`).

The email should be encrypted using the PGP key published in
[`PGP-PUBLIC-KEY.asc`](./PGP-PUBLIC-KEY.asc):

- **UID**: `Knovya Security <security@knovya.com>`
- **Master fingerprint**: `77CF 8D50 DDB2 1BC1 F818  731F 2197 3C6D 01F7 BD66`
- **Created**: 2026-04-27 &nbsp;·&nbsp; **Expires**: 2028-04-26
- **Import**: `gpg --import PGP-PUBLIC-KEY.asc` or `gpg --recv-keys 21973C6D01F7BD66`

Please verify the fingerprint against at least one independent source
(this file in Git, a keyserver lookup, or a Knovya-signed announcement)
before trusting an email that claims to come from us.

Send at least the proof-of-concept encrypted; plaintext summaries are
acceptable if the key is unavailable to you. If you cannot use PGP at
all, say so in a short unencrypted message and we will reply with an
alternative secure channel.

We do not use shared mailboxes or form-based intake for security reports.
Please do not file a public GitHub issue for any suspected vulnerability.
The **Security report** issue template in this repository exists only to
redirect people who open it to this email address.

## Our commitments

| Phase | Target |
|---|---|
| Initial acknowledgement | **48 business hours** from receipt |
| Triage + severity assessment | 5 business days |
| Partial patch / mitigation | 7 business days for P0 and P1 severity |
| Coordinated public disclosure | **≥90 days** from report, or earlier by mutual agreement |
| Post-mortem in [audit-history.md](./docs/audit-history.md) | Within 30 days of public disclosure |

We will keep you updated at each step and will credit you publicly (unless
you prefer anonymity) in `audit-history.md`, the release changelog, and any
accompanying blog post.

## Bug bounty

Knovya currently runs a **self-hosted** disclosure and recognition program.
We pay rewards for well-written, reproducible vulnerability reports on a
discretionary basis using the following severity guidance (USD-denominated
PayPal, SEPA, or wire; tax and jurisdictional rules apply):

| Severity | Example | Typical recognition |
|---|---|---|
| Critical | Plaintext exfiltration by a passive server operator | $2,000 – $5,000 |
| High | KEK recovery without the passphrase | $1,000 – $2,500 |
| Medium | IV or counter reuse under documented usage | $250 – $1,000 |
| Low | Protocol ambiguity, timing leak without practical impact | $100 – $500 |
| Informational | Documentation fixes, threat-model additions | Acknowledgement |

Amounts are guidance, not a contract. We reserve the right to adjust for
novelty, reproduction quality, and coordination; no payout is owed if the
report duplicates an earlier one, violates scope, or was obtained by
unlawful means.

A listing on a third-party platform (e.g. `huntr.com`) is a **future
consideration** that the maintainers will revisit approximately six
months after the public launch of this repository. In the interim, we
commit to a staffed self-hosted channel so that reports reach the
engineers who will fix them without intermediation.

## Reproduction environment

If you need to reproduce against a running instance rather than a local
checkout, please **do not** run your tests against production
(`knovya.com`). Request a scoped test environment by including "test
environment needed" in your initial email and we will provide a
short-lived workspace with synthetic data.

## Safe harbor

As long as you:

- Stay within the declared scope above,
- Respect user privacy (no accessing or exfiltrating real user data),
- Avoid service disruption (no DoS, no brute-force beyond what is needed
  for proof),
- Give us a reasonable opportunity to coordinate disclosure, and
- Comply with applicable law,

we will treat your report as authorized research and will not pursue
legal action or restrict your Knovya account solely on the basis of the
report.

## Public disclosures

Resolved issues, along with a redacted summary and references to the
fix commits, are published in
[`docs/audit-history.md`](./docs/audit-history.md).

## Why self-hosted

Knovya's users trust us with private thought. Running our own disclosure
channel — rather than intermediating through a third-party marketplace —
keeps sensitive reports on infrastructure we operate and preserves a
direct line between the reporter and the engineers who will fix the
issue. We revisit this stance every six months; the current review point
is set six months after the public launch of `knovya-labs/knovya-crypto`.
