# Contributing to knovya-crypto

Thank you for your interest in contributing to the Knovya cryptographic
reference implementation. This repository is maintained under a strict
security review protocol because a single faulty change can compromise the
confidentiality of every Knovya user.

Please read this document in full before opening your first pull request.
If anything is unclear, open a GitHub Discussion (not an issue) and we will
clarify.

## Before you start

- Read the [whitepaper](./docs/whitepaper/knovya-e2e-encryption-v1.md),
  especially §2 (cryptographic primitives), §3 (key hierarchy),
  §4 (protocol flows), and §12 (acceptable risks).
- Read the [threat model](./docs/whitepaper/threat-model.md) and the
  [public audit history](./docs/audit-history.md) — most "why is it
  done this way?" questions are answered there.
- For security-sensitive findings, please do **not** open a public issue.
  Follow [SECURITY.md](./SECURITY.md).

## Types of contributions we welcome

1. **Bug fixes** with a reproducing test.
2. **New test vectors** (Wycheproof-style) that exercise an edge case
   in AAD binding, IV handling, DEK derivation, or password change.
3. **Property-based test invariants** (fast-check / hypothesis) that
   strengthen round-trip, isolation, or idempotence guarantees.
4. **Documentation improvements** — corrections, clarifications, new
   examples, threat-model refinements.
5. **Cryptographic agility enhancements** — adding a new cipher, KDF, or
   AEAD mode behind the existing `ENCRYPTION_VERSION` dispatcher.
6. **Performance improvements** that do not change the security posture.

Contributions that **change the protocol** (e.g. adding a new AAD field,
changing the IV length, moving from PBKDF2 to Argon2id without a
versioned migration path) require a written design note attached to
the PR and a longer review period. See "New cipher or protocol change"
below.

## What the review protocol looks like

Every PR that touches `crypto/` is reviewed by at least two maintainers,
one of whom has a cryptography background. We explicitly ask the
following questions on every review:

1. **Version dispatch.** Does the change introduce a new behaviour
   without a new `ENCRYPTION_VERSION` enum value? If yes, revise.
2. **AAD binding.** Does the new ciphertext still authenticate against
   `note_id ∥ encryption_counter ∥ version`? If the AAD string changes,
   there must be an explicit migration story.
3. **Extractability.** Does any key material become `extractable=true`?
   No change may relax the current `extractable=false` posture without
   a signed-off rationale.
4. **Server boundary.** Does the backend touch plaintext? The backend
   **never** decrypts; all encryption operations live in the browser.
   A PR that adds a decrypt call in Python is rejected on sight.
5. **Y.js / real-time.** Does the change open a path for collaborative
   state to carry plaintext for encrypted notes? The 4-layer skip
   (frontend shell → hook → internal API → Hocuspocus) must remain intact.
6. **Audit log.** Does the change log anything that could leak
   plaintext or key material? All new log lines go through
   `CONTENT_SCRUB_KEYS`.
7. **Backward compatibility.** Can an existing note created on v1 still
   be decrypted after the change?

## Test requirements

| Test type | Tool | Threshold |
|---|---|---|
| Unit + integration | pytest / vitest | all new code paths covered |
| **Mutation** | Stryker (JS), mutmut (Python) | **score ≥ 80%** on any touched module |
| **Property-based** | fast-check (JS), hypothesis (Python) | **≥ 10 invariants** per new primitive |
| Known-answer (KAT) | Wycheproof vectors | all applicable vectors green |
| Round-trip | Built-in | encrypt → decrypt → equal, for each version |
| Cross-version | Built-in | v1 ciphertext still decrypts |

Run locally:

```bash
# Frontend
cd crypto/frontend && npm ci && npm test && npm run mutation
# Backend
cd crypto/backend && pip install -r requirements-dev.txt && pytest && mutmut run
```

CI (`.github/workflows/test.yml` and `crypto-audit.yml`) enforces the
thresholds above on every PR. You cannot merge a red pipeline.

## Commit style

- Small, self-contained commits. A PR with one focused commit is easier
  to review than ten tiny commits or one giant commit.
- Subject line: `<type>(scope): subject` (Conventional Commits).
  Types we use: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`,
  `sec` (for security-only changes).
- Scope: `crypto/frontend`, `crypto/backend`, `crypto/types`, `docs`,
  `ci`, `test`.
- Body: *why*, not *what*. The diff tells us what.

## New cipher or protocol change

If your PR introduces a new encryption version, new KDF, or changes the
AAD binding shape, open a design-note PR first. The design note lives at
`docs/design-notes/<short-name>.md` and contains:

- Motivation and threat model impact.
- Chosen primitive, parameters, and justification (NIST / RFC / academic
  reference).
- Migration plan for existing ciphertext.
- Dispatch plan (`ENCRYPTION_VERSION` value, feature flag, rollout
  order).
- Key rotation implications.
- Test vectors (KAT) from a trusted source.
- Interop concerns (other WebCrypto versions, Node versions,
  mobile browsers).

The design note lands first. The implementation lands in a subsequent PR
that references it.

## Cryptographic agility guardrails

- Never remove a version. Removing `ENCRYPTION_VERSION.V1_UNBOUND` would
  strand old ciphertext. Mark it deprecated, keep the decrypt path.
- Never change the meaning of an enum value. Always add a new one.
- Never store key material in `localStorage`, `sessionStorage`,
  IndexedDB without explicit review. The default is in-memory only.
- Never introduce a randomness source other than `crypto.getRandomValues`
  (or `secrets.token_bytes` in Python).
- Never log, Sentry-capture, or telemetry-emit any field that contains
  plaintext, KEK material, DEK material, or raw salt.

## Code of Conduct

Be respectful. Assume good faith. Review the work, not the author.
Security research benefits from diverse perspectives — we actively
welcome contributions from underrepresented groups in cryptography.

Violations of these norms in issues, PRs, or comments will be moderated
by the maintainers.

## License

By contributing, you agree that your contributions will be licensed
under [Apache License 2.0](./LICENSE). The whitepaper (under
[docs/whitepaper/](./docs/whitepaper)) is licensed under CC BY-SA 4.0;
contributions to documentation follow the respective license of the
file.

---

Thank you for helping make end-to-end encryption trustworthy in
practice. If your first review feels slow, that is by design: correct
cryptography is unforgiving.
