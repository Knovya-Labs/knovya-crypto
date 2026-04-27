# Changelog

All notable changes to `knovya-crypto` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Planned for upcoming releases:

- Argon2id (WASM) as an additional KDF behind the existing
  `ENCRYPTION_VERSION` dispatcher, with a documented migration path
  from PBKDF2-HMAC-SHA256.
- Additional Wycheproof test vectors for AAD-bound AES-256-GCM.
- Expanded property-based invariants around the 4-phase password-change
  protocol (prepare → commit → swap → cleanup).
- Third-party security audit (engagement planned; scope and vendor to
  be announced).

## [0.1.0] — 2026-04-27

Initial public release of `knovya-crypto` — the cryptographic
reference implementation that powers Knovya's zero-knowledge note
storage. Published as a standalone repository under Apache License 2.0
so that researchers, auditors, and independent security teams can
review, reproduce, and challenge the protocol claims.

### Added

- `README.md` with platform vision, threat-model summary, benchmarks,
  and competitive posture.
- `SECURITY.md` with self-hosted disclosure policy, triage SLAs,
  coordinated-disclosure timeline, and interim reward guidance.
- `CONTRIBUTING.md` with test requirements (mutation ≥ 80%, ≥ 10
  property-based invariants) and the cryptographic review checklist.
- `LICENSE` — Apache License 2.0 (© 2026 Knovya Contributors).
- `.github/` meta: SECURITY mirror, PR template with crypto checklist,
  issue templates (bug / feature / security-redirect).
- `.github/workflows/test.yml` — Node 20 + Node 22 + Python 3.12
  test matrix, including Wycheproof known-answer vectors.
- `.github/workflows/crypto-audit.yml` — Stryker mutation testing,
  fast-check and hypothesis property-based testing, `npm audit`, and
  `pip-audit`; weekly schedule plus per-PR runs.
- `crypto/` — the published cryptographic surface:
  - `README.md` documenting the public API inventory.
  - `types.ts` — `ENCRYPTION_VERSION` enum, `buildAAD`, shared
    constants.
  - `frontend/cryptoUtils.ts` — `deriveKEK`, `deriveDEK`,
    `encryptNote`, `decryptNote`, `reencryptBatch`, and
    `generateRecoveryKey`.
  - `backend/note_encryption_service.py` — `NoteEncryptionService`,
    `EncryptionInvariantViolation`, `build_aad`. The backend validates
    metadata shape and enforces the "encrypted notes never carry
    plaintext" invariant; it never decrypts.
  - `tests/` — unit, integration, property-based, and Wycheproof
    vector suites.
- `docs/audit-history.md` — public redacted summaries of the v1 audit
  (8-layer, 94 checkpoints, 33 substantive fixes) and v2 audit
  (10-perspective, 153 findings, 80%+ resolved) conducted internally
  by Knovya Engineering. A third-party independent audit is planned
  for an upcoming release.
- `docs/whitepaper/` — the full protocol specification (licensed
  CC BY-SA 4.0), including threat model, protocol flows, and
  post-quantum readiness roadmap.
- `PGP-PUBLIC-KEY.asc` — public disclosure key for
  `security@knovya.com`.
- `CODEOWNERS` — `@knovya-labs/crypto-maintainers` coverage with
  heightened sensitivity on `crypto/` and `.github/workflows/`.
- `.gitignore` — Node, Python, environment, and secrets patterns.

### Notes

- This repository begins its public history with this commit; no
  prior commits are published.
- `huntr.com` participation is not active and is documented as a
  future consideration in `SECURITY.md`.
- A third-party independent audit (e.g. Cure53, Trail of Bits, NCC
  Group) has **not** been performed at the time of this release; the
  maintainers commit to announcing scope and vendor when the
  engagement is scheduled.
