# knovya-crypto

**End-to-end encrypted reference implementation for the [Knovya](https://knovya.com) knowledge platform.**

This repository contains the cryptographic core that powers Knovya's zero-knowledge encryption: per-note AES-256-GCM with authenticated additional data (AAD), PBKDF2-HMAC-SHA256 key derivation (600,000 iterations), envelope encryption (DEK/KEK hierarchy), and a 4-phase atomic password-change protocol.

We publish this code under **Apache License 2.0** so that researchers, auditors, and independent security teams can review, reproduce, and challenge our claims. The full protocol specification is available in the [whitepaper](./docs/whitepaper/knovya-e2e-encryption-v1.md) (CC BY-SA 4.0).

> **Status — Initial public release (v0.1.0).** This repository is the standalone home of Knovya's cryptographic core, extracted from the Knovya platform codebase and published under Apache License 2.0. See [CHANGELOG.md](./CHANGELOG.md) for release notes.

---

## Why a zero-knowledge knowledge platform

Knovya is a second brain: a place where people keep research notes, decisions, medical records, legal drafts, private journals, business plans, and other thought in its most unedited form. For that to be usable as a knowledge substrate, the platform must guarantee — cryptographically, not contractually — that the server cannot read any of it.

Our threat model (see [docs/whitepaper/threat-model.md](./docs/whitepaper/threat-model.md)) treats ten distinct attacker profiles, including compromised server operators (T1), cloud-provider subpoena (T1a), in-browser XSS (T3), malicious browser extensions (T4, out-of-scope with documented rationale), insider access to backups (T6), and AI/LLM-based exfiltration (T10, a post-2025 profile). Knovya's answer is a layered design:

1. **Client-side encryption.** All ciphertext originates in the browser. The server receives only the encrypted blob plus metadata (IV, version, counter). `content_text` is `''` and `search_vector`/`embedding` are `NULL` for any note marked `is_encrypted=true` — enforced by a CHECK constraint and a PostgreSQL trigger.
2. **Per-note DEK isolation.** Each note has its own data-encryption key derived from the workspace KEK via HKDF v3 with the note id as context. A compromise of one note's DEK does not affect any other note.
3. **AAD binding (v3).** The ciphertext is authenticated against `note_id ∥ encryption_counter ∥ version`. A swapped blob cannot be decrypted against the wrong note, and a replayed blob cannot masquerade as a newer version.
4. **Password change without downtime.** A 4-phase protocol (prepare → commit → swap → cleanup) re-encrypts every note under a new KEK atomically, with pagination, resume tokens, and a 409 conflict guard.
5. **Zero plaintext on the hot path.** Y.js (collaborative editing) is disabled for encrypted notes at four independent layers (frontend shell guard, hook short-circuit, internal API 403, Hocuspocus `Database.store` reject). AI services (`co_edit`, `completion`, `batch_classify`) refuse encrypted inputs at both the API and service layer (defense-in-depth).
6. **Crypto-shredding on deletion.** Account deletion wipes the KEK material; the remaining ciphertext is permanently unreadable even if backups surface later. See [§8 of the whitepaper](./docs/whitepaper/knovya-e2e-encryption-v1.md).
7. **Operational hygiene.** Dual-secret key rotation (`SECRET_KEY_PREVIOUS`), hourly encrypted WAL backups with weekly restore drills, immutable audit log with PII redaction at write time.
8. **Auditable posture.** Two internal audits are public (see [audit-history.md](./docs/audit-history.md)): v1 (8-layer, 94 checkpoints, 33 resolutions), v2 (10-perspective internal audit pass, 153 findings, 80%+ resolved). A third-party engagement is planned for a future release.

---

## Repository layout

```
knovya-crypto/
├── README.md                   # this file
├── SECURITY.md                 # disclosure policy (self-hosted)
├── CONTRIBUTING.md             # PR + test + crypto-agility rules
├── CODEOWNERS                  # crypto-maintainers team
├── LICENSE                     # Apache License 2.0
├── CHANGELOG.md                # release notes
├── PGP-PUBLIC-KEY.asc          # security@knovya.com disclosure key
├── .gitignore
├── .github/
│   ├── SECURITY.md             # GitHub auto-discovery mirror
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   └── security_report.md  # email-first redirect
│   └── workflows/
│       ├── test.yml            # Node 20 + Python 3.12 matrix
│       └── crypto-audit.yml    # Stryker + fast-check + Wycheproof + audit
├── crypto/                     # the actual cryptographic surface
│   ├── README.md
│   ├── frontend/cryptoUtils.ts
│   ├── backend/note_encryption_service.py
│   ├── types.ts                # ENCRYPTION_VERSION, AAD schema, DEK envelope
│   └── tests/
└── docs/
    ├── audit-history.md        # public redacted v1 + v2 audit summaries
    └── whitepaper/             # symlink → ../../docs/whitepaper (in monorepo)
```

The `crypto/` directory is the part of the Knovya monorepo that is safe and
useful to publish in isolation: the WebCrypto frontend module, the Python
backend encryption service, the shared type definitions, and the test suite.
Everything else in the monorepo (billing, workspace membership, real-time
infrastructure, editor, AI gateway) is out of scope here.

---

## Usage (conceptual)

This repository is a *reference implementation*, not a drop-in library. The
patterns below show how Knovya uses its own primitives; adopting them in your
own product means reading the whitepaper, the threat model, and this source.

### Frontend (TypeScript, WebCrypto)

```ts
import { deriveKEK, encryptNote, decryptNote } from "./crypto/frontend/cryptoUtils";
import { ENCRYPTION_VERSION } from "./crypto/types";

const kek = await deriveKEK(password, { salt, iter: 600_000 });
const { ciphertext, iv, counter } = await encryptNote({
  kek,
  noteId,
  plaintext: noteBody,
  version: ENCRYPTION_VERSION.V3_AAD_BOUND,
});
// Send { ciphertext, iv, counter, version } to the server. Never the plaintext.
```

### Backend (Python)

```python
from crypto.backend.note_encryption_service import (
    NoteEncryptionService,
    EncryptionInvariantViolation,
)

service = NoteEncryptionService(db)
# The backend never decrypts. It only validates metadata shape and enforces the
# "encrypted notes never carry plaintext" invariant at write time:
await service.validate_encryption_invariant(note_id, payload)
```

See the [whitepaper §4 Protocol Flows](./docs/whitepaper/knovya-e2e-encryption-v1.md) for the full sequence diagrams.

---

## Threat model summary

End-to-end encryption is meaningful only when the threat model is explicit. Knovya's ten-profile model (full text in [docs/whitepaper/threat-model.md](./docs/whitepaper/threat-model.md)):

| # | Attacker | Capability | Primary mitigation |
|---|---|---|---|
| T1 | Malicious server operator | Database + code deploy | Client-side encryption; `content_text=''` CHECK + trigger |
| T1a | Cloud provider + legal process | Memory / process snapshot | KEK `extractable=false`, zero plaintext on disk |
| T2 | MITM / TLS adversary | DNS, BGP | TLS 1.3, strict CSP with nonces, SRI on CDN assets |
| T3 | XSS | Script execution in app origin | Nonce-based strict CSP, Trusted Types, `report-uri` |
| T4 | Malicious browser extension | DOM + storage access | **Out of scope** — documented rationale |
| T5 | Database dump thief | Postgres backup exfil | AES-256-GCM, per-note DEK, GPG-wrapped backups |
| T6 | Insider / admin | Sentry, logs, admin panel | Plaintext-redacted logs, ciphertext-only admin views |
| T7 | Device thief | Browser profile / cookies | 30-min idle lock, `Cache-Control: no-store` |
| T8 | GPU / ASIC attacker | Offline guess of KEK | PBKDF2 600K, Argon2id (WASM) roadmap |
| T9 | Collaborative-editing poisoner | Y.js state mutation | 4-layer Y.js skip for encrypted notes |
| T10 | AI/LLM-based exfil | Prompt injection, tool overreach | `knovya_ai` guard, `co_edit`/`completion` guard at API + service |

Profiles T9 and T10 were introduced in v2 of the audit (April 2026) to reflect threats that did not exist when earlier E2EE products (Standard Notes, Joplin) designed their protocols.

---

## Benchmarks (excerpt)

Full numbers and methodology in [whitepaper §11](./docs/whitepaper/knovya-e2e-encryption-v1.md).

| Operation | Desktop (Chrome 138, M3 Max) | Mobile (iOS 18, iPhone 15) | Note |
|---|---|---|---|
| PBKDF2 600K derivation | ~390 ms | ~1.45 s | One-time per session unlock |
| AES-256-GCM encrypt, 100 KB | <8 ms | <18 ms | Single note write |
| AES-256-GCM decrypt, 100 KB | <6 ms | <15 ms | Single note read |
| Batch re-encrypt, 50 notes | ~1.9 s | ~4.7 s | Password change, per page |
| HKDF v3 per-note DEK derive | <1 ms | <2 ms | Cache hit path |

An RTX 5090 class adversary offline-guessing a PBKDF2-600K keyed passphrase of 10 random lowercase letters (entropy ≈ 47 bits) is estimated at roughly **18 GPU-years** per target. A passphrase with a password-manager-generated 20-char alphabet is effectively ∞ for any attacker short of a nation-state.

---

## Competitive posture

| Property | Knovya | Standard Notes | Proton Pass / Docs | Bitwarden | Tutanota | Joplin E2EE |
|---|---|---|---|---|---|---|
| Per-object key isolation | ✅ HKDF v3 | ❌ single MK | ✅ | ❌ single MK | ✅ | ❌ single MK |
| Title / metadata encryption | ✅ (v3) | ✅ | ✅ | ✅ | ✅ | ✅ |
| AAD binding (note_id + counter + version) | ✅ | partial | partial | ❌ | ❌ | ❌ |
| Atomic password change | ✅ 4-phase | rotate MK only | ✅ | rotate MK only | ✅ | re-encrypt all |
| Public audit history | ✅ v1 + v2 | ✅ 3 external | ✅ external | ✅ external | ✅ external | community only |
| Third-party audit | planned | yes | yes | yes | yes | no |

Detailed methodology and caveats: [docs/whitepaper/competitive-comparison.md](./docs/whitepaper/competitive-comparison.md).

---

## Post-quantum readiness

Knovya's cryptographic agility is explicit. The 5-year roadmap
([docs/whitepaper/pqc-roadmap.md](./docs/whitepaper/pqc-roadmap.md)) moves from
PBKDF2-HMAC-SHA256 → Argon2id WASM → hybrid classical+ML-KEM-768 for any
future server-to-server key wrapping. Harvest-now-decrypt-later adversaries
are tracked as an active threat class (Federal Reserve FEDS 2025-093).

---

## Contributing, disclosure, license

- **Contributing:** See [CONTRIBUTING.md](./CONTRIBUTING.md). All changes that touch `crypto/` require mutation-score ≥80% (Stryker) and at least ten property-based invariants (fast-check / hypothesis).
- **Vulnerability disclosure:** See [SECURITY.md](./SECURITY.md). Email `security@knovya.com`, PGP key in [PGP-PUBLIC-KEY.asc](./PGP-PUBLIC-KEY.asc). Triage SLA: 48 business hours, partial patch target 7 days, coordinated disclosure ≥90 days.
- **License:** [Apache License 2.0](./LICENSE) for code, [CC BY-SA 4.0](./docs/whitepaper/knovya-e2e-encryption-v1.md) for the whitepaper.

---

## Acknowledgements

The Knovya cryptographic design draws on decades of published work. Standard Notes's three external audits (Trail of Bits 2020, Cure53 2021) set the bar for public auditability. The ETH Zürich 2024 paper on cloud E2EE weaknesses shaped our server-boundary validation. The EDPB 2025 crypto-shredding guidance informed our account-deletion flow. The NIST post-quantum standardization (FIPS 203, 204, 205, IR 8547) anchors our agility roadmap. Full references in [whitepaper §References](./docs/whitepaper/knovya-e2e-encryption-v1.md).
