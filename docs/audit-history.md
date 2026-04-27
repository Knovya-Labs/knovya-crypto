# Audit history

A public, redacted record of internal and external security audits performed
against the Knovya end-to-end encryption implementation. Sensitive details —
production credential patterns, attacker-reusable TTPs, and customer-specific
information — are withheld. Everything else is here, including original finding
titles, remediation commit references, and timing.

Unresolved findings are listed explicitly; we do not quietly archive issues.

## Quick reference

| Audit | Wave | Scope | Findings | Resolved | Remaining | Status |
|---|---|---|---|---|---|---|
| v1 — 8-layer internal | Apr 2026 | Cryptographic primitives + protocol | 94 checkpoints | 33 substantive fixes | 0 P0 open | **Complete** |
| v2 — 10-perspective internal | Apr 2026 | Surface coverage across 10 adversary lenses | 153 findings | 80%+ resolved | Documented acceptable risks | **Complete** |
| v3 — third-party external | TBD (future phase) | Independent cryptographic + code review | — | — | — | **Deferred — future phase** |

---

## v1 — 8-layer internal audit (Apr 2026)

An internal audit run across eight cryptographic and operational layers. The
perspective matches the structure of the whitepaper. Full layer-by-layer
narrative is summarised below; the original internal notes are not published.

### Layer coverage and outcomes

| Layer | Checkpoints | Findings summary | Resolution |
|---|---|---|---|
| L1 Cryptographic primitives | 18 | AES-256-GCM parameters, IV source, PBKDF2 iteration floor, tag length | All accepted; OWASP 2025 floors met. |
| L2 Key hierarchy (DEK/KEK envelope) | 14 | Per-note DEK isolation missing in v2; extractable surface | Fixed in v3 HKDF (commit `6966108`). |
| L3 Client-side surface | 11 | CSP nonce strategy, idle timeout, memory wipe on logout | Hardened in v2 (commit `0e9d6b7`). |
| L4 Server boundary | 12 | `content_text` write path, bulk export, audit log | Closed by NoteService invariant (v2, `358d48f`). |
| L5 Side-channel analysis | 9 | Y.js skip for encrypted notes, AI inference guard | Four-layer Y.js skip (v2, `9414a27`). |
| L6 Protocol flows | 10 | Password change atomicity, resume token semantics | 4-phase commit (v2, `d855e52`). |
| L7 Database layer | 11 | CHECK constraint, trigger, RLS, backup hygiene | Trigger + CHECK in place; GPG-wrapped WAL. |
| L8 Test coverage | 9 | Round-trip coverage, mutation score, property testing | Coverage 31% → 66% (+41 tests). |

### Notable resolved findings (redacted titles)

- **v1-F-003** — *[redacted protocol detail]*: AAD string included an extra delimiter in a transient build; fixed before staging rollout.
- **v1-F-017** — *DEK extractable surface*: extracted DEKs were held in-memory longer than necessary; replaced with non-extractable CryptoKey and reduced cache size to 500 (v2, commit `7f7871b`).
- **v1-F-029** — *Plaintext in update path*: NoteService `update` could persist both plaintext and ciphertext if a race produced two writers; closed with an invariant check (v2, commit `358d48f`).
- **v1-F-041** — *Search inference leak*: `search_vector` was populated before the encryption flag was respected; CHECK constraint + trigger ensure NULL (v2).
- **v1-F-072** — *Y.js state leak*: collaborative editor persisted deltas for encrypted notes on a slow code path; four-layer skip (v2, commit `9414a27`).

All v1 P0 items are closed. Remaining v1 observations are tracked as design
notes (Argon2id migration, title-encryption Phase IV, browser-extension T4).

---

## v2 — 10-perspective internal audit (Apr 2026)

A broader audit organised around ten adversary lenses rather than code layers.
Findings were triaged into P0/P1/P2/P3, with the current resolution rate above
80% as of publication.

### Perspectives exercised

| # | Perspective | Representative theme |
|---|---|---|
| A1 | Cryptographic primitives | Parameter hygiene, constant-time paths |
| A2 | Protocol flow | Replay, reorder, concurrent writers |
| A3 | Client surface | XSS, Trusted Types, SRI, idle policy |
| A4 | Server boundary | Plaintext paths, audit log redaction |
| A5 | Operational security | Backup encryption, key rotation, insider detection |
| A6 | Data lifecycle | Account deletion, crypto-shredding, export |
| A7 | Real-time collaboration | Y.js, Hocuspocus, presence data |
| A8 | AI / LLM | Prompt injection, tool overreach, completion guard |
| A9 | Industry atlas | Published attacks on comparable products |
| A10 | Legal / compliance | KVKK, GDPR, data-subject requests |

### Severity distribution

| Severity | Count | Resolved |
|---|---|---|
| P0 — critical | 6 | 6 (100%) |
| P1 — high | 18 | 17 |
| P2 — medium | 42 | 36 |
| P3 — low / informational | 87 | 64 |
| **Total** | **153** | **>80%** |

The remaining unresolved items are tracked in the whitepaper §12
(acceptable risks and future work) and in internal planning notes.
Examples include:

- **Title plaintext** — tracked for Phase IV (note title encryption).
- **Browser extension (T4)** — declared out-of-scope with documented rationale.
- **PQC migration** — tracked on the 5-year roadmap
  ([pqc-roadmap.md](./whitepaper/pqc-roadmap.md)).
- **Argon2id replacement for PBKDF2** — on the agility roadmap; gated on
  WASM performance parity on low-end mobile.

### Notable resolved findings (redacted titles)

- **v2-A1-007** — *[redacted KDF boundary]* — closed by HKDF v3 dispatcher.
- **v2-A3-014** — *CSP report drain*: a bug allowed certain CSP reports to be dropped under load; fixed with a dedicated `report-uri` endpoint and sampled storage.
- **v2-A4-022** — *Restore path plaintext*: a version-restore endpoint could produce plaintext for an encrypted note under a specific race; closed by the version service invariant (v2).
- **v2-A5-031** — *Backup hygiene*: WAL shipping could temporarily hold plaintext in disk cache; addressed by LUKS volume + GPG wrapping.
- **v2-A7-044** — *Hocuspocus bypass*: `Database.store` did not check `is_encrypted` under one code path; closed in v2.
- **v2-A8-058** — *AI completion on ciphertext*: AI services accepted encrypted payloads and attempted inference; closed with defense-in-depth (API + service) in v2 (`0494b1a`).

---

## v3 — third-party external audit

**Status: deferred — future phase.**

A third-party independent cryptographic audit has been **deferred** to
a future phase. This is a deliberate scheduling choice,
not a decision against public auditing. Two internal audit waves
(v1 + v2) have already been executed; the public release of this
repository and the whitepaper deliberately precedes a paid engagement
so that community reviewers can surface findings first.

When the engagement is scheduled we will publish here:

- The scope document and the rules of engagement.
- The firm name, lead auditor name (with consent), and engagement dates.
- The final report, either in full or with a named redaction policy.
- A remediation log keyed by finding identifier, with commit references.

Until then, **no third-party audit has been performed**. Any public
statement to the contrary is incorrect.

---

## Publication policy

For every resolved external or disclosed finding we commit to:

1. A redacted title and one-paragraph summary within 30 days of fix.
2. A commit reference (SHA) and release tag once the fix is merged.
3. Credit to the reporter (or pseudonym) on their request.

Omissions are rare and always documented in the entry (e.g. "withheld at the
reporter's request until <date>").

---

## Integrity of this document

The SHA-256 of this file at any given commit is part of the repository
history; consumers who want tamper evidence can verify against a tag.
Historical versions are preserved in Git history.

*Last updated: 27 Apr 2026.*
