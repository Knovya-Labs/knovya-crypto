# Knovya vs. Standard Notes / ProtonMail / Bitwarden / Tutanota / Joplin

| Field | Value |
|---|---|
| **Version** | 1.0 |
| **Date** | April 2026 |
| **Companion to** | [`knovya-e2e-encryption-v1.md`](./knovya-e2e-encryption-v1.md) |
| **License** | CC BY-SA 4.0 |

This document compares Knovya's E2E design against five notable peers across twelve security and operational dimensions. The selected peers are a deliberate cross-section: **Standard Notes** (the closest ideological neighbour — a per-note encrypted-notes app with multiple public audits), **ProtonMail** (the most widely cited E2E mail provider, OpenPGP-based), **Bitwarden** (a full-vault E2E password manager with the most-recent third-party audit), **Tutanota** (the only major mainstream provider shipping post-quantum E2E by default), and **Joplin** (a popular open-source notes app with optional sync E2E).

The comparison is **not** a ranking. Each product targets a different threat model and a different user base. Knovya is positioned closest to Standard Notes — single-user note-taking with personal-knowledge-base ambitions — and the comparison aims to make the design trade-offs explicit rather than to claim victory in any axis.

All numbers and dates reflect publicly available information as of April 26, 2026. Where a peer has updated its design after this date, the reader is encouraged to consult the peer's current documentation.

---

## Comparison Matrix — Twelve Dimensions

| # | Dimension | Knovya | Standard Notes | ProtonMail | Bitwarden | Tutanota | Joplin |
|---|---|---|---|---|---|---|---|
| 1 | **Encryption type** | Per-note E2E (AES-256-GCM + AAD v3) | Per-item E2E (`itemsKey` envelope, XChaCha20-Poly1305) | Per-message OpenPGP (RSA + AES) | Full-vault E2E (item-level keys, AES-CBC-HMAC migrating to AES-GCM) | Per-message hybrid (TutaCrypt: ML-KEM-1024 + x25519 + AES) | Sync-time E2E (AES-256-GCM, optional plug-in) |
| 2 | **Content cipher** | AES-256-GCM | XChaCha20-Poly1305 | OpenPGP / AES-256-CFB | AES-CBC-HMAC → AES-256-GCM (migration) | AES-256-GCM | AES-256-GCM |
| 3 | **KDF** | PBKDF2-HMAC-SHA-256, 600 K iter (Argon2id Phase IV planned) | Argon2id (m=64 MiB, t=5, p=1) | bcrypt + scrypt (legacy + modern) | PBKDF2 600 K (Argon2id available as setting) | Argon2id | Configurable: scrypt or Argon2id |
| 4 | **Title encryption** | Plaintext (Phase IV planned) | Encrypted (per-item title key) | Plaintext subject (PGP message-format limitation) | Mixed: item-level encryption (audit Issue 9 [\[1\]](#references) flagged "Malleable Vault Format") | Encrypted (full metadata encryption) | Encrypted (sync E2E covers everything) |
| 5 | **Per-item key isolation (DEK)** | ✅ Per-note DEK | ✅ Per-item key (and `itemsKey` intermediary, since 004) | ✅ Per-message PGP session key | ⚠️ Configurable disable (Issue 8 [\[1\]](#references)) | ✅ Per-item key | ✅ Per-note (when sync E2E enabled) |
| 6 | **AAD scope** | `noteId` + `workspaceId` + `userId` + algorithm parameters (v=3) | `item.uuid` + `v` + `kp` (key params) | message-specific | item-specific (vault format malleable, see Issue 9 [\[1\]](#references)) | message-specific (full metadata) | basic (limited binding) |
| 7 | **Independent third-party audit** | Internal v1 + v2 done; **third-party Cure53 PENDING** Q4 2026 – Q1 2027 | Trail of Bits 2020 + Cure53 2019 + Cure53 2021 | Cure53 ongoing (post-2024) + Securitum on-site no-logs audit Aug 2025 | ETH Zürich Applied Crypto 2025 + Fracture Labs 2025 + others | SySS GmbH 2024 + Cure53 2021 | None (community review only) |
| 8 | **Open-source license** | Apache 2.0 (planned, v1 public launch) | AGPL (server) + GPL (clients) | GPL (server) + MIT (clients) — partially open | GPL v3 (full stack) | GPL v3 (clients open; backend partially closed) | MIT (full) |
| 9 | **AI features encryption boundary** | ✅ Defense-in-depth in 7 service paths (co-edit, ghost completion, MCP tools, embedding, inference, webhook, feed) | N/A (no AI features) | N/A (no AI features) | N/A | N/A | N/A |
| 10 | **Audit-log immutability** | ✅ SHA-256 `prev_hash` chain + UPDATE/DELETE trigger | ⚠️ Standard append-only logs | ⚠️ Standard | ⚠️ Standard | ⚠️ Standard | ⚠️ Standard |
| 11 | **Crypto-shredding for GDPR Art. 17** | ✅ Immutable evidence (`crypto_shredding_audit_log`) + 30-day saga + EDPB 02/2025 alignment | ✅ Implicit (key destruction) | ✅ Implicit | ✅ Implicit | ✅ Implicit | ⚠️ Varies by sync provider |
| 12 | **Quantum-safe roadmap** | Symmetric layer PQ-resolved (NIST IR 8547 Cat-13); Argon2id + ML-KEM-768 hybrid Phase IV | None public | VPN ML-KEM (separate product); mail OpenPGP | None public | ✅ TutaCrypt default since March 2024 (production ML-KEM-1024) | None |

---

## Dimension-by-Dimension Discussion

### 1 & 2 — Encryption Type and Content Cipher

Knovya's choice of **AES-256-GCM** as the content cipher diverges from Standard Notes' move to **XChaCha20-Poly1305** in 2021 (specification 004). The trade-off is articulated in whitepaper §2.1 and §2.6:

- **AES-256-GCM** is hardware-accelerated on every CPU Knovya's users actually run (Intel AES-NI since 2010, ARMv8 Cryptographic Extension on every iPhone/Android phone). Throughput >1 GB/s per core.
- **XChaCha20-Poly1305** is software-friendlier on platforms without AES-NI and has a 192-bit nonce that sidesteps AES-GCM's 96-bit birthday bound. WebCrypto API support is a 2026 working draft (W3C WICG `webcrypto-modern-algos`); shipping a WASM polyfill costs ~50 KB on every page load and ~3× throughput penalty in Knovya's benchmarks (whitepaper §11).

Knovya's per-note DEK pattern (whitepaper §3.2) resolves the 96-bit IV birthday-bound concern at the protocol layer: each DEK encrypts a small number of messages over its lifetime, far below the 2³² catastrophic-failure bound. We track XChaCha20-Poly1305 as a future-work item (whitepaper §12.2) tied to broad WebCrypto API adoption, not as a v3.x priority.

ProtonMail and Tutanota use fundamentally different shapes (per-message asymmetric envelope) appropriate for *messaging*, not note-storage. Bitwarden's migration from AES-CBC-HMAC to AES-GCM is part of its 2025 audit-driven hardening; Joplin matches Knovya's AES-GCM choice directly (and uses scrypt or Argon2id as KDF).

### 3 — Key Derivation Function

Knovya is currently the only listed peer using **PBKDF2-SHA-256 600 K** as its primary KDF; every other peer (except Bitwarden and Joplin's `scrypt` mode) uses Argon2id by default. The reason is **WebCrypto API availability** (whitepaper §2.2): until W3C WICG `webcrypto-modern-algos` ships browser-natively, native Argon2id is not available, and shipping a WASM polyfill is a deliberate Phase IV decision rather than a launch-blocker.

The 600 K iteration count meets OWASP 2026's published minimum [\[2\]](#references) and delivers ~250 ms latency on mobile Chrome (whitepaper §11.1). Argon2id (m=256 MiB, t=3, p=1) increases per-attempt cost ~70× on attacker GPUs (RTX 5090 ~21 KH/s for PBKDF2 vs. ~87 H/s for Argon2id at that parameter set [\[3\]](#references)). The migration plan ([`pqc-roadmap.md`](./pqc-roadmap.md) §1) is engineered as a forward-only, login-triggered upgrade.

### 4 — Title Encryption

Knovya, ProtonMail, and (partially) Bitwarden have plaintext titles or subjects. Standard Notes, Tutanota, and Joplin have encrypted titles.

For Knovya the plaintext title is an **explicit UX trade-off** documented in whitepaper §5.2 and §6.1: encrypted titles would break the sidebar, the search bar, the notification subjects, and the workspace activity feed, all of which require the title to be readable client-side without first unlocking the encryption session. Phase IV ([`pqc-roadmap.md`](./pqc-roadmap.md) §3) plans an opt-in title-encryption mode using a per-workspace title key.

ProtonMail's plaintext subject is structural (OpenPGP message format). Bitwarden's "Malleable Vault Format and Unencrypted Metadata" (Issue 9 in the 2025 ETH Zürich audit [\[1\]](#references)) is the most directly comparable critique to ours; we cite the same issue in our own audit findings (A4.006, A6.007).

### 5 — Per-Item Key Isolation

Knovya, Standard Notes, ProtonMail, Tutanota, and (when enabled) Joplin all use per-item keys. Bitwarden's 2025 audit Issue 8 [\[1\]](#references) flagged that per-item keys are *configurable* in Bitwarden — meaning the server can disable them — which Knovya's design does not allow (per-note DEK is mandatory at the trigger and `CHECK` constraint level).

### 6 — Additional Authenticated Data Scope

Knovya's v=3 AAD (whitepaper §2.4) binds `noteId | workspaceId | userId` plus the algorithm parameters. Standard Notes' AAD is `{u: item.uuid, v, kp}`. Bitwarden Issue 9's "Malleable Vault Format" [\[1\]](#references) is the canonical 2026 reference for the cost of insufficient AAD scope: a malicious server can re-arrange ciphertext within a user's vault undetected.

Knovya extends Standard Notes' AAD with the workspace and user binding to support forward-looking shared-workspace E2E (Phase 3 / Phase IV). The ENCRYPTION_VERSION pipeline (whitepaper §2.5) maintains backward compatibility with v=1 and v=2 notes during the gradual upgrade.

### 7 — Independent Third-Party Audit

This is the dimension where Knovya is **most explicitly behind** the listed peers:

- **Standard Notes** — Trail of Bits 2020 [\[4\]](#references), Cure53 2019 + 2021. Three public audit reports.
- **Bitwarden** — ETH Zürich Applied Crypto 2025 (the audit our own work most directly cites), plus annual Cure53 and others.
- **ProtonMail** — Cure53 ongoing post-2024, Securitum on-site no-logs audit August 2025.
- **Tutanota** — SySS GmbH 2024 + Cure53 2021.
- **Joplin** — none (community-review only).

Knovya has completed two **internal** audits (April 9, 2026 — 8 layers, 94 audit points; April 26, 2026 — 10 perspectives, 153 findings, **80%+ resolved through the iterative v2 implementation effort**). The third-party audit is **PENDING** and **DEFERRED to Phase IV** (target Q4 2026 – Q1 2027). The whitepaper, the audit history, and this comparison document all mark this status explicitly.

We deliberately do not claim "audit-complete" status. Standard Notes' precedent is the model we follow: ship code under AGPL/Apache, publish the whitepaper, run a self-hosted bug-bounty policy at launch, and engage a third-party (Cure53 or Trail of Bits) once the user base justifies the ~€30 000 – €40 000 engagement cost. Until then, the publicly-readable internal audit reports plus the open-source code base plus the community-review-via-`SECURITY.md` channel are our trust-building substrate.

### 8 — Open-Source License

Knovya plans **Apache 2.0** for the `knovya-crypto` repo at the v1 public launch. The decision aligns with Standard Notes' commercial-friendly + patent-grant posture. AGPL (Standard Notes server, ProtonMail server) is more strict; GPL v3 (Bitwarden, Tutanota, Joplin) sits between Apache 2.0 and AGPL on the strictness axis. Apache 2.0 is the published licence for the open-source `knovya-crypto` repository.

### 9 — AI Features Encryption Boundary

Knovya is the **only peer with a meaningful AI surface**. The listed competitors do not ship AI features and therefore do not need to defend against the cluster of attacks (T10) covered in [`threat-model.md`](./threat-model.md): MCP tool poisoning, EchoLeak / indirect prompt injection, embedding inversion, context-handoff leakage.

The Knovya 7-path defense-in-depth (whitepaper §6.4) is therefore a **distinctive contribution** rather than an apples-to-apples comparison. We expect AI-augmented note-taking to become a category in the next two to three years; if and when peers ship AI features, this row of the matrix will fill in.

### 10 — Audit-Log Immutability

Knovya's SHA-256 hash-chain audit log (whitepaper §8.5) is **distinctive**. None of the listed peers publishes a comparable design. The closest analogue is `immudb` (open-source immutable database) and `checksum.dev` (Merkle-anchored audit logs, both 2026 productisations of the same pattern). Hash-chained, UPDATE/DELETE-trigger-protected `workspace_audit_log` is what supports Knovya's claim to SOC 2 CC7.2 evidentiary readiness.

### 11 — Crypto-Shredding for GDPR Article 17

Every peer that uses E2E supports crypto-shredding implicitly: destroying the user's key destroys access to the ciphertext. Knovya is **distinctive in publishing the explicit immutable audit-log evidence** (`crypto_shredding_audit_log` with hash chain, whitepaper §8.5) and in citing **EDPB Guidelines 02/2025** [\[5\]](#references) directly. The 30-day cooling-off saga (whitepaper §4.6) and the runbook `account-deletion-crypto-shredding.md` bring the implementation up to a level we believe satisfies KVKK and GDPR DPA inquiry standards.

### 12 — Quantum-Safe Roadmap

Tutanota is the **production leader** on this dimension: TutaCrypt (ML-KEM-1024 + x25519 + AES) has been the default for new accounts since March 2024 [\[6\]](#references). Every other peer, Knovya included, is on the symmetric-only baseline.

Knovya's position is articulated in [`pqc-roadmap.md`](./pqc-roadmap.md) and in NIST IR 8547 [\[7\]](#references) terms: AES-256 has effective 128-bit security under Grover's algorithm — already in NIST PQC Category 13. PBKDF2 / Argon2id are symmetric KDFs with no quantum vulnerability. The post-quantum migration concern for Knovya is therefore concentrated at the **TLS layer** (Cloudflare's hybrid X25519 + ML-KEM-768 rollout, whitepaper §12.2) and at the **future asymmetric layers** (recovery-key signing, multi-device key sharing) that we do not yet ship.

The five-year roadmap in [`pqc-roadmap.md`](./pqc-roadmap.md) is conservative compared with Tutanota's already-deployed posture but is in line with NIST's 2035 deprecation timeline for quantum-vulnerable algorithms.

---

## What Knovya Inherits and What It Adds

The honest summary: Knovya is closest in spirit to **Standard Notes** and we openly inherit their playbook:

- Per-item E2E with envelope encryption.
- Open-source clients.
- Public whitepaper.
- Multi-audit posture (internal + planned third-party).
- Explicit accepted-risk documentation.

We diverge on:

- **AES-256-GCM** vs. XChaCha20-Poly1305 (whitepaper §2.1) — hardware acceleration over nonce-space.
- **PBKDF2 600 K** vs. Argon2id (whitepaper §2.2) — WebCrypto API constraint, Phase IV migration planned.
- **Plaintext title** vs. encrypted title — explicit UX trade-off, Phase IV migration planned.

We add (no listed peer ships these):

- **AAD v3 with `workspaceId` and `userId` binding** — forward-looking shared-workspace E2E.
- **7-path AI / MCP defense-in-depth** — addresses T10 threat profile that other E2E note apps don't have because they don't ship AI.
- **Immutable hash-chained audit log** — SOC 2 CC7.2 evidentiary readiness on E2E provider scale.
- **Explicit EDPB 02/2025-aligned crypto-shredding with immutable evidence** — GDPR Article 17 documentation rather than implicit "we destroyed the key".

We are **explicitly behind** on:

- **Third-party audit** — PENDING Q4 2026 – Q1 2027.
- **Title encryption** — Phase IV.
- **Argon2id** — Phase IV.
- **Production post-quantum content cipher** — Tutanota leads; Knovya tracks.

---

## When to Choose What

A reader trying to pick between these products should match their threat model to the design:

- **Personal note-taking, AI-augmented, with full source-code review.** Knovya (this product) — once the public open-source release ships.
- **Personal note-taking, no AI, longest audit history.** Standard Notes.
- **Encrypted email and attachments, established CT-style key transparency.** ProtonMail.
- **Password vault, biggest annual third-party audit cycle.** Bitwarden.
- **Encrypted email, production post-quantum default.** Tutanota.
- **Self-hosted note sync without commercial trust dependencies.** Joplin (with E2E plug-in enabled).

For users who need Knovya's particular shape (single-user note-taking + AI features + publishable audit posture), the closest substitute is *no substitute* — there is no peer in the matrix that ships AI defense-in-depth. That is precisely why we wrote this whitepaper, and why we open-source the code.

---

## References

- \[1\] ETH Zürich. *Zero Knowledge (About) Encryption: Attacks on End-to-End Encrypted Cloud Storage*. USENIX Security '26. https://eprint.iacr.org/2026/058
- \[2\] OWASP. *Cryptographic Storage Cheat Sheet 2025–2026*.
- \[3\] Hashcat 6.2.6 RTX 5090 Benchmark. Chick3nman, February 2025; Treszyk RTX 5080 thesis benchmark, 2026.
- \[4\] Trail of Bits. *Standard Notes Audit Report*. 2020. https://standardnotes.com/help/audit
- \[5\] EDPB. *Guidelines 02/2025 on Processing of Personal Data through Blockchain and DLT* (crypto-shredding endorsement).
- \[6\] Tutanota. *TutaCrypt: Hybrid Post-Quantum Key Exchange*. https://tutanota.com/blog/post-quantum-encryption (March 2024).
- \[7\] NIST. *IR 8547: PQC Migration Risk Mappings* (Draft). September 2025. https://csrc.nist.gov/pubs/ir/8547/ipd

— *Knovya Engineering, April 26, 2026.*
