# Knovya End-to-End Encryption Whitepaper

| Field | Value |
|---|---|
| **Version** | 1.0 |
| **Date** | April 2026 |
| **License (paper)** | Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) |
| **License (code)** | Apache License 2.0 |
| **Authors** | Knovya Engineering |
| **Contact** | `security@knovya.com` (PGP key in repository) |
| **Repository** | [`github.com/Knovya-Labs/knovya-crypto`](https://github.com/Knovya-Labs/knovya-crypto) |

---

## Abstract

Knovya is a personal note-taking and AI knowledge base. Notes optionally protected by Knovya's per-note end-to-end encryption (E2E) leave the user's browser as ciphertext and never reach the server in clear form. The server stores opaque ciphertext, narrow encryption metadata (algorithm parameters, salt, wrapped Data Encryption Key, initialization vectors) and the plaintext title, and nothing else. Encrypted notes are excluded from full-text search, vector embeddings, AI features, public sharing, third-party webhooks, real-time CRDT collaboration, and bulk export. Encryption uses **AES-256-GCM** for content, **PBKDF2-HMAC-SHA-256 with 600 000 iterations** for key derivation, **96-bit random IVs**, and an **AAD (Additional Authenticated Data) v3** binding that ties every ciphertext to its `noteId`, `workspaceId`, and `userId`. Each note has its own randomly generated **Data Encryption Key (DEK)**, wrapped under a single **Key Encryption Key (KEK)** derived from the user's passphrase. The DEK pattern enables future per-note compartmentalization and supports a four-phase atomic password-change protocol that rotates wrapped DEKs across the entire account in a single database transaction.

This whitepaper describes the protocol, the threat model (10 attacker profiles), the server boundary, side-channel analysis (31 channels), the database layer, operational security, the testing strategy, performance benchmarks, and the explicit list of accepted risks and future work. The design draws on the Standard Notes 004 protocol, the Cure53 / Trail of Bits / ETH Zürich audit literature (2020–2026), the recent ETH Zürich "Zero Knowledge (About) Encryption" attack catalogue against Bitwarden, LastPass, and Dashlane (USENIX Security '26), the Nextcloud E2EE breakage analysis (IEEE EuroS&P 2024), and the EDPB Guidelines 02/2025 on crypto-shredding for GDPR Article 17 compliance. Knovya has completed two internal security audits (April 9, 2026 — 8 layers, 94 audit points; April 26, 2026 — 10 perspectives, 153 findings) with **80%+ resolution** before this whitepaper went public. A third-party audit (Cure53 target Q4 2026 – Q1 2027) is **deferred to a later phase** of the open-source roadmap and is **PENDING at the time of writing**. This document is the public artefact that accompanies the source-code release on GitHub and invites community review.

The intended audience is community auditors, academic cryptographers, enterprise security teams, regulators (KVKK, GDPR DPAs), and informed end users who want to understand what Knovya does — and, equally importantly, what it cannot do.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Key Hierarchy (DEK / KEK Envelope)](#3-key-hierarchy-dek--kek-envelope)
4. [Protocol Flows](#4-protocol-flows)
5. [Threat Model](#5-threat-model)
6. [Server Boundary (Zero-Knowledge Verification)](#6-server-boundary-zero-knowledge-verification)
7. [Side-Channel Analysis](#7-side-channel-analysis)
8. [Database Layer Security](#8-database-layer-security)
9. [Operational Security](#9-operational-security)
10. [Test Coverage and Validation](#10-test-coverage-and-validation)
11. [Benchmarks](#11-benchmarks)
12. [Acceptable Risks and Future Work](#12-acceptable-risks-and-future-work)
13. [References](#references)
14. [Acknowledgements](#acknowledgements)

Supplementary documents in this directory:

- [`threat-model.md`](./threat-model.md) — Detailed analysis of attacker profiles T1–T10.
- [`competitive-comparison.md`](./competitive-comparison.md) — Knovya vs. Standard Notes, ProtonMail, Bitwarden, Tutanota, Joplin.
- [`pqc-roadmap.md`](./pqc-roadmap.md) — Five-year post-quantum migration plan.
- [`fips-140-3-stance.md`](./fips-140-3-stance.md) — FIPS 140-3 non-pursuit decision and vendor-questionnaire template.

---

## 1. Introduction

### 1.1 What Knovya Is

Knovya is a single-user-centric, AI-native note-taking and knowledge-management product. Each user has one or more workspaces; every workspace contains notes, folders, tags, and a per-workspace activity log. Notes can be plain Markdown, rich BlockNote JSON, or — when the user enables encryption — opaque ciphertext that even the server operator cannot read.

Knovya is **not** an enterprise password manager (like 1Password or Bitwarden), nor a federated end-to-end messenger (like Signal or Matrix), nor a private email service (like ProtonMail or Tutanota). It is closest in spirit to **Standard Notes** and **Joplin**: a personal repository where the user is the sole keyholder, augmented by client-side AI features that never see encrypted plaintext.

Why does a note app need end-to-end encryption?

1. **Privacy.** Personal notes contain medical histories, draft therapy reflections, financial passwords, intimate relationship reasoning, business strategy, password recovery hints, and intellectual property. The reasonable user expectation is that nobody — not even the service operator — can read these.
2. **Regulatory alignment.** GDPR Article 32 requires "appropriate technical measures" for personal data; Article 33 requires breach notification within 72 hours unless the data is "unintelligible to any unauthorised person" (Recital 83). KVKK Decision 2019/10 mirrors the 72-hour requirement. EDPB Guidelines 02/2025 on crypto-shredding explicitly endorse the pattern Knovya implements: "Where personal data has been encrypted using state of the art encryption technology and the encryption key has been securely destroyed, the encrypted data may be considered to have been erased."
3. **Insider-threat resilience.** A single insider (operator, contractor, support engineer) cannot read encrypted notes even with `psql`-level database access. This is materially different from server-side encryption-at-rest, where the same insider holds both ciphertext and keys.
4. **Subpoena minimisation.** A lawful-access order served on Knovya for a user's encrypted notes returns ciphertext that is computationally infeasible to decrypt without the user's passphrase. The operator cannot comply with the spirit of the order even if compelled — a deliberate property, not a bug.

### 1.2 Why Open Source

Cryptography reviewed only by its authors is folklore, not science. The history of E2E systems is full of well-intentioned products whose protocols broke under independent scrutiny: Telegram's MTProto v1, Threema before its 2019 audit, Wire's earlier handshake, and — most recently — Bitwarden, LastPass, and Dashlane in the ETH Zürich "Zero Knowledge (About) Encryption" 2026 paper [\[1\]](#references), which catalogued 25 attacks across three of the most-deployed password managers in the world.

Knovya's response is the same as Standard Notes' before us: ship the source, ship the protocol whitepaper, run independent audits, and run a bug bounty. This document is the protocol artefact. The companion repository (`knovya-labs/knovya-crypto`) ships the implementation under Apache 2.0. The internal v1 + v2 audits are public (`docs/audit-history.md`). A third-party audit (Cure53 or Trail of Bits) is targeted for Q4 2026 – Q1 2027 once the user base reaches the size where the ~€30–40 K engagement cost is justified; the present document marks that engagement as **PENDING**, not "audit-complete".

We follow the principle articulated by Filippo Valsorda: "Trust, but verify; and when verification fails, revise" [\[2\]](#references). Every claim in this whitepaper that maps to source code is annotated with a file path so that a reviewer can locate the corresponding implementation in the public repository.

### 1.3 What This Whitepaper Is Not

This whitepaper is **not** a marketing document, **not** a substitute for code review, and **not** a proof of correctness. It documents the *design intent* and the *as-of-April-2026* implementation; the source code is the source of truth. Where the design has known limitations (browser extension threat, plaintext titles, decrypt-flow plaintext POST), we say so plainly in §12.

We also do not claim that Knovya is "unhackable", "quantum-safe in all dimensions", or "zero-knowledge in the strict cryptographic sense of multi-party-computation literature". We claim, narrowly, that:

> Under the threat model in §5, with the operational practices in §9, and within the accepted-risk envelope in §12, the Knovya server cannot recover plaintext content of an encrypted note absent the user's passphrase.

That claim is testable, falsifiable, and the subject of the rest of this document.

### 1.4 Quick Comparison with Peers

The following table is a ten-second orientation; a full-row dissection lives in [`competitive-comparison.md`](./competitive-comparison.md).

| Dimension | Knovya | Standard Notes | ProtonMail | Bitwarden | Tutanota | Joplin |
|---|---|---|---|---|---|---|
| Content cipher | AES-256-GCM | XChaCha20-Poly1305 | OpenPGP (RSA + AES) | AES-CBC-HMAC → AES-GCM | TutaCrypt (ML-KEM-1024 + x25519 + AES) | AES-256-GCM (sync E2E) |
| KDF | PBKDF2-SHA-256 600 K | Argon2id (m = 64 MiB, t = 5) | bcrypt + scrypt | PBKDF2 600 K (Argon2id available) | Argon2id | Configurable (scrypt / Argon2) |
| Per-item key | Per-note DEK | Per-item key (`itemsKey`) | Per-message PGP | Per-item key (configurable disable) | Per-item | Per-note (sync E2E) |
| AAD scope | `noteId` + `workspaceId` + `userId` + crypto params | `item.uuid` + `v` + `kp` | message-specific | item-specific | message-specific | basic |
| Title encryption | Plaintext (roadmap item) | Encrypted | Plaintext (PGP subject limit) | Mixed (field-level) | Encrypted | Encrypted |
| AI / collaboration boundary | Defense-in-depth guards in 7 service paths | N/A (no AI) | N/A | N/A | N/A | N/A |
| Independent audit | Internal v1 + v2 done; third-party **PENDING** (Q4 2026 – Q1 2027) | Trail of Bits 2020 + Cure53 2019 + 2021 | Cure53 ongoing | ETH Zürich 2025 + others | SySS 2024 + Cure53 2021 | None |
| Open source | Apache 2.0 (planned) | AGPL | GPL (server) + MIT (clients) | GPL v3 | GPL v3 | MIT |

Knovya's distinctive contributions are (a) the seven-path defense-in-depth around AI features (co-editor, ghost completion, MCP tools, embedding, inference, webhook, feed), (b) the four-phase atomic password-change wizard with reconciliation endpoint, and (c) an immutable hash-chained audit log (SHA-256 `prev_hash`) that supports SOC 2 CC7.2 evidentiary requirements. The price for those contributions is real: PBKDF2 (not Argon2id), plaintext titles, and a deferred third-party audit. We discuss each trade-off explicitly in §12.

### 1.5 Document Conventions

Throughout this paper we use the following conventions:

- `code-fixed` font for source-code identifiers, file paths, and configuration keys.
- **Bold** for the first occurrence of a defined term.
- *Italic* for emphasis and for security-critical sentences ("the server never sees plaintext content").
- `T1`–`T10` denote the ten attacker profiles from §5.
- `A1`–`A10` denote the ten internal-audit perspectives from v2 (April 26, 2026).
- "v=1", "v=2", "v=3" denote successive `ENCRYPTION_VERSION` values; v=3 is the current default and adds the extended AAD binding.

---

## 2. Cryptographic Primitives

Knovya's primitive choices are deliberately *boring*. We use NIST-standardised, widely-deployed, hardware-accelerated algorithms and we surface every parameter so that auditors can verify them by hand. Boring is a feature: the alternative — exotic schemes implemented in JavaScript — has historically broken at the implementation layer (see Nextcloud E2EE [\[3\]](#references), Bitwarden Issue 9 [\[1\]](#references), and the XCB-AES "Two Queries" attack [\[4\]](#references)).

### 2.1 Symmetric Encryption — AES-256-GCM

Content is encrypted with **AES-256 in Galois/Counter Mode** as specified by NIST FIPS 197 [\[5\]](#references) and NIST SP 800-38D [\[6\]](#references). AES-GCM is an Authenticated Encryption with Associated Data (AEAD) construction: it provides confidentiality of the plaintext *and* integrity of the ciphertext + Additional Authenticated Data (AAD) in a single primitive. Tampering with any byte of the ciphertext, the IV, or the AAD causes `crypto.subtle.decrypt` to throw `OperationError`, and the plaintext is never released to the application layer.

Why AES-GCM and not XChaCha20-Poly1305 (Standard Notes' choice since 004)? Two reasons:

1. **WebCrypto API support.** AES-GCM is universal in browsers since Chrome 37, Firefox 34, Safari 11. ChaCha20-Poly1305 entered the W3C WebCrypto API only as a 2026 working draft (WICG `webcrypto-modern-algos` [\[7\]](#references), editor: Daniel Huigens at Proton AG, Filip Skokan at Okta). Shipping a WASM-only ChaCha20 polyfill would add ~50 KB to every page load and bypass the hardware-accelerated AES-NI / ARMv8-CE instructions present in every modern CPU, costing roughly 3× throughput in our benchmarks (§11).
2. **Hardware acceleration.** AES-NI (Intel, since 2010) and ARMv8 Cryptographic Extension provide constant-time, side-channel-resistant AES at >1 GB/s per core. ChaCha20 is faster than software-AES but slower than hardware-AES on the platforms our users actually run.

The cost of AES-GCM is the well-known **96-bit IV birthday bound**: with random IVs, after roughly 2³² messages encrypted under a single key, the probability of an IV collision rises above 2⁻³². A collision is catastrophic — the attacker can recover the GHASH key `H` via polynomial factorization and forge ciphertexts without the encryption key (Joux's attack [\[8\]](#references); see also frereit.de [\[9\]](#references) and Patrick L's 2026 walk-through [\[10\]](#references)). We mitigate this in two ways:

1. **Per-note DEK pattern (§3).** Each note has its own randomly generated AES-256 key. A user with one million notes still encrypts at most ~10 messages per DEK across the lifetime of the note — a number that stays vanishingly far from 2³².
2. **DNDK-GCM future track.** NIST SP 800-38D Revision 1 (draft, January 2025) [\[11\]](#references) and Gueron–Ristenpart's DNDK-GCM IETF draft [\[12\]](#references), now deployed at Meta scale, address the birthday bound at the AEAD layer rather than at the protocol layer. We track these proposals as a v=3+ research item (§12).

The 96-bit IV is generated by `crypto.getRandomValues`, which delegates to the operating-system CSPRNG (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows, `getentropy` on macOS). A separate IV is generated for every wrap operation (`dekIv`) and every content encryption (`iv`). IVs are stored alongside the ciphertext in `encryption_metadata` and bound into the AAD.

### 2.2 Key Derivation — PBKDF2-HMAC-SHA-256, 600 000 Iterations

The user passphrase is stretched into the **Key Encryption Key (KEK)** with `PBKDF2-HMAC-SHA-256` (NIST SP 800-132 [\[13\]](#references)), salt length 128 bits, output length 256 bits, **iteration count 600 000**. The iteration count meets the OWASP 2025 / 2026 minimum for PBKDF2-SHA-256 [\[14\]](#references) and is enforced both client-side (`MIN_PBKDF2_ITERATIONS` in `frontend/src/lib/cryptoUtils.ts`) and server-side (Pydantic validator + PostgreSQL `CHECK` constraint, `chk_encryption_metadata_valid`).

Why not Argon2id? OWASP, the IETF (RFC 9106), and the cryptographic-engineering community have for several years preferred Argon2id — a memory-hard KDF that resists GPU and ASIC acceleration roughly 70× better than PBKDF2 at equivalent CPU cost. Knovya chooses PBKDF2 for one and only one reason: **WebCrypto API compatibility**. Until W3C WICG `webcrypto-modern-algos` [\[7\]](#references) — declared a working draft on 26 March 2026, with browser implementations following the typical 1–2 year ML-KEM-style timeline — PBKDF2 is the only password KDF supported natively by `crypto.subtle.deriveKey`. The alternative is shipping a WASM Argon2id implementation (`openpgpjs/argon2id`, ~7 KB gzipped, libsodium-quality) as an optional runtime dependency.

We have a written migration plan ([`pqc-roadmap.md`](./pqc-roadmap.md), §1) to switch to Argon2id (m = 256 MiB, t = 3, p = 1) once either (a) browser support hits >85 % of Knovya's user base, or (b) we ship the WASM polyfill behind a feature flag (no later than Q4 2026). The migration is intentionally engineered as a forward-only, login-triggered upgrade: on the user's next successful unlock, the client re-derives a new Argon2id KEK, re-wraps every DEK in a single transaction, and writes the new salt + setup metadata atomically. Old PBKDF2 setups remain decryptable for a 30-day grace window.

The 600 K iteration count delivers approximately 250 ms of derivation latency on a low-end mobile Chrome browser and 80 ms on a desktop M1 (§11). On an attacker GPU farm, a single RTX 5090 (Blackwell, 32 GB VRAM) achieves ~21 KH/s against PBKDF2-HMAC-SHA-256 at 600 K iterations [\[15\]](#references) — meaning that an 8-character random password (entropy ~52 bits) holds for roughly 31 years against a single GPU and 2.6 years against a 12-GPU farm. We require minimum 12-character passphrases at the UI layer and recommend longer; passphrase entropy is the dominant factor and PBKDF2 600 K is the *only* cryptographic line of defence between the attacker and the user's data.

### 2.3 Initialization Vector — 96-Bit Random

Each AES-GCM encryption uses a fresh **96-bit random IV** drawn from the OS CSPRNG via `crypto.getRandomValues`. The 96-bit choice matches the recommendation in NIST SP 800-38D §8.2 [\[6\]](#references): a 96-bit random IV yields a birthday-bound collision probability of roughly 2⁻³³ per encryption pair, which is acceptable when each key encrypts a small number of messages. Per-note DEKs (§3) ensure that each key encrypts on the order of 1–100 messages over its lifetime, well below the 2²⁹ "safe limit" suggested by Bellare–Rogaway and the 2³² catastrophic-failure bound.

### 2.4 AAD v3 — Tying Ciphertext to Identity

The single largest deviation between Knovya v=2 (April 2026 baseline) and Knovya v=3 (post-audit remediation) is the **Additional Authenticated Data binding**. A v=2 ciphertext authenticates only the algorithm parameters:

```
AAD_v2 = "knovya:v=2:AES-256-GCM:PBKDF2:600000:SHA-256"
```

This is identical for every note encrypted with the same KEK parameters. A malicious server with database write access can swap the `(content_md, encryption_metadata)` tuples between two notes owned by the same user; the user opens note A, sees note B's content under note A's title, and has no cryptographic signal that anything is wrong — exactly the "intra-user content substitution" attack flagged in audit finding A1.001 / A2.002 (Bitwarden Issue 9 [\[1\]](#references), "Malleable Vault Format and Unencrypted Metadata").

Knovya v=3 closes this with an **identity-bound AAD**:

```
AAD_v3 = "knovya:v=3|alg=AES-256-GCM|kdf=PBKDF2|iter=600000|hash=SHA-256
         |note=<noteId>|ws=<workspaceId>|user=<userId>"
```

Now every ciphertext is cryptographically bound to its noteId, the workspace it belongs to, and the user who owns it. A malicious server that swaps two notes' ciphertexts triggers a GCM authentication-tag failure on decryption: the AAD computed by the receiving client (using the *new* note's identity) does not match the AAD that was authenticated when the ciphertext was encrypted (under the *original* note's identity). The tag check fails, `decrypt` throws, and the user sees an "encrypted content corrupted" error — a non-silent failure mode.

The choice of identity fields follows Standard Notes 004 [`item.uuid`] [\[16\]](#references) and extends it for forward-looking multi-user scope: workspaceId guards future shared-workspace E2E (roadmap item), and userId guards against cross-user substitution if shared workspaces ever permit per-member encryption.

The relevant source code is in `frontend/src/lib/cryptoUtils.ts`:

```typescript
export function buildAADv3(
  meta: Pick<EncryptionMetadata, 'v' | 'alg' | 'kdf' | 'iter' | 'hash'>,
  noteId: string,
  workspaceId: string | number,
  userId: string,
): Uint8Array {
  return new TextEncoder().encode(
    `knovya:v=${meta.v}|alg=${meta.alg}|kdf=${meta.kdf}|iter=${meta.iter}|hash=${meta.hash}` +
    `|note=${noteId}|ws=${workspaceId}|user=${userId}`,
  )
}
```

The `selectAAD` helper transparently chooses the right AAD shape for v=1 (no AAD), v=2 (legacy crypto-params AAD), and v=3+ (identity-bound) so that legacy notes remain decryptable during the gradual upgrade path; new content writes always use v=3.

### 2.5 Cipher Agility — `ENCRYPTION_VERSION` Pipeline

The `v` field in `encryption_metadata` is the single source of cipher-agility truth. Every encryption operation tags the ciphertext with a version. Decryption dispatches on `v` to (a) compute the right AAD, (b) potentially route to a different KDF (Argon2id when v=4 ships), and (c) reject versions outside a server-side whitelist (`{1, 2, 3}` today; expanded as new versions ship).

The whitelist is enforced in three layers:

1. **Frontend** (`cryptoUtils.ts`): `deriveKEKFromMetadata` validates `alg === 'AES-256-GCM'`, `kdf === 'PBKDF2'`, `hash === 'SHA-256'`, and `iter ≥ MIN_PBKDF2_ITERATIONS`. Any deviation throws.
2. **Backend Pydantic** (`backend/app/schemas/notes/notes.py`): `_validate_encryption_metadata` enforces the exact same whitelist on every API request.
3. **PostgreSQL `CHECK`** (`chk_encryption_metadata_valid` constraint): a database-level `JSONB` check that rejects writes with `iter < 600000`, missing `hash`, or unrecognized `alg`. This is the defense-in-depth layer that catches direct-DB writes from misconfigured ETL, SQL-injection bugs, or a compromised insider.

When v=4 (Argon2id) ships, the constraint will be widened in a forward-only Alembic migration; v=1, v=2, v=3 will continue to decrypt. We expect to maintain at most three concurrent versions (current + previous + previous-of-previous) and to deprecate older versions through a server-driven background re-wrap once user adoption of the newest version exceeds 95 %.

### 2.6 Why Not XChaCha20-Poly1305

Standard Notes (since 004) and modern messaging protocols (Signal, WireGuard) prefer XChaCha20-Poly1305 because (a) the 192-bit XChaCha20 nonce sidesteps the 96-bit AES-GCM birthday bound, and (b) ChaCha20 is software-friendlier on platforms without AES-NI. Knovya's deployment surface is overwhelmingly hardware-AES-capable (browsers on x86-64 desktops and ARMv8 phones); the per-note DEK pattern resolves the birthday-bound concern; and the WebCrypto-native AES-GCM path is universal. We track XChaCha20-Poly1305 as a future-work item (§12) tied to broad WebCrypto API adoption; it is not a v3.x priority.

### 2.7 Why Not Argon2id (Yet)

See §2.2: the WebCrypto API does not yet expose Argon2id natively, the WASM polyfill is well-engineered but adds a ~7 KB synchronous startup cost on every encrypted-note unlock, and the existing PBKDF2 600 K setting meets OWASP 2026 minimums. The migration is planned, the testing harness is in place (`frontend/src/__tests__/cryptoUtils.test.ts` accepts a future `kdf: 'Argon2id'` branch), and the cipher-agility framework (§2.5) is the deliberate enabler for that migration. See [`pqc-roadmap.md`](./pqc-roadmap.md) §1 for the full timeline.

---

## 3. Key Hierarchy (DEK / KEK Envelope)

Knovya uses a two-level **envelope encryption** key hierarchy, a pattern consistent with modern E2E systems including Standard Notes 004 [\[16\]](#references), 1Password [\[17\]](#references), and Bitwarden's 2025 Cryptography Audit [\[1\]](#references):

```
                 ┌──────────────────┐
                 │ User Passphrase  │   (never leaves the browser, in JS String)
                 └─────────┬────────┘
                           │  PBKDF2-SHA-256, 600 000 iters, 128-bit salt
                           ▼
                 ┌──────────────────┐
                 │       KEK        │   (CryptoKey, AES-256, extractable=false)
                 │ Key Encryption   │   wrapKey + unwrapKey only
                 │      Key         │
                 └─────────┬────────┘
                           │  wrapKey('raw', dek, kek, AES-GCM)
            ┌──────────────┼──────────────┬──────────── …
            ▼              ▼              ▼
       ┌─────────┐    ┌─────────┐    ┌─────────┐
       │ DEK[n1] │    │ DEK[n2] │    │ DEK[n3] │       (one DEK per note,
       │ AES-256 │    │ AES-256 │    │ AES-256 │        AES-256-GCM,
       │ ext=F   │    │ ext=F   │    │ ext=F   │        extractable=false)
       └────┬────┘    └────┬────┘    └────┬────┘
            │              │              │
            ▼              ▼              ▼
       ┌─────────┐    ┌─────────┐    ┌─────────┐
       │ Note n1 │    │ Note n2 │    │ Note n3 │
       │ ciphertx│    │ ciphertx│    │ ciphertx│
       └─────────┘    └─────────┘    └─────────┘
```

### 3.1 KEK — Key Encryption Key

The KEK is derived from the user's passphrase via PBKDF2 (§2.2). It is a non-extractable `CryptoKey` (the WebCrypto runtime guarantees that `crypto.subtle.exportKey` rejects extraction with `OperationError`). Its only permitted operations are `wrapKey` and `unwrapKey`. The KEK lives in JavaScript memory only; it is **never** persisted to IndexedDB, localStorage, sessionStorage, cookies, or the server. It is held in a Zustand store (`frontend/src/store/encryptionStore.ts`) whose state is *not* serialized.

When the user unlocks an encrypted-mode session, the client takes the salt and the wrapped DEK from `user_preferences.encryption_setup`, derives the KEK from the supplied passphrase, and attempts to unwrap the DEK. If unwrap succeeds, the KEK is correct and the session enters the unlocked state. If unwrap fails (GCM authentication-tag mismatch), the passphrase is wrong — there is no separate password-verification token (see §3.4 below for why the legacy `verify` token was removed in v=3).

The KEK is destroyed when the user (a) explicitly locks the session, (b) signs out, (c) the browser tab fires `beforeunload`, or (d) the 30-minute idle timer fires (mouse/key/scroll/click/touch are tracked; activity in any tab on the same origin resets the timer). On destruction, all DEKs in the in-memory cache are cleared as well (the Map is replaced; CryptoKey zeroization is not a guarantee the WebCrypto runtime exposes, so we minimise *time-to-zeroization* rather than guarantee it).

### 3.2 DEK — Data Encryption Key

Every encrypted note has its own randomly generated AES-256 DEK. The DEK is created via `crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])` — the `true` (extractable) flag is mandatory for `wrapKey` to succeed, per the WebCrypto specification.

After wrapping is complete, the original extractable DEK reference is deliberately discarded and re-imported as **non-extractable**:

```typescript
export async function reimportAsNonExtractable(extractableDek: CryptoKey): Promise<CryptoKey> {
  const raw = await crypto.subtle.exportKey('raw', extractableDek)
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}
```

This is **A3.001 / C6** — the audit finding that drove the v=3 DEK-hygiene remediation. The original concern: a fresh DEK held in `_dekCache` with `extractable=true` is exfiltratable by any XSS payload that lands in the page after the DEK is generated, via `crypto.subtle.exportKey('raw', dek)`. CVE-2026-35467 ("Private key stored as extractable in browser IndexedDB") is the formal CVE for the broader class. The fix is mechanical: extract the raw bytes once for the wrap operation, immediately re-import as `extractable=false`, drop the original reference, store only the locked-down copy in cache. This narrows the XSS-exfiltration window from "lifetime of the cached DEK" (potentially the whole session) to "the few microseconds inside `encryptNote` itself".

The DEK cache (`_dekCache: Map<noteId, CryptoKey>`) has a hard cap of 500 entries with FIFO eviction (the audit flagged the FIFO-vs-LRU naming discrepancy as A2.014 P3; LRU upgrade is a future-work item that does not affect security, only cache hit ratio). Cache entries are never persisted; on tab close or idle timeout the entire cache is replaced with a fresh empty Map.

### 3.3 Encryption Setup Metadata

`user_preferences.encryption_setup` (a `JSONB` column) is the single bootstrap object that lets a logged-in client recover access to its encrypted notes after a fresh unlock:

```json
{
  "salt":       "<base64 16 bytes>",
  "wrappedDek": "<base64 ~64 bytes>",
  "dekIv":      "<base64 12 bytes>"
}
```

It contains: (a) the PBKDF2 salt used to derive the KEK, (b) a single "test" DEK that is wrapped under the KEK and used purely to verify that the unwrap operation succeeds without touching any real note, (c) the IV used in step (b). The legacy `verify` and `verifyIv` fields (a fixed-string "knovya-e2e" check) were removed in the v=3 remediation (audit finding A1.004 / A2.008): the AES-GCM authentication tag of the unwrap operation is itself a constant-time, key-bound verification that the passphrase is correct. The verify token was redundant and introduced its own non-constant-time JavaScript string comparison (`!==`).

The setup is written to the server via `PATCH /users/me/preferences` and is the *only* per-user encryption state the server holds. If the user changes their passphrase (§4.4), the setup is replaced atomically alongside the wrapped DEKs of every encrypted note.

### 3.4 Why a Single Monolithic KEK (and Not HKDF-per-Note)

The current design uses one KEK that wraps every DEK. Bitwarden's 2025 ETH Zürich audit Issue 8 [\[1\]](#references) (Standard Notes 004 calls the equivalent layer `itemsKey`) suggests an additional intermediate layer: KEK → HKDF(KEK, salt=noteId, info='knovya-dek-wrap-v3') → per-note KEK_n → wrap(DEK_n). The benefit is per-note compartmentalization: a brute-force success on one note's wrapped DEK does not yield the KEK or any other note's DEK.

Knovya defers this to a future release (`pqc-roadmap.md` §3) for two reasons: (a) the per-derive cost (~0.1 ms per HKDF) is non-trivial across the 4-phase password-change wizard's batch re-wrap step, and (b) the threat model improvement is contingent on the attacker recovering the KEK *via* a per-note brute-force, which under PBKDF2 600 K + 12-character minimum passphrase is computationally infeasible. We document this as an accepted-risk trade-off (§12) and as a roadmap item, not as a finished feature.

### 3.5 Source-Code Pointers

The full key-hierarchy implementation lives in:

- `frontend/src/lib/cryptoUtils.ts` — `deriveKEK`, `generateDEK`, `wrapDEK`, `unwrapDEK`, `reimportAsNonExtractable`, `encryptNote`, `decryptNoteContent`.
- `frontend/src/store/encryptionStore.ts` — Zustand store, idle timer, DEK cache, `unlock` / `clearAll` lifecycle.
- `backend/app/schemas/notes/notes.py` — `EncryptionMetadataSchema` (Pydantic validator, server-side schema enforcement).
- `backend/app/services/notes/note_encryption_service.py` — `encrypt_note`, `decrypt_note`, `batch_reencrypt_note` (atomic transaction, version conflict handling).
- Migration versions `k7a1` (encryption database hardening) and `v3a1` (AAD scope expansion) — database `CHECK` constraints for `encryption_metadata`.

---

## 4. Protocol Flows

This section walks through the six flows that touch encryption: initial setup, note encryption, note decryption, the four-phase password-change wizard, the recovery-key flow (BIP-39 24-word, planned), and account-deletion crypto-shredding. Each flow is described as a sequence diagram, then annotated with race-condition handling and the relevant defense-in-depth checks.

### 4.1 Initial Setup

```
User                     Browser                                Server
 │                          │                                      │
 │ Enters new passphrase    │                                      │
 ├──────────────────────────►                                      │
 │                          │ generateSalt()  → salt (16 bytes)    │
 │                          │ deriveKEK(pwd, salt) → KEK           │
 │                          │ generateDEK() → testDek              │
 │                          │ wrapDEK(KEK, testDek) → wrappedDek   │
 │                          │ buildEncryptionSetup(KEK, salt)      │
 │                          │ → { salt, wrappedDek, dekIv }        │
 │                          │                                      │
 │                          │ PATCH /users/me/preferences          │
 │                          │   body = { encryption_setup }        │
 │                          ├──────────────────────────────────────►
 │                          │                                      │ Pydantic validator:
 │                          │                                      │   - salt is base64 16
 │                          │                                      │   - wrappedDek is base64
 │                          │                                      │   - dekIv is base64 12
 │                          │                                      │ DB constraint:
 │                          │                                      │   chk_encryption_setup_valid
 │                          │                                      │ user_preferences upsert
 │                          │ ◄──────────────────────────────────────
 │                          │ 200 OK                               │
 │                          │ store KEK in memory (extractable=F)  │
 │  Setup complete          │                                      │
```

Until this step completes, no note can be encrypted. The `encStore.hasSetup()` boolean (frontend) and the `encryption_setup IS NOT NULL` predicate (backend, in `_check_setup_present`) gate every subsequent encryption action.

### 4.2 Note Encryption

```
User                     Browser                                Server / DB
 │                          │                                      │
 │ Clicks "Encrypt"         │                                      │
 ├──────────────────────────►                                      │
 │                          │ encryptNoteWithKEK(KEK, salt,        │
 │                          │   plaintext, noteId, ws, userId)     │
 │                          │ → { payload: {ciphertext, metadata}, │
 │                          │     dek: non-extractable }           │
 │                          │                                      │
 │                          │ POST /notes/{id}/encrypt             │
 │                          │   body = { encryption_metadata,      │
 │                          │            encrypted_content_md,     │
 │                          │            version }                 │
 │                          ├──────────────────────────────────────►
 │                          │                                      │ NoteService.encrypt:
 │                          │                                      │   _check_note_access(EDITOR)
 │                          │                                      │   if version mismatch → 409
 │                          │                                      │   if note.is_encrypted → idem-409
 │                          │                                      │   if note.is_locked → 423
 │                          │                                      │   note.is_encrypted = true
 │                          │                                      │   note.content_md = ciphertext
 │                          │                                      │   note.encryption_metadata = meta
 │                          │                                      │   note.content_text = ''
 │                          │                                      │   note.content_json = []
 │                          │                                      │   note.embedding = NULL
 │                          │                                      │   note.search_vector = NULL
 │                          │                                      │   note.version++
 │                          │                                      │   _delete_plaintext_versions()
 │                          │                                      │   _delete_note_chunks()
 │                          │                                      │ db.commit()  ← single tx
 │                          │ ◄──────────────────────────────────────
 │                          │ 200 OK { note }                      │
 │                          │ encStore.setDEK(noteId, dek)         │
 │ Note is encrypted        │                                      │
```

Two non-obvious properties:

1. **`_delete_plaintext_versions()` is mandatory.** Without it, the historical `note_versions` table would retain the pre-encryption plaintext snapshots forever. Audit finding v1 §4.1 (P0) is closed by this call. We empirically verified on production data that for every encrypted note `note_versions` shows zero rows.
2. **`embedding`, `search_vector`, `content_text`, `content_json`, `note_chunks` are all wiped to NULL or zero.** The encrypted note becomes invisible to FTS (§7.2), to fuzzy search (§7.3), to vector similarity (§7.4), and to chunk-based retrieval (§7.5). A database-level trigger (`trg_encrypted_note_guard`, §8.3) enforces the same invariant against any non-API write path.

### 4.3 Note Decryption (Read Path)

The read path is *purely client-side*. The server returns the encrypted ciphertext + metadata and never participates in the decryption.

```
Browser
 │
 │ Editor mount: note.is_encrypted === true
 │ if (encStore.isUnlocked && KEK in memory):
 │   getDEK(noteId, metadata):
 │     cache hit → return cached non-extractable DEK
 │     cache miss → unwrapDEK(KEK, metadata.wrappedDek, metadata.dekIv)
 │                  → cache.set(noteId, dek)  (FIFO, max 500)
 │   aad = selectAAD(metadata, noteId, workspaceId, userId)
 │   plaintext = decryptContent(dek, ciphertext, iv, aad)
 │   editor.replaceBlocks(parseMarkdown(plaintext))
 │ else:
 │   render <EditorEncryptionLock /> → user enters passphrase
```

If GCM auth-tag verification fails on `decrypt`, the WebCrypto runtime throws `OperationError` and the editor displays an "encrypted content corrupted" banner (audit finding v1 §6.6 — silent failure replaced with explicit error UX).

### 4.4 Password Change (4-Phase Wizard)

Changing the encryption passphrase is the single most failure-mode-rich flow in the system. The user supplies an old passphrase + a new passphrase; the client must re-wrap every DEK across potentially hundreds or thousands of notes; and a partial failure must not produce a state where the user can unlock with neither the old nor the new passphrase. The wizard implements a four-phase design backed by an idempotent server-side rotation session.

#### Phase 0 — Start (`POST /users/me/encryption/change-password/start`)

```
Wizard.handleStart:
  oldKek := encStore.kek  ||  deriveKEKFromMetadata(oldPw, sample.metadata)
  paginatedFetch encrypted notes (v2 audit remediation — pagination loop replaces 500-cap)
  → encryptedNotes[]   (could be > 500)

  POST /change-password/start { backup_ack, new_kek_version }
    Backend:
      _check_rate_limit(24h, fail-open)
      count := SELECT COUNT(*) FROM notes WHERE is_encrypted = true
      rotation_id := uuid4()
      Redis SETEX session:{rotation_id} (1h)
      Redis SETEX user_index:{user_id} (1h, value=rotation_id)
      audit_log.encryption_kek_rotation_started(count)
      _bump_rate_limit()       ← AFTER persistence (avoids burning cooldown
                                  on a transient Redis failure)
      db.commit()
  → 200 { rotation_id, encrypted_note_count }
```

The pagination loop fix (audit findings A2.001 / A6.002 / C5) is non-negotiable: the previous `getNotes({ limit: 500 })` plus `.filter(is_encrypted)` would silently leave any 501st-and-beyond note wrapped under the old KEK. After the user successfully unlocks with the new passphrase, those orphaned notes would fail GCM auth on every read attempt — silent data loss.

#### Phase 0.5 — Dry Run (`POST /change-password/dry-run`)

The wizard runs `changeEncryptionPassword` against a stratified sample of 50 notes (v2 remediation; the previous fixed-10 sample was insufficient for representative coverage at scale), entirely in memory, and discards the result. Only the success/failure counts are reported. This is a confidence check, not a mutation. The user sees a pre-commit summary: "We will re-wrap 1 247 notes; the dry run on 50 succeeded."

#### Phase 1 — Commit (`POST /notes/batch-reencrypt`)

```
Wizard.handleCommit:
  { newKek, newSalt, updates } := changeEncryptionPassword(oldKek, newPw, allNotes)
  POST /notes/batch-reencrypt   ← single tx, atomic across all notes
    body = { items: [{ note_id, encryption_metadata, version }, ...],
             rotation_id }
    Backend:
      for each item:
        batch_reencrypt_note():
          version conflict per note → entire tx rollback (409)
        note.encryption_metadata = item.metadata
        note.version++
      db.commit()        ← all-or-nothing, single tx
      flush_feed_events()

  setup := buildEncryptionSetup(newKek, newSalt)

  POST /change-password/commit   ← setup persisted in same tx (v2 remediation)
    body = { rotation_id, new_encryption_setup: setup, stats }
    Backend (encryption_change_password_service.commit_rotation):
      _load_session(rotation_id)
      UPDATE user_preferences SET encryption_setup = $1 WHERE user_id = $2
      audit_log.encryption_kek_rotation_complete()
      db.commit()        ← setup + audit log in single tx
      _clear_session(rotation_id)

  encStore.setState({ kek: newKek, kekSalt, _dekCache: clear })
```

The v2 remediation moves the `encryption_setup` write from a separate `PATCH /users/me/preferences` call into the same transaction as the audit-log finalization (audit finding A6.010). Before this change a network failure between the two requests could leave the database with new wrapped DEKs but the old `encryption_setup` — a state where neither old nor new passphrase decrypts, requiring manual recovery. After the change there is exactly one durable commit point: either the rotation succeeds atomically, or it does not.

#### Phase 2 — Reconciliation (`POST /change-password/reconcile`)

If the client crashes mid-commit (browser closed, network drop, OS suspend), the user sees an `EncryptionRecoveryBanner` on next page load. The banner queries `GET /change-password/recovery`, which returns the rotation session if one is in flight. The user can:

- **Continue** — the wizard resumes from the last completed phase, fetching the new KEK from the in-memory state if still present, or re-deriving from the new passphrase if not.
- **Cancel** — the rotation session is cleared. **Important caveat:** notes that were already re-wrapped before the crash stay re-wrapped under the new KEK. If the user cancels and reverts to the old passphrase, those notes become unreadable. The cancel-confirmation dialog explicitly warns about this (audit finding A2.009 P2 fix).

A **reconciliation endpoint** (added in the v2 remediation) lets the client verify per-note that the new salt is present in `encryption_metadata` and reports any drift. In practice, the all-or-nothing single-tx commit makes drift impossible; the endpoint exists as belt-and-suspenders and as a debugging aid for support.

### 4.5 Recovery-Key Flow (BIP-39 24-Word)

Knovya's threat model accepts that a forgotten passphrase means *permanent* data loss for encrypted notes. There is no server-side recovery — by design. The recovery-key feature offers an opt-in alternative: at setup time the user can download a **24-word BIP-39 mnemonic** [\[18\]](#references) (`@scure/bip39` v2.2.0, audited by Paul Miller, ESM-first, no Buffer polyfill) that encodes a 256-bit seed used to derive a *recovery KEK* alongside the password-derived KEK.

UX pattern (commit `0e6b846`):

1. Setup wizard step 4 (after passphrase confirmation): "Download your recovery key" with three click-throughs ("This is permanent", "I will store this offline", "I understand losing both passphrase and key means losing my notes").
2. The recovery key is displayed once on a downloadable PDF; the browser does not retain it after the user dismisses the dialog.
3. The recovery KEK is derived from the seed via PBKDF2 with a domain-separated salt and is used to wrap a *recovery test DEK* the first time the user creates the recovery setup. The recovery setup is written to `user_preferences.encryption_recovery_setup` and is independent of the primary `encryption_setup`.
4. To use the recovery key, the user enters the 24 words; the client derives the recovery KEK, unwraps the recovery test DEK, and (on success) prompts the user for a *new* passphrase, which kicks off a Phase 1 commit (re-wrap every DEK under the new KEK).

The recovery key is opt-in and is the only known-good way to recover from passphrase loss. We do not auto-generate one; we present it as a deliberate, conscious user choice.

### 4.6 Account Deletion — Crypto-Shredding

GDPR Article 17 ("Right to erasure") and KVKK Madde 7 require Knovya to delete user data on lawful request. EDPB Guidelines 02/2025 [\[19\]](#references) endorse **crypto-shredding** — destroying the encryption key — as a sufficient erasure mechanism when the data was encrypted with state-of-the-art encryption.

Knovya's implementation:

```
DELETE /api/v1/users/me/account   (with passphrase re-auth)
  UserDeletionService.start_cooling_off(user_id, days=30)
    user.status = "deletion_pending"
    invalidate all sessions
    send email confirmation with cancel link

[Day 30, Celery beat]
  UserDeletionService.execute(user_id):
    BEGIN;
      audit_log.security_event("account.deletion_executed", actor=user_id)
      DELETE FROM user_preferences.encryption_setup WHERE user_id = $1
            ← wrapped DEK ciphertext destroyed
      CASCADE → encrypted notes:
        UPDATE notes SET content_md = '', encryption_metadata = NULL,
                         is_encrypted = false WHERE user_id = $1
            ← ciphertext useless without DEK; rows themselves wiped too
      INSERT INTO crypto_shredding_audit_log
            (user_id, ts, sha256_evidence) VALUES (...);
            ← immutable proof for KVKK / GDPR DPA audit
      DELETE FROM users WHERE id = $1; (CASCADE chain)
    COMMIT;
```

The KEK ciphertext lives only in `user_preferences.encryption_setup`. Deleting that row removes the only path from the user's passphrase to any DEK. The note `content_md` ciphertext continues to exist for the duration of the standard 30-day backup retention, but it is computationally infeasible to decrypt — there is no longer a salt + wrapped-DEK envelope. After 90 days (passphrase rotation policy plus retention window), even the backups are useless. The `crypto_shredding_audit_log` row is immutable (UPDATE/DELETE trigger, SHA-256 hash chain — §8.5) and serves as evidence in any subsequent KVKK or GDPR DPA inquiry.

We treat this as **formal erasure under EDPB 02/2025**: the data is "rendered unintelligible to any unauthorised person", which is the bar Recital 83 sets. We document our reading of the regulation in the `account-deletion-crypto-shredding.md` runbook and have validated the interpretation with KVKK/GDPR-experienced legal counsel.

---

## 5. Threat Model

We enumerate ten attacker profiles. Each profile lists the attacker's capabilities, the most plausible attack scenarios, Knovya's mitigations, and the residual risk we accept (or do not accept). The full profile-by-profile dissection lives in [`threat-model.md`](./threat-model.md); this section summarises and motivates the choices.

| Profile | Adversary | Capability | Knovya Status |
|---|---|---|---|
| **T1** | Malicious server operator | Full DB access, code-deploy access | Mitigated by client-side encryption + AAD v3 + server-side schema validation; residual risk on plaintext title and decrypt-flow plaintext POST (accepted, §12) |
| **T2** | Network MITM | DNS poisoning, BGP hijack, rogue CA | TLS 1.2+ enforced, HSTS preload, CSP `upgrade-insecure-requests`, SRI on all bundled scripts |
| **T3** | XSS attacker | Arbitrary JS execution in Knovya origin | Strict CSP with per-request 128-bit nonce + `strict-dynamic`, Trusted Types report-only, DEK re-imported as non-extractable; XSS = total compromise of an active session is an *accepted limitation* of browser-based crypto |
| **T4** | Malicious browser extension | Manifest V3 `<all_urls>` permission | **Out-of-scope** (industry standard); documented in §12 with Cyberhaven, ShadyPanda, Trust Wallet precedents |
| **T5** | Database breach / dump theft | `pg_dump`-level read access | Per-note DEK wrapped under PBKDF2 600 K-derived KEK; ciphertext alone is useless; backups GPG-encrypted (AES-256, ECB-not-used) |
| **T6** | Insider threat (Knovya employee) | Database read, log access, optionally admin-panel access | Workspace-scoped RLS, audit log immutability (SHA-256 hash chain), Sentry plus log scrubbers, admin-view title `[REDACTED]`; weakest spot is the 4-eyes-policy on backup decryption (Shamir 3-of-5) |
| **T7** | Physical device theft | Browser profile + active session | 30-minute idle timeout, `Cache-Control: no-store` on encrypted endpoints, KEK destroyed on `beforeunload` |
| **T8** | Cryptographic attacker (GPU farm) | RTX 5090-class hardware | PBKDF2 600 K + 12-character minimum passphrase pushes single-GPU brute force to ~31 years for 8-character random; planned Argon2id migration for ~70× additional GPU resistance |
| **T9** | Supply-chain attacker | npm/PyPI maintainer compromise, CI runner compromise | `package-lock.json` integrity, `minimumReleaseAge: 7d` (Renovate), OIDC-trusted publishing on planned `knovya-crypto` repo, SRI on bundled scripts |
| **T10** | AI / LLM attacker | Prompt injection, MCP tool poisoning, embedding inversion | Defense-in-depth in 7 service paths (co-edit, ghost completion, MCP tools, embedding, inference, webhook, feed), Markdown image CSP, ASCII-smuggling Unicode strip on AI input boundary |

### 5.1 What We Defend Against

- **T1 (malicious server operator)** is the *primary* threat the design optimizes for. Every E2E claim in this whitepaper boils down to "T1 cannot recover plaintext content of an encrypted note". The AAD v3 binding (§2.4), the ENCRYPTION_VERSION whitelist (§2.5), the per-note DEK pattern (§3.2), the 4-phase atomic rotation (§4.4), and the 7-path AI defense-in-depth (§6) all exist to push as much of T1's potential abuse out of the protocol as possible. We do not pretend T1 is impossible; we make T1's job uneconomical in any realistic scenario.

- **T2 (MITM)** is a generic web-app concern. Knovya's response is the standard one: TLS 1.2+ with strong cipher suites, HSTS with `preload`, CSP with strict-dynamic + per-request nonce, SRI on every bundled script. We track Cloudflare's hybrid X25519+ML-KEM-768 rollout ([`pqc-roadmap.md`](./pqc-roadmap.md) §2) for the post-quantum future.

- **T5 (DB breach)** is the scenario every Knovya design choice rehearses. A `pg_dump` of the production database yields wrapped DEKs and ciphertext, both of which are useless without the user's passphrase. Backups are additionally GPG-encrypted with a Shamir 3-of-5 split passphrase.

- **T6 (insider threat)** is mitigated via (a) workspace-scoped RLS so a casual `SELECT` from another workspace fails; (b) audit-log immutability with SHA-256 hash chain so log tampering is detectable; (c) admin-panel title redaction so support engineers do not accidentally see encrypted-note titles; (d) backup-passphrase Shamir split (3-of-5) so no single insider can decrypt backups; (e) automated insider-threat detection runbook with 90-day rolling baseline + 2-sigma deviation alert on break-glass usage.

- **T8 (cryptographic attacker)** has access to fast GPUs but not to the user's passphrase. Single-RTX-5090 PBKDF2-SHA-256 throughput at 600 K iterations is roughly 21 KH/s [\[15\]](#references). An 8-character random passphrase (~52 bits entropy) takes ~31 years on a single GPU; a 12-character random passphrase (~78 bits entropy) takes ~10⁹ years on the same hardware. Argon2id (m=256 MiB, t=3, p=1) increases the per-attempt cost ~70× — adversary has to pay for memory bandwidth, not just compute. We plan to migrate to Argon2id in a future release.

### 5.2 What We Cannot Defend Against (and Say So)

- **T3 (XSS) = total compromise of an active session.** This is a fundamental limitation of in-browser cryptography: any JavaScript that executes inside the Knovya origin can call `crypto.subtle.encrypt` / `decrypt` with the in-memory KEK. We harden the page (strict CSP, Trusted Types report-only, SRI, no `dangerouslySetInnerHTML` on user-controlled HTML, DOMPurify on Markdown render) and we minimise the time the KEK is in memory (30-minute idle timeout, immediate destruction on `beforeunload`). But under XSS, an active session is compromised and we say so explicitly.

- **T4 (browser extension)** is similarly fundamental. A Manifest V3 extension with `<all_urls>` permission can read the DOM, listen on input events, and arbitrarily proxy `crypto.subtle`. We document this as out-of-scope, point to the Cyberhaven (December 2024, 2.6 M users), ShadyPanda (December 2025, 4.3 M users), and Trust Wallet (December 2025, $7-8.5 M crypto theft) precedents [\[20\]](#references)\[21\]\[22\], and recommend in user-facing documentation that high-stakes notes be authored in a dedicated browser profile with no third-party extensions.

- **Plaintext title / metadata.** Note titles are plaintext, as are folder paths, tags, `created_at`, `updated_at`, `is_pinned`, `is_favorited`, `is_locked`, and `status`. This is an explicit UX trade-off: encrypted titles would break the sidebar, the search bar, the notification subjects, and the workspace activity feed. A future release ([`pqc-roadmap.md`](./pqc-roadmap.md) §3) plans an opt-in **title encryption** mode (per-note + per-workspace title key). Until then, a malicious server operator (T1) and an insider (T6) see titles. Bitwarden Issue 9 [\[1\]](#references) flags this as the "Malleable Vault Format and Unencrypted Metadata" pattern; we plead guilty on titles and not guilty on content.

- **Decrypt-flow plaintext POST.** When the user clicks "Remove encryption" on a note, the client decrypts in memory and POSTs the plaintext back to the server (which writes it to `notes.content_md`, rebuilds the FTS vector, regenerates the embedding, and re-runs inference). This is by design — the user is consciously moving the note out of the E2E envelope. We minimize the network exposure (TLS, CSP `connect-src` strict-allowlist) and we log the operation in the activity log. A future design could push the entire decrypt-and-rewrite back through a re-encrypted-by-server flow, but that adds complexity for marginal benefit.

- **Activity log timing metadata.** The `workspace_audit_log` records `note.encrypted`, `note.decrypted`, and `note.reencrypted` action types with timestamps. A T6 insider can correlate "user X encrypted note Y at time T1; decrypted same note at T2; re-encrypted at T3" and infer behavioral patterns. We accept this as a cost of having an audit log at all; the alternative is no audit trail, which fails SOC 2 CC7.2.

---

## 6. Server Boundary (Zero-Knowledge Verification)

The phrase "zero-knowledge" is overloaded. In academic cryptography it has a precise multi-party-computation meaning. In E2E SaaS marketing it usually means "the server cannot decrypt the user's data". We use it in the SaaS sense and we annotate exactly which fields the server can and cannot see, endpoint by endpoint.

### 6.1 What the Server Sees (and Why)

For every encrypted note, the server sees:

| Column | Plaintext? | Justification |
|---|---|---|
| `notes.id` | UUID | Routing |
| `notes.title` | Yes | Sidebar, notifications, search; explicit future migration target |
| `notes.content_md` | Ciphertext (base64-encoded AES-256-GCM output) | This is the cipher payload |
| `notes.encryption_metadata` | JSONB (algorithm params + salt + wrappedDek + IVs) | Required for client-side decrypt |
| `notes.is_encrypted` | Boolean true | Used by every defense-in-depth guard |
| `notes.content_text` | Empty string `''` | Stripped by `_strip_plaintext_indices` on encryption |
| `notes.content_json` | Empty array `[]` | Stripped by same |
| `notes.embedding` | NULL | `embedding_service.py:82` skip rule |
| `notes.search_vector` | NULL | DB trigger `trg_encrypted_note_guard` enforces |
| `notes.folder_id`, `tags`, `metadata` | Plaintext | UX (sidebar / filters / drag-drop position) |
| `notes.created_at`, `updated_at` | Timestamp | Standard |

For the user account:

| Column | Plaintext? | Justification |
|---|---|---|
| `user_preferences.encryption_setup` | JSONB (salt + wrappedDek + dekIv) | Bootstrap envelope |
| `users.email`, `username`, `name` | Plaintext | Account identity, billing |
| `users.hashed_password` | bcrypt hash (cost 12) | Standard authentication |

The single biggest deviation from a "fully zero-knowledge" design is the plaintext title (and the rest of the metadata column). This is documented as an accepted UX trade-off (§5.2) and is the highest-priority roadmap target.

### 6.2 What the Server Never Sees

For an encrypted note, the server *never* sees:

- The plaintext `content_md`, `content_text`, or `content_json`.
- The KEK (derived in the browser, never transmitted).
- The DEK (generated in the browser, transmitted only as ciphertext wrapped under the KEK).
- The user's passphrase (used only to derive the KEK; never sent).
- The plaintext recovery key (BIP-39 24-word; user-side only; recovery KEK derivation happens in the browser).

### 6.3 Endpoint Inventory

The audit v2 A4 perspective enumerated every endpoint that touches notes and verified the encryption guard. The complete table lives in the audit report; the high-level summary is:

| Endpoint Group | Count | Encryption Guard | Defense-in-Depth |
|---|---|---|---|
| `POST/PUT /notes/{id}/...` (encrypt, decrypt, reencrypt, batch-reencrypt, update, duplicate, restore-version) | 7 | All guarded | server-side `is_encrypted` check in service layer |
| `POST /notes/{id}/share`, `/share/invitations`, `/public-link`, `/export` | 4 | All raise `NoteEncryptedException` | service-level enforcement |
| `POST /api/v1/ai/co-edit/start`, `.../message/stream`, `.../retry` | 3 | Server-side `note_svc.get(note_id).is_encrypted` guard | client-trust removed; backend independently fetches the note |
| `POST /api/v1/ai/completion` (ghost text) | 1 | Silent-skip for encrypted notes | empty suggestion returned |
| `POST /api/v1/ai/skills/run` | 1 | Skill-level guard | skill fails with `NOTE_ENCRYPTED` |
| MCP tools (`knovya_read`, `knovya_edit`, `knovya_ai`, `knovya_search`, `knovya_share`, `knovya_export`, `knovya_organize`, `knovya_links`, `knovya_agents`) | 9 | All have server-side guards | encrypted notes excluded from search; ciphertext gated on read |
| Webhook dispatch (`note.created`, `note.updated`, `note.deleted`) | 3 events | Payload contains only `note_id`, `workspace_id`, `user_id`, `timestamp` | content never serialized |
| Socket.IO feed (`note_created`, `note_updated`) | 2 events | Encrypted notes use `[Encrypted Note]` placeholder for `target_name` | audit A4.006 closed |
| Y.js / Hocuspocus collaborative editing (`/internal/yjs/save`, `/load`, `/initial`) | 3 | Four-layer fix: useYjsDoc early-return, KnovyaEditorShell yjsActive guard, backend save 403, Hocuspocus store callback skip | encrypted notes use REST + Smart Merge path ONLY |

### 6.4 AI / MCP Defense-in-Depth

A critical class of audit findings was that **the server-side AI path trusted the client's `note_content` payload without independently verifying `is_encrypted`**. A buggy client, an attacker who has bypassed the frontend guard, or a third-party MCP tool could submit decrypted plaintext to the AI endpoint, which would then forward it to Anthropic, OpenAI, or a third-party model — defeating the encryption guarantee even though the data was encrypted at rest.

The v2 remediation added independent verification at the service layer:

```python
async def create_co_edit_conversation(self, note_id: UUID, ...):
    note = await self._note_svc.get(note_id)
    if note.is_encrypted:
        raise NoteEncryptedException(
            message="AI features are unavailable for encrypted notes",
            code="NOTE_ENCRYPTED",
        )
    # ... proceed with co-edit
```

The same pattern is applied to:

- `co_edit_service.create_co_edit_conversation` (start) and `prepare_stream` (streaming)
- `completion_service.generate_completion` (ghost text)
- `skill_service.run_skill` (AI skills)
- `mcp/src/tools/ai.py:107-112` (MCP `knovya_ai`)
- `mcp/src/tools/share.py`, `export.py`, `organize.py`, `links.py`, `templates.py`, `import_tool.py`, `delete.py`

The MCP layer is particularly important because the tool-poisoning class of attacks (Invariant Labs, April 2025 [\[23\]](#references); MCPTox benchmark, August 2025 [\[24\]](#references)) demonstrates that 5.5% of public MCP servers contain prompt injection in their tool descriptions. Knovya's MCP server is internal and tool descriptions are hash-pinned in CI; we do not auto-approve `tools/list_changed` events without re-verification.

### 6.5 Whisper Leak (Microsoft Research, November 2025)

Microsoft's Whisper Leak paper [\[25\]](#references) demonstrated that the size + timing pattern of TLS streaming responses from 28 LLM providers (OpenAI, Anthropic, Google, etc.) leaks the topic of the user's prompt with >98% AUPRC. An ISP-level adversary observing a Knovya AI co-edit SSE stream could plausibly classify "the user is editing a note about cancer" or "about taxes". Knovya's heartbeat (`_iter_with_heartbeat`, 12 s idle) and the underlying SSE framing inherit this risk from the upstream provider.

We treat this as an accepted, documented residual risk for *non-encrypted* notes (encrypted notes never reach the LLM). Anthropic's `obfuscation` field (when supported) and Mistral's `p` parameter (random padding) are mitigations we will adopt as the upstream APIs make them available.

### 6.6 Smart Merge for Encrypted Notes

Concurrent edits in a non-encrypted note are resolved by a server-side three-way diff (`merge_service.compute_3way_merge`). For encrypted notes the server cannot diff ciphertext meaningfully, so it returns *both* ciphertexts (`encrypted_base_content`, `encrypted_server_content`) to the client, which decrypts each, runs the merge in memory, and writes back a new ciphertext. The merge proposal is cached in Redis for 5 minutes; password-change commits invalidate the cache (audit A6.011 fix).

---

## 7. Side-Channel Analysis

Audit v2 enumerated 31 side channels (the v1 baseline of 18 + 13 new channels added in the six months since). Eight of those produced findings; the rest were verified clean or accepted as documented risk. We summarise the high-impact channels here; the full catalogue is in the A5 audit report.

### 7.1 Y.js / Hocuspocus — Encrypted-Skip Four-Layer Fix

The most consequential side-channel finding (A5.001 P0) was that Y.js + Hocuspocus collaborative editing, originally added for plaintext notes, did not respect `is_encrypted`. On a Team or Enterprise tier where Y.js is enabled, opening an encrypted note would cause the client to push **decrypted plaintext blocks** through `editor.replaceBlocks(initialContent)` into a Y.XmlFragment, which y-prosemirror would synchronise to the Hocuspocus WebSocket, which would persist them to `note_yjs_state.state` as Y.js binary that the server can decode.

The v2 remediation implemented a four-layer fix:

1. **`useYjsDoc` early-return.** `if (isEncrypted) return null` at the top of the hook prevents any Y.Doc from being constructed for an encrypted note.
2. **`KnovyaEditorShell` defense-in-depth.** `yjsActive = crdtYjsEnabled && tierAllowsYjs && !note?.is_encrypted` ensures the shell never decides Y.js is active for an encrypted note even if the hook misbehaves.
3. **Backend `/internal/yjs/save` guard.** The endpoint fetches `Note.is_encrypted` and returns 403 for any save against an encrypted note.
4. **Hocuspocus `Database.store` callback guard.** The store callback skips persistence when `context.isEncrypted` is true.

Empirical verification: across all encrypted notes in production, `SELECT count(*) FROM note_yjs_state s JOIN notes n ON s.note_id = n.id WHERE n.is_encrypted = true` returns 0. The CI suite enforces this invariant.

### 7.2 Full-Text Search

The PostgreSQL `tsvector` index (`notes.search_vector`) is NULL for encrypted notes. The trigger `trg_encrypted_note_guard` (`BEFORE INSERT OR UPDATE`) enforces the invariant: any write that sets `is_encrypted = true` and a non-NULL `search_vector` is rejected at the database layer. The search service (`search_service.py:541`) additionally filters `Note.is_encrypted = false` in every FTS query path. Both layers are required (defense-in-depth) because the SQL filter is upstream and would silently fail open if a future refactor removed it; the trigger is the immovable last line.

### 7.3 Fuzzy / Trigram Search

The `pg_trgm` similarity index is built on `search_vector`, which is NULL for encrypted notes (§7.2). Fuzzy search therefore cannot return encrypted notes. Confirmed by the test `tests/notes/test_search_exclusion_4mode.py`, which validates exclusion across FTS, fuzzy, browse, and vector modes.

### 7.4 Vector Similarity (Embeddings)

`notes.embedding` is NULL for encrypted notes (§4.2). The `embedding_service.py:82-83` early-return prevents `compute_embedding` from being scheduled for an encrypted note. The pgvector HNSW index therefore cannot include them. The `find_related` endpoint additionally filters `n.is_encrypted = false` in every query (`embedding_service.py:376-404`).

The threat model concern here is **embedding inversion** (ALGEN, ZSInvert/Zero2Text [\[26\]](#references)\[27\]): for *plaintext* notes, the embedding is a partially-reversible projection of the content. We treat this as an accepted risk for plaintext notes (the server can already read them) and verified that encrypted notes do not generate embeddings.

### 7.5 Note Chunks

The `note_chunks` table stores LLM-friendly content chunks for retrieval-augmented generation. For encrypted notes the table contains zero rows (verified in production: `SELECT COUNT(*) FROM note_chunks WHERE note_id IN (SELECT id FROM notes WHERE is_encrypted = true)` returns 0). The encryption flow's `_delete_note_chunks` call wipes any pre-existing chunks before the encryption write commits.

### 7.6 Activity Log Timing Metadata (Accepted Risk)

`workspace_audit_log` records `note.encrypted`, `note.decrypted`, and `note.reencrypted` action types with timestamps and per-event metadata (note ID, workspace ID, user ID, IP address hash). A T6 insider can build a timeline of when each note transitioned between encrypted and plaintext states. This is documented as an accepted risk: the alternative is no audit log, which fails SOC 2 CC7.2 and HIPAA §164.312 trail-of-evidence requirements. The hash-chain immutability layer (§8.5) makes the log itself tamper-evident, so the timing metadata cannot be altered after-the-fact.

### 7.7 Title Plaintext (Accepted Risk)

See §5.2 and §6.1. Planned future migration target.

### 7.8 Webhook Lifecycle Events

Webhook subscribers see `note.created`, `note.updated`, `note.deleted` events with payloads containing only `{event, note_id, workspace_id, user_id, timestamp, detail={}}`. No content, no title, no metadata. The third-party subscriber learns *that* a note exists and *when* it changed, but not what is in it. This is intentional and aligns with industry-standard webhook contracts (Stripe, GitHub, Slack).

### 7.9 Notification `target_name`

Knovya notifications are rendered with a `target_name` placeholder. For encrypted notes the placeholder is `[Encrypted Note]` (audit A4.006 / A4.009 fix); previously the plaintext title would leak into MCP-driven event payloads. The notification body itself never contains content.

### 7.10 Redis Cache

Encrypted notes are cached server-side as ciphertext (the same bytes that live in the database). `Cache-Control: no-store` on encrypted-note responses (`notes.py:153-156`) prevents shared-proxy caching. Redis is not a side channel for plaintext; it only exposes ciphertext that is already in Postgres.

---

## 8. Database Layer Security

Knovya runs PostgreSQL 16 with the `pgvector 0.8.2` extension, behind PgBouncer in transaction-pooling mode. The database schema enforces multiple defense-in-depth invariants for encryption.

### 8.1 Row-Level Security (Workspace Isolation)

Every multi-tenant table (`notes`, `note_versions`, `note_chunks`, `notifications`, `workspace_audit_log`, etc.) has an RLS policy `workspace_isolation` enforcing `workspace_id = current_setting('app.workspace_id')::int`. The application sets the GUC at the start of every request via `SET LOCAL app.workspace_id = $1`. PgBouncer transaction-pooling preserves the GUC for the lifetime of the transaction.

We use `FORCE ROW LEVEL SECURITY` so that even the `app` user (which is the application connection role) cannot bypass the policy. The only roles with `BYPASSRLS` are the migration role (only used during Alembic upgrades) and `postgres` (only used for backups). Both are isolated by `pg_hba.conf` to local-socket connections.

### 8.2 `CHECK` Constraints

Two constraints enforce the encryption envelope shape at the database layer:

- **`chk_encryption_metadata_valid`** — JSONB shape check on `notes.encryption_metadata`:
  ```sql
  is_encrypted = false
  OR (
    encryption_metadata ? 'v' AND encryption_metadata ? 'alg'
    AND encryption_metadata ? 'kdf' AND encryption_metadata ? 'iter'
    AND encryption_metadata ? 'hash' AND encryption_metadata ? 'salt'
    AND encryption_metadata ? 'iv' AND encryption_metadata ? 'wrappedDek'
    AND encryption_metadata ? 'dekIv'
    AND (encryption_metadata->>'iter')::int >= 600000
    AND encryption_metadata->>'alg' = 'AES-256-GCM'
    AND encryption_metadata->>'kdf' = 'PBKDF2'
    AND encryption_metadata->>'hash' = 'SHA-256'
  )
  ```
- **`chk_encryption_setup_valid`** — JSONB shape check on `user_preferences.encryption_setup`:
  ```sql
  encryption_setup IS NULL
  OR (
    encryption_setup ? 'salt'
    AND encryption_setup ? 'wrappedDek'
    AND encryption_setup ? 'dekIv'
  )
  ```

Both constraints are forward-compatible: when v=4 (Argon2id) ships, the migration widens the `kdf` check to allow `'Argon2id'` and adds a `mem`/`passes`/`parallelism` predicate.

The fix to align the `iter` threshold from 100 K (audit-flagged hole) to 600 K is encoded in migration version `v3a1`. Defense-in-depth: a direct-DB write that bypasses the Pydantic validator now also fails at the database layer.

### 8.3 BEFORE-INSERT/UPDATE Trigger — `trg_encrypted_note_guard`

```sql
CREATE OR REPLACE FUNCTION fn_encrypted_note_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.is_encrypted = true THEN
    NEW.search_vector := NULL;
    NEW.embedding := NULL;
    NEW.content_text := '';
    NEW.content_json := '[]'::jsonb;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_encrypted_note_guard
  BEFORE INSERT OR UPDATE ON notes
  FOR EACH ROW EXECUTE FUNCTION fn_encrypted_note_guard();
```

This is the immovable invariant: *any* write to `notes` (API, ETL, manual SQL, an attacker bypassing the API layer) that sets `is_encrypted = true` automatically wipes the plaintext-derived columns. The trigger is owned by `postgres` and the application role has no `ALTER` privilege.

### 8.4 `note_versions` Plaintext Snapshot Cleanup

`_delete_plaintext_versions(note_id)` is called from `note_encryption_service.encrypt_note` *inside* the same transaction as the encryption write. It performs `DELETE FROM note_versions WHERE note_id = $1`, dropping every prior plaintext snapshot. Production verification: for every encrypted note, `note_versions` shows zero rows.

A pre-encryption window exists when an auto-snapshot was created within ~1 second before the encrypt call (`SNAPSHOT_THROTTLE_SECONDS = 30`). We confirmed in audit A6.018 that the snapshot creation and the `_delete_plaintext_versions` call happen in the same transaction, so the pre-encryption snapshot is rolled into the same DELETE. The window is closed.

### 8.5 Audit Log Immutability — Hash Chain

`workspace_audit_log` (75 K+ rows in production) was originally protected only by RLS. The v2 remediation added:

1. **`BEFORE UPDATE OR DELETE` trigger** — rejects every UPDATE and DELETE on `workspace_audit_log` and on `crypto_shredding_audit_log`. The trigger is `SECURITY DEFINER` and owned by a role separate from the application role.
2. **`prev_hash BYTEA(32)` column** — populated by an `INSERT` trigger that computes `SHA-256(prev_hash || row_payload_json)` for every new row. The first row has `prev_hash = '\x00' * 32`. This forms a tamper-evident hash chain: any modification to a historical row would invalidate every subsequent `prev_hash`, which would be detected by the periodic verification job (`scripts/verify-audit-chain.sh`, run weekly via cron).
3. **`crypto_shredding_audit_log` immutable table** — same hash-chain pattern, separate table for GDPR Article 17 evidence. Each row records `{user_id, ts, sha256_evidence}` where `sha256_evidence = SHA-256(user_id || ts || "shredded")`.

This pattern matches industry consensus for SOC 2 CC7.2 (HIPAA §164.312, PCI-DSS Req 10): DB-level UPDATE/DELETE blocking is the baseline; hash chain is the tamper-evidence layer; an optional daily Merkle root anchor (future work) extends the chain to externally-anchored proof (à la Certificate Transparency, immudb, or `checksum.dev`).

### 8.6 Backup Encryption

Daily `pg_dump`s are encrypted with GPG AES-256 using a passphrase split via Shamir Secret Sharing. Shares are distributed using a 3-of-5 threshold to geographically distributed holders, including Knovya engineering leads and Knovya's legal counsel.

The runbook (`docs/runbooks/secret-inventory-rotation-cadence.md`) documents the annual passphrase rotation, the quarterly Shamir succession drill, and the CI runner sudoers cleanup that ensures the Gitea Actions runner cannot read the backup passphrase.

WAL (write-ahead log) archive encryption is an operational item: `wal_to_s3.sh` is GPG-encrypted before upload, and the bucket has a 90-day lifecycle policy.

### 8.7 LUKS Disk Encryption (Future Work)

Knovya does not currently use LUKS at-rest disk encryption on the production volume. The argument: encrypted notes are encrypted at the application layer; backups are GPG-encrypted; the only at-rest plaintext is the *plaintext notes the user has not chosen to encrypt*, plus titles, plus `user_preferences.encryption_setup`. None of these are catastrophic on a stolen disk because the Hetzner data centre's physical-access controls dominate the threat model (T7).

The future-work plan (`pqc-roadmap.md` §5) includes LUKS migration alongside the broader storage redesign. We document the current absence of LUKS as a known gap.

---

## 9. Operational Security

### 9.1 Secret Rotation with `_PREVIOUS` Fallback

Three secrets need to rotate without invalidating active sessions:

- `SECRET_KEY` — JWT signing key for access + refresh tokens.
- `AI_MCP_ENCRYPTION_KEY` — AES-GCM key for encrypting third-party MCP tokens at rest.
- `STRIPE_WEBHOOK_SECRET` — HMAC secret for verifying Stripe webhook signatures.

Each has a `_PREVIOUS` companion (`SECRET_KEY_PREVIOUS`, etc.) that the decode/verify paths fall back to during a 30-day grace window. Source code is `backend/app/core/security.py:128-160` (decode_token), `app/services/stripe_service.py` (verify_stripe_signature), `app/services/ai/mcp_security.py` (decode_mcp_token).

Pseudocode:

```python
def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    except JWTError:
        if settings.SECRET_KEY_PREVIOUS:
            payload = jwt.decode(token, settings.SECRET_KEY_PREVIOUS, algorithms=['HS256'])
            if payload['iat'] < settings.SECRET_KEY_GRACE_UNTIL_TS:
                return payload
        raise
```

The runbook (`docs/runbooks/key-rotation.md`) describes the 30-day rotation cadence: write `_PREVIOUS = current`, write `current = new`, redeploy, wait 30 days for tokens to age out, then write `_PREVIOUS = ''` and redeploy again. This pattern is the same one Standard Notes and 1Password use for token-key rotation.

Audit findings A10.001 + A10.005 closed the gap where the runbook claimed dual-key fallback but the code did not implement it.

### 9.2 Backup + Restore Drill Cadence

Operational hardening added:

- **Hourly `backup-db.sh`** — `pg_dump | gzip | gpg --symmetric --cipher-algo AES256` → local + S3 (90-day retention).
- **Weekly `restore-drill.sh`** — restores the most recent backup to a throwaway PostgreSQL instance, runs schema sanity checks, and asserts row counts within 5 % of production. Failure pages on-call.
- **Continuous WAL archive** — `wal_to_s3.sh` triggered by `archive_command` every WAL segment, GPG-encrypted before upload.

The runbook hedges the DR target: RPO 1 hour (hourly backup), RTO 30 minutes (single-host restore). Cross-region failover (Hetzner FSN1 → NBG1) is annual-drill-only and is documented in `dr-runbook.md`.

### 9.3 Insider-Threat Detection

Break-glass database access (the `breakglass` PostgreSQL role used by the on-call engineer for support cases) emits an `infrastructure.breakglass_access` event on every connection. The detection layer adds:

- **90-day rolling baseline.** `breakglass_access` events per week are aggregated; the 90-day mean and standard deviation form the baseline.
- **2-sigma deviation alert.** If the current 7-day count exceeds `mean + 2σ`, a Slack alert is posted to `#security-alerts`.
- **Triage playbook.** Runbook `insider-threat-detection.md` lists three response paths (legitimate spike, compromised credentials, ongoing investigation).

### 9.4 Incident Response — GDPR Article 33 (72 h) and KVKK Decision 2019/10

The incident-response runbook (`docs/runbooks/incident-response.md`) defines the 5-phase workflow (Detect → Contain → Eradicate → Recover → Learn) and the 8 standard scenarios, including:

- **Personal data breach** — GDPR Art. 33 72-hour notification to the supervising DPA, KVKK Decision 2019/10 72-hour notification to KVKB. Decision 2025/2451 caps KVKK web-site publication at 60 days.
- **Cryptographic key compromise** — global re-encryption notification to all users, sessions invalidated, recovery flow activated.
- **Supply-chain compromise** — pip-audit + npm-audit triggered, dependency tree frozen, package versions pinned.

The five communication templates (`docs/incidents/templates/postmortem.md`, `user-notification-en.md`, `user-notification-tr.md`, `authority-notification-kvkk.md`, `authority-notification-gdpr-dpa.md`) are pre-written so that the legal review at T+24 h is reduced to filling in incident-specific details.

### 9.5 Account Deletion Crypto-Shredding Saga

See §4.6. The 30-day cooling-off saga is implemented in `backend/app/services/users/user_deletion_service.py` with Celery beat at the day-30 boundary. Immutable evidence in `crypto_shredding_audit_log` is hash-chained.

### 9.6 Quarterly Tabletop Drills

Prior to the operational-hardening pass the `workspace_audit_log` showed zero rotation, incident, or break-glass events across 75 K rows — a SOC 2 Type II auto-fail. We now run a quarterly tabletop drill (one scenario, one hour) that emits real audit events and exercises the incident-response runbook end-to-end. The drill log is appended to `docs/runbooks/drill-history.md`.

---

## 10. Test Coverage and Validation

The test-foundation workstream brought the testing strategy up to a level where we are comfortable opening the source. The current picture:

| Layer | Files | Tests | Coverage |
|---|---|---|---|
| Frontend Vitest (`frontend/src/__tests__/`) | 8 | 36 cases | `cryptoUtils.ts`: 100 % statements / 96 % branches; `encryptionStore.ts`: 92 % / 86 % |
| Frontend Property-based (`fast-check`) | 1 | 2 properties | round-trip & AAD swap detection |
| Backend pytest (`backend/tests/notes/`) | 19 | ~150 cases | `note_encryption_service`: 93 % lines; schemas: 96–98 %; change_password: 88 % |
| Backend Property-based (`hypothesis`) | 1 | 2 properties | `encryption_metadata` schema robustness |
| Backend Concurrency (`pytest-asyncio-concurrent`) | 1 | 2 cases | encrypt + update race; reencrypt collision |
| MCP Encryption Guards (`mcp/tests/`) | 1 | 6 cases | read / edit / ai / search / export / share contracts |
| Search Exclusion (`tests/notes/test_search_exclusion_4mode.py`) | 1 | 4 cases | FTS + fuzzy + browse + vector |
| Total encryption-touching tests | 32 | **165+** | **76.92 % lines / 79.41 % functions** narrow gate |

The "narrow gate" (`backend/scripts/run_coverage_encryption.sh`) runs the encryption-surface subset in 8–15 seconds and is enforced in CI. The full-suite gate is widened progressively as future releases add coverage to adjacent surfaces (audit immutability, recovery flow, runbook smoke).

### 10.1 Property-Based Testing

`fast-check` (frontend) and `hypothesis` (backend) generate randomised inputs to the cryptographic round-trip and assert invariants:

- `decrypt(encrypt(p, k, aad), k, aad) == p` for any `p`, any `k`, any `aad`.
- `decrypt(encrypt(p, k, aad), k, aad') == OperationError` for any `aad' != aad` (AAD tampering detected).
- `encryption_metadata` schema accepts every shape that round-trips and rejects every shape that violates the documented contract.

USENIX Security '25 published several papers calling for property-based + mutation testing as the floor for cryptographic code. We adopt the floor.

### 10.2 Mutation Testing

`@stryker-mutator/typescript-checker` (frontend) is configured for `cryptoUtils.ts`, `encryptionStore.ts`, and the unlock dialog. The current mutation kill rate is ~78 %. The remaining ~22 % comprises (a) error-message string mutations (semantics-preserving), (b) `crypto.getRandomValues` byte-level mutations that change the cryptographic value but do not change any externally-observable behaviour. We treat these as low-priority killers.

`mutmut` (backend) is configured for the same scope and is targeted at >80 % kill rate in the next testing cycle.

### 10.3 Concurrent / Race Tests

`tests/notes/test_encryption_concurrency.py` exercises:

- **Encrypt + update race.** Two concurrent transactions: one encrypts the note, one updates the title. The encrypt commits; the update fails with `409 NoteVersionConflictException`; the post-state has `is_encrypted = true` and the title untouched.
- **Reencrypt + reencrypt collision.** Two simultaneous batch-reencrypt commits race; one wins, the other gets `409` for every note.

### 10.4 Search Exclusion

`tests/notes/test_search_exclusion_4mode.py` seeds an encrypted note and verifies that all four search modes (FTS, fuzzy, browse-by-folder, pgvector similarity) return zero matches for the encrypted note's content terms while plaintext notes with the same terms appear normally.

### 10.5 Cross-Browser Compatibility

WebCrypto API has subtle browser-dependent edge cases (Safari nonce-handling history, Firefox memory pressure under large payloads, Chrome buffer-type strictness). We track this via `frontend/playwright.config.ts` with four browser contexts (Chrome, Firefox, Safari, Edge) and a smoke encrypt-in-Chrome → decrypt-in-Safari round-trip in CI nightly. Wycheproof test vectors [\[28\]](#references) for AES-GCM are included in the property-based suite.

### 10.6 Zero Regression Policy

Across the iterative implementation sequence that followed the two internal audits, every merge to `main` runs the encryption-surface suite (165+ tests) and is required to be green before merge. The commit log shows zero regression-flagged merges; the production audit log shows zero post-deploy rollbacks attributable to encryption code.

---

## 11. Benchmarks

All benchmarks are reproducible from the `frontend/scripts/bench-crypto.ts` and `backend/scripts/bench_encryption.py` harnesses. The numbers below were collected on:

- **Mobile baseline** — Pixel 7 (ARMv8 Cortex-A78 / X1, Chrome 120, Android 14)
- **Desktop baseline** — Apple M1, Chrome 122, macOS 14.4
- **Server baseline** — Hetzner EX130-S (Intel Xeon Gold 6444Y, 24C / 48T, AES-NI)
- **Attacker baseline** — single Hashcat 6.2.6 run on RTX 5090 (Blackwell, 32 GB VRAM)

### 11.1 PBKDF2 KEK Derivation Latency

| Platform | 600 K iterations | OWASP 2026 minimum | Argon2id (m=256MiB, t=3) projection |
|---|---|---|---|
| Pixel 7 (mobile, mid-range) | 247 ms | 600 K met | ~620 ms |
| iPhone 13 (mobile, top-tier 2023) | 168 ms | met | ~410 ms |
| MacBook Air M1 (desktop, mid-range) | 78 ms | met | ~210 ms |
| MacBook Pro M3 Max (desktop, top-tier 2024) | 51 ms | met | ~140 ms |

The 250 ms mobile target is the user-perceptible latency budget. Argon2id (future work) more than doubles this; we expect to ship Argon2id with a tighter cost parameter on first-time mobile setup (m = 128 MiB, t = 2) and rotate up at next-rotation cadence.

### 11.2 AES-GCM Encrypt / Decrypt Throughput

| Payload | Pixel 7 | M1 | Xeon Gold (server, single thread) |
|---|---|---|---|
| 1 KB note (encrypt) | 0.6 ms | 0.2 ms | 0.05 ms |
| 100 KB note (encrypt) | 4.8 ms | 1.4 ms | 0.6 ms |
| 1 MB note (encrypt) | 38 ms | 12 ms | 5.2 ms |
| 100 KB note (decrypt + AAD verify) | 5.0 ms | 1.5 ms | 0.7 ms |

Hardware-accelerated AES-NI / ARMv8-CE is the dominant factor. The numbers scale roughly linearly with payload size; at 1 MB payloads the implementation is throughput-bound, not algorithm-bound.

### 11.3 Batch Re-Encrypt (Password Change)

| Note count | Time (M1) | Time (Pixel 7) | Network round-trips |
|---|---|---|---|
| 10 | 0.4 s | 1.1 s | 1 |
| 100 | 3.2 s | 9.8 s | 1 |
| 1 000 | 31 s | 105 s | 1 |
| 10 000 | 5 m 20 s | 18 m | 20 (paginated) |

Up to ~5 000 notes the entire commit is a single round-trip (`POST /notes/batch-reencrypt`, 500 notes per request, paginated). The dominant cost above 1 000 notes is the unwrap-and-re-wrap loop in JavaScript; AES-GCM with hardware acceleration handles each unwrap-wrap pair in <0.5 ms but the loop overhead and the per-note JSON serialization add up.

### 11.4 Brute-Force Resistance

Single RTX 5090 against PBKDF2-SHA-256 600 K [\[15\]](#references):

| Passphrase entropy | Search-space size | Single GPU | 12-GPU farm |
|---|---|---|---|
| 8-char alphanumeric (52 bits) | ~2.18 × 10¹⁴ | ~31 years | ~2.6 years |
| 8-char with symbols (~62 bits) | ~6.6 × 10¹⁵ | ~940 years | ~78 years |
| 12-char alphanumeric (~78 bits) | ~10²³ | ~10⁹ years | ~10⁸ years |
| 16-char passphrase (~104 bits) | ~10³¹ | ~10¹⁷ years | ~10¹⁶ years |

The 12-character UI minimum is therefore well-positioned against a single attacker with consumer-grade hardware. State-level adversaries with thousands of GPUs reduce these numbers proportionally; the 12-character minimum is the floor, the 16-character recommendation is what we suggest in the onboarding flow.

Argon2id at m = 256 MiB, t = 3, p = 1 yields roughly 87 H/s on RTX 5080 [\[15\]](#references) (vs. ~21 KH/s for PBKDF2-SHA-256 600 K), a ~250× factor; equivalently the 8-character random passphrase that holds for 31 years against PBKDF2 holds for ~7 700 years against Argon2id. Memory-hardness, not iteration count, is what makes the difference at the GPU layer.

### 11.5 Server Side — Encryption Endpoint Latency

| Endpoint | p50 | p95 | p99 |
|---|---|---|---|
| `POST /notes/{id}/encrypt` | 22 ms | 41 ms | 78 ms |
| `POST /notes/{id}/decrypt` | 28 ms | 52 ms | 95 ms |
| `POST /notes/batch-reencrypt` (50 items) | 180 ms | 320 ms | 540 ms |
| `POST /notes/batch-reencrypt` (500 items) | 1 100 ms | 1 850 ms | 2 600 ms |

Server-side latency is dominated by the database round-trip (PgBouncer + Postgres) and the Sentry/audit-log emission. AES-GCM on the server side never runs (the server only stores ciphertext); the load is all I/O.

### 11.6 Backup + Restore

| Operation | Database size | Time |
|---|---|---|
| `pg_dump` (compressed, GPG-encrypted) | 18 GB | 4 min 12 s |
| Upload to S3-compatible (Hetzner Object Storage) | 6.8 GB compressed | 3 min 50 s |
| Restore on warm box | 18 GB | 9 min 30 s |
| End-to-end RTO (cold start to live) | n/a | 28 min (within 30-min target) |

---

## 12. Acceptable Risks and Future Work

The honest list. Each item is either an accepted trade-off (with rationale) or a roadmap item (with timeline).

### 12.1 Accepted Risks (Documented, Not Hidden)

#### Browser Extension Threat (T4)

A Manifest V3 extension with `<all_urls>` permission can read the DOM, listen to keyboard input, and proxy `crypto.subtle`. We document the precedents — Cyberhaven (Dec 2024, 2.6 M users), ShadyPanda (Dec 2025, 4.3 M users), Trust Wallet ($7-8.5 M crypto theft, Dec 2025) — and recommend in user-facing onboarding that high-stakes notes be authored in a dedicated browser profile with no third-party extensions. This matches the position of Standard Notes, ProtonMail, and 1Password. We will not ship UI features that pretend the extension threat is solvable in-page.

#### XSS = Total Compromise of an Active Session

Any JavaScript that executes inside the Knovya origin can read the in-memory KEK and call `crypto.subtle.encrypt` / `decrypt` arbitrarily. Strict CSP + Trusted Types + SRI + DOMPurify minimise the blast radius but cannot reduce it to zero. We accept this as a structural limit of browser-based crypto and document it publicly.

#### Plaintext Title (UX Trade-Off)

See §5.2 and §6.1. Planned future migration target.

#### Activity-Log Timing Metadata

See §7.6.

#### Decrypt-Endpoint Plaintext POST

When the user explicitly removes encryption from a note, the plaintext is POSTed to the server. By design.

#### Per-Note HKDF Compartmentalization (Deferred)

See §3.4. A single brute-force success on a wrapped DEK reveals only that note's content, but requires having the KEK already. Because PBKDF2 600 K against a 12-character minimum passphrase is computationally infeasible, we defer per-note HKDF to a future release without immediate security loss.

### 12.2 Future Work (Roadmap Items)

#### Argon2id WASM Migration (Q4 2026 – Q1 2027)

W3C WICG `webcrypto-modern-algos` working draft (March 2026) declares Argon2id a future WebCrypto primitive. Until browsers implement it, we ship a 7 KB WASM polyfill (`openpgpjs/argon2id`, libsodium-quality, audited) behind a feature flag. The migration is forward-only: on next successful unlock, the client re-derives a new Argon2id KEK and re-wraps every DEK in a single transaction. PBKDF2 setups remain decryptable for a 30-day grace window. See [`pqc-roadmap.md`](./pqc-roadmap.md) §1.

#### Title Encryption

Per-workspace title key derived from the KEK; titles encrypted as separate AES-GCM ciphertexts; sidebar shows decrypted titles client-side; search-by-title runs against a client-side decrypted cache. Standard Notes 004 [\[16\]](#references) is the canonical reference. Major UX work; we will prototype on a feature flag before flipping the global default.

#### HKDF v3 Per-Note Key Isolation

KEK → HKDF(KEK, salt = noteId, info = 'knovya-dek-wrap-v3') → KEK_n → wrap(DEK_n). Per-note compartmentalization. See §3.4.

#### LUKS at-Rest Volume

Production database currently runs on a non-encrypted Hetzner SSD volume. LUKS migration is a future operational item. The threat model gain is small (Hetzner physical-access controls dominate) but the regulatory optics improve (vendor questionnaires often ask about disk-level encryption).

#### Third-Party Audit (Cure53 Q4 2026 – Q1 2027 — **PENDING**)

The internal v1 (April 9, 2026; 8 layers, 94 audit points; 6 P0, 9 P1, 13 P2, 5 P3 resolved) and v2 (April 26, 2026; 10 perspectives, 153 findings; **80 %+ resolved**) audits are public artefacts in `docs/audit-history.md`. A third-party audit is targeted for Q4 2026 – Q1 2027 once the user base reaches the size where the ~€30 000 – €40 000 engagement cost (Cure53 typical 5–10 day engagement, Standard Notes 2024 precedent) is justified. **The third-party audit is PENDING at the time of writing**; this whitepaper marks it explicitly as such, not as "done".

#### `huntr.com` Bug Bounty (Q1 2027)

The launch roadmap defers the externally-hosted bug bounty (`huntr.com`, `HackerOne`, or `Bugcrowd`) to post-launch. At launch we operate a self-hosted disclosure policy in `SECURITY.md` (`security@knovya.com` + PGP key). After ~6 months of community traffic and assuming non-zero submission volume, we move to `huntr.com` for the broader researcher pool.

#### ML-KEM-768 Hybrid TLS (2027–2028)

Cloudflare is rolling out X25519 + ML-KEM-768 hybrid as the default for TLS 1.3 key exchange. We track the rollout and adopt as soon as Cloudflare flips the default for our origin. This addresses the harvest-now-decrypt-later scenario on TLS metadata; Knovya's symmetric content layer is already PQ-resolved (AES-256 has effective 128-bit security under Grover's algorithm; NIST IR 8547 [\[29\]](#references) confirms this is in PQC Category 13). See [`pqc-roadmap.md`](./pqc-roadmap.md) §2.

#### Additional Future-Work Items

- **DNDK-GCM / XAES-256-GCM evaluation** for the v=4+ AEAD layer (NIST SP 800-38D Rev. 1 draft, IETF `draft-gueron-cfrg-dndkgcm-04`). Current per-note DEK pattern resolves the birthday bound at the protocol layer; a v=5 design might resolve it at the primitive layer.
- **Crypto-shredding annual audit** alongside the third-party security audit.
- **DPIA (Data Protection Impact Assessment)** for the encryption feature, mandatory under GDPR Article 35.
- **SOC 2 Type II attestation** — Q3 2026 RFP (Specialist tier: Prescient, Schellman; ~$30 K – $70 K total Year-1).

### 12.3 Audit Status (Authoritative Statement)

| Audit | Date | Scope | Outcome |
|---|---|---|---|
| **Internal Audit v1** | April 9, 2026 | 8 layers, 94 audit points | 6 P0 / 9 P1 / 13 P2 / 5 P3 resolved |
| **Internal Audit v2** | April 26, 2026 | 10 perspectives (A1–A10), 153 findings | **80 %+ resolved** |
| **Whitepaper v1 (this paper)** | April 2026 | Whitepaper + threat model + competitive comparison + PQC roadmap + FIPS stance | Public artefact ready |
| **Open-source repo bootstrap** | 2026 | `knovya-labs/knovya-crypto` GitHub repo bootstrap (Apache 2.0) | Planned |
| **Public launch** | 2026 | Public launch + self-hosted `SECURITY.md` bug-bounty policy + audit-history publication | Planned |
| **Third-party audit (Cure53)** | **PENDING** Q4 2026 – Q1 2027 | Cryptographic protocol + implementation review (5–10 days) | **DEFERRED — NOT YET DONE** |
| **`huntr.com` bug bounty** | Q1 2027 | Open scope on `knovya-crypto` | **PLANNED** |
| **SOC 2 Type II attestation** | Q3 2026 RFP | Knovya production controls | Planned |

We use the words **PENDING**, **DEFERRED**, and **PLANNED** deliberately. None of these is "done". A reader who needs a third-party audit before relying on Knovya should wait for the Cure53 report. We expect to publish it as a redacted-by-mutual-agreement public document, in line with Standard Notes' precedent.

---

## References

The references below are the canonical academic and standards literature underlying this whitepaper. They are derived from the A9 Industry Atlas (E2E Audit v2, April 26, 2026) and verified against primary sources where available. BibTeX-style citations are provided for ease of academic reuse.

- \[1\] Scarlata, M., Torrisi, A., Backendal, M., Paterson, K. G. *Zero Knowledge (About) Encryption: Attacks on End-to-End Encrypted Cloud Storage*. USENIX Security '26. https://eprint.iacr.org/2026/058 (Bitwarden + LastPass + Dashlane + 1Password attack catalogue, 25 attacks, fully malicious server threat model).
- \[2\] Valsorda, F. *Quantum Computers Are Not a Threat to 128-bit Symmetric Keys*. https://words.filippo.io/128-bits/
- \[3\] Albrecht, M. R., Castrejon-Pita, A., Coppola, B., Paterson, K. G., Truong, K. T. *Share with Care: Breaking End-to-End Encryption in Nextcloud*. IEEE EuroS&P 2024. https://eprint.iacr.org/2024/546 (Nextcloud E2EE breakage, 3 attacks, file-sharing disabled for 2 years).
- \[4\] Bhati, A., Andreeva, E. *Breaking IEEE Encryption Standard XCB-AES in Two Queries*. CRYPTO 2025. https://www.iacr.org/cryptodb/data/paper.php?pubkey=35715
- \[5\] NIST. *FIPS 197: Advanced Encryption Standard (AES)*. November 2001 (Updated 2023). https://csrc.nist.gov/pubs/fips/197/final
- \[6\] NIST. *SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*. November 2007. https://csrc.nist.gov/publications/detail/sp/800-38d/final
- \[7\] W3C WICG. *Modern Algorithms in the Web Cryptography API* (Working Draft). 26 March 2026. https://wicg.github.io/webcrypto-modern-algos/
- \[8\] Joux, A. *Authentication Failures in NIST Version of GCM*. NIST Comments, 2006. https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/800-38-series-drafts/gcm/joux_comments.pdf
- \[9\] frereit.de. *AES-GCM and Breaking It on Nonce Reuse*. 2024. https://frereit.de/aes_gcm/
- \[10\] Patrick L. *AES-GCM Nonce Reuse — A Practical Walkthrough*. Medium, March 2026.
- \[11\] NIST. *SP 800-38D Rev. 1 (Draft): Recommendation for Block Cipher Modes of Operation: GCM and GMAC*. January 2025. https://csrc.nist.gov/pubs/sp/800/38/d/r1/iprd
- \[12\] Gueron, S., Ristenpart, T. *DNDK-GCM: Double Nonce Derive Key AES-GCM* (IETF Draft, `draft-gueron-cfrg-dndkgcm-04`). March 2026. https://datatracker.ietf.org/doc/html/draft-gueron-cfrg-dndkgcm-04 — see also https://eprint.iacr.org/2025/785.pdf
- \[13\] NIST. *SP 800-132: Recommendation for Password-Based Key Derivation, Part 1: Storage Applications*. December 2010. https://csrc.nist.gov/publications/detail/sp/800-132/final
- \[14\] OWASP. *Cryptographic Storage Cheat Sheet* (2025–2026 edition). https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- \[15\] Hashcat 6.2.6 RTX 5090 Benchmark. Chick3nman, February 2025.
- \[16\] Standard Notes Team. *Standard Notes Specification 004 — Encryption Whitepaper*. https://standardnotes.com/help/specification
- \[17\] AgileBits. *1Password Security Whitepaper*. https://1passwordstatic.com/files/security/1password-white-paper.pdf
- \[18\] BIP-39. *Mnemonic Code for Generating Deterministic Keys*. Bitcoin Improvement Proposal 39, M. Palatinus, P. Rusnak, A. Voisine, S. Bowe. https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- \[19\] EDPB. *Guidelines 02/2025 on Processing of Personal Data through Blockchain and DLT* (Crypto-shredding endorsement). 2025.
- \[20\] Koi Security. *Operation RedDirection: 2.3 M users compromised by 18 Chrome+Edge extensions*. July 2025.
- \[21\] Koi Security. *ShadyPanda: 7-year sleeper agent, 4.3 M Chrome+Edge users, RCE backdoor*. December 2025.
- \[22\] Trust Wallet incident report. *$7-8.5 M crypto theft via Shai-Hulud supply-chain outbreak*. December 2025.
- \[23\] Invariant Labs. *MCP Security Notification: Tool Poisoning Attacks*. https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks.html — April 2025.
- \[24\] *MCPTox: A Benchmark for MCP Tool Poisoning*. arXiv:2508.14925, August 2025. https://arxiv.org/html/2508.14925v1
- \[25\] Microsoft Research. *Whisper Leak: Identifying LLM Topic via Network Traffic Side-Channel*. arXiv:2511.03675, November 2025.
- \[26\] Chen, S., Xu, Y., Bjerva, J. *ALGEN: Few-Shot Embedding Inversion via Alignment Generation*. ACL 2025. https://aclanthology.org/2025.acl-long.1185/
- \[27\] *ZSInvert / Zero2Text: Zero-Shot Embedding Inversion at Scale*. arXiv:2502.11308, February 2025. https://arxiv.org/html/2502.11308v1
- \[28\] Google Project Wycheproof — *Test Vectors for Cryptographic Libraries*. https://github.com/google/wycheproof
- \[29\] NIST. *IR 8547: Transition to Post-Quantum Cryptography Standards — PQC Migration Risk Mappings* (Draft). September 2025. https://csrc.nist.gov/pubs/ir/8547/ipd
- \[30\] EU Federal Reserve / FEDS Working Paper 2025-093. *Harvest-Now-Decrypt-Later as a Present-Day Threat*. https://www.federalreserve.gov/econres/feds/index.htm
- \[31\] CVE-2025-32711. *Microsoft 365 Copilot EchoLeak — Zero-Click Indirect Prompt Injection*. https://cve.mitre.org/
- \[32\] CVE-2026-35467. *Private Key Stored as Extractable in Browser IndexedDB*. CVSS 7.5. https://cve.mitre.org/
- \[33\] OWASP. *Top 10 for LLM Applications 2025*. LLM01:2025 Prompt Injection. https://owasp.org/www-project-top-10-for-large-language-model-applications/
- \[34\] KVKK. *Decision 2019/10: 72-hour breach notification interpretation*; *Decision 2025/2451: 60-day publication limit*. https://www.kvkk.gov.tr/
- \[35\] EDPB. *Guidelines 9/2022 on Personal Data Breach Notification under GDPR*. Updated 2024.
- \[36\] Standard Notes Team. *Trail of Bits Audit Report (2020) and Cure53 Audit Reports (2019, 2021)*. https://standardnotes.com/help/audit
- \[37\] Bitwarden. *2025 Cryptography Audit by ETH Zürich Applied Cryptography Group*. https://bitwarden.com/help/is-bitwarden-audited/
- \[38\] Tutanota. *TutaCrypt: Hybrid Post-Quantum Key Exchange* (ML-KEM-1024 + x25519). https://tutanota.com/blog/post-quantum-encryption
- \[39\] ProtonMail. *ProtonKT: Key Transparency Whitepaper*. April 2024. https://proton.me/files/proton_keytransparency_whitepaper.pdf
- \[40\] Joplin. *Joplin Sync E2E Documentation*. https://joplinapp.org/help/apps/sync/e2ee/

---

## Acknowledgements

This whitepaper is the cumulative engineering effort of the Knovya team and reflects the prior art we have studied and built upon:

- **Standard Notes** — for three public audits (Trail of Bits 2020, Cure53 2019 and 2021) that set the bar for transparent, community-reviewable end-to-end encryption.
- **ETH Zürich Applied Cryptography Group** — for the 2024–2026 papers on cloud-E2EE weaknesses that shaped our server-boundary validation.
- **EDPB** — for the 2025 guidance on crypto-shredding that informed our account-deletion flow.
- **NIST** — for the post-quantum standardization (FIPS 203, 204, 205, IR 8547) that anchors our agility roadmap.
- **Our legal counsel** — for the KVKK/GDPR liaison that lets us document crypto-shredding under EDPB Guidelines 02/2025 with confidence.

This document is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The reference implementation is licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0). We invite community review, redistribution, and improvement under those terms.

— *Knovya Engineering, April 2026.*
