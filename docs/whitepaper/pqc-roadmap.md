# Knovya Post-Quantum Cryptography Roadmap (2026 – 2032)

| Field | Value |
|---|---|
| **Version** | 1.0 |
| **Date** | April 2026 |
| **Companion to** | [`knovya-e2e-encryption-v1.md`](./knovya-e2e-encryption-v1.md) |
| **License** | CC BY-SA 4.0 |
| **Status** | Roadmap — not yet implemented; serves as Phase IV planning artefact |

This document is Knovya's five-year post-quantum cryptography (PQC) migration plan. It articulates *why* we believe Knovya's current symmetric-only architecture is already PQ-resolved at the content layer, *where* the meaningful PQ migration work actually lives (TLS, future asymmetric layers, KDF), and *when* we expect to ship each step. The plan is conservative, NIST-aligned, and explicitly tracks the production-deployed precedents — Tutanota's TutaCrypt (March 2024) [\[1\]](#references), Cloudflare's hybrid X25519+ML-KEM-768 default [\[2\]](#references), and Apple iMessage PQ3 [\[3\]](#references).

The reader should treat this as a planning document, not as a description of shipped functionality. Where milestones depend on external standards (W3C WICG `webcrypto-modern-algos` [\[4\]](#references), NIST IR 8547 [\[5\]](#references), CNSA 2.0 [\[6\]](#references), FIPS 140-3 [\[7\]](#references)), we cite the upstream timeline.

---

## Executive Summary

The single most important sentence in this document:

> Knovya's content encryption pipeline is symmetric-only (AES-256-GCM + PBKDF2-SHA-256). Under Grover's algorithm, AES-256 retains 128-bit effective security, which NIST IR 8547 [\[5\]](#references) places in PQC Category 13 — already PQ-resolved.

What this means in practice:

- A "harvest-now, decrypt-later" adversary who captures encrypted Knovya note ciphertext today and waits for cryptographically-relevant quantum computers (NIST Q-Day estimate: 2030 ± 5 years) **cannot decrypt the captured ciphertext** even with a CRQC, because the per-note DEK is wrapped under a passphrase-derived KEK, and AES-256 + PBKDF2 are both classified as PQ-safe symmetric primitives.
- The post-quantum migration concern for Knovya is concentrated at three points: **(a)** the TLS layer (currently classical X25519, migrating to hybrid X25519+ML-KEM-768 as Cloudflare default flips), **(b)** the password KDF (PBKDF2-SHA-256 → Argon2id, a symmetric improvement that is also marginally more PQ-friendly), **(c)** future asymmetric layers if and when we ship recovery-key signing or multi-device key sharing.

The five-year plan below addresses each in sequence.

---

## Phase IV — 2026 Q4 to 2027 Q2: Argon2id WASM Migration

**Status:** Planned. Dependencies tracked.

**Trigger conditions:**

- W3C WICG `webcrypto-modern-algos` [\[4\]](#references) Working Draft (declared March 26, 2026) reaches *Candidate Recommendation* OR
- Browser support for native Argon2id reaches >85 % of Knovya user base (per `caniuse.com`) OR
- 2026-Q4 hard deadline — ship a 7 KB WASM polyfill (`openpgpjs/argon2id`, libsodium-quality) behind a feature flag, regardless of native support.

**Migration mechanics:**

1. New `ENCRYPTION_VERSION = 4` ships. v=4 metadata replaces `kdf: 'PBKDF2'` with `kdf: 'Argon2id'`, adds `mem`, `passes`, `parallelism` fields. v=1, v=2, v=3 metadata continue to decrypt transparently (cipher agility — whitepaper §2.5).
2. On the user's next successful unlock, the client:
   - Derives a new Argon2id KEK using `m = 256 MiB, t = 3, p = 1` (desktop) or `m = 128 MiB, t = 2, p = 1` (mobile, slower devices).
   - Re-wraps every existing DEK under the new KEK in a single transaction (via the existing 4-phase password-change flow, whitepaper §4.4).
   - Writes the new `encryption_setup` atomically alongside the wrapped DEK rotation.
3. PBKDF2 setups remain decryptable for a 30-day grace window, then are server-side flagged as deprecated and force-rotate on next login.

**Parameter rationale:**

- `m = 256 MiB` — RFC 9106 [\[8\]](#references) "second recommended option" for high-memory environments. RTX 5080 benchmark: ~87 H/s [\[9\]](#references), a ~250× factor improvement over PBKDF2 600 K (~21 KH/s on the same hardware).
- `t = 3` — RFC 9106 default; provides time-cost margin against algorithmic improvements.
- `p = 1` — single-threaded; matches WebCrypto / WASM execution model.

**Mobile compromise:** the desktop parameter set is too slow on low-end mobile (Pixel 4-class, ~2 second derivation). For initial setup on mobile we ship `m = 128 MiB, t = 2, p = 1` (~620 ms on Pixel 7) and rotate up to the desktop parameters at next-rotation cadence on devices that demonstrate sufficient capability.

**Why now (and why not earlier):**

- OWASP 2026 lists Argon2id as the first-choice password KDF [\[10\]](#references); PBKDF2 is "FIPS 140 compliance only".
- Single-RTX-5080 benchmark differentiation: ~70× attacker-cost improvement on the password layer.
- Tutanota and Standard Notes already use Argon2id (Standard Notes since 2018-era specifications). The technique is mature; Knovya's only blocker is browser-native API availability.

---

## Phase IV — 2027 Q1 to 2027 Q4: TLS Layer Hybrid (X25519 + ML-KEM-768)

**Status:** Tracking Cloudflare's deployment.

**Background:** Cloudflare announced X25519+ML-KEM-768 as the default key-exchange for TLS 1.3 in late 2025. As of early 2026 the rollout is partial (origin-by-origin opt-in). The hybrid design ensures that even if ML-KEM-768 (FIPS 203 [\[11\]](#references)) is broken in the future, the X25519 fallback preserves classical security; conversely, even if X25519 is broken by a CRQC, the ML-KEM-768 component preserves PQ security.

**Knovya milestone:** adopt the hybrid as soon as Cloudflare flips the default for our origins (`api.knovya.com`, `app.knovya.com`, `mcp.knovya.com`). Expected timeline: 2027 Q1–Q4. No code changes required on Knovya side; this is a Cloudflare configuration toggle.

**What this addresses:**

- "Harvest-now, decrypt-later" on TLS metadata. While Knovya note content is already PQ-safe at the content layer, the TLS-layer encryption of the API request/response (which carries note IDs, encrypted-payload bytes, and other metadata) is currently classical. A future CRQC could recover the TLS session keys from a captured packet trace, exposing routing metadata.
- Post-quantum forward secrecy for new sessions. Hybrid X25519+ML-KEM-768 closes the metadata channel against the harvest-now adversary.

**Backend follow-up (2027 Q3–Q4):**

- nginx with OpenSSL 3.4+ ML-KEM enable for any direct (non-Cloudflare) traffic.
- mTLS internal service connections (backend ↔ PgBouncer ↔ Postgres) classical-only for the foreseeable future; the threat model on internal-network traffic is dominated by physical-access controls (Hetzner data centre).

---

## Phase IV — 2028 Q1 to 2029 Q2: Recovery Key + Sharing Public-Key Migration

**Status:** Conditional on feature delivery.

This phase is contingent on Knovya shipping two features that do not exist today:

1. **Recovery-key signing.** The BIP-39 24-word recovery key (whitepaper §4.5) is currently used purely as a symmetric KDF input. If we add per-device recovery-key signing (so the user can prove possession of the recovery key on a fresh device), the signature scheme will be **ML-DSA-65** (FIPS 204 [\[12\]](#references), security level 3 — public key 1 952 bytes, signature 3 293 bytes) in hybrid with classical Ed25519.
2. **Multi-device / shared-workspace key sharing.** When (if) Knovya ships shared-workspace E2E (currently a Phase 3 / Phase IV item), the public-key encapsulation will use **ML-KEM-768** (FIPS 203 [\[11\]](#references), 1 184-byte public key, 1 088-byte ciphertext) in hybrid with X25519. The corresponding signature scheme for workspace-membership invitations will be **ML-DSA-65**.

**Cryptographic-agility framework:** the existing `ENCRYPTION_VERSION` pipeline (whitepaper §2.5) is the deliberate enabler. When ML-KEM/ML-DSA ship, the sharing protocol's metadata schema gains an `asymmetric_v` field independent of the symmetric content `v`. Hybrid mode is mandatory at first; transition to PQ-only follows NIST IR 8547's 2030+ timeline.

**Library candidates:**

- **Cryspen libcrux** [\[13\]](#references) — formally verified Rust + C ML-KEM, deployed in OpenSSH, Firefox, Signal. WASM port exists.
- **`mlkem-wasm`** [\[14\]](#references) — ~50 KB gzipped, suitable for browser bundle.
- **Bouncy Castle** ML-KEM port — viable for backend Python/Java integration if needed.

---

## Phase IV — 2029 Q3 to 2030 Q4: Internal Service-to-Service PQC

**Status:** Conditional on Phase IV-1 + IV-2 success.

This phase migrates the *internal* signing and encryption layers that today use classical primitives:

- `INTERNAL_AUTH_SECRET` (HMAC-SHA-256, 32-byte secret) → Ed25519-signed JWTs in hybrid with ML-DSA-44.
- Backup encryption — GPG (AES-256 + symmetric passphrase) → Age (ChaCha20-Poly1305 + X25519+ML-KEM-768 hybrid for asymmetric envelope).
- Hocuspocus internal JWTs → ML-DSA-44 hybrid signatures.
- `STRIPE_WEBHOOK_SECRET`, `AI_MCP_ENCRYPTION_KEY` — symmetric layer remains AES-GCM (PQ-safe); rotation cadence unchanged.

**Why later than Phase IV-1 + IV-2:** the internal trust boundary is dominated by physical-access and operational controls. Post-quantum HMAC-via-asymmetric is over-engineering until external surfaces (TLS, recovery key, sharing) are migrated.

---

## Phase IV — 2030 Q1 to 2031 Q4: CNSA 2.0 Mandate Alignment

**Status:** Tracking the mandate.

NSA's CNSA 2.0 [\[6\]](#references) requires PQC for U.S. federal national-security systems by 2030; NIST IR 8547 [\[5\]](#references) targets 2035 for the broader migration. Knovya is not a U.S. federal customer-facing product, so the mandate does not directly apply; however, the deadline is the trigger for an end-to-end audit of our PQC readiness:

- All new features ship default-PQC (hybrid where the standard mandates, PQ-only where the standard permits).
- `workspace_audit_log` hash chain migrates from SHA-256 to **SHA-3-512** (NIST SP 800-208 [\[15\]](#references) stance — SHA-3 is preferred when post-quantum confidence is required, even though SHA-256 has 128-bit Grover-resistant security).
- FIPS 140-3 module selection decision (see [`fips-140-3-stance.md`](./fips-140-3-stance.md)) — re-evaluated if Knovya enters federal-customer enterprise tier.
- Third-party PQC end-to-end audit (Cure53 or Trail of Bits) — ~€60 000 – €120 000 engagement (estimate based on 2026 pricing).

---

## Phase V — 2031+: Legacy Deprecation

**Status:** Forward-looking; details defined as the milestones approach.

By 2031 Knovya's PQ posture should be:

- All password setups on Argon2id (PBKDF2 deprecated post-2027).
- All TLS sessions hybrid X25519+ML-KEM-768 (default at Cloudflare and at any direct origin).
- All recovery-key signing + sharing public-key encapsulation hybrid ML-KEM-768 + ML-DSA-65.
- `workspace_audit_log` hash chain on SHA-3-512.

Legacy code paths:

- v=1, v=2, v=3 PBKDF2 encryption metadata: forced upgrade on next-login basis. Users with locally cached old metadata are prompted to unlock and re-derive.
- Old PBKDF2 password hashes — force-rotate via login prompt.
- Old AES-256-GCM ciphertext — kept (PQ-safe). The cipher-agility framework lets us swap KDF and AAD without re-encrypting content.
- Old RSA / ECC keys (if any have shipped by 2031) — public deprecation announcement and ledger entry.

The Knovya whitepaper v3 (the planned Phase V revision of this document) will include a chapter dedicated to the PQC migration retrospective: what shipped on schedule, what slipped, what surprised us.

---

## Cryptographic-Agility Principle

Every PQC migration step above relies on a single design property: **cipher agility** built into the protocol from day one. The `ENCRYPTION_VERSION` pipeline (whitepaper §2.5) is the canonical implementation:

- v=1 (no AAD, legacy)
- v=2 (crypto-params AAD only — Bitwarden Issue 9-vulnerable)
- v=3 (identity-bound AAD with `noteId | workspaceId | userId` — current default)
- v=4 (Argon2id KDF — Phase IV-1)
- v=5 (DNDK-GCM or XAES-256-GCM AEAD — research item, beyond Phase IV)
- v=6 (asymmetric-bound AAD for shared workspaces — Phase IV-3)

Each version is forward-only. Users on older versions decrypt transparently and upgrade on next-write or next-rotation. The framework's correctness is tested via property-based round-trips (`fast-check` frontend, `hypothesis` backend) and via mutation testing (Stryker, mutmut) across the cipher-agility code paths.

---

## Why "Knovya is Already PQ-Resolved at the Content Layer"

We use the phrase carefully, with the following authority:

- **NIST FIPS 197** [\[16\]](#references) — AES-256 baseline.
- **NIST IR 8547** [\[5\]](#references) — places AES-256 in PQC Category 13. Symmetric-only protocols using AES-256 are *not* on the deprecation list.
- **NIST SP 800-208** [\[15\]](#references) — discusses post-quantum status of symmetric primitives.
- **CNSA 2.0** [\[6\]](#references) — does not list AES-256 as quantum-vulnerable; AES-128 is "approved with caution"; AES-256 is "approved".
- **Filippo Valsorda — *Quantum Computers Are Not a Threat to 128-bit Symmetric Keys*** [\[17\]](#references) — a clear, accessible articulation of the same conclusion.

What this **does not** mean:

- It does not mean Knovya is "fully post-quantum". The TLS layer, the OAuth/JWT signing, and any future asymmetric layers have classical exposure.
- It does not mean we will not migrate. AES-256 is PQ-safe; PBKDF2 is PQ-safe. But the Phase IV migration to Argon2id is also a meaningful classical-attacker improvement (~70× GPU-cost factor), and the hybrid TLS layer addresses the metadata-layer harvest-now scenario.
- It does not mean we ignore "harvest-now, decrypt-later" alarms. The Federal Reserve FEDS 2025-093 [\[18\]](#references) and the NIST IR 8547 draft both formally recognize HNDL as a present-day threat. Knovya's content layer is robust against it; the metadata layer is the migration target.

---

## What Knovya Will Not Do

- **Quantum-key-distribution (QKD) hardware.** QKD is interesting research; it is not a viable consumer-SaaS deployment. NIST IR 8547 explicitly de-emphasises QKD relative to PQC algorithm migration.
- **Custom post-quantum primitives.** We deploy only NIST-standardised (FIPS 203/204/205) or in-process (FIPS 206 Falcon, when finalized) algorithms.
- **Pre-hybrid PQ-only deployment.** Until the broader ecosystem matures (browser support, library audit history), every PQ deployment is hybrid (classical + PQ) so that a flaw in either component does not compromise the other.

---

## References

- \[1\] Tutanota. *TutaCrypt: Hybrid Post-Quantum Key Exchange* (March 2024). https://tutanota.com/blog/post-quantum-encryption
- \[2\] Cloudflare. *Post-Quantum Cryptography Rollout: X25519+ML-KEM-768 Default* (2025–2026). https://blog.cloudflare.com/pq-2025/
- \[3\] Apple. *iMessage with PQ3: Post-Quantum Forward Secrecy* (2024). https://security.apple.com/blog/imessage-pq3/
- \[4\] W3C WICG. *Modern Algorithms in the Web Cryptography API* (Working Draft, 26 March 2026). https://wicg.github.io/webcrypto-modern-algos/
- \[5\] NIST. *IR 8547: Transition to Post-Quantum Cryptography Standards — PQC Migration Risk Mappings* (Draft, September 2025). https://csrc.nist.gov/pubs/ir/8547/ipd
- \[6\] NSA. *Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)*. https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3148990/
- \[7\] NIST CMVP. *FIPS 140-3 Cryptographic Module Validation Program*. https://csrc.nist.gov/projects/cryptographic-module-validation-program
- \[8\] RFC 9106. *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*. https://datatracker.ietf.org/doc/rfc9106/
- \[9\] Treszyk Vaulton thesis. *Architecture vs. Brute Force: Benchmarking KDFs for My Thesis*. dev.to, 2026.
- \[10\] OWASP. *Cryptographic Storage Cheat Sheet 2026*. https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- \[11\] NIST. *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*. August 2024.
- \[12\] NIST. *FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)*. August 2024.
- \[13\] Cryspen libcrux. *Formally Verified ML-KEM in Rust + C* (Real-World Crypto 2025). https://cryspen.com/post/rwc-2025/
- \[14\] dchest/mlkem-wasm. *ML-KEM WebAssembly Port*. https://github.com/dchest/mlkem-wasm
- \[15\] NIST. *SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes*.
- \[16\] NIST. *FIPS 197: Advanced Encryption Standard (AES)*. November 2001 (Updated 2023).
- \[17\] Valsorda, F. *Quantum Computers Are Not a Threat to 128-bit Symmetric Keys*. https://words.filippo.io/128-bits/
- \[18\] U.S. Federal Reserve. *FEDS Working Paper 2025-093: Harvest-Now-Decrypt-Later as a Present-Day Threat*. https://www.federalreserve.gov/econres/feds/index.htm

— *Knovya Engineering, April 26, 2026.*
