# Knovya FIPS 140-3 Stance

| Field | Value |
|---|---|
| **Version** | 1.0 |
| **Date** | April 2026 |
| **Companion to** | [`knovya-e2e-encryption-v1.md`](./knovya-e2e-encryption-v1.md) |
| **License** | CC BY-SA 4.0 |
| **Status** | Decision document — Knovya does not pursue FIPS 140-3 module certification at this time |

This document records Knovya's deliberate decision regarding the [Federal Information Processing Standards (FIPS) 140-3 Cryptographic Module Validation Program (CMVP)](https://csrc.nist.gov/projects/cryptographic-module-validation-program) [\[1\]](#references). It also provides a vendor-questionnaire-ready answer template that Knovya can supply to enterprise customers who ask "are your cryptographic modules FIPS 140-3 validated?".

The position is stable as of April 26, 2026 and will be re-evaluated under specific conditions enumerated below. The decision was made on the basis of the audit and product-strategy work captured in the Knovya E2E Audit v2 (April 26, 2026) and the associated internal implementation plan.

---

## TL;DR

> Knovya is a B2C SaaS product targeting individual users and small teams. Knovya **does not** pursue FIPS 140-3 cryptographic-module certification at this time. The decision is driven by (a) absence of U.S. federal-customer demand, (b) deployment topology incompatibility (browser-based WebCrypto API is not a FIPS-validated module), and (c) cost-benefit analysis (~$ 100 K – $ 500 K certification cost vs. addressable enterprise pipeline that does not require the certification). We use industry-standard, NIST-published cryptographic primitives (AES-256-GCM per FIPS 197, PBKDF2-HMAC-SHA-256 per SP 800-132 with 600 K iterations, ML-KEM and ML-DSA roadmap items per FIPS 203/204), but we do not pursue the formal CMVP module-validation route.

---

## Decision

**Knovya will not seek FIPS 140-3 cryptographic-module validation.**

The decision is recorded as of April 26, 2026 and is informed by the post-deferral E2E audit v2 master implementation plan. It is **subject to re-evaluation** under three explicit triggers (see §"Re-evaluation Triggers" below).

---

## Rationale

### 1. Customer-Profile Mismatch

FIPS 140-3 certification is a U.S. federal procurement requirement (Federal Risk and Authorization Management Program / FedRAMP, NIST SP 800-53 [\[2\]](#references)). It applies to vendors selling to U.S. federal agencies, U.S. Department of Defense suppliers, federal-contractor sub-suppliers, and a narrowing set of regulated industries (HIPAA-covered entities at certain enterprise tiers, some financial-services regulated firms).

Knovya's current customer base is:

- Individual users (free + paid) — explicitly out-of-scope for FIPS 140-3.
- Small teams and personal-knowledge-base users — explicitly out-of-scope.
- Enterprise tier — not yet launched. When it does launch, the target market is *not* U.S. federal procurement.

The certification cost would not produce a return until Knovya enters the federal-procurement market, which is outside the founder's stated business plan for the foreseeable future.

### 2. Deployment-Topology Incompatibility

The Knovya cryptographic operations that protect end-user content live in **the user's browser** via the WebCrypto API. The W3C WebCrypto specification [\[3\]](#references) is not itself a FIPS 140-3 module: it is a JavaScript API that delegates to whatever cryptographic implementation the browser ships. Browsers ship a mixture of NSS (Firefox), BoringSSL (Chrome), and SecureTransport / CoreCrypto (Safari) — none of which is uniformly FIPS-validated.

A FIPS 140-3 certification is granted to a *cryptographic module*, not to an algorithm or to a protocol. To be FIPS 140-3 validated, Knovya would have to:

1. Identify a specific FIPS-validated module the browser exposes (which the WebCrypto API does *not* expose discoverably).
2. Bypass the WebCrypto API in favour of a vendor-specific FIPS module (which would break our universal-browser support story and increase bundle weight by ~500 KB to 2 MB depending on the module).
3. Certify the *Knovya server-side* cryptographic operations, which today are minimal — JWT HMAC signing, GPG backup encryption, Stripe webhook HMAC verification, AI-MCP token encryption. The server-side stack is FastAPI / Python, using the `cryptography` library, which has FIPS-mode support (via the underlying OpenSSL FIPS module) but the application has not been independently validated.

The shortest path to a meaningful FIPS 140-3 statement would be the server-side scope, which would not actually secure any of the encrypted-note content (that lives in the browser). Customers asking the question "is your cryptography FIPS 140-3 validated?" usually want the answer to apply to the data they care about — which, for encrypted notes, is browser-side. Knovya cannot honestly say "yes" without significant additional engineering.

### 3. Cost-Benefit Analysis

CMVP certification cost in 2026 (per industry pricing) [\[4\]](#references):

- Lab-validation engagement: ~$ 80 K – $ 250 K (AES-NI, GoodCrypto, atsec, KeyPair, etc.)
- Internal engineering effort: 6–18 months FTE
- Annual re-validation if the module changes: ~$ 30 K – $ 80 K
- **Total Year-1 cost:** $ 100 K – $ 500 K (lab + internal engineering)
- **Annual maintenance:** $ 50 K – $ 150 K

The Knovya 2026 budget allocates these funds to:

- Third-party cryptographic protocol audit (Cure53 ~€ 30 K – € 40 K, Q4 2026 – Q1 2027)
- SOC 2 Type II attestation (Specialist tier ~$ 30 K – $ 70 K Year-1)
- ISO 27001 (deferred; Q3 2027 evaluation)
- KVKK / GDPR legal compliance (external legal counsel retainer, ~TRY 60 K – 150 K Year-1)

Cure53 + SOC 2 + ISO 27001 cover the customer questions Knovya actually receives. FIPS 140-3 covers a question we do not receive from our target market.

### 4. Open-Source Trust Substrate

Knovya's open-source-by-default strategy (Apache 2.0 `knovya-crypto` repo planned for the upcoming public launch) provides a *different* trust substrate than FIPS 140-3:

- **FIPS 140-3** validates that a specific module implements specific algorithms correctly under specific deployment conditions. The validation is an attestation, not a guarantee.
- **Open-source + community audit** allows independent verification of the protocol design, the implementation, and the deployment topology. The verification is recurring, not point-in-time.

Standard Notes is the canonical comparable: open-source, three public audits (Trail of Bits 2020, Cure53 2019 + 2021), no FIPS 140-3 module certification. Bitwarden similarly: GPL v3, ETH Zürich Applied Crypto 2025 + others, no FIPS 140-3 module certification (Bitwarden does have FedRAMP work in progress, but it scopes the *deployment*, not a module).

---

## Vendor Questionnaire Template

Enterprise customers occasionally include a question about FIPS 140-3 in standard procurement questionnaires (Vanta-template, Drata-template, custom forms). The recommended Knovya answer is:

> **Q: Do you use FIPS 140-3 validated cryptographic modules?**
>
> **A:** Knovya uses industry-standard cryptographic primitives published by NIST: AES-256-GCM (FIPS 197 / SP 800-38D), PBKDF2-HMAC-SHA-256 with 600 000 iterations (SP 800-132, meeting OWASP 2026 minimum), and SHA-256 / SHA-3-512 (FIPS 180-4 / FIPS 202). Our cryptographic operations leverage the W3C WebCrypto API in the browser and the OpenSSL-backed `cryptography` library on the server, both of which implement these algorithms following NIST specifications.
>
> Knovya does not currently hold FIPS 140-3 module certification (CMVP) for the deployed cryptographic boundary, because (a) our target market does not include U.S. federal procurement, and (b) browser-based WebCrypto API does not expose a FIPS-validated module in a way that would let us assert validation for the encrypted-content path that protects end-user data.
>
> We have completed two internal cryptographic audits (April 9 and April 26, 2026), are pursuing a third-party audit with Cure53 (target Q4 2026 – Q1 2027), and are pursuing SOC 2 Type II attestation (Specialist tier RFP Q3 2026). The cryptographic protocol design is publicly documented in our [E2E Encryption Whitepaper v1](./knovya-e2e-encryption-v1.md), and the implementation will be open-sourced under Apache 2.0 prior to launch.
>
> If FIPS 140-3 module validation is a hard requirement for your procurement, we are happy to discuss the timeline and budget for a server-side-scope certification (as the browser-side path is structurally outside the CMVP boundary).

The template is intentionally honest: it answers "no, we are not FIPS-validated", explains why, and offers a path forward for customers who genuinely need the certification (which would require a custom enterprise engagement).

---

## What We Do Use

To be unambiguous about the algorithm choices that underlie Knovya:

| Primitive | Standard | Knovya parameters | Used in |
|---|---|---|---|
| AES-256-GCM | NIST FIPS 197 + SP 800-38D | 256-bit key, 96-bit random IV, 128-bit auth tag | Note content encryption, DEK wrapping, GPG backup, AI-MCP token encryption |
| PBKDF2-HMAC-SHA-256 | NIST SP 800-132 | 600 000 iterations, 128-bit salt, 256-bit output | KEK derivation from passphrase |
| SHA-256 | NIST FIPS 180-4 | Standard | `workspace_audit_log` hash chain, AAD (post 2.4 fix), `crypto_shredding_audit_log` evidence |
| HKDF-SHA-256 | RFC 5869 | Standard | (Phase IV) per-note KEK derivation |
| Argon2id | RFC 9106 + W3C WICG draft | m=256 MiB, t=3, p=1 (desktop) / m=128 MiB, t=2, p=1 (mobile) | (Phase IV) KDF migration target |
| ML-KEM-768 | NIST FIPS 203 | Standard parameters | (Phase IV) TLS hybrid (via Cloudflare); future shared-workspace key exchange |
| ML-DSA-65 | NIST FIPS 204 | Security level 3 | (Phase IV) recovery-key signing, sharing-invitation signing |
| ChaCha20-Poly1305 | RFC 8439 | Standard | (Optional Phase IV) WASM polyfill if hardware-AES is unavailable |

Every primitive is published by NIST (or, in the case of ChaCha20-Poly1305 and Argon2id, IETF + RFC + NIST endorsement-pending). None requires custom cryptography. Boring, by design (whitepaper §2).

---

## Re-evaluation Triggers

This decision is **not permanent**. We re-evaluate under any of the following:

1. **Enterprise tier launch with federal-customer pipeline.** If Knovya's enterprise tier acquires a customer whose procurement explicitly requires FIPS 140-3, we re-cost the engagement. The most likely path is a server-side-scope certification (covering JWT signing, backup encryption, MCP-token encryption) under a separate enterprise SKU.

2. **Regulated-industry expansion.** HIPAA-covered entities at certain enterprise tiers, some financial-services regulated firms, and certain U.S. defense-contractor sub-suppliers ask for FIPS 140-3 in procurement. If Knovya develops material market traction in any of these segments, the calculus changes.

3. **Browser-side FIPS module availability.** If a future browser ships a discoverable, vendor-stable FIPS-validated WebCrypto subset (which Apple Security Framework and ChromeOS BoringSSL make plausible on a 5–10 year horizon), the structural barrier to encrypted-content-path FIPS certification falls. We re-evaluate at that point.

The re-evaluation cadence is **annual**, captured in the runbook `secret-inventory-rotation-cadence.md` under the heading "Compliance & Certification Posture Annual Review".

---

## What We Do Pursue Instead

The Knovya 2026–2027 compliance posture is intentionally diversified across complementary attestations:

- **Internal cryptographic audit v1 + v2** (✅ completed April 2026) — public artefacts in `docs/audit-history.md`.
- **Third-party cryptographic protocol audit** (PENDING — Cure53 target Q4 2026 – Q1 2027, ~€ 30 K – € 40 K).
- **SOC 2 Type II attestation** (RFP Q3 2026, Specialist tier — Prescient or Schellman, ~$ 30 K – $ 70 K Year-1; ongoing $ 50 K – $ 100 K annual).
- **ISO 27001** (deferred to Q3 2027 evaluation; bundle pricing with SOC 2 firm typically ~$ 20 K – $ 40 K incremental).
- **KVKK / GDPR legal compliance** (continuous; external legal counsel retainer; DPIA for E2E feature mandatory under GDPR Article 35).
- **Open-source release** (Apache 2.0 `knovya-crypto` repository on GitHub).
- **Self-hosted bug-bounty policy** (`SECURITY.md` + `security@knovya.com` PGP key at public launch); migration to `huntr.com` planned Q1 2027.
- **`huntr.com` bug bounty registration** (Phase IV — Q1 2027).

The combined posture is, in our judgment, materially stronger than FIPS 140-3 alone for our actual user base. We document this trade-off honestly: a customer who asks for FIPS 140-3 and is unwilling to accept the alternative attestations will not be a Knovya customer in 2026–2027. We are at peace with that.

---

## References

- \[1\] NIST CMVP. *FIPS 140-3 Cryptographic Module Validation Program*. https://csrc.nist.gov/projects/cryptographic-module-validation-program
- \[2\] NIST. *SP 800-53 Rev 5: Security and Privacy Controls for Information Systems and Organizations*. https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- \[3\] W3C. *Web Cryptography API*. W3C Recommendation. https://www.w3.org/TR/WebCryptoAPI/
- \[4\] CMVP-experienced consultancy quotes (atsec, Acumen Security, KeyPair Consulting). 2026 industry survey via NIST CMVP lab list. https://csrc.nist.gov/projects/cryptographic-module-validation-program/testing-laboratories
- \[5\] NIST FIPS 197, FIPS 180-4, SP 800-38D, SP 800-132, FIPS 203, FIPS 204. https://csrc.nist.gov

— *Knovya Engineering, April 26, 2026.*
