# `crypto/` — cryptographic surface

This directory is the subset of the Knovya codebase that is safe and
useful to publish in isolation under Apache License 2.0. It contains
the frontend WebCrypto module, the backend encryption invariant
service, shared type definitions, and the test suite.

Everything outside this directory (billing, workspace membership,
real-time infrastructure, editor, AI gateway, observability) lives in
the monorepo and is intentionally not included here.

## Public API surface

### Frontend (`crypto/frontend/`)

| Export | Purpose |
|---|---|
| `deriveKEK(password, { salt, iter })` | PBKDF2-HMAC-SHA256 600K → AES-256 KEK, `extractable=false`. |
| `deriveDEK(kek, { noteId, counter })` | HKDF v3 per-note DEK, `extractable=false`. |
| `encryptNote({ kek, noteId, plaintext, version })` | AES-256-GCM with AAD v3 binding; returns `{ ciphertext, iv, counter, version }`. |
| `decryptNote({ kek, noteId, envelope })` | Inverse of `encryptNote`. |
| `reencryptBatch({ oldKek, newKek, notes, pageSize })` | 4-phase password-change batch worker. |
| `generateRecoveryKey()` | BIP-39 24-word seed wrapping the KEK. |
| `ENCRYPTION_VERSION` | Enum dispatch; see `crypto/types.ts`. |

### Backend (`crypto/backend/`)

| Export | Purpose |
|---|---|
| `NoteEncryptionService.validate_encryption_invariant(note_id, payload)` | Reject writes that carry plaintext for notes marked `is_encrypted=true`. |
| `NoteEncryptionService.ensure_server_boundary(note)` | Enforce `content_text == ''`, `search_vector IS NULL`, `embedding IS NULL`. |
| `EncryptionMetadataSchema` | Pydantic v2 schema for `encryption_metadata`. |
| `AADString.build(note_id, counter, version)` | Canonical AAD construction (matches the frontend byte-for-byte). |
| `EncryptionInvariantViolation` | Custom exception; mapped to HTTP 409 by the API layer. |

### Shared (`crypto/types.ts`)

- `ENCRYPTION_VERSION` enum (`V1_UNBOUND`, `V2_AAD_BOUND`, `V3_HKDF_PER_NOTE`).
- `EncryptedEnvelope` interface.
- `AADSchema` string shape and constants.
- `MIN_PBKDF2_ITERATIONS`, `DEFAULT_PBKDF2_ITERATIONS` (600,000).

## Release status

This initial release publishes the **public API surface** and the
invariants that any reference implementation must preserve. The full
reference implementation is scheduled for a future release and will be
committed into this repository at that point.

Until then, the build and test steps below are provided for
documentation value; concrete execution depends on the reference
implementation. See the top-level `CONTRIBUTING.md` and
`.github/workflows/` for the expected layout once the implementation
lands.

## Tests

- `crypto/tests/round-trip.test.ts` — per-version `encrypt → decrypt → equal`.
- `crypto/tests/aad-binding.test.ts` — swapping `note_id`/`counter`/`version` fails authentication.
- `crypto/tests/wycheproof-aes-gcm.test.ts` — Google Wycheproof AES-GCM vectors.
- `crypto/tests/property/isolation.test.ts` — per-note DEK isolation (fast-check).
- `crypto/tests/backend/test_invariant.py` — server-boundary enforcement (hypothesis).

## License

Apache License 2.0. See [`../LICENSE`](../LICENSE).
