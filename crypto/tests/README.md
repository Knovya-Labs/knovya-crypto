# `crypto/tests/` — test vector skeletons

This directory lists the tests that will run in `knovya-labs/knovya-crypto`
once the reference implementation is available in this repository. In
this initial release, only the file headers and planned invariants are
committed. Running these files today will report `describe.skip` /
`pytest.skip` until the implementation lands in a future release.

| File | Runner | Purpose |
|---|---|---|
| `round-trip.test.ts` | vitest | `encrypt → decrypt → equal` for each `ENCRYPTION_VERSION`. |
| `aad-binding.test.ts` | vitest | Mutating `note_id`, `counter`, or `version` flips GCM authentication. |
| `wycheproof-aes-gcm.test.ts` | vitest | [Google Wycheproof](https://github.com/google/wycheproof) AES-GCM vectors. |
| `wycheproof-pbkdf2.test.ts` | vitest | NIST CAVP / Wycheproof PBKDF2-HMAC-SHA256 vectors. |
| `property/isolation.test.ts` | vitest + fast-check | Per-note DEK isolation: swapping DEKs across notes fails. |
| `property/idempotence.test.ts` | vitest + fast-check | `reencryptBatch` is idempotent under safe retry. |
| `backend/test_aad.py` | pytest + hypothesis | Byte-for-byte equality of frontend `buildAAD` and backend `build_aad`. |
| `backend/test_invariant.py` | pytest + hypothesis | `NoteEncryptionService` rejects any plaintext on an encrypted note. |

## Running

```bash
cd crypto/frontend && npm ci && npm test
cd crypto/backend  && pip install -r requirements-dev.txt && pytest
```

## Current status

A repository-layout smoke test (run internally by the maintainers)
verifies that the directory structure, `LICENSE`, `SECURITY.md`, and
top-level `README.md` remain consistent between releases. The full
suite above activates once the reference implementation is available
in this repository.
