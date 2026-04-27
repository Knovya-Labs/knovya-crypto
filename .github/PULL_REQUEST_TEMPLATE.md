<!--
Thank you for contributing to knovya-crypto. Please fill in this template
completely. PRs that leave the crypto checklist unchecked without a written
justification will be held for review.
-->

## Summary

<!-- One paragraph: what and why. -->

## Type of change

- [ ] Bug fix (no protocol impact)
- [ ] New test / test vector
- [ ] Documentation / threat-model update
- [ ] Performance improvement (no security impact)
- [ ] New `ENCRYPTION_VERSION` value (requires design note — see CONTRIBUTING.md)
- [ ] Cryptographic agility enhancement (new primitive behind existing dispatcher)
- [ ] Other (please describe)

## Cryptographic review checklist

Every PR that touches `crypto/` must verify all items below. If a box
cannot be checked, explain why in the PR description.

- [ ] **Version dispatch.** No behaviour change without a new
  `ENCRYPTION_VERSION` enum value.
- [ ] **AAD v3 binding preserved.** Ciphertext still authenticates
  against `note_id ∥ encryption_counter ∥ version`.
- [ ] **`extractable=false` guard held.** No key material becomes
  extractable; any CryptoKey import still passes `extractable: false`.
- [ ] **Y.js skip intact.** For encrypted notes, none of the four
  layers (frontend shell, `useYjsDoc` hook, `internal/yjs.py`,
  Hocuspocus `Database.store`) starts persisting state.
- [ ] **Server boundary held.** No backend code path decrypts note
  content or learns DEK/KEK material.
- [ ] **No plaintext in logs.** New log statements go through
  `CONTENT_SCRUB_KEYS`; no PII, note body, key material, or raw salt
  is serialised.
- [ ] **Wycheproof vectors pass** (or documented N/A for the affected
  module).
- [ ] **Mutation score ≥ 80%** on touched modules (Stryker / mutmut).
- [ ] **≥ 10 property-based invariants** per new primitive
  (fast-check / hypothesis).
- [ ] **Round-trip holds.** For each supported version, encrypt →
  decrypt → equals-original in test.
- [ ] **Cross-version compatibility.** A note created by a previous
  version still decrypts after this change.

## Tests

<!--
List the tests you added or updated. For cryptographic changes, prefer
property-based invariants (fast-check / hypothesis) over example-based
tests. Known-answer tests for new primitives are required.
-->

- [ ] Unit / integration tests added or updated.
- [ ] Property-based invariants added (count: _____).
- [ ] Known-answer vectors added (source: _____).
- [ ] Mutation score report attached.
- [ ] CI is green on this branch.

## Threat-model impact

<!--
Does this change affect the assumed capabilities of any attacker
profile (T1–T10)? If yes, describe. If it reduces residual risk,
say so; if it opens a new risk, say so.
-->

## Migration / backward compatibility

<!--
If existing ciphertext is affected, describe the migration plan,
feature-flag rollout, and rollback procedure.
-->

## Related issues / design notes

<!--
- Closes #___
- Design note: docs/design-notes/___.md
- Whitepaper section: §__
-->
