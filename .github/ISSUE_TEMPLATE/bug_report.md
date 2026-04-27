---
name: Bug report
about: Report a non-security bug in the reference implementation
title: "[bug] <short description>"
labels: bug
assignees: ''
---

> **Stop.** Do not use this template to report a security vulnerability.
> Follow [SECURITY.md](../SECURITY.md) and email `security@knovya.com`.
> Examples of security issues: anything that could allow plaintext
> exfiltration, key recovery, signature forgery, or authenticated-data
> tampering.

## Summary

A clear, one-sentence description of the bug.

## Affected area

- [ ] `crypto/frontend/` (WebCrypto / TypeScript)
- [ ] `crypto/backend/` (Python encryption service)
- [ ] `crypto/types.ts` (shared schema)
- [ ] `crypto/tests/` (test vectors, round-trip)
- [ ] Documentation (`README.md`, `docs/`)
- [ ] CI workflows (`.github/workflows/`)

## Reproduction steps

1.
2.
3.

Minimum reproducing example (code / test vector) is strongly preferred
over a narrative description.

## Expected behaviour

## Actual behaviour

## Environment

- Commit hash: `<sha>`
- Node version: `<e.g. 20.17.0>`
- Python version: `<e.g. 3.12.5>`
- Browser (if frontend): `<e.g. Chrome 138>`
- OS: `<e.g. macOS 14.6>`

## Additional context

Logs, stack traces, screenshots. **Do not paste encrypted user data,
KEK material, or PGP-protected content into a public issue.** If a log
line is sensitive, replace it with `[redacted]` and describe the shape.
