---
name: Feature request
about: Propose an improvement, new test vector, or agility enhancement
title: "[feat] <short description>"
labels: enhancement
assignees: ''
---

## Motivation

What problem are you trying to solve? Who benefits?

## Proposal

Describe the change you would like to see. Be concrete — a specific
API, new test vector set, or documentation addition is easier to
discuss than a general wish.

## Type of change

- [ ] New test vector (Wycheproof-style)
- [ ] New property-based invariant (fast-check / hypothesis)
- [ ] Documentation improvement (README, whitepaper, threat model)
- [ ] Performance improvement (no security impact)
- [ ] Cryptographic agility (new primitive behind existing `ENCRYPTION_VERSION`)
- [ ] **Protocol change** (new `ENCRYPTION_VERSION` value) — requires
  design note, see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Other

## Threat-model impact

Does this affect any of the T1–T10 attacker profiles? If yes, how?
(Reference: [threat model](../docs/whitepaper/threat-model.md).)

## Alternatives considered

What else did you think about, and why did you prefer this approach?

## References

Standards, papers, related issues, similar implementations in other
projects.

## Willingness to contribute

- [ ] I'm willing to open a PR for this.
- [ ] I can help write tests or design notes but not the full PR.
- [ ] I'm raising this as a suggestion for the maintainers.
