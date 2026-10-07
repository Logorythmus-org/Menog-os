# Menog OS Governance

Status: public, experimental project governance.

This document defines participation and decision roles. Repository-setting controls are documented
separately in [docs/REPOSITORY_GOVERNANCE.md](docs/REPOSITORY_GOVERNANCE.md).

## Principles

Menog OS governance follows the same boundaries as the runtime:

- authority should be explicit;
- evidence should be reviewable;
- high-impact decisions should not be hidden in automation;
- security and trust boundaries require stronger review than ordinary documentation or test changes.

## Roles

### Contributor

Anyone who submits an issue, pull request, review, documentation improvement, test, reproduction, or
other useful project input.

Contributors do not need prior membership in the organization.

### Reviewer

A contributor or maintainer who provides technical review.

Reviewers can recommend approval, request changes, identify risks, and ask for evidence. Review alone
does not create merge, release, or security authority.

### Maintainer

A person with repository maintain/admin responsibility.

Maintainers may:

- merge reviewed pull requests;
- manage issues and labels;
- maintain project/community files;
- coordinate releases;
- resolve governance questions;
- handle security-sensitive project decisions.

Maintainer status is based on explicit repository/organization responsibility, not number of commits.

### Code owner

A reviewer assigned to a high-impact path through `.github/CODEOWNERS`.

Code ownership is a review-routing mechanism. It does not override CI, Security, or maintainer merge
authority.

## Decision classes

### Routine

Examples: docs, tests, examples, typo fixes, narrowly scoped CLI UX.

Normal PR review is sufficient.

### Architectural

Examples: package boundaries, public contracts, persistence model, federation protocol, GETIG
representation, major dependency/toolchain migrations.

Requires design rationale and maintainer review.

### Security / authority critical

Examples: policy engine, capability checks, execution gates, isolation, cryptography, trust/admission,
secret handling, evidence integrity, network-to-execution boundaries.

Requires explicit risk analysis, tests, CI/Security evidence, and maintainer authorization.

## Merge policy

The normal path is:

```text
issue or rationale
→ branch
→ pull request
→ CI + Security
→ review
→ explicit maintainer merge
```

Automation may propose changes, but it does not receive autonomous merge or release authority.

## Releases

A merge is not a release.

Tags, GitHub Releases, package publication, deployment artifacts, and production support statements
require an explicit release decision.

## Becoming a maintainer

There is no automatic promotion rule.

Sustained high-quality contributions, reliable review, security judgment, respect for project
boundaries, and demonstrated ownership can lead to a maintainer invitation.

The maintainer set should remain small enough that authority and responsibility stay clear.
