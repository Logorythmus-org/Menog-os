# Repository Governance — Menog OS

Status: **PUBLIC / ACTIVE**
Scope: GitHub repository operation for `Logorythmus-org/Menog-os`.

This document describes the repository controls that support Menog OS's
**OBSERVABILITY FIRST**, **ZERO TRUST**, and **COMPLIANCE BY DESIGN** principles.
It governs repository mutation; it does not grant runtime authority or imply
production readiness.

## 1. Canonical branch and mutation model

- `main` is the canonical public branch.
- Normal development is pull-request first.
- A change begins from the live `main` head verified immediately before branch creation.
- Direct pushes to `main`, force-pushes, tags, GitHub Releases, package publication,
  deployment, and repository-rule changes are separate privileged actions.
- Merge authorization is a human decision made after the PR diff and checks are reviewed.

Normal flow:

```text
main
  ↓
bounded branch
  ↓
draft PR
  ↓
CI + Security
  ↓
review / repair
  ↓
Ready for review
  ↓
explicit human merge authorization
  ↓
main
```

## 2. Required verification surface

The target protected-`main` policy requires these checks before merge:

### CI

- `install (frozen lockfile)`
- `typecheck`
- `build`
- `test`

### Security

- `dependencies (runtime)`
- `dependencies (development)`

The runtime dependency audit is a hard security gate. The development audit may
report explicitly accepted dev-tooling debt, but the job itself must execute
successfully so that audit coverage cannot silently disappear.

## 3. Protected-main target

Repository setting work is tracked in GitHub issue #3.

The intended `main` protection/ruleset is:

- require a pull request before merge;
- require the branch to be up to date before merge;
- require conversation resolution;
- require the checks listed above;
- block force-push;
- block branch deletion;
- do not require an approving review while the project has only one maintainer,
  because GitHub does not allow meaningful self-approval;
- do not require linear history while normal merge commits remain the project policy;
- do not require signed branch commits until the connector/local authoring path is
  consistently signed.

These controls must be verified from the live GitHub repository after they are applied.
This document alone does not enable repository protection.

## 4. GitHub Actions supply-chain policy

Third-party GitHub Actions used by Menog OS are pinned to immutable commit SHAs.
The corresponding audited major tag is retained as a comment for readability.

Pinned actions at this revision:

| Action | Audited tag | Immutable commit |
|---|---|---|
| `actions/checkout` | `v7` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-node` | `v7` | `820762786026740c76f36085b0efc47a31fe5020` |
| `pnpm/action-setup` | `v6` | `0977fd99725f1db4007ccb2928dbb4e90d06cc86` |

Do not replace these references with `@main`, `@master`, or an unpinned floating
reference. Dependabot may propose updates, but each update still goes through the
normal PR + CI + Security + human-authorization path.

## 5. Dependency update automation

`.github/dependabot.yml` monitors:

- the root pnpm/npm dependency graph; and
- GitHub Actions references.

Dependabot is allowed to propose updates. It does not have merge authority.
Automated update PRs must satisfy the same repository checks and human merge gate
as any other change.

For npm/pnpm dependencies, routine automation is limited to patch/minor version
updates. Semver-major dependency/toolchain upgrades are treated as explicit
migration work: open or reference an issue, describe compatibility risks, and
use a maintainer-controlled migration PR. This policy exists because the first
Node type-definition and TypeScript major upgrades both required real compatibility
repairs before CI became green.

GitHub Actions remain monitored by Dependabot, but accepted updates must stay pinned
to immutable commit SHAs.

## 6. External contributions

External contributions are open under the public contribution model in
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

The repository distinguishes a fast path for low-risk documentation/tests/tooling work
from a core-change path for policy, authority, isolation, cryptography, federation trust,
runtime execution, evidence semantics, and other high-impact boundaries.

`.github/CODEOWNERS` routes review for high-impact paths. Code ownership does not
grant autonomous merge authority and does not replace CI, Security, or maintainer review.

AI-assisted contributions are permitted when material assistance and human verification
are disclosed in the pull request.

## 7. Release boundary

A merged PR is not a release.

Tags, GitHub Releases, npm/package publication, deployment artifacts, and production
support statements require separate explicit authorization and their own release
evidence.
