# ADR-0001 — Canonical Repository (Single Ground Truth)

- Status: Proposed
- Date: 2026-09-05

## Context

Menog OS is bootstrapping from a zero-assumption baseline. A single canonical
repository is required to avoid:

1. split / parallel histories with divergent trust anchors;
2. accidental "second canonical" copies promoted to public remotes;
3. ambiguous event-ledger provenance across environments;
4. confusion over which copy is the authority for the first manual commit.

The on-disk working copy exists at the repository root,
contains zero commits, zero remotes, and the Phase-0 prompt-pack documentation
assets only.

## Decision

- **One canonical local working copy**: the repository root
  directory is designated the sole canonical
  bootstrap workspace. No sibling Menog OS working copies shall be declared
  canonical for Phase 0.
- **One canonical remote repository**: the remote whose URL is recorded in
  `PROJECT_SETUP.md` as `MENOG_REPO_URL` (currently **pending human input** —
  see CURRENT_STATE.md, Human Decisions Required D1–D2) is the sole canonical
  remote. No mirror, fork, or alternate origin may be treated as authoritative
  in Phase 0.
- **Default branch**: `main`. The first commit must land on `main`; no
  parallel `master` or other default branch names may be introduced.
- **First commit gate**: Day-1 first commit is **manual**. The runtime must
  never create commits. The human reviews `git status --short`, `git diff`,
  test results, and `DAY1_AUDIT.md` before running `git commit`.
- **Repository naming**: recommended public slug is `menog-os`. If the
  governing organization has a naming convention (`Menog.os`, scoped package,
  etc.), the human finalizes the choice in `PROJECT_SETUP.md` before the first
  push.

## Alternatives considered

1. **Monorepo + separate policy/event repos** — rejected in Phase 0; a single
   repo keeps audit, ledger, code, and docs together.
2. **Two-remote (public + private) topology from day one** — deferred. Only
   one canonical remote exists in Phase 0.
3. **Detached-HEAD / tag-first releases** — deferred; Phase 0 requires a
   normal branch (`main`).

## Security impact

- A single canonical source of truth reduces the chance of executing
  un-reviewed code from a parallel copy.
- Manual commit gate prevents the runtime (or model output) from becoming a
  write authority on history.
- The pending `MENOG_REPO_URL` must be treated as authoritative: check
  fingerprints / ownership the first time it is added via `git remote add`.
- Push authentication and branch-protection rules on the canonical remote are
  **out of scope for this ADR** (they must be set up manually before the
  first push).

## Reversibility

- The canonical local path and canonical remote URL are both reversible:
  reassigning the canonical remote is a config change (documented in a new
  ADR).
- Changing the default branch name after the first commit is possible with
  coordinated rename (`git branch -m`, remote default branch update, CI
  updates); recorded evidence of the rename must be preserved because event
  hashes reference workspace IDs.

## Evidence

- Repository facts: `CURRENT_STATE.md` → Repository Identity
- Prompt-pack rule: [README.md → Choose one canonical name and do not create parallel histories](README.md#L84-L91)
- Day-1 criteria: [docs/DAY1_ACCEPTANCE_CRITERIA.md → Repository section](docs/DAY1_ACCEPTANCE_CRITERIA.md#L3-L9)
- Template: [templates/PROJECT_SETUP_TEMPLATE.md](templates/PROJECT_SETUP_TEMPLATE.md)
