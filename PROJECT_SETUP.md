# Menog OS — Project Setup

Canonical public project configuration after the first public merge.

```text
ORGANIZATION=Logorythmus-org
REPOSITORY_NAME=Menog-os
MENOG_REPO_URL=https://github.com/Logorythmus-org/Menog-os
REMOTE_SSH_URL=git@github.com:Logorythmus-org/Menog-os.git
DEFAULT_BRANCH=main

LANGUAGE=TypeScript
PACKAGE_MANAGER=pnpm@10.11.1
NODE_VERSION=>=22.0.0
CI_NODE_MAJOR=24

PUBLIC_REPOSITORY=true
PUBLICATION_STATE=PUBLIC_EXPERIMENTAL_SOURCE
CORE_LICENSE=MPL-2.0
COPYRIGHT_HOLDER_OF_RECORD=Menog OS contributors
SEMANTIQ_INTEGRATION=OPTIONAL_EXTERNAL

TAGGED_RELEASE=false
PUBLISHED_PACKAGE=false
DEPLOYED_ARTIFACT=false
```

## Canonical repository rule

The canonical repository is `Logorythmus-org/Menog-os` and the canonical branch is `main`.
Do not hard-code a mutable `main` commit SHA into project configuration; resolve the live head at
the start of any mutation workflow.

Any substantive change should descend from the live `main` head verified at execution time.
Do not import another repository's `.git` directory or replace canonical history.

## Repository mutation policy

Normal development is PR-first:

1. verify the live `main` head;
2. create a bounded branch;
3. make the smallest reviewable change;
4. run CI / Security checks;
5. review the resulting diff and evidence;
6. merge only after explicit human authorization.

Direct push to `main`, force-push, tagging, GitHub Releases, package publication, deployment, and
branch-protection/ruleset changes are separate mutations and are not implied by ordinary PR work.

## Current governance boundaries

- Core licence: **MPL-2.0 — ratified**.
- Copyright holder of record: **“Menog OS contributors” — ratified collective attribution label**.
- External contributions: **closed** until a contributor model is ratified.
- Patent/professional-review material: retained outside the first public source surface.
- Public repository status does not imply a tagged release or production-readiness claim.

## Local setup

Use the committed toolchain metadata and frozen lockfile:

```sh
node scripts/setup-local.mjs
pnpm typecheck
pnpm build
pnpm test
node scripts/verify-local.mjs
```

The root `package.json`, `pnpm-lock.yaml`, GitHub workflows, `README.md`, and `SECURITY.md`
are the public operational references. Internal preparation/freeze records are not part of the
public repository surface.
