# Menog OS — Project Setup

Canonical project configuration. Fields are filled only where the value is **factual**. Nothing in
this file grants or implies permission to publish.

```text
ORGANIZATION=Logorythmus-org
REPOSITORY_NAME=Menog-os
MENOG_REPO_URL=https://github.com/Logorythmus-org/Menog-os
REMOTE_SSH_URL=git@github.com:Logorythmus-org/Menog-os.git
DEFAULT_BRANCH=main
CANONICAL_REMOTE_HEAD=4b03d2c559564ac2045fcbeeb2c26b01ffa6bae7

LANGUAGE=TypeScript
PACKAGE_MANAGER=pnpm@10.11.1
NODE_VERSION=>=22.0.0
NODE_VERSION_VERIFIED=v24.20.0
PNPM_VERSION=10.11.1

PUBLIC_REPOSITORY=true
LICENSE_DECISION=PENDING
SEMANTIQ_INTEGRATION=OPTIONAL_LATER

COMMIT_AUTHORIZED=false
PUSH_AUTHORIZED=false
PUBLICATION_AUTHORIZED=false
```

## Notes on each field

- `ORGANIZATION` / `REPOSITORY_NAME` / `MENOG_REPO_URL` — resolved from the live remote. The
  repository name is spelled **`Menog-os`** on GitHub (earlier drafts assumed lowercase `menog-os`).
- `MENOG_LOCAL_PATH` — **removed.** A hard-coded absolute path to the maintainer's machine has no
  place in a project-setup document and is not recorded anywhere in this repository.
- `LICENSE_DECISION=PENDING` — deliberately still pending. Decision `IP-001` proposes MPL-2.0 and a
  `LICENSE` file containing the verbatim steward text is present, but the decision is **PROPOSED**
  and not ratified, and the copyright holder (`IP-002`) is unresolved. This file must not be read
  as a licence election. See `docs/governance/IP_DECISION_LOG.md`.
- `NODE_VERSION=>=22.0.0` — the value the project actually enforces (`package.json` `engines`). The
  verified development runtime is `v24.20.0`. Earlier versions of this file recorded `22.15.0`,
  which was a stale snapshot rather than a requirement.
- Authorization flags are `false`. No gate in the preparation track authorizes commit, push, tag,
  remote mutation, PR creation or publication. `GP-R13` is a human decision gate; `GP-PUSH` may
  mutate the remote only after explicit human authorization made *after* `GP-R13`.

## Canonicalization rule

There must be one clearly documented canonical repository: `Logorythmus-org/Menog-os`.

If an older Menog / Agent-OS repository is reused for reference, do **not** merge it blindly. Import
code only after evidence-based review. No external `.git` directory may ever be imported as
canonical history — any substantive commit must descend from the live remote `main` head verified at
execution time.

## Pending human decisions before any first push

- `LICENSE_DECISION` — which licence to ratify, and who the copyright holder is (`IP-001`, `IP-002`).
- `ORGANIZATION` legal identity — whether a legal entity named `Logorythmus` exists and can hold
  copyright. The GitHub *organization slug* is factual; the *legal holder* is not resolved.
- Contributor model — DCO, CLA or hybrid (`IP-007`); external contributions remain closed until then.
- Patent-review triage for the seven `PATENT-REVIEW` candidates (`IP-005`).
- Publication authorization itself (`GP-R13`).

See `CURRENT_STATE.md` §7 for the full governance table and
`docs/governance/PUBLICATION_GATE.md` for the 21-row pre-push checklist, none of which is checked.
