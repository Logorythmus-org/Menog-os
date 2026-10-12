# Menog OS

**The Observable Runtime Between Invisible Intelligence and Visible Digital Reality.**

Menog OS is an open-source, local-first agentic runtime for building AI systems that are observable,
policy-governed, auditable, and explicit about authority.

Instead of treating model output as executable intent, Menog OS separates **proposal**, **policy**,
**execution**, **evidence**, and **human control**.

[![CI](https://github.com/Logorythmus-org/Menog-os/actions/workflows/ci.yml/badge.svg)](https://github.com/Logorythmus-org/Menog-os/actions/workflows/ci.yml)
[![Security](https://github.com/Logorythmus-org/Menog-os/actions/workflows/security.yml/badge.svg)](https://github.com/Logorythmus-org/Menog-os/actions/workflows/security.yml)

> **Maturity:** experimental pre-release software. There is no tagged release, published package,
> deployment artifact, support SLA, production-readiness claim, or compliance certification yet.

## Why Menog OS

Agentic systems increasingly combine language models, tools, memory, networking, automation, and
long-lived state. The hard problem is no longer only *what can an agent do?* It is also:

- who or what is allowed to authorize an action;
- what evidence exists for a decision;
- how local and remote trust are separated;
- how failures can be inspected and reproduced;
- how visible interfaces avoid becoming accidental authority.

Menog OS is built around a small set of architectural rules:

- **Policy is authority.** Model output, tool output, remote messages, and rendered state are not authority.
- **Local first.** Critical execution and trust decisions are made locally.
- **Zero trust.** Reachability, identity, admission, authority, and execution are distinct.
- **Observability first.** Important actions produce inspectable evidence.
- **Human control remains explicit.** Critical writes, merges, releases, and governance changes remain reviewable.
- **Visible AI is a projection of evidence, not a new source of truth.**

## Architecture

New to the vocabulary? See the [authority and trust glossary](docs/GLOSSARY.md).

```text
Human intent
    │
    ▼
Typed verbs / plans
    │
    ▼
Policy + capability gate
    │
    ├── deny ──► evidence / ledger
    │
    ▼
Local runtime execution
    │
    ▼
Event ledger + memory
    │
    ├──► agents / federation / mesh
    └──► GETIG visible runtime / inspection
```

Core workspace components:

| Component | Purpose |
|---|---|
| `@menog/core` | typed runtime contracts |
| `@menog/verbs` | declarative action vocabulary |
| `@menog/planner` | deterministic proposal layer |
| `@menog/policy` | deny-by-default execution authority |
| `@menog/runtime-linux` | governed local execution and isolation |
| `@menog/event-ledger` | append-only, hash-chained evidence |
| `@menog/memory` | scoped runtime memory |
| `@menog/agents` | multi-agent allocation and mediation |
| `@menog/durable-state` | persistence, federation, mesh, transport, GETIG and renderer planning |
| `@menog/commit-engine` | commit candidates and approval evidence |
| `@menog/semantiq` | optional external evaluation adapter |
| `apps/cli` | public `menog` CLI |

## What works today

The public tree includes:

- typed intent, verb, planner, policy, runtime, ledger, memory and multi-agent layers;
- governed tool execution and Linux isolation boundaries;
- durable state and recovery primitives;
- authenticated local federation and transport primitives;
- local mesh topology and route planning;
- GETIG projection and read-only inspection structures;
- renderer planning and WebGPU-oriented qualification structures;
- a CLI vertical slice for inspecting a workspace;
- CI, dependency-security checks, and pinned GitHub Actions.

Important limitations:

- no tagged release or published package;
- no production deployment workflow;
- no WAN/public-network transport;
- no remote administration path;
- no autonomous merge or release authority;
- no claim that the current renderer planning layer is a production WebGPU runtime.

For deeper technical boundaries, see [docs/BOUNDARIES_AND_NONGOALS_v0.md](docs/BOUNDARIES_AND_NONGOALS_v0.md).

## Quick start

Requirements:

- Node.js 22 or newer
- pnpm 10 or newer
- Linux is the primary runtime target

```sh
git clone https://github.com/Logorythmus-org/Menog-os.git
cd Menog-os

node scripts/setup-local.mjs
pnpm typecheck
pnpm build
pnpm test
```

Try the CLI:

```sh
pnpm build
node apps/cli/dist/bin/menog.js inspect .
```

The command emits a structured `menog-inspect/v0` JSON report containing workspace, Git,
manifest, test, policy, warning, and event information.

## Contributing

Contributions are welcome.

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The repository uses two contribution paths:

- **Fast contribution path** — docs, examples, tests, CLI ergonomics, reproducibility improvements,
  and well-scoped issues.
- **Core change path** — policy, authority, isolation, cryptography, federation trust, runtime
  execution, evidence semantics, or architecture.

Good first contributions are tracked in GitHub Issues using the **good first issue** label.

Public development flow:

```text
Issue / idea
   ↓
fork or branch
   ↓
tests + local verification
   ↓
pull request
   ↓
CI + Security
   ↓
review
   ↓
merge
```

AI-assisted contributions are allowed, but the PR must disclose material AI assistance and the
human verification performed.

## Community roles

Menog OS uses simple repository roles:

- **Contributor** — proposes issues, documentation, tests, code, or design improvements.
- **Reviewer** — provides technical review; review does not itself grant merge authority.
- **Maintainer** — owns repository integration, release decisions, security-sensitive changes, and merge authority.
- **Code owner** — provides focused review for high-impact paths defined in `.github/CODEOWNERS`.

See [GOVERNANCE.md](GOVERNANCE.md) for decision boundaries.

## Roadmap

The public roadmap is maintained in [ROADMAP.md](ROADMAP.md).

Near-term priorities are repository maturity, deterministic tests, a real private security reporting
channel, stable contributor onboarding, stronger runtime observability, and continued qualification
of the local/federated runtime.

Roadmap entries are direction, not release promises.

## Security

For normal bugs, use GitHub Issues.

For security-sensitive findings, **do not publish exploit details in an issue or pull request**.
Read [SECURITY.md](SECURITY.md) first. A private reporting channel is still an explicitly tracked
pre-release requirement.

## Governance

Repository mutation is PR-first and evidence-driven. CI and Security checks are expected before merge.
Tags, releases, deployments, and package publication require separate authorization.

See:

- [GOVERNANCE.md](GOVERNANCE.md)
- [docs/REPOSITORY_GOVERNANCE.md](docs/REPOSITORY_GOVERNANCE.md)
- [PROJECT_SETUP.md](PROJECT_SETUP.md)

## License

Core source code is licensed under the [Mozilla Public License 2.0](LICENSE).

Documentation/configuration paths may carry CC-BY-4.0 or CC0-1.0 metadata as recorded in
`.reuse/REUSE.toml` and the `LICENSES/` directory.

Copyright holder of record: **Menog OS contributors**.
