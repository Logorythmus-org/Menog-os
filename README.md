# Menog OS

**The Observable Runtime Between Invisible Intelligence And Visible Digital Reality.**

Menog OS is a **local-first, observable, zero-trust, Linux-native agentic runtime**. It converts
human intent into typed actions, evaluates those actions through deny-by-default policy and
capability boundaries, executes them inside a local unprivileged runtime, records evidence in an
append-only hash-chained ledger, and makes the result inspectable and reproducible.

> ## ⚠ Maturity: experimental. Not production software.
>
> This repository is a **public pre-release experimental implementation**. The first canonical
> public source candidate was merged to `main` on 2026-10-07 through PR #1 after CI and Security
> checks. There is still **no tagged release, published package, deployment artifact, or support
> commitment**. **No production-readiness, stability, security, or compliance certification is
> claimed or should be inferred.** Do not run this against systems or data you cannot afford to lose.

---

## 1. What this runtime is built to enforce

The architecture is organised around a small number of laws that the code is written to uphold:

| Law | Meaning |
|---|---|
| **POLICY IS AUTHORITY** | Model output, tool output and repository content are *never* authority. The deny-by-default policy engine is the sole execution authority. |
| **PIXELS ARE PRESENTATION, NOT AUTHORITY** | Rendered reality is a materialisation of governed intent — not a new source of semantics, truth, or authority. |
| **REMOTE INTELLIGENCE MAY PROPOSE; IT MAY NOT COMMAND** | A federated peer's message can be admitted, but it grants nothing. Authority is only ever minted locally, after a fresh local allocation and a fresh local policy decision. |
| **NETWORK REACHABILITY ≠ IDENTITY ≠ ADMISSION ≠ AUTHORITY ≠ EXECUTION** | Being able to reach a peer is not trust, admission, authority, or the right to execute. |

Execution pipeline:

```text
Intent → Verb → Algorithm → Policy → Runtime → Event Ledger → Human review
```

---

## 2. What is actually implemented today

Verified against the source tree in this repository, not from a roadmap. The workspace is **14
projects** (13 packages + 1 CLI), **157 TypeScript source files**.

| Package | Role |
|---|---|
| `@menog/core` | Typed contracts: Actor, CapabilityId, Intent, VerbContract, Event, PolicyResult, Exec |
| `@menog/verbs` | Verb registry — the WHAT layer (12 frozen verbs) |
| `@menog/planner` | Deterministic planner — **proposal-only** authority |
| `@menog/policy` | Deny-by-default policy engine — the **sole execution authority** |
| `@menog/runtime-linux` | Authoritative execution gate, controlled write, diff engine, git read-only integration, unprivileged Linux isolation (namespaces / cgroups v2 / seccomp / Landlock) |
| `@menog/event-ledger` | Append-only, hash-chained, tamper-evident ledger with mandatory secret redaction |
| `@menog/memory` | Working / project / execution memory with scope-isolated retrieval |
| `@menog/algorithms` | Agentic algorithm kernel |
| `@menog/semantiq` | Optional external evaluation adapter (deliberately zero internal importers) |
| `@menog/agents` | Multi-agent runtime: allocation, mediation, recovery |
| `@menog/commit-engine` | Commit-candidate builder, human approval workflow, evidence engine |
| `@menog/durable-state` | Durable store + the federation, mesh, transport and GETIG/renderer stacks (59 source modules) |
| `@menog/shared` | Single shared module — cross-cutting helpers only |
| `apps/cli` | The `menog` CLI |

Implemented subsystems, by phase of work:

- **Core runtime** — typed contracts, verb registry, deterministic proposal-only planner,
  deny-by-default policy engine, authoritative exec gate with a read-only command allowlist,
  controlled write with preview-before-write, append-only hash-chained event ledger, memory
  stores, algorithm kernel, multi-agent runtime, commit candidates with human-only approval.
- **Phase 20** — unprivileged Linux isolation layer (namespaces / cgroups v2 / seccomp /
  Landlock), bound to Policy.
- **Phase 21** — governed tool runtime: registry, manifest validation, a single execution
  junction, skill binding, tool evidence, non-executing replay.
- **Phase 22** — durable store: frozen record kinds, append-only ledger and evidence persistence,
  lifecycle state, recovery, reconciliation, schema migration.
- **Phase 23** — runtime continuity: state coordinator with a durability barrier, live-memory
  wiring, recovery-bootstrap to live-runtime handoff, process-kill crash windows.
- **Phase 24** — federation: node identity, local Ed25519 identity with signed envelopes, peer
  registry with admission and quarantine, authenticated bounded bus, cross-node task proposals,
  federated provenance.
- **Phase 25** — operational federation: threat model, key lifecycle, peer trust operations with
  intent-gated local admin, egress disclosure and data-minimisation gate, native-Linux and
  crash/durability qualification, adversarial hardening.
- **Phase 26** — local-network stack: transport trust model, endpoint/listener boundary, bounded
  framed transport, authenticated session, the single ingress junction, resilience and
  backpressure, adversarial local-network validation — plus a real two-process loopback scenario
  exercising the whole stack across a live socket.
- **Phase 27** — local mesh: trust contract, topology graph and lifecycle, capability
  advertisement, route-path planning, multi-hop forwarding, partition reconciliation, mesh
  observability, adversarial mesh validation.
- **Phase 28** — GETIG: representation, runtime entity projection, temporal frames, semantic
  visual mapping, observer-relative world views, provenance explanation graph, read-only
  inspection runtime, visible-runtime end-to-end scenario.
- **Phase 29** — renderer: scene-graph compiler, render-frame composer, GPU render plan and
  resource lifecycle, read-only picking resolver, renderer trust contract, temporal transition
  planner, WebGPU qualification harness.

---

## 3. Phase-29 status — read this before trusting any rendering claim

**Phase 29 is DISPUTED. It is not an affirmed freeze.**

- The Phase-29 re-audit gate (`29K`) reached `PHASE29_FROZEN_WITH_NONBLOCKING_DEBT` on the state of
  disk *before* its reconciliation gate ran.
- Its reconciliation gate (`29K-R1`) ended **`29K_R1_BLOCKED`**. Reason: the gate's own
  pin-maintenance tooling rewrote **20 historical evidence records** (201 pin values, 10 of them
  changing meaning), violating the gate's own constraints. The pre-gate bytes are **unrecoverable**.
- `docs/release/PHASE_29_FREEZE.md` states of itself: **"NOT a verified freeze. The filename grants
  nothing."** It is retained as-is and is not re-affirmed here.
- **No Phase-30 authorization has been granted.** Phase 30 has not been started.

Two recorded limitations remain open and are **not** to be read as passes:

| ID | Status | Meaning |
|---|---|---|
| `29I-44` | **UNSUPPORTED** | Malformed-WGSL / shader-compiler adversarial case. No WGSL source and no WebGPU compiler exist in this repository, so the attack cannot be mounted here. `UNSUPPORTED != PASS`. |
| `29I-33` | **INCONCLUSIVE** | `sourceFrameId` / label-binding tamper question. Provenance, not pixels; no later evidence re-executes the exact attack. `INCONCLUSIVE != PASS`. |

**What the renderer does and does not confer:** rendering, GPU, picking and animation confer
**zero** authority. A pixel-driven pick resolves to `authority: none` and `executionAuthorized:
false`. Nothing rendered can become an instruction.

---

## 4. What is NOT implemented

Stated plainly, because an honest boundary is more useful than an optimistic one:

- **No WebGPU execution path in the shipped source.** No WGSL shader source and no WGSL/WebGPU
  compiler exist in this repository. The renderer models, plans and qualifies; a *non-shipped*
  browser probe was used at gate 29J to execute against a real WebGPU adapter and verify rendered
  output. That probe is evidence, not a shipped capability, and it does not convert `29I-44` to a
  pass.
- **No Three.js**, no GLB/glTF avatars. Neither appears in any dependency or any source file.
- **No Internet or WAN transport, no public or wildcard endpoints, no discovery protocols, no
  cloud relay, no NAT traversal.** Local loopback and local-network only. The single socket bind
  owner is the Phase-26 endpoint boundary.
- **No distributed consensus, no global ordering, no trusted clock, no remote authority.**
  Provenance ordering is per-node-local only.
- **No remote administration and no network→tool path.** A federated message carries no
  capability, no allocation, no policy decision, no actor binding and no tool invocation.
- **No rollback or replay *execution*.** Rollback and replay plans are produced as evidence
  documents; no executable restoration path exists.
- **No wallets, blockchain or marketplace.**
- **No autonomous root, unrestricted MCP, hidden background agents.**
- **No commit automation.** Every commit requires manual human review; critical commits require
  explicit human approval.
- **No deployment or release automation.** GitHub CI and dependency-security workflows are present, but there is no package publishing, deployment tooling, or tagged-release automation.
- **No batch/multi-file atomic mutation** (the never-executed 14C/14E slots).
- **No Phase 30 spatial runtime.**

---

## 5. Stack

- **Language:** TypeScript 5.7.2 — strict, composite build, ESM (`"type": "module"`),
  `noUncheckedIndexedAccess`, `verbatimModuleSyntax`
- **Package manager:** pnpm 10.11.1 workspaces (frozen lockfile)
- **Tests:** Vitest 2.1.9 — **131 physical `*.test.ts` files** (90 unit, 31 security, 10 integration); the approved public CI surface currently runs 110 test files / 3,031 tests
- **Runtime:** Node.js — `engines: >=22`; verified on Node `v24.20.0`
- **Third-party runtime dependencies: 0.** Every package dependency is an internal `workspace:*`
  link; the only external packages are 5 root devDependencies (`@types/node`, `@webgpu/types`,
  `rimraf`, `typescript`, `vitest`). `@webgpu/types` ships ambient type declarations only and is
  used for typing, not for execution.

> The current public CI baseline is 3,031 tests across 110 test files. The repository physically
> contains 131 `*.test.ts` files; internal evidence/governance tests excluded by `vitest.config.ts`
> are not part of the public CI gate. Run `pnpm test` locally to verify the same public surface.

## 6. Quick start

```sh
# Verify toolchain and install from the FROZEN lockfile (no rewrites, no auto-upgrade).
# Exits before installing anything if the toolchain does not satisfy engines.
node scripts/setup-local.mjs          # or: pnpm setup:local

pnpm typecheck                        # tsc -b --pretty false
pnpm build                            # tsc -b
pnpm test                             # vitest run
node scripts/verify-local.mjs         # read-only local verification suite
```

Try the vertical slice:

```sh
pnpm build
node apps/cli/dist/bin/menog.js inspect ./packages
```

Expect a `menog-inspect/v0` structured JSON report on stdout — zero network, and no writes outside
the target workspace.

---

## 7. Governance and legal state

This section states the current public repository facts; it does not claim production readiness or
external certification.

- **Core licence: MPL-2.0 — ratified.** The top-level `LICENSE` and
  `LICENSES/MPL-2.0.txt` carry the canonical licence text.
- **Copyright holder of record: “Menog OS contributors” — ratified.** This is a collective
  attribution label, not a claim that a separate legal entity named Menog OS owns the work.
- **Documentation/config licensing:** CC-BY-4.0 and CC0-1.0 licence texts are present under
  `LICENSES/`, with path-level metadata recorded in `.reuse/REUSE.toml`.
- **Patent review is not completed.** Patent-review and professional-review material remains
  internal and is deliberately withheld from the public source surface.
- **External contributions remain CLOSED** pending a ratified contributor model. Absence of a
  `CONTRIBUTING.md` file is intentional at this stage.
- **Publication state: PUBLIC EXPERIMENTAL SOURCE.** PR #1 was merged to `main` on 2026-10-07.
  No tag, GitHub Release, npm package, deployment artifact, or production release has been created.
- **REUSE per-file compliance is not claimed.** The project has licence metadata, but the remaining
  REUSE schema/header work is tracked separately and must not be inferred as complete.
- **Compliance:** this is a compliance-*oriented* architecture. **No external certification or
  audit is claimed or implied.**

## 8. Evidence and history

Historical work is organised in numbered phases with per-gate evidence retained outside this
public source tree. The public repository carries the resulting status, not the withheld evidence
archive. Two things about that history are worth stating plainly rather than burying:

1. **The event lineage is disputed, not pristine.** The 29K-R1 integrity failure is recorded above
   and in `docs/release/PHASE29K_R1_RECONCILIATION.json`. Where this repository's evidence is
   internally inconsistent, it now says so rather than presenting a clean narrative.
2. **A document was lost and was not recovered.** On 2026-10-02 an agent tool call overwrote
   `CURRENT_STATE.md` in place, destroying 145,788 bytes of prior content. Recovery was attempted
   and failed: the repository had zero commits, and no backup, shadow copy or recycle-bin entry
   contained the file. The loss is recorded in the retained internal state history and is the project's own argument
   for committing work early.
3. **Most of that evidence is deliberately not included here.** Internal development evidence and
   forensic release records are retained separately from the initial public source release. The
   `docs/release/**` tree — 250 recorded gate, audit and evidence artefacts — is **excluded from
   this first public tree**, together with the internal state, audit, readiness, manifest and
   IP-review records. Where the documents above cite `docs/release/…` or those records, they are
   pointing at retained internal material, not at files shipped in this repository.

   **This withholds the records, not the status.** The Phase-29 position stated in §3 is drawn from
   those records and is unchanged by their exclusion — it is summarised here precisely because the
   records themselves are not published. The exclusion is deliberate for two reasons: the event
   lineage is disputed and cannot be certified as pristine (point 1), and publishing a selection of
   fragments from a disputed record would misrepresent it in a way that publishing none does not.
   The first public release is therefore the source tree without its internal evidence base.

## 9. Repository status

| Field | Value |
|---|---|
| Canonical repository | `Logorythmus-org/Menog-os` (public) |
| Default branch | `main` |
| First public merge | PR #1 — 2026-10-07 |
| CI | Active on pull requests and pushes to `main` |
| Tagged releases | **None** |
| Published packages / deployments | **None** |
| Maturity | **Experimental pre-release source** |

This repository is now public. Public availability does **not** imply a tagged release, package
publication, deployment, support commitment, production readiness, or external certification.
