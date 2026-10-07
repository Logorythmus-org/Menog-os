# Menog OS — Phase-0 Boundaries & Non-Goals v0

**Document purpose**: a single reference for the execution pipeline, stage
authorities, and the things Menog OS Phase 0 explicitly **does not do**.
Cross-references the ADRs; this file is readable without ADR diving, while
the ADRs carry full rationale + reversibility + security impact.

---

## 1. Execution Pipeline (Authoritative Shape)

```text
Intent → Verb → Algorithm → Agent/Skill → Policy → Linux Runtime → Event Ledger → Human Review
```

### 1.1 Authoritative diagram

```
   [Human / System Event]
          │
          ▼  Intent = WHY (typed input; Phase 0: explicit CLI string)
 ┌─────────────────────┐
 │    Intent Engine    │
 └─────────┬───────────┘
           │
           ▼  Verb = WHAT (registered; typed; side-effect classed)
 ┌─────────────────────┐
 │    Verb Registry    │   inspect / observe / search / retrieve /
 └─────────┬───────────┘   compare / plan / execute / modify / validate /
           │               communicate / commit / recover
           │
           ▼  Algorithm = HOW TO REASON (recommendations only)
 ┌─────────────────────┐
 │ Algorithm Registry  │   OIDA-lite / Runtime Risk Eval / Skill Sel-lite /
 │   (Strategy family) │   Self-Monitoring-lite + 6 contract-only families
 └─────────┬───────────┘   NEVER executes.  NEVER authorizes.
           │
           ▼  Agent/Skill = WHO + HOW TO ACT (allowed mapping only)
 ┌─────────────────────┐
 │   Agent/Skill Map   │   maps verb → allowed local skills/tools
 └─────────┬───────────┘   never bypasses the policy gate
           │
           ▼  Policy = MAY IT (AUTHORITATIVE GATE)
 ┌─────────────────────┐   ┌──────────────────────────────────────┐
 │  Policy & Capability│   │ Checks: capability · scope · args    │
 │        Gate         │   │         workspace · env · timeout    │
 └─────────┬───────────┘   └──────────────────────────────────────┘
           │  allow  │  deny → emit policy.denied → return
           ▼
      ┌───────────────────────────────────────────┐
      │ Linux Runtime = WHERE (EXECUTES ONLY)     │
      │  • argv array, no shell default          │
      │  • cwd locked to workspace root          │
      │  • env allowlist only                    │
      │  • timeout + process-tree kill           │
      │  • stdout/stderr/exit captured           │
      │  • re-validates args (defense in depth)  │
      └─────────┬─────────────────────────────────┘
                │
                ▼  Ledger = WHAT HAPPENED (RECORDS ONLY)
      ┌───────────────────────────────────────────┐
      │ Append-Only Event Ledger (.menog/*.jsonl) │
      │  • hash-chained · local only · no secrets │
      │  • never networked · never trimmed in P0  │
      └─────────┬─────────────────────────────────┘
                │
                ▼  Human = CRITICAL WRITE AUTHORITY
      ┌───────────────────────────────────────────┐
      │  Manual Review → Manual Commit / Manual   │
      │  Policy Adjustment.  NEVER automatic.     │
      └───────────────────────────────────────────┘
```

### 1.2 Stage authority (clarifications, encoded)

| Stage | Authority | Allowed mutation |
|---|---|---|
| Intent Engine | none — input only | none |
| Verb Registry | declarative | none |
| Algorithm | **recommends only** | none |
| Agent/Skill Map | declarative mapping | none |
| **Policy & Capability Gate** | **YES — allow/deny authority** | writes events only |
| **Linux Runtime** | **YES — executes allowed** | within workspace + allowlist only |
| Event Ledger | records (append-only) | appends to itself only |
| Human Reviewer | **YES — critical write / commit** | manual commit / policy edits |

### 1.3 One-line clarifications

- **Algorithms recommend**; they never execute and never authorize.
- **Policy authorizes**; a `deny` short-circuits and is logged.
- **Runtime executes**; and re-validates arguments as defense-in-depth.
- **Event ledger records**; locally, append-only, hash-chained, never by-network in P0.
- **Human controls critical writes / commits**; first commit always manual.
- **SemantIQ evaluates later, through an adapter**; reads events, never sits inside the pipeline.

---

## 2. Explicit Non-Goals (Phase-0 Hard Exclusions)

Everything below is **out of scope for Phase 0**. Introducing any of these
before Phase-0 Day-1 acceptance criteria are met is a scope regression.

| # | Non-goal | Why excluded | Blocking ADR |
|---:|---|---|---|
| NG-01 | **No mesh networking** | Phase 0 is local-only, single process, single machine. Federation topologies add unbounded network complexity. | ADR-0003, ADR-0004 |
| NG-02 | **No federation / multi-node consensus** | No distributed runtime, no Raft/Paxos, no event replication. Events stay on the local machine. | ADR-0003, ADR-0005 |
| NG-03 | **No WebGPU / GPU compute** | No shader pipelines, no Web Workers × GPU, no CUDA/ROCm, no compute graphs. | ADR-0006 |
| NG-04 | **No 3D runtime / WebXR / Three.js world** | No GLB assets, no spatial runtime, no avatars, no physics sim. | ADR-0006 |
| NG-05 | **No wallet / blockchain / tokenomics** | No key material, no chain calls, no NFT/marketplace primitives, no signing runtime. | ADR-0004, ADR-0006 |
| NG-06 | **No marketplace** | No package marketplace, no skill marketplace, no paid-tool mediation. | — |
| NG-07 | **No kernel fork / no custom distro** | No Linux kernel patches, no init, no buildroot/Yocto images, no ISO. | ADR-0006 |
| NG-08 | **No autonomous commit** | No `git commit` invoked by runtime. No auto-merge. Commit gate is human. | ADR-0001, ADR-0003 |
| NG-09 | **No self-modification** | Runtime may not patch its own source, re-write its own policies, or upgrade itself in-band. | ADR-0004 (invariants) |

### 2.1 Also implicitly excluded (non-blocking, still out of scope)

For completeness, the following are **also** not in Phase 0 even though they
were not individually called out in the prompt-pack non-goals list:

- no MCP-in-pipeline (MCP is deferred; any future MCP goes through the
  control plane in SECURITY_BASELINE.md, not agent-direct).
- no Docker socket, no container build, no OCI image as a hard dependency.
- no telemetry, no analytics, no error-reporting network calls.
- no cloud credentials, no SaaS API keys required (SemantIQ is optional,
  evaluation-only, and has no keys in Phase 0).
- no autonomous background agents / scheduled jobs / daemon mode.
- no root / sudo / setuid requirement.

---

## 3. Phase-0 Scope (Positive Mirror of Non-Goals)

For easy orientation against the negative list above, Phase 0 **includes**
only:

```
✔ repository bootstrap + single canonical working copy + docs
✔ TypeScript/pnpm monorepo with strict TS
✔ CLI skeleton (apps/cli) — menog <verb> <args>
✔ verb contracts + verb registry (packages/verbs)
✔ algorithm strategy contracts + registry (packages/algorithms)
  → implemented: OIDA-lite, Runtime Risk, Skill Sel-lite, Self-Monitoring-lite
  → declared only (contracts): the other 6
✔ policy/capability gate (packages/policy)
✔ read-only unprivileged Linux local executor (packages/runtime-linux)
✔ append-only local event store, hash-chained (packages/event-ledger)
✔ shared primitives (packages/shared)
✔ core pipeline glue + types (packages/core)
✔ fixtures + unit + integration + deny tests (tests/*)
✔ menog inspect <workspace> vertical slice end-to-end
✔ manual commit gate + commit candidate artifact
✔ minimal CI (install → typecheck → test, no publish)
✔ baseline security (deny tests 1–12 from SECURITY_BASELINE.md)
```

---

## 4. Cross-References

- Full ADR index under [docs/adr/](docs/adr/)
  - [ADR-0001 Canonical Repository](docs/adr/ADR-0001-canonical-repository.md)
  - [ADR-0002 TypeScript + pnpm Monorepo](docs/adr/ADR-0002-typescript-pnpm-monorepo.md)
  - [ADR-0003 Local-First Runtime Pipeline](docs/adr/ADR-0003-local-first-runtime.md)
  - [ADR-0004 Deny-by-Default Security](docs/adr/ADR-0004-deny-by-default-security.md)
  - [ADR-0005 Event Ledger Phase 0](docs/adr/ADR-0005-event-ledger-phase0.md)
  - [ADR-0006 No Kernel Fork Phase 0](docs/adr/ADR-0006-no-kernel-fork-phase0.md)
  - [ADR-0007 SemantIQ Optional Adapter](docs/adr/ADR-0007-semantIQ-optional-adapter.md)
- Prompt-pack originals: [docs/](docs/)
  (PROJECT_BASELINE, ARCHITECTURE_BASELINE, SECURITY_BASELINE, VERB_REGISTRY_v0,
   ALGORITHM_REGISTRY_v0, EVENT_SCHEMA_v0, LINUX_RUNTIME_CONTRACT,
   DAY1_ACCEPTANCE_CRITERIA)
- Ground truth audit: `CURRENT_STATE.md`
