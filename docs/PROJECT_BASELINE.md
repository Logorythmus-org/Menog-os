# Menog OS — Project Baseline v0

> ### ⚠ SUPERSEDED SNAPSHOT — this is not current status
>
> This document records the **Day-1 / Phase-0 baseline**. Its classification table below is
> **historical** and no longer describes the repository:
>
> - **`Skill = ROADMAP`, `Tool = ROADMAP`, `Commit = ROADMAP`, `Memory = ROADMAP` are all out of
>   date.** Since it was written, the Phase-21 governed tool runtime was implemented, along with
>   `@menog/commit-engine` and `@menog/memory`.
> - **The workspace is now 14 projects (13 packages + a CLI)**, not the Day-1 set — see
>   `docs/ARCHITECTURE_BASELINE.md`'s layout, which is likewise a v0 snapshot.
> - **The "151 tests total" figure in the scope section is a Day-1-era count.** The repository now
>   holds **141 test files** (96 unit / 34 security / 11 integration) across Phases 12–29.
>
> Retained rather than rewritten, because it is a dated baseline record. For current truth see
> [`README.md`](../README.md) and [`CURRENT_STATE.md`](../CURRENT_STATE.md).
>
> One row below is still accurate: the **16 `CapabilityId`** count matches the source today.

## Official definition

Menog OS is a **local-first, observable, zero-trust, Linux-native agentic runtime** for controlled human–AI execution. It converts human intent into typed actions, evaluates those actions through policy and capability boundaries, executes them inside a local unprivileged runtime, records evidence, and makes the resulting changes inspectable, reproducible, and reversible.

## Baseline classification legend

Every capability and subsystem below is explicitly classified as exactly one of:

- **IMPLEMENTED_NOW** — Present and exercised by tests in this repository (Phase 0 v0).
- **ROADMAP** — Planned for a future phase; not present; explicitly not shipping in v0.
- **OPTIONAL_EXTERNAL** — May never be core; optional integration boundary only if ever adopted.

## Core formula classification

```text
Intent     = WHY                                       IMPLEMENTED_NOW  (taskId/actor/ws, Goal type)
Verb       = WHAT                                      IMPLEMENTED_NOW  (verb registry + inspect)
Algorithm  = HOW TO REASON                             IMPLEMENTED_NOW  (17A: strategy contracts + registry +
                                                                           selector in packages/algorithms; 17B: OIDA state machine
                                                                           + Goal Priority; 17C: memory-retrieval port integration,
                                                                           risk verdicts (restrict/deny, policy=floor), capability-
                                                                           aware skill selection; 17D: bounded metric-driven
                                                                           self-monitoring with audited in-bounds parameter
                                                                           adaptation — NO source mutation; recommend-only)
Agent      = WHO                                       IMPLEMENTED_NOW  (Actor type + 3 subtypes)
Skill      = HOW TO ACT                                ROADMAP
Tool       = WITH WHAT                                 ROADMAP
Policy     = MAY IT                                    IMPLEMENTED_NOW  (deny-by-default engine)
Planner    = Goal → PlanSteps                          IMPLEMENTED_NOW  (DeterministicPlanner proposal-only,
                                                                           no execution authority)
Plan Graph = Plan → DAG / Canonical Serialization       IMPLEMENTED_NOW  (3-color cycle detect, Kahn topo sort,
                                                                           canonical JSON audit/replay hash)
Dual Gate  = Planner step.caps ⊆ Policy Allows         IMPLEMENTED_NOW  (planner↔policy coupling invariant;
                                                                           bypass not possible, proven by tests)
Bridging   = PlannerObs → typed MenogEventInput[]       IMPLEMENTED_NOW  (pure factory, ZERO authority, no append)
Linux      = WHERE                                     IMPLEMENTED_NOW  (allowlist-only child_spawn,
                                                                           no-shell argv, cwd/env lock)
Ledger     = WHAT HAPPENED                             IMPLEMENTED_NOW  (AppendOnlyLedger, SHA-256 chain,
                                                                           planner observations appendable)
SemantIQ   = HOW WELL                                  OPTIONAL_EXTERNAL (external eval boundary only,
                                                                           NOT shipped in v0)
Commit     = WHAT CHANGED                              ROADMAP           (manual review only, NO
                                                                           automation)
Memory     = WHAT WAS LEARNED                          ROADMAP
```

## Phase-0 scope — explicit classification

### Included (IMPLEMENTED_NOW)

- **Repository bootstrap**: TypeScript strict composite build, pnpm workspaces, ESM-only (`"type": "module"`).
- **TypeScript/pnpm workspace**: `apps/*`, `packages/*` composites; `pnpm-lock.yaml` frozen; `packageManager` + `engines` fields pinned.
- **CLI skeleton**: bin `menog` → `apps/cli/dist/bin/menog.js`.
- **Verb contracts**: `@menog/verbs` registry, `inspect` verb definition, `VerbLookup` API.
- **Event schema**: typed `EventEnvelope`, `policy_decision` + `exec_intent` + `exec_result` event types, `resultSummary` JSON payloads.
- **Goal / Plan / Task contracts**: `Goal`, `GoalBudget`, `PlanStep`, `Plan`, `PlannerProposal`, **`PlanGraph`**, **`PlanGraphEdge`**, **`PlanGraphCycle`** in `@menog/core`; 7 `GoalStatus`, `SideEffectClassUpperBound` rank arithmetic, 4 `PlanDependencyKind` (sequential/capability/dataflow/approval).
- **Deterministic planner proposal engine**: `@menog/planner` package → `DeterministicPlanner.propose(Goal) => PlannerProposal`. Proposal-only, NO execution authority; each `PlanStep` carries `verbId` + `requiredCapabilities` + `sideEffectClass` + `requiresHumanApproval[]` from the registry.
- **Plan → DAG graph layer**: `buildPlanGraph(plan, { explicitDependencies, includeSequentialChainEdges, explicitDependencyKind })` → typed `PlanGraph`. 3-color DFS cycle detection (back-edge stack → `PlanGraphCycle[]`); Kahn topological sort (step-index tiebreak stable); sorted-key canonical JSON serialization (`serializedCanonical`) + deterministic `serializedCanonicalHash` for audit/replay equality. Self-loops / nonexistent-node / negative-index / float-index edges all fail-closed as `invalid_edge_rejected` disposition (structured rejection metadata: rejectedEdgeIndex, rejectedEdgeReason, reason).
- **Budget enforcement at plan time**: `budget.maxSteps`, `budget.maxRuntimeMs`, `budget.maxSideEffectClass` upper-bound checks before plan is proposed.
- **Planner → Ledger observability**: `PlannerObservationEvent[]` stream with typed `observationType`, `schemaVersion`, `trace[]`; callers append to `AppendOnlyLedger`.
- **Planner observations → ledger pure bridging helper**: `plannerObservationToMenogEventInputs(observations, actor, options?)` in `@menog/planner`. ZERO-authority pure factory: does NOT import event-ledger, does NOT call ledger.append, returns typed `MenogEventInput[]` only. Caller retains append authority (NO WRITE WITHOUT SCOPE).
- **Planner↔Policy dual-gate coupling invariant**: proven by adversarial tests that planner output *never* bypasses policy: (gate 1) `unsupportedCapabilityDeny` catches unknown caps at plan time before proposal; (gate 2) even if planner gate disabled explicitly, `DenyByDefaultPolicyEngine.evaluate()` still denies all smuggled / forbidden caps via `perCapability` full map. For any `PlanStep` produced by proposal, `PolicyEngine.allowedCapabilities ⊇ step.requiredCapabilities` is enforced by test coverage.
- **Planner security / negative test families**: 27 adversarial tests (12D-gate requirement) covering scope-escalation denied (sideEffect class lattice + maxSteps cap), capability smuggling denied (6 vectors: case/whitespace/suffix/typosquat/variant/duplicate-case plus dual-gate bypass proof), malformed graph denied (non-monotonic stepIndex, crafted cycle, 1000-node scale, negative/float/oob edges, duplicate indexes), hidden write denied (DAY1_FORBIDDEN union invariant, verbatim cap copy check, `<script>` embedded content leakage guard across planId / serializedCanonical / trace / summary), ledger denial evidence (unknown-verb + smuggling observations bridged → ledger append → verify count-match; policy deny decision events via wrapLedger).
- **Policy/capability model**: `DenyByDefaultPolicyEngine`, 16 `CapabilityId` (Slot-1/Slot-2 split; includes 5 newly enumerated verbs-declared caps: `workspace:read-file`, `workspace:search`, `plan:generate`, `process:spawn`, `git:recover`), `PolicyResult.perCapability` full map, risk class none/low/medium/high/critical, `requiresHumanApproval` flag.
- **Read-only local executor**: `AuthoritativeExecGate` 5 phases; allowlist only (`git`, `node`, `pnpm`); `child_process.spawnSync` with `argv[]` no shell; cwd lock; env allowlist-only; timeout + process-tree cleanup; stdout/stderr/exit capture.
- **Append-only local event storage**: `AppendOnlyLedger.at()`, in-memory option, constructor-level chain integrity verification (SHA-256 hash chain, line-size cap, JSONL, redactSummary).
- **`menog inspect <workspace>`**: full vertical slice through Verb → Policy → Gate → Ledger → InspectReport.
- **Unit/integration/security tests**: 151 tests total (137 non-security + 14 deny-test security cases) under Vitest (18 planner tests; 25 graph tests; 27 new 12D planner-security adversarial tests covering scope-escalation/cap-smuggling/malformed-graph/hidden-write/ledger-denial-evidence families + dual-gate policy coupling; 15 policy tests; 12 verbs tests; 11 event-ledger tests; 15 runtime-linux tests; 14 integration inspect tests; 14 security deny-tests preserved).
- **Manual commit gate**: documented manual-review process; NO automated commit/replay.

### Excluded (ROADMAP)

These are roadmap items. They are **NOT present** and **NOT authorized** in v0. Any documentation references are placeholders only:

- Planner *execution* authority: planner proposes; downstream decider (human + policy engine) must approve each step separately before any execution.
- Planner *rewrites* / backtracking / multi-algorithm search / heuristic scoring.
- Mesh / Federation / distributed runtime.
- Custom Linux kernel or custom distro.
- WebGPU compute or GPU-shader runtime.
- Three.js runtime world, GLB avatars, 3D/XR presentation.
- Wallets / blockchain / marketplace.
- Autonomous root or hidden background agents.
- Unrestricted MCP or tool-calling without capability scope.
- Autonomous commit engine / commit replay enforcement / diff auto-apply.
- Merkle block ticks, Ed25519 block signatures.
- cgroup/seccomp executionRef hashes.
- Before/after actual-side-effects comparison.
- SemantIQ evaluation runtime.
- Memory / training / fine-tuning subsystems.
- Algorithm registry with pluggable agentic algorithms. → **Reclassified 17A: IMPLEMENTED_NOW** as
  strategy contracts + registry + selector in `packages/algorithms` (recommend-only; six families
  remain contract-only with fail-closed evaluation denial).
- Skill registry with pluggable execution implementations.
- Tool registry with sandbox boundaries.

### OPTIONAL_EXTERNAL subsystems

- **SemantIQ** — If a future evaluation boundary is adopted, it must remain **external** to the core runtime (same category as a CI or third-party audit system). The core v0 runtime treats model output as untrusted input; SemantIQ must not be an authority over policy.

## Architectural layers (layer-by-layer classification)

```text
Human / System Event                  — input, boundary
      ↓
Intent Engine                         — ROADMAP (v0 parses CLI argv only)
      ↓
Verb Registry                         — IMPLEMENTED_NOW
      ↓
Goal / Task Model                     — IMPLEMENTED_NOW (typed Goal, PlanStep, Plan, PlanGraph)
      ↓
Deterministic Planner                 — IMPLEMENTED_NOW (proposal-only, verb→cap)
      ↓
Plan / Verb Graph                     — IMPLEMENTED_NOW (DAG, cycle detect, topo sort, canonical JSON audit hash)
      ↓
Planner↔Policy DUAL GATE             — IMPLEMENTED_NOW  (unsupportedCapabilityDeny + per-cap deny-map
      ↓                                bypass IMPOSSIBLE, proven by adversarial tests)
Agentic Algorithm Registry            — IMPLEMENTED_NOW (17A: ten family contracts, one replaceable
      ↓                                strategy per family; 17B: OIDA + Goal Priority implemented;
                                    17C: risk verdicts + capability-aware skill selection + port-
                                    bound memory retrieval; 17D: bounded self-monitoring + audited
                                    in-bounds parameter adaptation (default registry: 5 of 10
                                    families with concrete strategies; retrieval is opt-in via port);
                                    recommend-only, deny-by-default selection)
      ↓
Agent / Skill Runtime                 — ROADMAP (v0 has Actor type only)
      ↓
Policy & Capability Gate              — IMPLEMENTED_NOW  (deny-by-default, full per-cap map)
      ↓
Linux Execution Runtime               — IMPLEMENTED_NOW  (5-phase gate)
      ↓
Planner Obs → Ledger BRIDGE          — IMPLEMENTED_NOW  (pure factory, ZERO authority, no append)
      ↓
Event Ledger                          — IMPLEMENTED_NOW  (SHA-256 chain, planner obs)
      ↓
Memory / Replay / Optional SemantIQ   — MEMORY=ROADMAP; SEMANTIQ=OPTIONAL_EXTERNAL
      ↓
Commit Engine                         — ROADMAP (manual-only in v0)
```

## Design philosophy — operational interpretation

```text
OBSERVABILITY FIRST                   — IMPLEMENTED_NOW  (typed events, redactSummary,
                                                           inspect report)
LOCAL FIRST                           — IMPLEMENTED_NOW
ZERO TRUST                            — IMPLEMENTED_NOW  (deny-by-default, untrusted input
                                                           doctrine, env/cwd/argv locks)
VISIBLE AI                            — IMPLEMENTED_NOW  (policy decisions in ledger,
                                                           human-visible report)
COMPLIANCE BY DESIGN                  — Compliance-oriented architecture;
                                       no external certification or audit is claimed.
FEDERATED LATER                       — ROADMAP           (not in v0)
```
