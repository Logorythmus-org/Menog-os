# Phase-23 Continuity Threat Model (23A) — Live/Durable Authority Boundary

**Gate:** 23A · **Mode:** CONTRACT-FIRST / NO LIVE WIRING · **Date:** 2026-09-29
**Scope:** the 23A continuity contract (`packages/durable-state/src/continuity.ts`) and the
seams a future 23B coordinator must respect. This is a THREAT MODEL of a CONTRACT layer —
there is no live runtime to attack yet, so every entry disposes of the CLASS, with the test
evidence that pins the disposition.
**Presupposes:** `docs/security/PHASE22_STORAGE_THREAT_MODEL.md` (durable-layer threats
remain covered there and are not re-audited here), frozen Phase-20/21 boundaries.

---

## 1. Assets and trust boundary

**Assets:** the durable store (append-only evidence + mutable state); the single-live-owner
claim; the durability barrier (the ack boundary); recovered data after restart; the lifecycle
machine (BOOTING→RECOVERING→READY→LIVE / RECOVERED).

**Boundary:** everything outside one local process on the WSL2 target-of-record is untrusted;
the durable layer is trusted only to the exact claims frozen in Phase 22 (engine WAL
transaction, no power-loss certification, quarantine-as-found, fail-closed recovery). The 23A
layer trusts NOTHING on the live side except shape-valid epoch identity — every live input is
decided on, never trusted.

## 2. Adversarial classes and dispositions

| ID | Class | Attack | Disposition (contract law) | Test evidence |
|:--|:--|:--|:--|:--|
| T1 | Forge live ownership | Present a malformed, empty, or carried-in epoch id to pose as a live owner | `makeRuntimeEpoch` refuses malformed ids; a carried id over a fresh store is refused; ids are `re-<ts12>-<rnd16>` and property-unique | contract suite L5 cases |
| T2 | Split brain | Two local owners claim the same store simultaneously | A LIVE claim held by another epoch id refuses admission (`epoch_refused_live_owner`); two live owners are unrepresentable | contract suite L5 |
| T3 | Ambiguous ownership | Present an `unverifiable` or anonymous (no id) prior-owner claim | Refused (`epoch_refused_unverifiable`) — ambiguity never resolves to admission | contract suite L5 (gap F1 below) |
| T4 | Stale-epoch replay | Reuse a decision/ownership from a finished epoch | Every decision carries its epoch; `decisionStillFresh` marks any other epoch stale; mutations from another epoch are refused at admission (`rejected_epoch_mismatch`) | contract suite L5 |
| T5 | Phantom durability | Acknowledge work to the user without a durable commit | The ONLY ack is `acknowledgedBarrier` = `committed` + present commitSequence; `rolled_back`/`ambiguous`/sequence-less barriers fail closed; barrier from another epoch is unrecognized | contract suite L4 |
| T6 | Late-barrier healing | After an ambiguous store error, retroactively attach a barrier and claim the work was durable | Terminal mutation outcomes never advance; a late barrier is ignored by construction | contract suite L4 |
| T7 | Authority laundering via admission | Treat `admitted` continuity decisions as execution/policy authority | The admitted decision carries NO authority fields (JSON key-surface pinned); epochs and snapshots hard-type `executionAuthorized:false` / `policyAuthorized:false` | contract suite L1/L2 + structural scan |
| T8 | Recovered-state authority laundering | Expose recovered state and treat it as policy-capable | Bootstrap returns EXACTLY the frozen 22A triple on every path; a rejected recovery can never bootstrap | contract suite L2 |
| T9 | Live-skip | Reach execution without recovery (`BOOTING→LIVE`, `RECOVERING→LIVE`, `RECOVERED→LIVE`) | The machine's edge table + reason pinning refuse every skip; `RECOVERED→LIVE` is refused for ALL ten reasons | contract suite L6 |
| T10 | Unevidenced handoff | Advance RECOVERING→READY without a recovery decision | `advanceLifecycle` requires `recovery_decision` evidence for READY | contract suite L6 (gap F2 below) |
| T11 | Derived-state laundering | Inject `derived_index`/`store_checkpoint` as a live/durable mutation | Type-level exclusion PLUS runtime set check at the boundary; a hostile cast still refuses (`rejected_derived_kind`) | contract suite L8 |
| T12 | Auto-resume | Restart and silently continue interrupted work | No resume/continue vocabulary exists (structural scan); interruptions land in RECOVERED; re-entry only via RECOVERING | contract suite L7 + structural scan |
| T13 | Execution smuggling in the contract layer | Hide execution/wiring/replay vocabulary inside the contract module | Structural scan pins `executeToolRun`, `runToolInLauncher`, `runIsolated`, `generateRollbackPlan(`, `generateReplayPlan(`, `child_process`, `spawn(`, `fetch(`, `node:sqlite`, `BEGIN IMMEDIATE` absent; `selfAuthorized: false` is the only self flag | contract suite L9 scan |
| T14 | Wiring through the back door | Import the store, junction, planner, policy, or agents packages into the contract layer | Scan pins `from "./store.js"`, `@menog/policy`, `@menog/planner`, `@menog/agents`, `@menog/runtime-linux`, `DurableStore` absent from `continuity.ts`; the barrel only re-exports vocabulary | contract suite structural scan |
| T15 | Repair-as-attack | "Heal" ambiguous state into visible state | Ambiguity is terminal for visibility; repair vocabulary is absent (matches the 22B/22E quarantine-as-found law) | contract suite L4 + 22H pins |

## 3. Fail-closed gaps found and closed in 23A

| ID | Gap | Closure |
|:--|:--|:--|
| F1 | `unverifiable` prior-owner claims and anonymous live claims would have OPENED an epoch (ambiguous ownership resolving to admission) | Refused with `epoch_refused_unverifiable`; regression-pinned (2 test cases) |
| F2 | RECOVERING→READY would have applied without requiring recovery-decision evidence (unevidenced handoff) | `advanceLifecycle` now refuses READY without `recovery_decision` evidence; regression-pinned |
| F3 | The admitted continuity decision carried no derived-kind check (the L8 exclusion was type-level only) | Runtime `DERIVED_CONTINUITY_KINDS` check at the decision boundary; hostile-cast case pinned |

Each gap was found during 23A's own adversarial self-review of the contract (before any
wiring exists — this is the point of contracts-first), closed in the same gate, and pinned by
the contract suite.

## 4. Residual risks (recorded, not closed — later gates)

- **Kill-window empirics:** barrier honesty under a process kill between statements inside a
  commit is a RUNTIME question (23E); 23A only guarantees the vocabulary cannot lie.
- **Coordinator-side attacks** (claim-record forgery, lease expiry races, barrier fabrication
  in the wiring): out of 23A scope by design; 23B inherits the obligation to keep
  `decideContinuity`/`decideRecoveryBootstrap` as the ONLY admission boundaries, and 23F must
  attack the wiring, not just the contract.
- **`node:sqlite` version sensitivity (DEBT-22-04)** and the WSL2-native gap remain recorded.

## 5. Test mapping

Structural + behavioral evidence lives in `tests/unit/durable-continuity-contract.test.ts`
(43 tests). Fail-closed gap closures are regression-pinned there (F1: two cases; F2: one
case; F3: one case). The Phase-22 adversarial suite (19/19) and freeze-audit pins (11)
remain green and untouched.

STOP — CONTRACT-ONLY threat model; no wiring exists to certify.
