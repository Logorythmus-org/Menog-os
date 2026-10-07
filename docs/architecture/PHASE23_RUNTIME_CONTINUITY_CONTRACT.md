# Phase-23 Runtime Continuity Contract — Live/Durable Authority (23A)

**Gate:** 23A · **Mode:** CONTRACT-FIRST / NO LIVE WIRING · **Date:** 2026-09-29
**Entry state:** `PRE23_R0_READY_WITH_NONBLOCKING_DEBT` (Phase-22 frozen semantics preserved verbatim)
**Implementation:** `packages/durable-state/src/continuity.ts` · **Tests:** `tests/unit/durable-continuity-contract.test.ts` (43)
**Status:** CONTRACT ONLY. Nothing here is wired to the store, the coordinator, the launcher, or any live surface. 23B must satisfy this contract; no 23B code exists in this gate.

---

## 1. Purpose and scope

Phase 22 made durable state trustworthy but explicitly did NOT wire any live runtime
surface to it (DEBT-22-02). Phase 23 closes that gap. Before any wiring exists, this gate
formalizes — as closed types and pure, fail-closed decision functions — what it MEANS for
one local runtime to be the single live owner of a durable store, how live-visible work
becomes durable work, and how a restarted runtime may be explicitly handed recovered state.

The central Phase-23 statement (extends, never relaxes, the Phase-22 invariant):

```text
durable state ≠ execution authority ≠ Policy authorization ≠ executable replay
acknowledged-to-the-user ≠ durably committed
```

Non-goals honored: no coordinator, no process supervision, no scheduler, no executable
replay, no Phase-14 rollback closure, no network/cloud DB, no federation, no super-agent,
no auto-resume, no silent repair.

## 2. The nine laws (L1–L9)

| Law | Statement | Structural enforcement |
|:--|:--|:--|
| L1 | Persistence grants no execution authority | `RuntimeEpoch`/`RuntimeContinuitySnapshot` hard-type `executionAuthorized:false` / `policyAuthorized:false`; the admitted continuity decision carries no authority fields at all (test: JSON key surface) |
| L2 | Recovered state reuses no Policy authority | `decideRecoveryBootstrap` returns exactly the frozen 22A triple (`recovered_data`, false, false) on EVERY path, success and refusal |
| L3 | Terminal/quarantined facts cannot resurrect | No resurrection vocabulary exists in the module (structural scan); admission flows only through the 22A/22E recovery decision, which already refuses it |
| L4 | No durability acknowledgement before durable confirmation | The ONLY ack predicate is `acknowledgedBarrier` = outcome `committed` AND commitSequence present; a mutation without such a barrier is never admitted; `rolled_back`/`ambiguous`/sequence-less barriers all fail closed; terminal mutation outcomes can never advance |
| L5 | Ambiguous ownership and stale epochs fail closed | Epoch id mandatory and shape-checked; a carried id over a fresh store is refused; a LIVE claim held by another id is refused (split-brain); an UNVERIFIABLE or anonymous claim is refused (`epoch_refused_unverifiable`); every decision carries its epoch and `decisionStillFresh` detects staleness |
| L6 | Recovery→live is explicit and evidenced | The machine is BOOTING→RECOVERING→READY→LIVE; READY is never skipped; RECOVERING→READY requires `recovery_decision` evidence (`advanceLifecycle` refuses otherwise); RECOVERED→LIVE is unrepresentable for every reason |
| L7 | No auto-resume | Interruptions land in RECOVERED; re-entry passes only through RECOVERING; the module contains no resume/continue vocabulary (structural scan pins `autoResume`/`continueTask` absent) |
| L8 | Derived state is non-authoritative | Derived kinds are excluded from `ContinuityRecordKind` at the type level AND re-checked at the decision boundary (`DERIVED_CONTINUITY_KINDS`), so a hostile cast is still refused (`rejected_derived_kind`) |
| L9 | Executable replay stays out of scope | No execution vocabulary: structural scan pins `executeToolRun`, `runToolInLauncher`, `runIsolated`, `generateRollbackPlan(`, `generateReplayPlan(`, `child_process`, `spawn(`, `fetch(`, `BEGIN IMMEDIATE`, `node:sqlite` absent from the module; the only self-authorization flag is hard-typed `selfAuthorized: false` |

## 3. Runtime lifecycle (closed machine)

States: `BOOTING`, `RECOVERING`, `READY`, `LIVE`, `RECOVERED`.

- **BOOTING** — process started; nothing durable read yet.
- **RECOVERING** — 22E startup recovery running (or fresh store detected); no state exposed.
- **READY** — recovery decision in hand; recovered state exposed as `recovered_data`; NO live
  execution surface open.
- **LIVE** — the single live owner; execution requests may be made through the normal chain.
- **RECOVERED** — a LIVE runtime lost the store (or shut down); everything visible is
  recovered data; the process is NOT authoritative and MUST re-traverse RECOVERING.

Edges (total table; all others unrepresentable):

```text
BOOTING → RECOVERING
RECOVERING → READY | RECOVERED
READY → LIVE
LIVE → RECOVERED
RECOVERED → RECOVERING
```

Reasons are pinned to targets (`process_start`→BOOTING, `recovery_started`→RECOVERING,
`recovery_decision_ready`→READY, `recovery_bootstrap_rejected`→RECOVERED,
`lifecycle_transition`→LIVE, `barrier_lost`/`store_unavailable`/`explicit_shutdown`/
`operator_pause`→RECOVERED, `fresh_store_detected`→RECOVERING). A legal edge with the wrong
reason is refused. `RECOVERED → LIVE` is refused for every reason.

## 4. Runtime epochs (ownership)

- `RuntimeEpochId` (`re-<ts12>-<rnd16>`) is generated fresh per process start via the pure
  factory `makeRuntimeEpochId(now, randomness)` (injectable clock/randomness; deterministic
  in tests; property test: 200 generated ids are unique and shape-valid). It is identity,
  never authority: an opened epoch hard-types both authority flags false.
- `makeRuntimeEpoch` is the ONLY sanctioned constructor. It refuses: malformed/empty ids;
  a declared (carried-in) id that mismatches the generated id; a carried id over a FRESH
  store; a LIVE claim held by ANOTHER id (split-brain); an `unverifiable` prior claim; and a
  live claim with no attributable id. It admits re-ownership only for `same_epoch_id`
  (the crash-resume special case of ONE process identity) and `stale_claim_present`.
- The durable layer (23B) owns the claim RECORD; this contract decides on what the layer
  reports. Ambiguity is never resolved here — it refuses.

## 5. Live/durable mutations and the durability barrier

- A `LiveDurableMutation` starts at phase `requested` with NO barrier and NO outcome. The
  only advancing call is `advanceLiveDurableMutation` with exactly one of:
  `barrier_confirmed` (→ phase `durable`, outcome `durable`), `refused` (→ outcome
  `refused_pre_commit`, stays at `requested`), or `store_error` (→ outcome
  `unknown_after_error`). Terminal outcomes can never advance again: a barrier arriving
  after an ambiguity is ignored by construction.
- A `DurabilityBarrier` is the store layer's confirmation of ONE atomic persist. Outcomes:
  `committed` / `rolled_back` / `ambiguous` — engine-honest, mirroring 22F fault-injection
  reality. ONLY `committed` with a present `commitSequence` acknowledges (L4).
- `decideContinuity` is the ONLY LIVE-side admission. It refuses: no epoch; lifecycle not
  LIVE; mutation from a different (stale) epoch; derived kind; missing barrier;
  non-acknowledged barrier; barrier from another epoch. The admitted decision carries the
  commit sequence and NO authority fields — admission makes work VISIBLE, never authorized.

## 6. Recovery bootstrap (RECOVERING → READY) and the handoff

`decideRecoveryBootstrap` consumes the frozen 22A/22E `RecoveryDecision` verbatim:

- ACCEPT codes (`accept_full_state`, `accept_without_quarantined`, `rebuild_derived_required`)
  → `bootstrap_to_ready`, exposing EXACTLY the decision's admitted ids as `recovered_data`
  with `executionAuthorized:false` / `policyAuthorized:false`.
- REJECT codes (`rejected_schema_mismatch`, `rejected_unverifiable`, `rejected_scan_bound`)
  → `bootstrap_refused_recovery_failed` — the runtime may not expose state; re-enter
  RECOVERING only via an explicit, evidenced retry.
- Wrong lifecycle or no epoch → refuse (fail closed).

There is NO path from READY (or RECOVERED) to LIVE inside this decision. Reaching LIVE is a
separate explicit machine transition (`advanceLifecycle`, `lifecycle_transition` reason),
and the real authority gates remain downstream: fresh execution after restart must traverse
Planner → Allocation → Policy → Isolation → Governed Tool Runtime (frozen Phase-20/21/22
law, untouched).

## 7. Source-of-truth, failure behavior, and interrupted work (the prompt's questions, answered by the types)

- **Source of truth while LIVE:** the durable store. The live runtime is the single WRITER
  (ownership by epoch); the ledger/records remain the authoritative evidence. Live-visible
  state that is not barrier-confirmed is not yet durable and must be presented as such.
- **Accepted vs durable vs visible:** `requested` (accepted by the live surface) → `durable`
  (barrier-confirmed) → `visible` (presentable). Visibility BEFORE `durable` is
  unrepresentable through the admission boundary.
- **Persistence failure:** refusal keeps work invisible (`refused_pre_commit`); a store error
  marks the mutation `unknown_after_error` — acknowledged ambiguity, never visible, never
  healed (matching the engine's own rolled-back/ambiguous commit reality; kill-window
  empirics are gate 23E).
- **Interrupted work:** any LIVE→RECOVERED event makes everything the old epoch saw
  recovered data; there is no resume path — work re-enters only through re-planning via the
  normal authority chain (L7).
- **Corrupt/quarantined store:** handled by the frozen 22E machinery; this contract's
  bootstrap refuses on any hard recovery rejection and exposes only admitted records as
  `recovered_data`.
- **Derived views:** never mutations, never admissions; rebuildable, non-authoritative (L8).

## 8. Deliberately excluded (and why)

- **Local ownership lease record with expiry/heartbeat:** deferred to 23B, which owns the
  durable claim record and must define its staleness empirics. 23A already fails closed on
  every ambiguous claim shape, so adding the lease later cannot weaken these laws.
- **Multi-owner arbitration, consensus, timestamps-as-truth:** out of scope by the global
  invariants (no distributed consensus; single local owner or refusal).

## 9. Verification (actual counts, 2026-09-29)

- Contract/property suite: `tests/unit/durable-continuity-contract.test.ts` — **43/43 PASS**.
- Structural pins: no execution/wiring/repair vocabulary in `continuity.ts`; authority
  dead-ends hard-typed; the barrel exports the 23A vocabulary; no live wiring exists.
- Full-suite, verify-local and setup-local results are recorded in
  `docs/release/PROMPT_23A_REPORT.md` (this gate's report; counts re-run, never copied).

## 10. Downstream obligations (non-binding here, binding later)

- **23B** must implement the coordinator ON these types: durable epoch/claim record, barrier
  production from real store transactions, one durability barrier per commit — and must not
  add any admission path that bypasses `decideContinuity`/`decideRecoveryBootstrap`.
- **23D** must make the recovery→LIVE handoff produce the evidence this contract demands
  (`recovery_decision` on RECOVERING→READY; explicit `lifecycle_transition` to LIVE).
- **23E/23F** must attack exactly the seams named here: mid-commit kills (barrier honesty),
  duplicate local owners (split-brain refusal), stale-epoch decisions, and derived-kind
  injection.

STOP — 23A closes; 23B is the next gate.
