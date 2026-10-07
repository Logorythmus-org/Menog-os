# PHASE 27C — Node & Edge Lifecycle (Topology-Observation Lifecycle)

**Phase:** 27 — Governed Local Mesh & Runtime Topology
**Gate:** 27C (lifecycle separate from PeerTrustState; pinned transitions; terminal anti-resurrection; freshness ordering; zero-authority recovery)
**Entry:** `27B_PASS` (2026-10-03 — explicit topology graph, 37/37). **Honest status note:** `PRE27-R1` (D-26-2 evidence-writer race repair) is **still NOT executed** — the operator sequence has run `PRE27-R0 → 27A → 27B → 27C`; D-26-2 remains carried, unrepaired. No `PRE27_R1_PASS` is claimed anywhere.
**Status:** implemented, tested, pure decision layer — no store, no socket, no clock

> **Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
> Separation law: `PEER ≠ PATH ≠ TOPOLOGY ≠ TRUST ≠ AUTHORITY ≠ EXECUTION`.

---

## 1. What this gate implements

`packages/durable-state/src/meshTopologyLifecycle.ts` (exported from
`@menog/durable-state`) — the lifecycle of a TOPOLOGY OBSERVATION: how the
knowledge record produced by 27B may move between lifecycle states. Pure
decisions over caller-supplied facts: no store, no socket, no clock
(caller-supplied `evidenceAtEpochMs` only), no I/O.

## 2. Lifecycle separation from PeerTrustState

| | Frozen 24C PeerTrustState | 27C TopologyObservationState |
|---|---|---|
| Vocabulary | `unknown` · `candidate` · `admitted` · `quarantined` · `retired` | `observed` · `stale` · `quarantined_observation` · `retired_observation` · `unknown_observation` |
| Owner | 24C registry (store-backed, evidenced) | 27C (pure decisions over observation facts) |
| Overlap | **NONE — the two sets are disjoint** (suite-pinned) | |

The module only **reads** `NODE_TRUST_STATES` in order to **refuse** it:
any trust value presented as a record state or transition target refuses
`refused_cross_lifecycle_state` (cross-lifecycle confusion fails closed).
The module never mutates, exports, or re-exports trust state, never calls
`isPeerTrustTransition`, and has no path into the 24C registry — the
suite re-proves the frozen 24C machine behaves exactly as before.

## 3. Pinned semantics

**Closed transition table (7 legal edges):**
`observed → {stale, quarantined_observation, retired_observation}` ·
`stale → {observed, quarantined_observation, retired_observation}` ·
`quarantined_observation → {retired_observation}` (quarantine exits ONLY
to retirement — never back to observed) ·
`retired_observation → {}` (**terminal: no out-edge, anti-resurrection**) ·
`unknown_observation → {}` (unnamed states cannot move).

**Closed reason→target map (5 reasons):** `freshness_expired → stale` ·
`re_observed → observed` · `evidence_conflict → quarantined_observation` ·
`operator_retirement → retired_observation` · `unknown_reason → ∅`.
Both the table AND the reason map must agree or the transition refuses
(`refused_illegal_transition` / `refused_reason_mismatch`).

**Pinned validation order (first match wins):**
1. record state vocabulary (trust value → `refused_cross_lifecycle_state`;
   unknown → `refused_unknown_state`)
2. target state vocabulary (same classification)
3. reason vocabulary (`refused_unknown_reason`)
4. epoch validity/boundary (`refused_invalid_epoch` / `refused_stale_epoch` —
   cross-epoch records must recover first)
5. terminal (`refused_terminal_state` — absolute within the epoch)
6. fact validity (`refused_invalid_fact` — non-finite/negative evidence)
7. freshness ordering (`refused_stale_fact` — evidence older than the
   record refuses; returning to `observed` requires **strictly newer**
   evidence; equal refuses)
8. edge legality (`refused_illegal_transition`)
9. reason-target agreement (`refused_reason_mismatch`)
10. allowed → next record, `authority: "none"` structural literal

**Recovery (`recoverTopologyObservation`) — grants nothing:**
1. any `trustClaim ≠ "none"` refuses `refused_no_trust_inheritance`
   **before anything else is evaluated**
2. state vocabulary → 3. record shape → 4. epoch ids → 5. fact validity
6. restore rules: `retired` restores **EXACTLY terminal** (`terminal: true`,
   and a subsequent resurrection attempt still refuses) · `quarantined`
   restores **EXACTLY quarantine** (never auto-clears) · `observed`
   recovered into a **different epoch** restores as **`stale`** — freshness
   never inherits across epochs; re-observation with strictly newer
   evidence is required · `observed` within the same epoch stays observed.
Every success carries `authority: "none"`, `trustInherited: false`,
`autoResumed: false` as **structural literals** (suite-scanned: the module
contains no `authority` other than `"none"`, no `trustInherited: true`,
no `autoResumed: true`).

**Refusal vocabulary (closed, 13 codes):** `refused_cross_lifecycle_state`
· `refused_unknown_state` · `refused_unknown_reason` ·
`refused_reason_mismatch` · `refused_illegal_transition` ·
`refused_terminal_state` · `refused_stale_fact` · `refused_invalid_fact` ·
`refused_stale_epoch` · `refused_invalid_epoch` · `refused_invalid_record` ·
`refused_no_trust_inheritance` · `refused_unknown`.

## 4. Out of scope (binding)

No store access or alternate persist path (no `acceptMutation`, no
`.persist(`, no coordinator) · no socket/listener/spawn · no discovery/
gossip/relay/consensus · no Policy or tool vocabulary · no clock read ·
no trust mutation of any kind · zero new dependencies.

**Non-claims:** 27C decides lifecycle transitions only — it does not
store them (a later gate's explicit problem), does not re-open 27B's
graph record shape, handles no capability advertisement (27D), plans no
route (27E), forwards nothing (27F), and fabricates no physical-LAN
evidence (D-26-1 carried).

## 5. Verification

`tests/unit/mesh-topology-lifecycle.test.ts` — 33/33: structural
forbidden-surface scan (30 pinned tokens, 0 hits) · vocabulary
disjointness from `NODE_TRUST_STATES` · every trust value refuses as both
record state and target (`refused_cross_lifecycle_state`) · frozen 24C
machine re-proven unchanged · legal-edge set pinned (7 edges) with exact
reason agreement, authority `"none"`, record advancement · wrong-reason
and unknown-reason refusals · illegal-edge refusals incl.
quarantine-never-returns · terminal anti-resurrection over every
target × reason (pinned order vs. facts/reasons) · freshness ordering
(older evidence, equal re-observation, strictly-newer re-observation) ·
fact validity · full pinned validation-order chain (9 precedence
assertions) · cross-epoch refusal and invalid epochs · recovery
(trust-claim-refused-first, structural literals on every success,
terminal/quarantine exact restore + post-recovery resurrection still
refused, observed→stale across epochs with strictly-newer re-observation,
same-epoch observed preserved, invalid-record/epoch/fact refusals) ·
determinism of provenance hashes for both entry points · no
store/persist/control path in source.

See `docs/release/PROMPT_27C_REPORT.md` for the gate report.
