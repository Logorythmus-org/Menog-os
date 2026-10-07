# PHASE 27G — Partition & Reconciliation (Local World-Views / No Consensus)

**Phase:** 27 — Governed Local Mesh & Runtime Topology
**Gate:** 27G (partition & rejoin reconciliation of two LOCAL world-views — conflicts attributable, stale data cannot resurrect terminal facts, quarantine never auto-clears, no consensus/global truth/authority inheritance/auto-resume)
**Entry:** `27F_PASS` (2026-10-03 — multi-hop forwarding, 36/36). **Honest status note:** `PRE27-R1` (D-26-2 evidence-writer race repair) is **still NOT executed** — the operator sequence has run `PRE27-R0 → 27A → 27B → 27C → 27D → 27E → 27F → 27G`; D-26-2 remains carried, unrepaired (present at `scripts/phase25e-environment-probe.mjs:351`). No `PRE27_R1_PASS` is claimed anywhere.
**Status:** implemented, tested, pure function — no store, no socket, no clock

> **Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
> Separation law: `PEER ≠ PATH ≠ TOPOLOGY ≠ TRUST ≠ AUTHORITY ≠ EXECUTION`.

---

## 1. What this gate implements

`packages/durable-state/src/meshPartitionReconciliation.ts` (exported
from `@menog/durable-state`) — the LOCAL logical decision layer for
reconciling TWO node-local world-views after a split/rejoin:
`reconcilePartitionViews(input)` takes ONE `ReconciliationInput`
(`reconciliationId`, `localView`, `remoteView`) and returns ONE
`ReconciliationDecision`. The function is PURE: it mutates neither
view, reads no clock, reaches no network, creates no store, and
advances no lifecycle. Each node RETAINS its own world-view — the
merged view is an additional classification, never a replacement of,
or authority over, either side's knowledge.

## 2. The law this reconciler enforces

- **No consensus, structurally.** Every success carries
  `authority: "none"`, `consensusReached: false`,
  `globalOrdering: false`, `autoResumed: false`,
  `trustTransferred: false` as **structural literals** (source scan
  pins every `authority:` literal to `"none"` and forbids every `*:
  true` counter-literal). Reconciliation does NOT decide which side
  is right: there is no Raft/Paxos, no gossip, no quorum, no leader,
  no global ordering, no discovery — merging knowledge is not
  agreeing, ordering, resuming, or inheriting anything.
- **Conflicts are ATTRIBUTABLE, never a winner.** Every conflict
  record carries both owners, both states, both recorded times, and
  the resolution class; nothing is silently dropped, last-write-wins,
  or averaged. A disagreement between two different non-terminal
  claims merges to `unknown_observation` with resolution
  `no_consensus_unknown` — unknown stays unknown.
- **Stale data cannot resurrect terminal facts.** If EITHER view
  records a 27C terminal state (`TOPOLOGY_TERMINAL_OBSERVATION_STATES`
  = `retired_observation`), the merged state stays terminal and the
  opposing claim is recorded as an attributed conflict (resolution
  `terminal_retained`). **Time NEVER decides:** recorded times are
  attribution only — even a strictly fresher `observed` claim cannot
  move a terminal fact (suite pins both directions plus a time-swap
  invariance case).
- **Quarantine never auto-clears.** If EITHER view records a 27C
  quarantine state (`TOPOLOGY_QUARANTINE_OBSERVATION_STATES` =
  `quarantined_observation`), the merged state stays quarantine with
  the conflict attributed (resolution `quarantine_retained`) — rejoin
  is not a legal transition. Precedence is pinned: terminal outranks
  quarantine; quarantine outranks the no-consensus unknown.
- **Merging never transitions.** The 27C lifecycle is read (its
  frozen state/quarantine/terminal vocabularies are imported), never
  advanced: the merged state is a CLAIM CLASSIFICATION, not a state
  transition. Exclusive one-sided claims keep their holder's state
  exactly as recorded (a stale exclusive fact stays stale on rejoin).
- **Duplicate proposals are no-ops.** Reconciliation is pure and
  deterministic: two identical inputs produce byte-identical decisions
  with equal `reconciliationHash` (canonicalHash over the schema
  version, reconciliation id, and both input views); merged facts are
  sorted by subject regardless of input array order; inputs are never
  mutated (suite deep-freezes both views and diffs byte-identical
  JSON across success and refusal).

## 3. Pinned semantics

**Schema (`RECONCILIATION_SCHEMA_VERSION`):**
`menog-mesh-reconciliation/v0`.

**Frozen bounds (`RECONCILIATION_BOUNDS`; a caller may exceed a
bound, never redefine one):** `maxFactsPerView: 64` ·
`maxViewIdChars: 128` · `maxNodeChars: 128` ·
`maxEvidenceIdChars: 128`. Past a bound = refusal, never truncation
or eviction; a 64-fact view reconciles, a 65-fact view refuses.

**Refusal vocabulary:** closed, **8** codes, `Object.freeze`d
(`refused_invalid_view`, `refused_field_bound`,
`refused_epoch_mismatch`, `refused_duplicate_fact`,
`refused_unknown_state`, `refused_unknown_provenance_source`,
`refused_invalid_provenance`, `refused_unknown`); every refusal
carries an explanation matching `/refus/` and a `reconciliationHash`,
and exposes NO `authority`/`merged`/`consensusReached` key (suite
pinned; 7 codes reachable by construction, `refused_unknown` is the
unmapped fail-closed catch-all).

**Pinned validation order (first match wins):**
1. both views are objects with non-empty view/owner/epoch ids and an
   array of well-formed facts (`refused_invalid_view`);
2. view-level field bounds — ids, fact count (`refused_field_bound`);
3. the two views claim the SAME epoch (`refused_epoch_mismatch` —
   cross-epoch merging would fabricate a world the evidence never
   described; epoch substitution refused);
4. per-fact, local view first then remote, array order: inner shape →
   subject/evidence bounds → fact epoch (≠ view epoch refuses) →
   27C state vocabulary → 27B provenance (source must be
   `local_configuration` or `governed_evidence` — `unknown_source`
   and unnamed sources refuse; governed must cite a non-empty
   evidence id, local must cite none; recorded time must be finite
   and ≥ 0) → duplicate subject (`refused_duplicate_fact` — a view
   that contradicts itself cannot be reconciled);
5. merge (pure, sorted by subject, local attribution first):
   equal states = agreement with both attributions · either terminal
   = terminal retained + attributed conflict · either quarantine =
   quarantine retained + attributed conflict · other disagreements =
   `unknown_observation` + attributed conflict · one-sided = that
   side's claim attributed to that side;
6. success with the no-consensus structural literals.

**Output shape (suite-pinned exact keys):** decision
(`ok, code, reconciliationId, merged, conflicts, agreementCount,
localExclusiveCount, remoteExclusiveCount, authority,
consensusReached, globalOrdering, autoResumed, trustTransferred,
explanation, reconciliationHash`) · merged view
(`viewId, epochId, facts` — `viewId` = reconciliationId) · merged
fact (`subjectNodeId, state, conflicted, attributions`) · attribution
(`ownerNodeId, state, source, evidenceId, recordedAtEpochMs`) ·
conflict (`subjectNodeId, localState, remoteState, localOwnerNodeId,
remoteOwnerNodeId, localRecordedAtEpochMs, remoteRecordedAtEpochMs,
resolution`). Everything returned is `Object.freeze`d; merged output
JSON contains no authority/trust/grant/quorum/leader token and no
consensus/auto-resume/global-ordering key (the pinned label
`no_consensus_unknown` is the conflict vocabulary ASSERTING the
absence of consensus, not a consensus claim).

**Counts:** `agreementCount + conflicts.length + localExclusiveCount
+ remoteExclusiveCount === merged.facts.length` (suite-pinned
additivity — every merged fact is accounted for exactly once).

**Docs:** `docs/architecture/PHASE27G_PARTITION_RECONCILIATION_CONTRACT.md`
(this file).

## 4. Scope law (LOCAL-ONLY)

No consensus/global truth/global ordering/authority inheritance,
no Raft/Paxos/gossip/quorum/leader/discovery, no
discovery/scanning/mDNS/broadcast/gossip membership/WAN/Internet/
cloud relay/NAT traversal/UPnP/tunnel; no socket, no listener, no
spawn, no clock (caller-supplied epochs and recorded times only), no
store access; no alternate listener/spawn/persist/control path; no
tool or Policy surface. Observability is read-only, never control;
recovery/reconnect/reconciliation grants nothing and never
auto-resumes. Suite-pinned: 29 forbidden surfaces absent from module
source, imports pinned to exactly `{./canonical.js,
./meshTopologyGraph.js, ./meshTopologyLifecycle.js}`, 11 forbidden
law/consensus tokens absent (incl. `Paxos`, `quorum`,
`leaderElect`, `authorize(`, `admit(`, `granted`), zero network-call
tokens (independently grep-verified against verify-local's pattern
list).

## 5. Test suite

`tests/unit/mesh-partition-reconciliation.test.ts` — **31/31**:
structural pins (29 forbidden surfaces pinned + absent, import pin,
schema version + bounds exact + frozen, 8-code refusal vocabulary
exact + frozen, authority/consensus literal scan + 11 law tokens
absent, export surface exactly one pure function) · split/rejoin
(disjoint views: zero conflicts, exclusive counts per holder, sorted
subjects, stale exclusive stays stale; shared agreement: both
attributions local-first, counts add up) · conflicts attributable
(observed vs stale → `unknown_observation` with both owners/states/
times asserted; mirrored stale vs observed and unknown vs observed —
no side wins) · anti-resurrection (fresher remote observed vs local
retired, fresher local observed vs remote retired, time-swap
invariance — all `terminal_retained`) · quarantine (fresher remote
quarantine retained; local quarantine vs stale and unknown;
terminal outranks quarantine) · purity (deep-frozen inputs,
byte-identical success AND refusal; duplicate reconciliations
byte-identical with equal hashes; deterministic subject sorting
across input orders) · fail-closed inputs (cross-epoch views, fact
from another epoch, duplicate subject local+remote, unknown state,
unknown/unnamed/missing provenance source, governed-must-cite/
local-must-not/time rules ×6, malformed shapes ×6, bounds: 64 ok /
65 + oversize viewId/owner/subject/evidence refuse, refusal-table
closed-set + no authority surface) · output shape (exact key sets for
decision/merged/fact/attribution/conflict, merged JSON free of
authority/trust/grant/quorum/leader and consensus-key literals,
viewId/epoch identity, conflicts = conflicted-fact count).

## 6. Non-claims

Reconciliation grants nothing: no authority, no trust, no admission,
no consensus, no global ordering, no auto-resume, no lifecycle
transition, no execution — every execution still requires fresh LOCAL
allocation + fresh LOCAL Policy for the assigned actor + frozen
Phase-20/21. UNSUPPORTED is never PASS; no physical-LAN evidence
exists or is fabricated. **TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
