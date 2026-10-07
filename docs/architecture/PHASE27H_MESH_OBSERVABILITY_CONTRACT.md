# PHASE 27H — Mesh Observability (Deterministic Redacted Read-Only Projection)

**Phase:** 27 — Governed Local Mesh & Runtime Topology
**Gate:** 27H (deterministic, redacted, read-only topology/runtime projection for later GETIG work — VISUALIZATION != CONTROL PLANE; no mutation/action API; no secrets/raw payload/store content; unknown stays unknown)
**Entry:** `27G_PASS` (2026-10-03 — partition & reconciliation, 31/31). **Honest status note:** `PRE27-R1` (D-26-2 evidence-writer race repair) is **still NOT executed** — the operator sequence has run `PRE27-R0 → 27A → 27B → 27C → 27D → 27E → 27F → 27G → 27H`; D-26-2 remains carried, unrepaired (present at `scripts/phase25e-environment-probe.mjs:351`). No `PRE27_R1_PASS` is claimed anywhere.
**Status:** implemented, tested, pure function — no store, no socket, no clock, no mutation surface

> **Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
> Separation law: `PEER ≠ PATH ≠ TOPOLOGY ≠ TRUST ≠ AUTHORITY ≠ EXECUTION`.

---

## 1. What this gate implements

`packages/durable-state/src/meshObservability.ts` (exported from
`@menog/durable-state`) — ONE pure function,
`buildMeshObservabilitySnapshot(input)`, projecting caller-supplied
local topology/runtime KNOWLEDGE into a deterministic, redacted,
read-only `ObservabilitySnapshot` for later GETIG visualization:
nodes, edges, routes (with origin/forwarders/destination roles),
lifecycle state distinctions, freshness, provenance **metadata**,
recorded refusals, partition/reconciliation summaries, and the
projection's own zero-authority state. The function mutates no input,
reads no clock (`asOfEpochMs` is caller-supplied), reaches no
network, creates no store, and exposes no action of any kind.

## 2. VISUALIZATION != CONTROL PLANE (the law this projector enforces)

- The export surface is exactly **one pure builder function** — no
  class, no mutation method, no apply/set/update/execute/trigger
  surface; the suite pins every exported name against an
  action/authority-name regex.
- Every snapshot carries the structural literals
  `authority: "none"`, `controlPlane: false`, `readOnly: true`;
  source scans pin every `authority:` literal to `"none"`, every
  `controlPlane:` literal to `false`, every `readOnly:` literal to
  `true`, and forbid the counter-literals.
- The success explanation and the exported
  `OBSERVABILITY_SCOPE_TEXT` both carry the law text
  ("VISUALIZATION != CONTROL PLANE … unknown stays unknown …
  recovery/reconnect/reconciliation grants nothing and never
  auto-resumes … fresh LOCAL allocation + fresh LOCAL Policy for the
  assigned actor + frozen Phase-20/21").
- A refusal exposes **no snapshot at all** (nothing partial ever
  escapes) and no `authority`/`controlPlane` key.

## 3. REDACTION (no secrets / raw payload / store content)

- The input schema has **no free-text channel**: every string is a
  bounded identifier (≤ 128 chars), a token-shaped refusal code
  (≤ 64 chars, `/^[a-z][a-z0-9_]*$/`), or a frozen vocabulary member.
  The suite pins the absence of any content-channel word in module
  code (`payload`, `freeText`, `storeContent`, `rawBody`, `plaintext`,
  `credential`, `password`, `secret`).
- Provenance is projected as **metadata only** (`source`,
  `evidenceId`, `recordedAtEpochMs`); evidence content is never
  accepted, never stored, never rendered.
- Mechanical proof: a maximally-stuffed snapshot (128-char ids, 64-char
  codes) is walked recursively in the suite — every string in the
  serialized snapshot stays ≤ `maxIdChars`, and the hash is 64 hex.

## 4. DETERMINISM and UNKNOWN STAYS UNKNOWN

- Identical input → byte-identical snapshot **and** equal
  `projectionHash` (canonicalHash over schema version + input);
  shuffled section order → byte-identical canonical *content* (the
  hash is input-derived by design, so it legitimately differs).
- Every section is canonically sorted in UTF-16 code-unit order (no
  locale dependence); partition conflicts are sorted by subject;
  everything returned is `Object.freeze`d.
- `unknown_node`, `unknown_edge`, `unknown_route`, `unknown_role`,
  `unknown_source`, `unknown_observation` project exactly as recorded —
  nothing is inferred, promoted, averaged, or invented. Missing
  sections project as explicit empty arrays with zero lifecycle
  counts.
- **Freshness is classified, not decided:** `ageMs = asOfEpochMs −
  recordedAtEpochMs`; a record AFTER `asOfEpochMs` cannot be ordered,
  so it projects as `unknown_freshness`; the frozen window (300 000
  ms) separates `within_window` from `outside_window`. No freshness
  value ever authorizes anything.

## 5. Pinned semantics

**Schema (`OBSERVABILITY_SCHEMA_VERSION`):**
`menog-mesh-observability/v0`.

**Frozen bounds (`OBSERVABILITY_BOUNDS`; a caller may exceed a bound,
never redefine one):** `maxNodes: 64` · `maxEdges: 256` ·
`maxRoutes: 64` · `maxHopsPerRoute: 16` · `maxRefusals: 64` ·
`maxPartitions: 64` · `maxConflictsPerPartition: 64` ·
`maxIdChars: 128` · `maxCodeChars: 64` · `freshnessWindowMs: 300000`.
Past a bound = refusal, never truncation or eviction.

**Freshness vocabulary (`OBSERVABILITY_FRESHNESS`, frozen):**
`within_window`, `outside_window`, `unknown_freshness`.

**Conflict-resolution classes (`OBSERVABILITY_CONFLICT_RESOLUTIONS`,
frozen, typed as 27G's `ConflictResolution`):** `terminal_retained`,
`quarantine_retained`, `no_consensus_unknown`.

**Refusal vocabulary:** closed, **8** codes, `Object.freeze`d
(`refused_invalid_input`, `refused_field_bound`,
`refused_epoch_mismatch`, `refused_unknown_vocabulary`,
`refused_invalid_provenance`, `refused_non_finite_time`,
`refused_duplicate_entry`, `refused_unknown`); every refusal carries
an explanation matching `/refus/` and a `projectionHash`. Seven codes
are reachable by construction; `refused_unknown` is the unmapped
fail-closed catch-all.

**Pinned validation order (first match wins):**
1. input shape — object, non-empty snapshot/epoch ids, numeric
   `asOfEpochMs`, six arrays (`refused_invalid_input`);
2. field bounds — ids and section sizes (`refused_field_bound`);
3. `asOfEpochMs` finite and ≥ 0 (`refused_non_finite_time`);
4. per section in pinned order **nodes → edges → routes → refusals →
   partitions**; per item, array order: inner shape → field bounds →
   epoch match (the snapshot's own epoch only) → frozen vocabulary →
   provenance rules (`refused_invalid_provenance` /
   `refused_non_finite_time`) → unique identifier
   (`refused_duplicate_entry`);
5. build — canonical sorting, freshness classification, lifecycle
   counts, deep freeze, structural zero-authority literals, hash.

**Lifecycle distinctions:** counts over the frozen 27C vocabulary
(`observed`, `stale`, `quarantined_observation`, `retired_observation`,
`unknown_observation`) derived from node records only; conflict states
inside a partition are attributed knowledge, not node lifecycle.

**Routes expose origin/forwarders/destination as knowledge:**
`originNodeId`, `originFixed`, `forwarderNodeIds` (grouped from hops
by role, in hop order), `destinationNodeId`, and the ordered `hops`
with their `role` — an `unknown_role` hop is never counted as a
forwarder.

**Snapshot schema (suite-pinned exact keys):** `schemaVersion`,
`snapshotId`, `epochId`, `asOfEpochMs`, `nodes`, `edges`, `routes`,
`lifecycle`, `refusals`, `partitions`, `authority`, `controlPlane`,
`readOnly`, `projectionHash` — with element key sets pinned for node
(+ provenance), edge, route (+ hops), refusal, and partition
(+ conflicts).

**Docs:** `docs/architecture/PHASE27H_MESH_OBSERVABILITY_CONTRACT.md`
(this file).

## 6. Scope law (LOCAL-ONLY)

No discovery/scanning/mDNS/broadcast/gossip membership/WAN/Internet/
cloud relay/NAT traversal/UPnP/tunnel/consensus/global authority; no
socket, no listener, no spawn, no clock (caller-supplied times only),
no store access; no alternate listener/spawn/persist/control path; no
tool or Policy surface. This module consumes the 27A/27B/27C/27G
vocabularies **read-only** and advances none of them. Suite-pinned: 29
forbidden surfaces absent from module source, imports pinned to
exactly `{./canonical.js, ./meshPartitionReconciliation.js,
./meshTopologyGraph.js, ./meshTopologyLifecycle.js,
./meshTopologyTrust.js}`, 11 forbidden law/consensus tokens absent,
and zero network-call tokens (independently grep-verified against
verify-local's pattern list).

## 7. Test suite

`tests/unit/mesh-observability.test.ts` — **33/33**: structural pins
(29 forbidden surfaces, redaction word pin, import pin, schema +
bounds + freshness + code pattern exact and frozen, 8-code refusal
vocabulary, shared 27A/27B/27C vocabularies exact, scope text,
zero-authority literal scan, single-builder export) · snapshot
schema (exact key sets at every level, zero-authority JSON, stuffed
redaction walk, decision shape) · determinism and purity (duplicate
builds byte-identical with equal hashes, shuffled sections canonical,
deep-frozen inputs unchanged across success and refusal) · unknown
stays unknown (all unknown members project verbatim, empty sections
explicit) · lifecycle (exact counts, sums to node count) · routes
(roles projected, forwarders grouped, unknown_role never promoted,
no grant surface) · freshness (within/boundary/outside, un-orderable
→ unknown, non-finite times refuse) · partitions and refusals (counts,
sorted attributed conflicts, code-only records, token rules, duplicates
in every section) · fail-closed inputs (malformed shapes, bounds,
cross-epoch in every section, every enum field, provenance types,
hop-sequence/role/count violations, closed-set refusal table).

## 8. Non-claims

The projection renders knowledge; it grants nothing: no authority, no
trust, no admission, no consensus, no ordering, no auto-resume, no
execution, and no mutation of any recorded state. Every execution
still requires fresh LOCAL allocation + fresh LOCAL Policy for the
assigned actor + frozen Phase-20/21. UNSUPPORTED is never PASS; no
physical-LAN evidence exists or is fabricated. **TOPOLOGY IS
KNOWLEDGE, NOT AUTHORITY.**