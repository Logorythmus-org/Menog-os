# PHASE 27B — Explicit Topology Graph

**Phase:** 27 — Governed Local Mesh & Runtime Topology
**Gate:** 27B (deterministic bounded LOCAL graph; config-and-evidence only; no discovery; no Policy/tool; no authority)
**Entry:** `27A_PASS` (2026-10-03 — mesh trust contract, 28/28). **Honest status note:** `PRE27-R1` (D-26-2 evidence-writer race repair) is **still NOT executed** — the operator sequence has run `PRE27-R0 → 27A → 27B`; D-26-2 remains carried, unrepaired. No `PRE27_R1_PASS` is claimed anywhere.
**Status:** implemented, tested, in-memory bounded state — no store, no socket, no discovery

> **Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
> Separation law: `PEER ≠ PATH ≠ TOPOLOGY ≠ TRUST ≠ AUTHORITY ≠ EXECUTION`.

---

## 1. What this gate implements

`packages/durable-state/src/meshTopologyGraph.ts` (exported from
`@menog/durable-state`) — the explicit local topology graph: ONE bounded,
deterministic, in-memory state object (`LocalTopologyGraph`) over the
frozen 27A mesh trust contract. All mutation goes through `addNode` /
`addEdge`, which validate in a **pinned order (first match wins)** and
leave the graph EXACTLY as it was on any refusal. The module never reads
a wall clock (caller-supplied `recordedAtEpochMs` only), performs no
I/O, touches no store, and has no trust/admission/membership/authority/
execution/Policy field anywhere — structurally, not by convention.

## 2. The laws it enforces

| Law | Mechanism |
|---|---|
| Config + governed evidence ONLY | `TOPOLOGY_PROVENANCE_SOURCES` is a closed vocabulary (`local_configuration` · `governed_evidence` · `unknown_source`); any other source refuses `refused_unknown_provenance_source`. Governed evidence MUST cite an `evidenceId`; local configuration MUST NOT pretend to (asymmetry is checked — `refused_invalid_provenance`). |
| Every record has provenance + epoch | Stored records are exactly `{nodeId, kind, epochId, provenance}` / `{edgeId, fromNodeId, toNodeId, kind, epochId, provenance}` — suite-pinned key sets. |
| Stale / invalid fail closed | Record from a different epoch → `refused_stale_epoch`; empty ids → `refused_invalid_record`; non-finite time → `refused_invalid_provenance`; unknown kind → `refused_unknown_node_kind` / `refused_unknown_edge_kind` (delegated to the 27A contract). Every refusal is a no-op (fingerprint unchanged). |
| Duplicates idempotent | Identical re-record (content hash equal) → `duplicate_idempotent`, counts unchanged; same id with DIFFERENT content → `refused_conflicting_record`, never overwrites (first evidenced knowledge stands). |
| Bounded | Frozen `TOPOLOGY_GRAPH_BOUNDS = { maxNodes: 64, maxEdges: 256 }`. A new record at capacity refuses `refused_graph_bound` — never evicts, never grows; the bounds object is `Object.freeze`d so a caller can never redefine one. Idempotent duplicates still work at capacity (no growth). |
| Edges cannot conjure nodes | Both endpoints must already be recorded nodes — else `refused_dangling_edge`. |
| Topology ≠ peer-trust state | The module contains no trust/admission/authority field, no `PeerRegistry`/`DurableStore`/`RuntimeStateCoordinator` reference, no `acceptMutation`/`.persist(` path. The graph is knowledge; the frozen 24C registry remains the only peer-trust state, and nothing here reads or writes it. |
| Determinism | Identical input sequences → identical fingerprints; fingerprints and snapshots are order-insensitive (canonical sort by id); snapshots are frozen read-only views. |

**Pinned validation order (first match wins):**
1. provenance source → 2. provenance shape → 3. record shape (non-empty ids) →
4. epoch → 5. kind (27A contract) → 6. existing id (duplicate/conflict) →
7. (edges) both endpoints recorded → 8. bound → 9. record added.

## 3. Refusal vocabulary (closed, 11 codes)

`refused_invalid_epoch` · `refused_unknown_provenance_source` ·
`refused_invalid_provenance` · `refused_invalid_record` ·
`refused_stale_epoch` · `refused_unknown_node_kind` ·
`refused_unknown_edge_kind` · `refused_conflicting_record` ·
`refused_dangling_edge` · `refused_graph_bound` · `refused_unknown`.

## 4. Out of scope (binding)

No discovery/scanning/mDNS/broadcast/gossip membership/WAN/Internet/cloud
relay/NAT traversal/UPnP/tunnel/consensus/global authority — an unnamed
provenance source cannot contribute knowledge. No socket, no listener, no
spawn, no store access (persistence, if ever sanctioned, is a later
gate's explicit problem, never an alternate path from here). No Policy
call, no tool vocabulary, no authority field that could ever become
true. Zero new dependencies.

**Non-claims:** no node/edge lifecycle transitions yet (27C owns
lifecycle) · no capability advertisement handling (27D) · no route
planning over the graph (27E) · no forwarding (27F) · no physical-LAN
evidence (D-26-1 carried; 26I stays `UNSUPPORTED_ON_CURRENT_TARGET`).

## 5. Verification

`tests/unit/mesh-topology-graph.test.ts` — 37/37: structural forbidden-
surface scan (23 pinned tokens) · separation scan (no trust/admission/
membership/authority/execution/Policy field or tool vocabulary in code) ·
schema/bounds/sources/refusals exact-equality · open/empty-epoch ·
provenance matrix (config, governed-with-id, governed-without-id refuses,
config-pretending-to-cite refuses, unknown source refuses, non-finite
time refuses) · stale epoch no-op for nodes and edges · unknown kinds
refuse via 27A delegation · duplicate idempotence (node + edge,
fingerprint unchanged) and conflict refusal (never overwrites) ·
dangling edge · malformed ids · node and edge bounds (refuse, never
evict, duplicates at capacity still idempotent, frozen bounds) · pinned
validation order (provenance > epoch > kind > conflict > bound) ·
refusal-set fingerprint invariance · record key-set separation ·
determinism and order-insensitive fingerprints · frozen snapshots.

See `docs/release/PROMPT_27B_REPORT.md` for the gate report (commands,
actual counts, files changed, debt, non-claims, verdict, next gate).
