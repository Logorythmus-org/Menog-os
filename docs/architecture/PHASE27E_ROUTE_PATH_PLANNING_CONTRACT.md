# PHASE 27E — Route & Path Planning (Bounded Deterministic Zero-Authority Routing)

**Phase:** 27 — Governed Local Mesh & Runtime Topology
**Gate:** 27E (deterministic bounded path computation over explicit topology; ROUTE ≠ AUTHORIZATION; PATH ≠ ADMISSION; loops and graph explosion refused; stale/quarantined never route)
**Entry:** `27D_PASS` (2026-10-03 — capability advertisement, 49/49). **Honest status note:** `PRE27-R1` (D-26-2 evidence-writer race repair) is **still NOT executed** — the operator sequence has run `PRE27-R0 → 27A → 27B → 27C → 27D → 27E`; D-26-2 remains carried, unrepaired (present at `scripts/phase25e-environment-probe.mjs:351`). No `PRE27_R1_PASS` is claimed anywhere.
**Status:** implemented, tested, pure decision layer — no store, no socket, no clock

> **Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
> Separation law: `PEER ≠ PATH ≠ TOPOLOGY ≠ TRUST ≠ AUTHORITY ≠ EXECUTION`.

---

## 1. What this gate implements

`packages/durable-state/src/meshRoutePlanning.ts` (exported from
`@menog/durable-state`) — deterministic bounded path computation over
the EXPLICIT topology knowledge of a 27B graph snapshot, with an
explicit 27C observation-state overlay. Two pure functions:

- `planRoute(input)` — computes the route (node path + resolved edge
  path) from an origin to a destination;
- `validateRoutePath(input)` — checks a caller-supplied candidate node
  sequence against the same knowledge.

Both mutate NOTHING, read no clock (caller-supplied epochs only), touch
no store, and open no socket. A route is a PLAN over knowledge — it
authorizes no message, no peer, no Policy, and no execution.

## 2. Zero-authority composition with the frozen 27A contract

Every SUCCESS from both functions is composed through the frozen 27A
decisions and carries these **structural literals**:

| Literal | Source law | Meaning |
|---|---|---|
| `admission: "none"` | 27A M2 (composed `decideMeshPath`) | a path never admits — the frozen 24C registry remains the only admission decision |
| `authorization: "none"` | 27A M3 (composed `decideMeshRoute`) | a route never authorizes a message or action |
| `executionAuthorized: false` | 27A M3 | execution still requires fresh LOCAL allocation + fresh LOCAL Policy + frozen Phase-20/21 |
| `transitiveTrust: false` | 27E | walking knowledge through a node transfers no trust |
| `capabilityUnion: false` | 27E | planning accumulates no capability |

The composed 27A explanation text ("M2 PATH != ADMISSION …", "M3 ROUTE
!= AUTHORIZATION … fresh LOCAL allocation …") is carried into every
success explanation verbatim (suite-pinned). The module exports ONLY
`planRoute` and `validateRoutePath` — no class, no authorize/approve/
admit surface — and source-scans pin that no `authority` literal other
than `"none"` exists and no trust/Policy token appears.

## 3. Pinned semantics

**Frozen bounds (`ROUTE_BOUNDS`; a caller may exceed a bound, never
redefine one):** `maxInputNodes: 64` · `maxInputEdges: 256` ·
`maxPathHops: 63` (= maxInputNodes − 1). An input graph over a bound is
**graph explosion and is refused BEFORE any search** (counters stay 0);
a candidate walk over the hop cap is refused before membership — a
huge adversarial path is never walked.

**Observation overlay (fail closed):** an element is traversable ONLY
when its explicit state is `observed` AND its record epoch matches the
snapshot epoch. **Absent state is NOT observed.** `stale`,
`quarantined_observation`, `retired_observation`,
`unknown_observation` never traverse (mirrors 27C: quarantine never
returns, terminal never resurrects). A non-observed ENDPOINT refuses
`refused_endpoint_not_observed`; a non-observed interior element
excludes its corridor — blocking the only way fails closed as
`refused_no_route`, while an observed DETOUR still routes with
excluded-element counters reported (never silent).

**Determinism (no ties left to chance):** shortest-hop paths only; among
equal-length candidates the **lexicographically smallest node sequence**
wins (BFS layering + greedy reconstruction over forward/reverse
distances); parallel edges resolve to the lexicographically smallest
edge id; adjacency is sorted at subgraph construction; graph
construction order does not change the result; identical input yields
byte-identical decisions (hash-bound).

**Loop handling:** planned paths are loop-free BY CONSTRUCTION (visited
set; distances strictly increase along the result); self-loop edges are
excluded and counted; cycles in the graph are knowledge, never a trap —
they never appear in a result. A caller-supplied candidate that repeats
a node refuses `refused_route_loop`.

**Pinned validation order — `planRoute` (first match wins):**
1. input shape (`refused_invalid_request`)
2. input graph bounds — explosion refused pre-search (`refused_route_bound`)
3. epoch agreement (`refused_epoch_mismatch`)
4. origin ≠ destination (`refused_same_endpoint` — even for unknown nodes)
5. endpoints exist (`refused_unknown_node`)
6. endpoints EXPLICITLY observed (`refused_endpoint_not_observed`)
7. observed-subgraph construction (excluded elements counted; duplicate
   edge ids resolve first-wins, idempotent knowledge)
8. forward BFS — unreachable ⇒ `refused_no_route` (search counters reported)
9. reverse BFS layering
10. lexicographically smallest shortest-path reconstruction (invariant
    guard refuses a partial path — never returned)
11. composition with the frozen 27A path + route decisions (M2 + M3)

**Pinned validation order — `validateRoutePath` (first match wins):**
shape → graph bounds → epoch → single node → **hop cap before
membership** → membership (`refused_unknown_node`) → loop
(`refused_route_loop` — structure before overlay) → endpoints observed
→ per-hop resolution in order: smallest observed directed edge
resolves; a pair whose edges/endpoints are not observed for this epoch
refuses `refused_hop_not_observed`; a pair with no directed edge
refuses `refused_route_gap` (the reverse edge is NOT this edge).

**Refusal vocabulary:** closed, 11 codes, `Object.freeze`d; every code
carries an explanation; any 27A path/route refusal maps fail-closed to
`refused_unknown` with the composed 27A text carried through.

**Docs:** `docs/architecture/PHASE27E_ROUTE_PATH_PLANNING_CONTRACT.md`
(this file).

## 4. Scope law (LOCAL-ONLY)

No discovery/scanning/mDNS/broadcast/gossip membership/WAN/Internet/
cloud relay/NAT traversal/UPnP/tunnel/consensus/global authority; no
socket, no listener, no spawn, no clock, no store access; no alternate
listener/spawn/persist/control path. Planning is pure knowledge —
observability read-only, never control. Suite-pinned: 29 forbidden
surfaces absent from module source, imports pinned to
`{./canonical.js, ./meshTopologyGraph.js, ./meshTopologyLifecycle.js,
./meshTopologyTrust.js}`, zero network-call tokens (independently
grep-verified against verify-local's pattern list).

## 5. Test suite

`tests/unit/mesh-route-planning.test.ts` — **42/42**: structural pins
(vocabularies, bounds, 29 forbidden surfaces, import pin, zero-authority
literal scan, forbidden law tokens, export surface) · deterministic
planning (line graph, byte-identical reruns, lexicographic tie-break,
parallel-edge resolution, construction-order independence) · planning
refusals in pinned order (shape, explosion pre-search with zero
counters, epoch, same-endpoint-over-unknown, unknown endpoint, absent/
stale/quarantined/retired/unknown endpoint states, foreign-epoch record,
disconnected + direction-only no-route with counters) · observation
overlay (stale interior blocks only corridor, stale edge blocks,
quarantined endpoint refuses, quarantine-with-detour routes with
excluded counters, all-observed control) · loops and explosion (cyclic
graph loop-free results, self-loop excluded+counted, duplicate edge
first-wins, dense 64-node/256-edge graph within pinned counters +
determinism) · candidate validation (valid, malformed, same-endpoint,
bound-before-membership, unknown-before-loop, loop, loop-before-state,
endpoint states, gap vs not-observed incl. direction, epoch, oversized
graph, malformed graph) · integration with a real 27B
`LocalTopologyGraph` snapshot (plan + validate + graph fingerprint
unchanged — planning mutates nothing).
