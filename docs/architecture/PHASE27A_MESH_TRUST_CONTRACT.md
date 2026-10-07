# PHASE 27A — Mesh Trust Contract

**Phase:** 27 — Governed Local Mesh & Runtime Topology
**Gate:** 27A (contract-first, no socket, no listener, no discovery, no routing execution)
**Entry:** `PRE27_R0_READY_FOR_R1` (2026-10-03). **Honest status note:** the pack sequence places `PRE27-R1` (D-26-2 evidence-writer race repair) before 27A; the operator advanced directly to 27A, so **PRE27-R1 has NOT been executed** and D-26-2 remains carried, unrepaired, by this gate. No `PRE27_R1_PASS` is claimed anywhere.
**Status:** contract layer over frozen primitives — implemented, tested, no execution surface

> **Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
> Separation law: `PEER ≠ PATH ≠ TOPOLOGY ≠ TRUST ≠ AUTHORITY ≠ EXECUTION`.

---

## 1. What this contract is

`packages/durable-state/src/meshTopologyTrust.ts` (exported from
`@menog/durable-state`) defines the CLOSED vocabularies and deterministic,
fail-closed decisions for the Phase-27 mesh trust model **before** any
topology store, advertisement propagation, route computation, or forwarding
code exists (27B+). Pure decisions only: no socket, no listener, no
discovery, no crypto, no store access, no execution surface, no wall clock
(caller-supplied `observedAtEpochMs` only). Every output is a deterministic
function of caller-supplied facts with an embedded explanation.

## 2. The six pins (M1–M6)

| Pin | Law | Meaning |
|---|---|---|
| M1 | `EDGE ≠ TRUST` | An edge records that two nodes were observed in relation; it carries no trust and never mutates the frozen 24C registry. |
| M2 | `PATH ≠ ADMISSION` | A path is knowledge of how bytes WOULD travel; it never admits a peer — admission stays the 24C registry's evidenced local decision. |
| M3 | `ROUTE ≠ AUTHORIZATION` | A route plans hops; it authorizes no message, no Policy, no execution. Every execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21. |
| M4 | `FORWARDER ≠ ORIGIN` | Forwarding never moves origin attribution; origin is fixed at creation. |
| M5 | `ADVERTISEMENT ≠ GRANT` | A capability advertisement is remote DATA describing claims; it grants none of them. |
| M6 | `TOPOLOGY KNOWLEDGE ≠ MEMBERSHIP` | Knowing the graph is not being a member; membership remains the frozen 24C registry's evidenced local decision. |

Each pin has one deterministic, closed explanation string
(`MESH_TRUST_PIN_EXPLANATIONS`) embedded verbatim in every decision that
cites it — greppable, suite-pinned, no free-form authority prose.

## 3. The closed typed entities

`MeshNode` · `MeshEdge` · `MeshPath` · `MeshTopology` · `MeshObservation`
· `MeshAdvertisement` · `MeshRoute` · `MeshHop` · `MeshOrigin` ·
`MeshForwarder` · `MeshDestination` — all readonly interfaces over
caller-supplied facts, each keyed to a closed kind/state/role vocabulary
with an `unknown_*` sentinel that refuses (fail closed):

| Vocabulary | Closed values |
|---|---|
| Node kinds (4) | `local_node` · `admitted_node` · `observed_node` · `unknown_node` |
| Edge kinds (4) | `configured_edge` · `observed_edge` · `advertised_edge` · `unknown_edge` |
| Path states (4) | `path_open` · `path_unverified` · `path_blocked` · `unknown_path` |
| Observation kinds (8) | `node/edge/path/route/origin/forwarder/destination_observed` · `unknown_observation` |
| Advertisement kinds (4) | `capability/topology/route_advertisement` · `unknown_advertisement` |
| Capability claims (5) | `claim_can_forward_proposals` · `claim_reachable_on_local_lan` · `claim_supports_framed_transport` · `claim_topology_summary` · `unknown_capability_claim` |
| Route states (4) | `route_planned` · `route_unverified` · `route_unavailable` · `unknown_route` |
| Hop roles (4) | `origin` · `forwarder` · `destination` · `unknown_role` |
| Refusal codes (15) | one per unknown/boundary case, `refused_unknown` as terminal default |
| MAY scope (8) | record observation/node/edge/path/route · receive advertisement as data · plan route · summarize knowledge |
| MAY-NOT scope (15) | `execute_tool` · `choose_policy` · `admit_peer` · `grant_authority` · `grant_capability` · `persist_record` · `administer_peer` · `discover_peers` · `bind_public` · `traverse_nat` · `relay_cloud` · `reach_internet` · `gossip_membership` · `consensus_join` · `forward_as_origin` — each mapped to the pin that refuses it |

All vocabularies are `Object.freeze`d (callers can never widen them), and
MAY ∩ MAY-NOT = ∅ (suite-pinned).

## 4. Deterministic decisions

- **`decideMeshNode`** — known kinds record with `membership: "none"` (M6);
  `unknown_node` refuses.
- **`decideMeshEdge`** — known kinds record with `trust: "none"` (M1);
  `unknown_edge` refuses.
- **`decideMeshPath`** — known states record with `admission: "none"` (M2);
  `unknown_path` refuses.
- **`decideMeshObservation`** — known kinds record read-only with
  `authority: "none"`; `unknown_observation` refuses. Observability is
  read-only, never control.
- **`decideMeshAdvertisement`** — anonymous claimant refuses before
  evaluation; `unknown_advertisement` and `unknown_capability_claim` refuse
  (fail closed); acceptance yields `grant: "none"` (M5) — claims are
  recorded as remote DATA and never honored as grants.
- **`decideMeshRoute`** — pinned check order: state → hop roles (first
  match wins). `unknown_route` refuses; `unknown_role` refuses the whole
  route; a forwarder recorded at the origin node refuses naming M4
  (`refused_forwarder_as_origin`); acceptance yields
  `authorization: "none"` and `executionAuthorized: false` structurally
  (M3), with the fresh-LOCAL-allocation → LOCAL Policy → Phase-20/21 law
  embedded verbatim.
- **`decideMeshScope`** — closed MAY passes; closed MAY-NOT refuses naming
  its pin; unknown capability refuses with `violatedPin: null` (fail
  closed).
- **`decideMeshClaim`** — six fact claims (node kind, edge relation, path
  state, observation, route plan, capability advertisement) are receivable
  as DATA with `authority: "none"`; the six conflation claims (edge trust,
  path admission, route authorization, forwarder origin, advertisement
  grant, topology membership) refuse naming their exact pin — one
  conflation per pin. Anonymous subjects refuse before evaluation. The
  deterministic `provenanceHash` (22A canonical) binds (kind, subject,
  observedAt).
- **`meshTrustFingerprint`** — canonical self-description (pins + all
  vocabularies) for provenance bindings; no I/O.

## 5. Out of scope (binding)

This contract represents **no** socket, listener, discovery, scanning,
mDNS, broadcast, gossip membership, WAN/Internet, cloud relay, NAT
traversal, UPnP, tunnel, consensus, or global authority — these exist only
as closed MAY-NOT refusals. It holds no tool vocabulary at all: no
network/topology path can reach a tool through this module. No alternate
listener/spawn/persist/control path. Zero new dependencies.

**Non-claims:** no topology store exists yet (27B owns the graph record);
no route is computed over real data (27E); no proposal is forwarded (27F);
no physical-LAN evidence exists (D-26-1 carried; 26I stays
`UNSUPPORTED_ON_CURRENT_TARGET`, never validation).

## 6. Verification

`tests/unit/mesh-topology-trust.test.ts` — 28/28: structural no-socket /
no-policy / no-tool token pins; the six pins + explanations exact-equality;
all eleven vocabularies exact-equality with `unknown_*` sentinels present
and MAY ∩ MAY-NOT = ∅; frozen-object pins; per-entity zero-authority
structurals (`"none"` / `false` literals) with unknown-sentinel refusals;
anonymous advertisement refusal; M4 forwarder-as-origin refusal; unknown
hop-role refusal; the full claim matrix (6 facts accepted as DATA,
6 conflations refused with exact pins, one per pin); scope MAY/MAY-NOT/
unknown matrix; determinism (same input → same provenance hash) and
fingerprint determinism.

See `docs/release/PROMPT_27A_REPORT.md` for the gate report (commands,
actual counts, files changed, debt, non-claims, verdict, next gate).
