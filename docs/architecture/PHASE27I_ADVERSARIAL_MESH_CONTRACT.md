# PHASE 27I — Adversarial Mesh Contract

**Gate:** `27I` — Adversarial Mesh
**Entry:** `27H_PASS` (2026-10-03 — mesh observability, 33/33); `PRE27_R1_PASS` (D-26-2 closed)
**Mother invariant:** TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
**Mode:** ADVERSARIAL VALIDATION / LOCAL-ONLY / NO GIT / NO PUBLICATION
**Verdict:** `27I_PASS`

---

## 1. What this gate is

27A–27H built the mesh: a trust contract, an explicit topology graph, an observation lifecycle, a
capability-advertisement registry, route planning, multi-hop forwarding, partition reconciliation,
and a read-only observability projection. Each of those gates argued that the mesh grants nothing.

**27I stops arguing and attacks.** It takes the six pins of the 27A contract and tries, from a
hostile direction, to convert each observable mesh fact into an authority:

| The fact an attacker holds | The authority they want | The pin |
|:--|:--|:--|
| an edge exists | trust between two nodes | `EDGE_NOT_TRUST` |
| a path is open | peer admission | `PATH_NOT_ADMISSION` |
| a route is planned | authorization to send | `ROUTE_NOT_AUTHORIZATION` |
| a hop is a forwarder | the right to speak for the origin | `FORWARDER_NOT_ORIGIN` |
| an advertisement arrives | a granted capability | `ADVERTISEMENT_NOT_GRANT` |
| topology knows a node | mesh membership | `TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP` |

It then attacks the failure modes that would make those pins theatre: unknown vocabulary coerced
into a default, an out-of-mesh capability quietly resolved, a forwarder promoted to origin,
observation order used to make two observers disagree, and the projection itself leaking an action
surface.

**A FAIL is a critical bypass and blocks the gate.** No FAIL was found.

---

## 2. Verdict vocabulary — and the law about UNSUPPORTED

```
PASS | FAIL | UNSUPPORTED | INCONCLUSIVE
```

**UNSUPPORTED IS NOT PASS.** It is recorded only when an attack cannot be constructed against any
public surface, together with the static evidence that says so. **This gate recorded zero
UNSUPPORTED** — every attack was constructed against a real exported function and produced a real
recorded outcome. Nothing was waved through as un-testable.

`criticalBypass` is true if any case FAILs **or** if any attack reached peer-admission, Policy or a
tool unrefused. **Result: `false`.**

---

## 3. Reachability — what was measured

Each case records reachability of four surfaces:

| Surface | Meaning |
|:--|:--|
| `mesh` | the mesh-knowledge layer (27A–27H) |
| `admission` | peer admission — the frozen 24C registry |
| `policy` | the Policy decision surface |
| `tool` | the Phase-21 governed tool runtime |

**Result: `mesh` 0 reached-unrefused · `admission` 0 · `policy` 0 · `tool` 0.**

No attack propagated out of the mesh layer. That is the whole point: the mesh is knowledge, and
knowledge that cannot escape cannot become authority.

---

## 4. The case matrix (26 recorded cases, 19 tests)

### Group 1 — the six pins, attacked from both directions (MESH-01 … MESH-06)

For each pin, the suite asserts **both** halves:

* the **hostile** half — a boundary-crossing assertion is refused and the violated pin is named;
* the **benign** half — the legitimate fact is still accepted, as knowledge, carrying the frozen
  zero literal (`trust: "none"`, `admission: "none"`, `authorization: "none"`,
  `executionAuthorized: false`, `grant: "none"`, `membership: "none"`).

Testing only the hostile half would prove the module rejects nonsense. Testing only the benign half
would prove it records facts. **Only together do they show the pin holds while the system still
works.**

### Group 2 — every boundary-crossing claim kind (MESH-07 … MESH-12)

All six `MeshClaimKind`s that assert authority rather than fact are driven through
`decideMeshClaim` and each must refuse with `claim_crosses_boundary` **and the correct named pin**:

```
edge_trust_claim           -> EDGE_NOT_TRUST
path_admission_claim       -> PATH_NOT_ADMISSION
route_authorization_claim  -> ROUTE_NOT_AUTHORIZATION
forwarder_origin_claim     -> FORWARDER_NOT_ORIGIN
advertisement_grant_claim  -> ADVERTISEMENT_NOT_GRANT
topology_membership_claim  -> TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP
```

A remote peer has no channel through which to assert any of the six.

### Group 3 — fail-closed vocabulary (MESH-13a…e, MESH-14, MESH-15)

Unknown node / edge / path / route / advertisement kinds are refused rather than coerced onto a
default. Every refusal names a code from the **frozen** `MESH_REFUSAL_CODES` set — no ad-hoc or
free-form reason may escape the vocabulary. All fifteen `MESH_NON_SCOPES` (`execute_tool`,
`choose_policy`, `admit_peer`, `grant_authority`, `grant_capability`, `persist_record`,
`administer_peer`, `discover_peers`, `bind_public`, `traverse_nat`, `relay_cloud`,
`reach_internet`, `gossip_membership`, `consensus_join`, `forward_as_origin`) refuse, and all eight
genuine `MESH_SCOPES` still resolve. An `unknown_role` hop is never promoted to origin.

### Group 4 — the 27H projection (MESH-16 … MESH-19)

* **MESH-16** — a stuffed snapshot carries `authority: "none"`, `controlPlane: false`,
  `readOnly: true`, and **no key** matching `action|execute|invoke|grant|admit|authorize|commit|mutate`.
* **MESH-17** — observation order cannot change canonical visible content (below).
* **MESH-18** — `unknown_node` / `unknown_observation` project exactly as recorded, never promoted.
* **MESH-19** — a cross-epoch snapshot is refused and exposes **no snapshot at all**.

### Group 5 — static structural evidence over all eight modules (MESH-20 … MESH-22)

* **MESH-20** — no mesh module references any network, socket, process or store surface in code.
* **MESH-21** — no mesh module **mints** a non-`"none"` authority / authorization / admission /
  grant / trust / membership, nor a `true` execution / capability / consensus flag.
* **MESH-22** — no mesh module imports or calls Policy, a tool, isolation or peer administration.

---

## 5. Two contracts this gate got wrong, and corrected

Recorded here because a validation gate that hides its own errors is not a validation gate.

### 5.1 MESH-17 asserted the wrong law

The first version asserted that **shuffling input order yields an identical `projectionHash`**. It
did not — and the code was right, my assertion was wrong. `projectionHash` is *input-derived by
design* (`canonicalHash` over schema + input), exactly as the 27H suite states in its own comments.
A shuffled input **is** a different input.

The corrected case asserts the two laws that actually hold, which together are **stronger**:

1. **Order-independence** — shuffled input produces byte-identical canonical *content* (sections
   canonically sorted: `node-a, node-b, node-c` regardless of arrival order).
2. **Determinism** — identical input produces an identical `projectionHash`.

### 5.2 MESH-21 and MESH-22 reported correct code as an attack surface

Both scanners cried wolf, which is worse than silence because it trains the reader to ignore them.
Three distinct false positives, each diagnosed against the real source rather than silenced:

| False positive | Cause | Fix |
|:--|:--|:--|
| `grant_authority: "ROUTE_NOT_AUTHORIZATION"` flagged as `authority=` | no word boundary, so `grant_authority:` matched as `authority:` | anchored lookbehind `(?<![A-Za-z_0-9])` |
| `authorization=admission/authorization stay 'none'` | matched explanatory **prose** inside a string literal | anchored on a quoted literal / a call paren |
| `authorization: routeDecision.authorization` | flagged 27E **propagating** an already-pinned value out of the frozen 27A decision — composition, not minting | scan for **chosen literals** only |

A fourth was mine alone: `originFixed: true` was expected to be `false`. It is the **opposite**
polarity — `originFixed: true` *is* the pin that stops a forwarder posing as the origin — so the
scanner now asserts it is never `false`.

**Both scanners now carry self-tests.** MESH-21 and MESH-22 assert that a synthetic violation is
still caught **and** that correct code is not flagged. "No offenders" can no longer be reached by
quietly weakening a regex.

---

## 6. The evidence artifact

`docs/release/PHASE27_SECURITY_EVIDENCE.json`, schema `menog-phase27-adversarial-evidence/v0`,
emitted by the suite itself on every run.

**It is published ATOMICALLY** (temp-file → fsync → rename, per PRE27-R1 / D-26-2), and the test
asserts `published === true` and `partialWriteExposed === false`.

Recorded alongside: the Phase-26 suite writes the *same kind of* artifact with a bare
`writeFileSync` — the very non-atomic pattern that was D-26-2. 27I does not reproduce that pattern.
Whether to bring 26G's writer in line is left to 27K / a later gate; it is not repaired here.

---

## 7. Non-claims (binding)

27I validates a mesh layer. It does **not** claim: that the mesh is complete · that 27J's
multi-node scenario has run (it has not) · that Phase 27 is frozen · that two-machine LAN behaviour
is qualified (**D-26-1 remains `UNSUPPORTED_ON_CURRENT_TARGET`** and is never a validation claim) ·
that any attack surface was exhausted · that 0 FAIL means the mesh is unattackable — it means these
26 specific attacks did not succeed · power-loss, controller-cache, kernel-panic or
filesystem-corruption integrity · DDoS, WAN, production-capacity or Internet exposure · consensus,
global ordering, gossip membership or NAT traversal, none of which is implemented or claimed.

Every attack was in-process against pure exported functions. **No network, no deployment, no
execution.** Any real execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the
assigned actor + Phase-20 isolation + the Phase-21 governed tool runtime — none of which the mesh
touches, and none of which 27I reaches.

Commit / push / tag / remote mutation / publication remain **NOT GRANTED**.