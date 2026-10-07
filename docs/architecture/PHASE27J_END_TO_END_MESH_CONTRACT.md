# PHASE 27J — End-to-End Multi-Node Mesh Contract

**Gate:** `27J` — End-to-End Multi-Node Mesh Scenario
**Entry:** `27I_PASS` (26 cases, `criticalBypass: false`); `PRE27_R1_PASS`
**Mother invariant:** TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
**Mode:** SCENARIO / TWO OS PROCESSES / REAL SOCKET / LOOPBACK ONLY
**Verdict:** `27J_PASS`

---

## 1. What this gate is

27A–27I each argued and attacked the mesh in isolation. **27J proves the stack COMPOSES** across a
real OS process boundary over a real `127.0.0.1` socket — and that composition produces the one
result the whole phase exists to guarantee:

> **OBSERVER-RELATIVE VIEWS ARE FIRST-CLASS. THERE IS NO GLOBAL TRUTH.**

This gate does **not** re-test the units. Those suites own them. Its single question is: when two
real nodes each build their own world and then hear from each other, do they end up with *the same*
world? **They must not.** If they matched, one of them would be a global truth — which is precisely
the bug this gate hunts.

---

## 2. The scenario

| Step | What happens | Surface used |
|:--|:--|:--|
| 1 | Node **B** binds and listens on an explicit loopback port (41920) | real Phase-26 **26B** `LocalEndpointListener` |
| 2 | **Both** nodes independently open a graph on their own epoch | real **27B** `LocalTopologyGraph` |
| 3 | each records **itself** as `local_node` and its peer as `observed_node` | real 27B, fail-closed provenance |
| 4 | each adds the link edge and snapshots its own graph | real 27B |
| 5 | each plans a route **over its own graph** | real **27E** `planRoute` |
| 6 | each projects **its own** world | real **27H** `buildMeshObservabilitySnapshot` |
| 7 | **A** dials B's real port and sends ONE line of JSON — observations, as DATA | `node:net` + 26B's sanctioned `onConnection` handler |
| 8 | **B** folds what arrived into **its own** view and projects **its own** snapshot | real 27H |
| 9 | the two snapshots are compared — **and must differ** | 27H `projectionHash` |
| 10 | **control**: both nodes re-project under the **same** `snapshotId` — and must **still** differ | 27H `projectionHash` |
| 11 | **control**: each node repeats its own projection from its own vantage — and must **match itself** | 27H `projectionHash` |

No state is shared between the processes. There is no shared store, no shared clock, and no
coordinator. Each side derives everything it knows from its own local facts plus what the wire
carried.

---

## 3. What must remain true after composition

These are the assertions the suite makes, and they are the gate's actual output:

1. **The wire carried real bytes.** B received A's observations through the real listener; A saw B
   acknowledge; the listener stopped cleanly.
2. **Each node's route starts at itself.** A's route begins at `node-a`; B's at `node-b`. Origin is
   never the peer, and never drifts across the boundary.
3. **A planned route is knowledge, never authorization.** On both nodes:
   `admission: "none"`, `authorization: "none"`, `executionAuthorized: false`,
   `transitiveTrust: false`, `capabilityUnion: false`.
4. **The two snapshots DIFFER.** Same wire, same epoch, same instant — different `projectionHash`,
   different `snapshotId`, each naming itself as origin and the other as destination. **Neither is
   a global truth.**
5. **Same-label control — the difference survives removing the label.** Assertion 4 alone is
   *under-determined*: the snapshots also differ in `snapshotId`, and `projectionHash` demonstrably
   folds the id in. So both nodes re-project under one shared id (`shared-id`) — identical epoch,
   instant, wire and label — and the hashes **still differ** (observed: A `166fac21…`, B
   `6f0bd654…`). The only variable left is the vantage, so the vantage is what produces the
   difference. Each still calls itself origin.
6. **Determinism control — the difference is content, not noise.** Each node re-projects the
   **byte-identical** input a second time from the **same** vantage and must reproduce its own first
   hash. Same vantage ⇒ same hash, on both nodes. Without this, assertion 5 could be satisfied by an
   unstable hash, and "observer-relative" would be indistinguishable from "random".
7. **Both snapshots stay read-only with zero authority after the wire** —
   `authority: "none"`, `controlPlane: false`, `readOnly: true`, and **no** key matching
   `action|execute|invoke|grant|admit|authorize|commit|mutate`.
8. **A wire observation changed no authority.** Nothing that arrived carried an `authority`,
   `admission` or `authorization` field, and B invented none.
9. **Roles are separated, not blurred.** 27H flattens the origin (`originNodeId` / `originFixed`)
   and groups `forwarderNodeIds` rather than nesting them.
10. **Nothing reached peer admission, Policy, or a tool.**

---

## 4. Three things this gate got wrong, and corrected

Recorded because a scenario gate that hides its own errors is not a scenario gate.

### 4.1 The first draft produced a `route_refused`

The fixture built nodes with `provenance: { source: "local_configuration", evidenceId: "ev-a" }`.
27B refused it — `refused_invalid_provenance` — because **local configuration must not pretend to
cite an evidence id**. The record was refused, the edge became `refused_dangling_edge`, and
`planRoute` returned `refused_unknown_node`.

This was **not** a bug in 27B. It was the 27B contract working exactly as designed, and the fixture
being wrong. Fixed at the root:

```js
evidenceId: source === "local_configuration" ? null : evidenceId
```

After the fix both nodes plan their routes and both snapshots carry both nodes. **The first draft
silently produced two single-node worlds and a refused route on each** — a scenario that would have
"passed" many weak assertions while proving nothing about composition. The listener also refused
first (`endpoint_unset`) until the config supplied the required `source`, another fail-closed
control the first draft walked into.

### 4.2 The headline claim was true but under-determined

The first version of assertion 4 asserted only that the two `projectionHash` values differ. It is
true — but the two snapshots also carried different `snapshotId`s, and `projectionHash` measurably
folds the id in — measured directly: node A's identical world hashes `c4fd5f7c…` under `snap-A` but
`166fac21…` under `shared-id`. A reviewer could therefore attribute the difference to the **label**
and the gate would have had no rebuttal, even though the observer-relative law was satisfied.

The claim was not defended more loudly; the confound was **removed**. Steps 10 and 11 of §2 exist for
this. The result: a global-truth implementation — one whose hash ignored vantage — now fails both
assertion 4 and assertion 5, and an unstable hash fails assertion 6. The law is now falsifiable
rather than merely asserted, which is the only form in which it is worth anything.

### 4.3 The route assertion assumed the wrong shape

The suite asserted `route.origin.nodeId`, but 27H **flattens** the origin into `originNodeId` /
`originFixed` and groups forwarders. The test failed on `undefined`; the code was right and the
assertion was wrong. Corrected to the real projected shape — which let the test assert something
stronger: that each node's own view names *itself* as origin and the *other* as destination.

---

## 5. Scope honesty

**Loopback only.** No Internet or public endpoint, no discovery, no relay, no NAT traversal, no
consensus, no remote authority, no deployment.

**This is a PROCESS-boundary scenario, not a power-cut one.** No power-loss, controller-cache,
kernel-panic or hardware-failure claim is made or testable here.

**This is NOT the two-machine LAN.** D-26-1 remains `UNSUPPORTED_ON_CURRENT_TARGET` with matrix
M1–M7 `NOT_RUN`. Two processes on one host over loopback is what gate 26H proved, and what 27J
extends to the mesh; it is never a substitute for cross-machine evidence and is never claimed as one.

Commit / push / tag / remote mutation / publication remain **NOT GRANTED**.