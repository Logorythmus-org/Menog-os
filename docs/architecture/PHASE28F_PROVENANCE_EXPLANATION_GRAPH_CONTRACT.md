# PHASE 28F — PROVENANCE & EXPLANATION GRAPH CONTRACT

**Gate:** 28F
**Mode:** DESIGN-FIRST / LOCAL-ONLY / READ-ONLY / NO GIT / NO PUBLICATION
**Schema version:** `menog-getig-explain/v0`
**Mother invariant:** VISIBLE WORLD IS A PROJECTION OF EVIDENCE, NOT A SOURCE OF TRUTH OR AUTHORITY.
**Short law:** VISIBILITY != AUTHORITY. PROVENANCE IS METADATA ONLY.

---

## 1. Scope

28F answers one question about a visible object: **"why am I seeing this?"**

It produces a bounded, deterministic, cycle-safe explanation graph over an
existing 28A frame. It creates no runtime object, opens no capability, and
returns nothing that can be acted upon. An explanation is a reading aid, not a
grant.

28F is a pure projection step downstream of 28A (`buildGetigFrame`) and it
consumes only the frame it is given. It never re-reads runtime state, never
resolves provenance itself, and never asks whether the world agrees.

### Non-goals — 28F does NOT

- call Policy, tools, isolation, peer administration, or network admission
- spawn, persist, mutate, or control anything
- reach the network, discover peers, traverse NAT, or join any consensus
- introduce WebGPU or any renderer dependency (Phase 29 owns WebGPU)
- create a workspace package (adding one would mutate `pnpm-lock.yaml`)

---

## 2. Artifacts

All figures measured on disk after the fixes recorded in §10.

| Artifact | Bytes | Lines | sha256 (first 16) |
|---|---|---|---|
| `packages/durable-state/src/getigProvenance.ts` | 27,169 | 647 | `4f250a8aeaa797e3` |
| `packages/durable-state/src/index.ts` (barrel; 28F export at line 342) | 22,072 | 356 | `5aad5f4aa9693f85` |
| `tests/unit/getig-provenance.test.ts` | 30,376 | 637 | `50476d9fd1d2a3fe` |
| `scripts/phase28f-smoke.mjs` | 13,215 | 223 | `755597d006ca71a7` |

Suite: **55 tests** across **10 `describe` blocks**. Probe: **37 checks**, all
driving the real code path.

All Phase-28 code lives in new modules inside `packages/durable-state/src/`
plus one `export *` line in the barrel. No dependency, lockfile or workspace
change.

---

## 3. Public surface

### Functions

| Export | Purpose |
|---|---|
| `buildGetigExplanationGraph(input)` | Build the bounded explanation graph for one frame. Returns `ok: false` + a refusal code, or a frozen `GetigExplanationGraph`. |
| `explainGetigSubject(graph, subjectVisibleId)` | Walk the graph breadth-first and answer "why is this subject visible?" Returns a bounded, cycle-safe `SubjectExplanation`. |
| `refuseProvenanceAsTrust(refId, request?)` | The trust guard. It cannot succeed under any input. |

`refuseProvenanceAsTrust` exists so that "provenance is not trust" is a
**testable property of the surface**, not a property of absence. It returns
`ok: false`, `refusal: "refused_trust_not_granted"`, `confersTrust: false`,
`confersAuthority: false`, `authorizesExecution: false` — for a valid id, an
empty id, a nonsense id, and `null`.

### Constants

| Constant | Value |
|---|---|
| `GETIG_GRAPH_SCHEMA_VERSION` | `"menog-getig-explain/v0"` |
| `GETIG_GRAPH_BOUNDS` | `{ maxNodes: 4096, maxEdges: 8192, maxExplainDepth: 8, maxExplainNodes: 128, maxIdChars: 128 }` |
| `GETIG_EXPLANATION_NODE_KINDS` | `subject, observer, frame, provenance_ref, route_role, lifecycle_fact, freshness_fact, conflict_attribution, unknown` |
| `GETIG_EXPLANATION_RELATIONS` | `observed_by, projected_in, has_provenance_ref, provenance_missing, has_role, attributed_to, has_lifecycle_fact, has_freshness_fact` |
| `GETIG_EXPLANATION_ROLES` | `none, origin, forwarder, destination` |
| `GETIG_FORBIDDEN_CONTENT_FIELDS` | 22 names (see §5) |
| `GETIG_GRAPH_REFUSAL_CODES` | 8 codes (see §6) |

---

## 4. The graph

`GetigExplanationGraph` carries these **structural** fields, which are not
defaults but part of the type:

```
explainsWhy: true
authorizes: false
cycleSafe: true
bounded: true
readOnly: true
authority: "none"
```

Every `ExplanationNode` carries `isEvidenceContent: false`, `confersTrust:
false`, `confersAuthority: false`, `authority: "none"`. Every `ExplanationEdge`
carries `confersTrust: false`, `confersAuthority: false`. These are asserted
across **every node and every edge** for a real built graph, not on a sample.

Because `authorizes` is typed `false` rather than `boolean`, no caller can
construct a graph that explains and authorises.

---

## 5. Disclosure is secret-safe

`GETIG_FORBIDDEN_CONTENT_FIELDS` holds 22 names covering content, raw text,
tool output, secrets, credentials, paths, hidden Policy text and store content:

```
content, raw, rawtext, text, body, payload, prompt, tooloutput,
secret, privatekey, apikey, token, password, credential,
path, filepath, privatepath, policytext, memorycontent, storecontent,
blob, data
```

Matching **normalises** the name first — lowercase, strip every non-alphanumeric
character — so `raw_text`, `rawText`, `RAW-TEXT` and `raw text` all match, and
so `private-key` matches `privateKey`. Two self-tests prove the matcher works:
one normalises a planted name and asserts it is caught, and one reads the emitted
`.d.ts` off disk and asserts that **no declared field in the public surface** is
able to hold content.

A frame or provenance record carrying a forbidden field is **refused**, not
sanitised. Fail closed — a value that cannot be safely represented is never
silently dropped and quietly represented as absent.

---

## 6. Failure behaviours

All 8 declared refusal codes are reachable, and the probe drives each one:

| Code | Cause |
|---|---|
| `refused_graph_frame_invalid` | no usable frame |
| `refused_graph_provenance_record_invalid` | malformed provenance record |
| `refused_graph_provenance_content_present` | forbidden content field present |
| `refused_graph_role_substitution` | a route lists its own origin as a forwarder |
| `refused_graph_bounds_exceeded` | node/edge budget exceeded |
| `refused_explain_not_a_graph` | explain called on a non-graph |
| `refused_explain_subject_unknown` | subject absent, missing, or over-long |
| `refused_trust_not_granted` | any request to turn provenance into trust |

### Missing provenance stays missing

An entity visible with **no** provenance reference produces an explicit `unknown`
node, a `provenance_missing` edge, and an entry in `graph.unknownProvenanceSubjects`.
It is never fabricated, never back-filled, and never quietly omitted.

### Forwarder is never origin

`route_role` nodes carry their role explicitly, and no forwarder edge is ever
labelled `origin`. A route that lists its own origin among its forwarders is
**refused** with `refused_graph_role_substitution` rather than accepted with a
silently dropped entry.

---

## 7. Bounds and cycle safety

Traversal is breadth-first with an explicit visited set and hard caps at
`maxExplainDepth` (8) and `maxExplainNodes` (128).

**The hop budget is enforced per expansion, not only between queue items.** A
single node may carry more outgoing edges than the entire budget, so the check
lives inside the inner edge loop as well as at the top of the queue loop. This is
the property that was silently violated before this gate's repairs; see §10.

Verified against:

- a genuinely cyclic three-edge graph → terminates, `cycleBroken: true`
- a 5,000-edge self-loop storm on one node → terminates at exactly **128 hops**,
  `boundedStop: true`
- a 500-node deep chain → terminates, `boundedStop: true`

A cycle is reported as broken. The walk never pretends it completed.

---

## 8. Determinism

- Collections are sorted with **code-unit comparison**, never `localeCompare`,
  so canonical output does not depend on host locale.
- `canonicalDurableJson` sorts object keys and preserves array order; 28F
  therefore sorts every collection it emits before hashing.
- `graphHash` is stable across runs and across differing input key order.

**One subject, one answer.** The graph is keyed by collection
(`entities:n1`), but the trace speaks the **visible-world** id (`n1`).
`entities:n1` and `n1` name the same subject and produce a byte-identical trace —
otherwise the answer to "why is this visible?" would depend on how the caller
spelled the query. `questionAnswered` is derived from the canonical id for the
same reason. An unqualified node key reports `subjectCollection:
"unqualified"` rather than losing a character to a string slice.

---

## 9. Renderer neutrality

28F is pure data. It imports no renderer, no WebGPU, no Three.js/PlayCanvas/
Babylon/Unity/Unreal, and contains no geometry, no draw call, and no animation.
A renderer may simplify the graph's presentation, but may never strengthen a
semantic claim it depicts: a node that confers nothing cannot be drawn as though
it granted.

---

## 10. Repairs made at this gate

The gate did not pass on first execution. Five defects were found and fixed;
three were in the 28F module itself and two were in the test harness.

| # | Defect | Where | Fix |
|---|---|---|---|
| 1 | Stray `}` in a `built(...)` call → `TS1005`/`TS1128`; the suite never compiled and `vitest` collected **no tests at all** | test L329 | removed the brace |
| 2 | `ent()` helper under-typed (`provenanceRefs: [] as unknown[]`) → 3 × `TS2322` on the 28A integration path | test | typed as `(id, over: Partial<VisibleEntity>): VisibleEntity` |
| 3 | **Hop budget not enforced per expansion.** One node with 5,000 outgoing edges produced `hopCount: 5000` against a budget of 128 — `maxExplainNodes` was a claim the code did not keep | module | cap moved inside the inner edge loop; sets `boundedStop` |
| 4 | **Trace echoed the caller's spelling.** `entities:n1` yielded `subjectVisibleId: "entities:n1"`, so one question got two different answers | module | canonicalised to the bare visible id; `questionAnswered` derives from it |
| 5 | `subjectCollection` used an unguarded `indexOf(":")`; an unqualified key `solo` would have produced `"sol"` | module | explicit `unqualified` case |

Defects 3–5 are the **same failure pattern** recorded at 28C, 28D and 28E: a
guarantee stated in the contract and in the probe, but never actually asserted.
The 35-check probe asserted only that the storm *terminated* — not that it
remained bounded — which is precisely how defect 3 shipped. The probe now
asserts the hop budget and the trace-identity property directly, and the suite
gained a dedicated `unqualified` collection test. Both new assertions fail
against the pre-fix module.

---

## 11. Debt carried unchanged

- **D-26-1** — physical two-machine LAN never executed. Open.
- **D-26-2**, **D-26-3**, **D-26-4** — inherited Phase-20–26 debt. Open.
- 28F inherits no new debt and closes none of the above.

---

## 12. Governance

Commit / push / tag / remote mutation / publication: **NOT GRANTED**, unchanged.
Repository state at gate exit: 0 commits, 0 staged, 0 remotes, 0 tags, 0 stash,
39 untracked top-level entries. `pnpm-lock.yaml` (36,919 B) and `package.json`
(767 B) are byte-identical to the PRE28-R0 baseline. Zero new dependencies:
0 runtime dependencies, 4 devDependencies.