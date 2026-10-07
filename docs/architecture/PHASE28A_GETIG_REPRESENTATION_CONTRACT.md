# PHASE 28A — GETIG Representation Contract

**Gate:** `28A` — GETIG Representation Contract (the first Phase-28 gate)
**Entry:** `PRE28_R0_READY` (Phase 27 verified frozen on disk; 66/66 pinned artifacts byte-identical)
**Mother invariant:** VISIBLE WORLD IS A PROJECTION OF EVIDENCE, NOT A SOURCE OF TRUTH OR AUTHORITY.
**Short law:** VISIBILITY != AUTHORITY.
**Mode:** CONTRACT-FIRST / RENDERER-NEUTRAL / READ-ONLY
**Verdict:** `28A_PASS`

---

## 1. What this gate is

Every later Phase-28 gate links to something. 28A is what they link to: the closed set of shapes a
visible world may take, and the one pure function that assembles them.

**Source:** `packages/durable-state/src/getigRepresentation.ts` (35,637 B)
**Tests:** `tests/unit/getig-representation.test.ts` — **62 tests**

The contract is deliberately small and deliberately inert. It is the floor everything else stands on,
so it is built to be *unable* to do the wrong thing rather than merely instructed not to.

---

## 2. The decision that shaped the file: new module, not new package

The obvious home for a GETIG foundation is a new workspace package. That would have **changed
`pnpm-lock.yaml`** — the lockfile lists every workspace importer (`packages/durable-state:`,
`apps/cli:`, …), and every gate since Phase 26 has verified it **byte-identical** at
`bd289ce7ad6d0d8c`.

So 28A adds a **new module inside `packages/durable-state/src/`** and one line to `index.ts`. Same
pattern 27A–27H used for the mesh stack. Cost: **0 dependencies, 0 lockfile bytes.**

---

## 3. The seven pinned laws are TYPES, not comments

Every law the prompt pins is a literal in a closed type. A caller cannot widen one without a
compile error — which is a stronger guarantee than a documented convention, and a stronger one than a
runtime check that someone can forget to call.

| Law | How it is pinned |
|:--|:--|
| visible entity != runtime entity | `VisibleEntity.isRuntimeObject: false` |
| relation != trust | `VisibleRelation.trust: "none"` |
| visual route != authorization | `VisibleRoute.admission/authorization: "none"`, `executionAuthorized: false` |
| visible capability claim != grant | `VisibleEntity.grant: "none"` |
| visible event != executable action | `VisibleEvent.executable: false`, `action: "none"` |
| visual replay != runtime replay | `GetigFrame.replaySemantics: "visual_only_not_executable"` |
| observer view != global truth | `GetigFrame.globalTruth: false`, `VisibleObserverContext.isGlobalTruth: false` |

Plus **VISUALIZATION != CONTROL PLANE**: `authority: "none"`, `controlPlane: false`,
`readOnly: true`, `visibleCapabilities: readonly []`.

`GETIG_STRUCTURAL_ZERO_FIELDS` names all eighteen of these in one exported, frozen map so a later gate
can *assert* them instead of re-deriving the list.

---

## 4. The ten closed contracts

`GetigFrame`, `VisibleEntity`, `VisibleRelation`, `VisibleEvent`, `VisibleConflict`,
`VisibleRefusal`, `VisibleRoute`, `VisibleProposalFlow`, `VisibleProvenanceRef`,
`VisibleObserverContext` — all exported, all `readonly`.

Both facts are audited against the **emitted `.d.ts`**, not against intent: three tests confirm all
ten are exported, confirm **all 81 members across them are `readonly`**, and carry a self-test proving
the reader detects a deliberately mutable member. The reader **fails loudly** when it cannot parse a
body — because a green result that examined nothing is worse than no result.

The prompt's required coverage is met by a **closed 13-kind entity vocabulary**, every member of which
is proven to build: `runtime_node`, `agent`, `goal`, `task`, `tool_reference`, `memory_reference`,
`policy_gate`, `execution_boundary`, `proposal`, `route`, `evidence`, `refusal`, `partition`.

---

## 5. The frame binds two DISTINCT hashes

```ts
sourceProjectionHash: string   // where the view came from (upstream evidence projection)
canonicalVisibleHash: string   // what is being shown (this frame's own content)
```

They are separate fields **on purpose**. Collapsing them would make *"the evidence changed"* and
*"the view changed"* indistinguishable — and a later gate cannot honestly diff two observer views
without that distinction. The upstream hash is carried **verbatim, never recomputed**; the canonical
hash is computed from the assembled frame through the frozen Phase-20 canonical hasher.

Determinism is **verified, not assumed**: the builder recomputes the hash and refuses
`refused_non_deterministic_hash` if it does not reproduce.

---

## 6. Fail-closed is the default, and it has teeth

Unknown vocabulary **refuses** — never defaults, never coerces, never drops. Verified independently of
the suite, each of these produces its own distinct code:

| Input | Refusal |
|:--|:--|
| unknown entity kind | `refused_unknown_entity_kind` |
| unknown freshness | `refused_unknown_freshness` |
| unknown lifecycle | `refused_unknown_lifecycle_state` |
| unknown relation kind | `refused_unknown_relation_kind` |
| unknown event kind | `refused_unknown_event_kind` |
| unknown conflict kind | `refused_unknown_conflict_kind` |
| authority-shaped field present | `refused_unknown_authority_claim` |
| structural zero violated | `refused_unknown_authority_claim` |
| missing / malformed `sourceProjectionHash` | `refused_missing_projection_hash` |
| duplicate visible id | `refused_duplicate_visible_id` |
| collection over its bound | `refused_collection_bound` |

**A refusal exposes no partial world at all** — no `frame` key, no collections. A half-built visible
world is worse than none, because a renderer would draw what it got.

`unknown` is a real, buildable value for freshness and lifecycle. That is the point: **unknown stays
unknown.** A refused fact is not silently upgraded to `current`.

---

## 7. Law 8 — no raw or sensitive content, enforced two ways

`GETIG_FORBIDDEN_CLAIM_FIELDS` refuses these on **mere presence, whatever the value**:
`policy`, `policyDecision`, `hiddenPolicy`, `toolCall`, `toolResult`, `toolOutput`, `rawPrompt`,
`prompt`, `transcript`, `memoryContent`, `storeContent`, `secret`, `privateKey`, `credential`,
`env`, `environment`, `localPath`, `invoke`, `execute`, `allocate`, `escalate`, `override`, `sudo`,
`permission`, `capability`, `capabilities`, `consent`, `approved`.

The walk is depth-bounded (12) so a deeply nested smuggle cannot recurse without limit.

---

## 8. Renderer-neutral, and how that is proven rather than promised

The module imports **only** the frozen canonical hasher. No graphics, no DOM, no GPU, no socket, no
child process, no store.

Four tests assert this by reading the source: no renderer token, no socket/spawn/store token, no
exported function whose name looks like an action API, and the structural zeros all pinned.

**And the scanner is itself tested.** 27I's scanners cried wolf until they gained self-tests proving
they still catch synthetic violations; 28A does not repeat that mistake. A self-test plants a fake
source containing `ctx.getContext("2d")` *inside a comment mentioning WebGPU* and proves the scan
(a) ignores the prose and (b) still sees the code. A scan that passes only because it cannot read
code is not a scan.

---

## 9. Conflicts stay visible and unresolved

`VisibleConflict` carries `attributedToObserverId` and a `claims` list, and is pinned `resolved: false`.
Two observers disagreeing produces **both claims and no winner**. Freshness alone never decides truth,
and this gate has no code path that could pick a side — a later gate that synthesises consensus would
have to add the capability deliberately, which is where it belongs.

---

## 10. Provenance is metadata only (Law 9)

`VisibleProvenanceRef` is a *reference*, never evidence content. Its fields are exactly
`refId`, `recordedAtEpochMs`, `sourceKind`, `evidenceId`, `confersTrust: false` — asserted by
asserting the **key set**, so inlining a record would fail the test.

`evidenceId` may be explicitly `null` for `local_configuration`. **Missing provenance becomes an
explicit unknown, never fabricated** — the same rule 27B enforces on the mesh side.

---

## 11. What 28A does NOT claim

It does not claim any renderer exists (there is none — WebGPU is Phase 29), that any runtime entity
was read, that any frame was produced from real runtime state, that the observer-relative law is
implemented (28B/28E own it), or that Phase 28 is anything but begun.

It is a **contract and a constructor**, nothing more. A contract that could be talked into acting
would not be a contract.

---

## 12. Debt

None created. All four carried debts are unchanged and remain **non-blocking**: D-26-1 (two-machine LAN
never executed), D-26-2 (one non-atomic evidence writer remains), D-26-3 (inherited Phase-20–26), D-26-4
(stale `CURRENT_STATE.md`).

— 28A, 2026-10-03