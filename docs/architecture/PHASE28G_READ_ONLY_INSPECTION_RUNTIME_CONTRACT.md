# PHASE 28G CONTRACT — READ-ONLY INSPECTION RUNTIME

**Gate:** 28G · **Mode:** INSPECTION ONLY / NO CONTROL PLANE
**Module:** `packages/durable-state/src/getigInspectionRuntime.ts`
**Schema:** `menog-getig-inspection/v0`

---

## 1. Central laws

```
INSPECTION != CONTROL
SELECTION  != PERMISSION
FILTERED   != COMPLETE
PICKING    != EXECUTION
QUERY      != MUTATION
```

An inspection runtime is the most privileged-looking thing in a system that
still has no privileges. It sees everything and can do nothing. This contract
exists because that gap is easy to state and easy to erode: one convenience
method, one "temporary" flag, one helper that writes a cache, and the read-only
runtime becomes the control plane wearing a costume.

## 2. Why the read-only property is structural, not enforced

The usual approach is a permission check at each call site. That is the wrong
shape: a check that can be forgotten is a hole, and a property that depends on
every future edit has not been established, only asserted.

So this module has **no mutating operation to disable**. There is no `execute`,
`approve`, `admit`, `quarantine`, `retire`, `grant`, `resume`, setter, or
mutator anywhere on any exported type. Read-only-ness is a property of the API's
shape, not of its runtime behaviour.

`INSPECTION_FORBIDDEN_ACTIONS` declares the prompt's forbidden list so a scanner
can *prove* the absence rather than take it on trust. The test suite scans the
module source for `function <forbiddenAction>` and `export const <forbiddenAction>`
declarations, and asserts no `set`/`update`/`remove`/`commit`/`apply`/`persist`/
`write` method exists on any result type.

One export deliberately contains a forbidden word: `refuseInspectionAsControl`.
It is the refusal itself, and it cannot succeed under any input. It exists so a
reader can see the refusal was deliberate and reachable — the same reasoning 28E
used for `refuseGlobalTruthSynthesis`.

## 3. Allowed surface

Nine closed query kinds, nine closed operations:

| Kind | Operation | Reads |
|---|---|---|
| `select` | `select` | 28E view |
| `inspect` | `inspect` | 28E view |
| `filter` | `filter` | 28E view |
| `focus` | `focus` | 28E view |
| `expand_collapse` | `expand_collapse` | 28E view |
| `timeline_navigate` | `timeline_navigate` | 28C sequence |
| `compare_views` | `compare_views` | 28E view |
| `trace_provenance` | `trace_provenance` | 28F graph |
| `enumerate_refusals` | `enumerate_refusals_conflicts` | 28E view |

The vocabularies are closed and exported. Adding a member is a governance-visible
act, not an incidental edit.

## 4. Filtered results are a different type

The most dangerous property an inspection tool can have is a filter that makes a
partial world look whole. Someone filters to one subject and reads the answer as
"this is what the system contains."

So a filtered result is **not** a smaller `GetigObserverView`. It is
`FilteredInspection`, a distinct type carrying required literals:

```ts
readonly isFiltered: true;
readonly isComplete: false;
readonly excludedCount: number;   // quantified, not merely implied
readonly canonicalViewAltered: false;
```

There is no code path producing a filtered result without those markers. An
unknown `filterBase` is **refused, never ignored** — a predicate the runtime
cannot evaluate would otherwise silently return an unfiltered set that looks
like a filtered one.

## 5. Binding: every result names its frame, observer and hash

An unbound result could be carried next to a frame it does not describe. All
three are mandatory; a mismatch against the frozen input is a **refusal**, not a
relabelling.

```ts
interface InspectionBinding {
  readonly frameId: string;
  readonly observerId: string;
  readonly canonicalVisibleHash: string;
  readonly viewHash: string;
}
```

Each absent field reports its **own** refusal code, so a caller learns which
field was missing rather than that "something in the binding" was.

## 6. Selection confers nothing

`InspectionSelection` carries structural literals — not fields to set:

```ts
readonly authority: "none";
readonly confersPermission: false;
readonly isExecution: false;
readonly grantsNothing: true;
```

Selecting a tool does not permit it. Highlighting a subject does not approve it.
`select` and `focus` require a subject; `inspect` and `compare_views` do not,
because describing a whole view is the natural reading of those verbs.

A mutation attempt riding on a selection gets its own refusal code
(`refused_selection_mutation_attempt`), distinct from a generic malformed query —
selecting something and asking to change it is the exact conflation this gate
refuses, so it is not folded into a generic bucket.

## 7. Timeline navigation is not resumption

`timeline_navigate` consumes a `GetigFrameSequence` whose own
`replaySemantics` is `visual_history_not_executable`, and refuses a sequence that
does not declare it. Output carries `resumesRuntimeState: false` and
`restoresRuntimeState: false`.

When the ordering basis is absent, the result reports
`temporalOrderEstablished: false` — an honest "no chronology claimed" rather than
an implied order.

## 8. Provenance explains and never authorises

Tracing delegates to the frozen 28F graph shape and is cycle-safe: a node already
seen is not re-entered. Every hop carries `confersTrust: false` and
`confersAuthority: false`; the result carries `authorizes: false`. Traversal
stops at `maxTracedHops` and reports `boundedStop: true` rather than running
away.

## 9. Bounds fail closed

| Bound | Value |
|---|---|
| `maxSubjectsPerQuery` | 2 048 |
| `maxTracedHops` | 256 |
| `maxResultLimit` | 2 048 |
| `minResultLimit` | 1 |

An oversized view is **refused** (`refused_bounds_exceeded`), not truncated. A
truncated inspection that looked complete would be the exact lie this module
exists to prevent. An out-of-range `limit` is refused rather than clamped, for
the same reason: clamping returns fewer rows than asked for while looking like a
complete answer.

## 10. No cache, therefore no mutable authority

The prompt forbids a mutable cache becoming authority. This module has **no
cache** — every operation recomputes from the frozen input. The prohibition is
structurally satisfied rather than merely enforced, and identical queries over
identical inputs are byte-identical.

## 11. Invariants

Every successful decision reports `authority: "none"`, `readOnly: true`,
`mutatedCanonicalState: false`. Every result echoes its binding. Every one of the
15 refusal codes is reachable from a real input, and a test asserts it.

## 12. What this contract does NOT establish

- No GUI. 28G is a query surface; drawing is 29+.
- No adversarial suite of its own (28I's job).
- No claim that inspection is safe for a human to act on. It confers nothing, so
  acting on it requires the same fresh authority as any other path.
