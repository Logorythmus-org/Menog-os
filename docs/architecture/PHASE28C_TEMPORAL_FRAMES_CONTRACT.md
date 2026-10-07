# PHASE 28C — Temporal Frames & Runtime Timeline Contract

Gate: 28C · Verdict: **28C_PASS**
Mode: VISUAL HISTORY ONLY / LOCAL-ONLY / READ-ONLY / DESIGN-FIRST / NO GIT / NO PUBLICATION
Schema version: `menog-getig-temporal/v0`
Mother invariant: VISIBLE WORLD IS A PROJECTION OF EVIDENCE, NOT A SOURCE OF TRUTH OR AUTHORITY.
Central law: **VISUAL_REPLAY != EXECUTABLE_REPLAY.**

Source: `packages/durable-state/src/getigTemporalFrames.ts` (26,540 B · 649 L · `b5ebc6c9d1dae259`)
Tests: `tests/unit/getig-temporal-frames.test.ts` (81 tests · 43,724 B · 925 L · `853c281095fe66c2`)

---

## 1. What this gate does

Two pure functions and one that can only refuse.

| Export | Purpose |
|---|---|
| `buildGetigFrameSequence(input)` | Assembles an immutable, bounded, deterministic sequence of frame references. |
| `diffGetigFrames(from, to)` | Computes a deterministic semantic diff between two frames. |
| `refuseResumeFromFrame(frameId, asOfEpochMs)` | The ONLY navigation-adjacent export. It cannot succeed under any input. |

Nothing else. There is no writer, no store, no control path, and no mechanism by which this module could restore, rewind or re-enter runtime state — which is why the resume law can be enforced by making it *unrepresentable* rather than merely guarded.

## 2. The three identities — and why they are never collapsed

| Identity | Names | Changes when |
|---|---|---|
| `sourceProjectionHash` | the upstream evidence a frame was derived from | the evidence changes |
| `canonicalVisibleHash` | what that one frame shows | the visible content changes |
| `sequenceIdentity` | the ordered SET of frame references | the membership or the supplied order changes |

Collapsing any two of them destroys a capability a later gate needs. Two different evidence projections can yield the same visible content; two different ordered sets can point at different evidence; and the sequence is a third thing that is neither of its parts. A timeline that cannot tell them apart cannot say *which one* changed.

This is enforced three ways:

- the sequence builder never substitutes one hash for another, and `sequenceIdentity` is a hash over **references only** — never over frame content;
- a diff reports the frames' own two identities by their own names, and the suite asserts that `fromSequenceIdentity` / `toSequenceIdentity` do **not** exist on `SemanticDiff`. (An earlier draft of this gate used those field names for visible hashes. That conflated identities 2 and 3 and was corrected before the suite was written.)
- a test asserts the three values are pairwise distinct, and a second test with eight frames asserts the sequence identity equals *none* of them.

## 3. No global distributed-time claim

There is no clock. A sequence declares an explicit ordering basis and nothing else:

| Basis | Meaning |
|---|---|
| `observed_order` | The observer declares this is the order it saw. The sequence records that as **the observer's claim**, not as a fact. |
| `unknown` | No ordering could be established, so none is asserted. |

Three decisions follow, and each is tested:

1. **Positions are as-supplied, never re-sorted.** A sort would manufacture a chronology the module has no evidence for. The suite feeds frames in deliberately anti-chronological order and asserts positions survive intact — including that `entries[0].asOfEpochMs > entries[1].asOfEpochMs`.
2. **`temporalOrderEstablished: false` is sequence-wide, not per-entry.** When the basis is `unknown`, *every* entry says `false`. An unknown order is unknown for the whole timeline.
3. **A reordering is a different sequence, not a corrected one.** Same frames, same observer, same epoch, different supplied order ⇒ different `sequenceIdentity`. The gate does not tidy the caller's input.

Times are still echoed per entry as `asOfEpochMs` — the observer's own instant, carried as metadata.

## 4. Causality is never invented

A diff records **what** differs and nothing about **why**. `GETIG_FORBIDDEN_DIFF_FIELDS` names ten fields that would turn an observation into a claim:

`cause`, `causedBy`, `because`, `reason`, `triggeredBy`, `explains`, `causalChain`, `rootCause`, `blame`, `responsibleFor`

The suite walks a **rich real diff** looking for any of them at any depth, and reports which one appeared if any does. A companion test plants each of them synthetically and asserts the walk catches them — because a scan that cannot fail is a scan that reports PASS while matching nothing.

`SemanticDiff.causalityClaimed` is a structural `false`, not a value a caller can set.

## 5. Classification — and the rule that keeps "identical" honest

Six classes, closed: `added`, `removed`, `changed`, `stale`, `unknown`, `conflicted`.

The subtle part is **when** a state class is reported. The naive rule — "report `stale` if the subject is stale" — is a lie: an entity that is stale in *both* frames has not changed, and reporting it would make two byte-identical frames differ.

The rule this gate uses:

> A state class (`stale` / `unknown` / `conflicted`) is reported when the subject **appeared or disappeared** — recording the state it arrives in or leaves in — or when that state **moved** between the two frames. Otherwise it is not a difference and is not reported.

Two further distinctions:

- **Absent is not unknown.** A member that declares no `freshness` field is not classified `unknown`. Only an explicitly declared `unknown` is. Forcing the former would classify every relation — which has no freshness field in the 28A shape — as unknown on sight.
- **An unusable time is an unknown time.** An event with no numeric `atEpochMs` is classified `unknown`. Unknown stays unknown.

Subjects are keyed by `(collection, id)`, not by id alone, so a relation and an entity sharing an id string remain two subjects. The suite covers exactly that collision.

## 6. Historical navigation never restores runtime state

`refuseResumeFromFrame()` returns `refused_resume_not_permitted` for every input tested, including a real frame id, an empty string, `NaN`, a path-shaped string and `null`. Its result carries `restoredRuntimeState: false` and `resumedRuntimeState: false` structurally, and its explanation names the law.

The suite additionally parses the emitted `.d.ts` and asserts no export matches a mutating/executing name — a check that would catch a future `restoreFromFrame` or `applyPolicy` being added beside it.

## 7. Stable visible identity is never authority

Every `FrameSequenceEntry` carries `authority: "none"`, whatever the frame id — the suite uses a frame id of `"system-privileged-handle"` specifically to prove the label confers nothing. Sequence-level zeros: `replaySemantics: "visual_history_not_executable"`, `restoresRuntimeState: false`, `resumesRuntimeState: false`, `controlPlane: false`, `readOnly: true`, `globalTruth: false`.

## 8. Bounded retention and fail-closed limits

| Bound | Value |
|---|---|
| `maxFramesPerSequence` | 128 |
| `maxDiffEntries` | 512 |
| `maxIdChars` | 128 |

The suite accepts a sequence exactly at 128 and refuses 129. Refusals return `sequence: null` / `diff: null` — no partial timeline escapes, because a partially-valid sequence is itself a claim about order.

## 9. Refusals — all ten reachable

Every code in `GETIG_TEMPORAL_REFUSAL_CODES` is driven by a real input and asserted to be the code that came back. A declared code that no input could produce is worse than no code, so the suite fails if any becomes unreachable.

| Code | Raised by |
|---|---|
| `refused_sequence_invalid_input` | non-object input, missing/over-long id, non-array frames |
| `refused_sequence_frame_not_a_frame` | non-object frame, missing id/time/hash, non-hex64 hash |
| `refused_sequence_duplicate_frame` | the same `frameId` appearing twice |
| `refused_sequence_frame_epoch_mismatch` | a frame from another epoch |
| `refused_sequence_frame_observer_mismatch` | a frame observed by another observer |
| `refused_sequence_retention_bound` | over-length sequence, over-length diff |
| `refused_sequence_unknown_ordering_basis` | a basis outside the closed two |
| `refused_diff_input_invalid` | non-object input, missing `frameId` |
| `refused_diff_not_a_sequence` | a sequence supplied where a frame is required |
| `refused_resume_not_permitted` | any resume attempt |

Two ordering decisions are deliberate and tested:

- **Epoch is checked before observer.** A frame from another epoch is not this sequence's frame at all, before any vantage-point question is asked.
- **Sequence detection precedes the `frameId` check.** A sequence has no `frameId`, so testing `frameId` first would report a generic "invalid input" for a specific, recoverable caller mistake. The suite feeds a real sequence and asserts it gets `refused_diff_not_a_sequence`.

## 10. Separation laws and renderer neutrality

The module imports exactly one thing: `canonicalHash` from `./canonical.js`. No Policy, no tools, no isolation, no peer administration, no network admission, no process control, no `node:fs`, no `child_process`, no WebGPU, no Three.js, no renderer of any kind. A suite audit scans the source for 17 capability tokens using word-boundary matching for identifiers — plain substring matching was tried first and flagged the English word "three" in this gate's own prose, which is the kind of audit people learn to ignore. The audit carries a self-test that plants each token and proves detection.

Ordering inside `diffGetigFrames` uses code-unit comparison, never `localeCompare`: a locale-dependent ordering would make the sequence identity machine-dependent.

## 11. Non-claims

- This gate does not render anything. WebGPU and all rendering belong to Phase 29.
- It does not establish time, synchronise clocks, or reconcile observers.
- It does not resolve conflicts, pick a winner, or drop a losing claim.
- It does not restore, resume, replay or recover any runtime state.
- It does not call Policy, allocate, or grant authority.
- It does not add a dependency; the lockfile is byte-identical.

## 12. Debt

None new. Carried forward unchanged: D-26-1, D-26-2, D-26-3, D-26-4.

## 13. Defects found and corrected during this gate

Recorded because the corrections are the evidence, not the prose:

1. **`entries.length = -1` sentinel** — the first draft forced a refusal by assigning a negative array length, which throws `RangeError` at runtime rather than refusing. Replaced with a single loop returning one code per failure mode.
2. **Three declared refusal codes were unreachable** — `..._duplicate_frame`, `..._observer_mismatch` and `..._epoch_mismatch` existed in the vocabulary but no input could produce them. Every failure mode now maps to its own code.
3. **Identity conflation in the diff** — `fromSequenceIdentity` / `toSequenceIdentity` were populated from `canonicalVisibleHash`. Renamed to `fromVisibleHash` / `toVisibleHash`, with the source-projection hashes reported alongside.
4. **A sequence supplied as diff input was refused as "invalid"** — not as the specific mistake it was. The sequence check now runs first.
5. **"Identical" could be false for identical frames** — the naive freshness rule made two frames showing the same stale entity differ. Replaced with the appeared/disappeared-or-moved rule.
6. **Detail counts were wrong** — every structural difference incremented `entities` regardless of collection. Replaced with an explicit `subjectCollection` per entry.
7. **Entries were not individually frozen** — a frozen array of mutable objects is not an immutable history.
8. **Three stray NUL bytes** in the source file, from an escaped separator written literally. Removed; the subject key is now JSON-encoded, so it is unambiguous and the file is plain text again.
9. **The capability audit flagged the word "three"** in prose. Fixed with word-boundary matching plus a false-positive test.

Items 1, 2, 3, 5 and 7 were real behavioural defects. Items 4, 6, 8 and 9 were found by the checks built to catch them — which is the only reason they are listed rather than shipped.