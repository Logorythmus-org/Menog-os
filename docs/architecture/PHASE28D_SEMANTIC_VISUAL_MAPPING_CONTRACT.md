# PHASE 28D — Evidence-to-Visual Semantic Mapping Contract

Gate: 28D · Verdict: **28D_PASS**
Mode: SEMANTIC TOKENS ONLY / NO GRAPHICS BACKEND / RENDERER-NEUTRAL / LOCAL-ONLY / READ-ONLY / NO GIT / NO PUBLICATION
Schema version: `menog-getig-visual/v0`
Central law: **GEOMETRIC OR STYLISTIC SIMPLIFICATION MUST NOT STRENGTHEN SEMANTIC CLAIMS.**

Source: `packages/durable-state/src/getigVisualMapping.ts` (33,986 B · 742 L · `c349fd1d1424a8b0`)
Tests: `tests/unit/getig-visual-mapping.test.ts` (78 tests · 43,097 B · 925 L · `633e5562e3d31851`)

---

## 1. What this gate does

Three functions and no graphics whatsoever.

| Export | Purpose |
|---|---|
| `buildGetigVisualMapping(input)` | Turns a 28A frame into renderer-neutral semantic tokens. |
| `planGetigPresentationCoarsening(mapping, request)` | Decides whether a renderer may draw one whole axis the same way. |
| `refuseVisualSelectionToPermission(tokenId, intent)` | The ONLY interaction-adjacent export. It cannot succeed. |

Plus `getigVisualSemanticRank` and `getigVisualPermittedTiers`, which expose the rank arithmetic the other two rely on so a reader can check a decision rather than trust it.

There is no renderer, no colour, no style field, no graphics dependency, and no import beyond `canonicalHash`.

## 2. The central law, made arithmetic instead of advisory

"May simplify, must not strengthen" is one-directional, and it is easy to state and easy to get wrong. The module enforces it in two independent layers.

### Layer 1 — the stronger value does not exist

There is no `trusted` beside `unknown`, no `granted` beside `claim`, no `authorized` beside `planned`, no `admitted_by_inference` beside `not_admitted`, no `global_truth` beside an observer view. A renderer cannot promote a fact to a claim it has no token for.

### Layer 2 — weakening is allowed, strengthening is not computable

Every axis is an ordered list running **weakest claim → strongest claim**, so each value carries a rank:

```
knowledge    unknown(0) < known(1)
freshness    unknown(0) < stale(1) < current(2)
lifecycle    retired(0) < quarantined(1) < observed(2)
grant        grant_none(0) < claim(1)
route_state  unknown(0) < unavailable(1) < planned(2)
admission    not_admitted(0) < admitted_explicit_evidence(1)
route_role   origin, forwarder, destination        (uncomparable)
authority    read_only_zero_authority
refusal / partition / conflict   single-claim, non-collapsible
```

Each token then publishes `permittedPresentationTiers` — **exactly** the tiers at or below its own rank:

| Semantic rank | Permitted tiers |
|---|---|
| 0 (`unknown`) | `["withheld"]` |
| 1 (`stale`) | `["withheld", "minimal"]` |
| 2 (`current`) | `["withheld", "minimal", "declared"]` |

An `unknown` fact can only ever be drawn as `withheld`. There is no code path that produces a stronger tier for it, because the list does not contain one. The suite asserts this for **every token of a mixed frame**, not just for a convenient example.

## 3. The coarsening gate

`planGetigPresentationCoarsening()` is where a renderer declares "I am drawing this axis the same way". Two checks:

**Strengthening is refused.** The chosen tier's rank must not exceed the **minimum** semantic rank present on that axis. A frame holding both `current` and `stale` entities cannot have its freshness axis drawn at `declared`, because that would draw the stale fact as current → `refused_mapping_strengthening`. The same frame drawn at `withheld` is legal; it under-claims.

**Suppression is refused, unconditionally, before rank is consulted.** Four axes may never be collapsed at all:

| Axis | Why collapsing it is deletion, not weakening |
|---|---|
| `route_role` | origin, forwarder and destination become indistinguishable — this is exactly `forwarder → origin` |
| `conflict` | a conflicted fact becomes indistinguishable from a settled one |
| `refusal` | a refusal stops being visible content |
| `partition` | a partition stops being visible content |

The order matters and is tested: suppression is checked first because it does not depend on which tier was chosen.

## 4. What each prompt-named axis maps to

| Prompt token | 28D mapping |
|---|---|
| known / unknown | `knowledge`: `known` / `unknown`; absent field maps to `unknown` |
| current / stale / unknown freshness | `freshness`, rank-ordered; stale can never reach the `declared` tier |
| observed / quarantined / retired | `lifecycle`, rank-ordered |
| claim / grant-none | `grant`: `claim` / `grant_none`; every structural zero maps to `grant_none` |
| planned route / unavailable route | `route_state`; **defaults to `unknown`**, never `planned` |
| admission only when explicitly evidenced | `admission`; `not_admitted` unless `admissionEvidence` names that route |
| origin / forwarder / destination | `route_role`, three separate tokens per route on a non-collapsible axis |
| refusal | `refusal: refused`, emitted for every refusal in the frame |
| partition | `partition: partitioned`, emitted for every partition supplied as evidence |
| conflict | `conflict: conflict_visible`, emitted for every conflict |
| read-only / zero-authority | `authority: read_only_zero_authority`, plus `authority:"none"` on every token |

Two defaults deserve emphasis, because both are places where the honest answer is the boring one:

- **A route with no supplied state maps to `unknown`.** 28A's visible route carries no planned/unavailable state, so defaulting to `planned` would be inventing evidence. The caller may supply a state; it must be in the closed vocabulary or the whole mapping is refused.
- **A route with no admission evidence maps to `not_admitted`.** Admission is emitted only when `admissionEvidence` names that specific route. Evidence for `rt1` never leaks onto `rt2`, and evidence for a route that is not in the frame attaches to nothing.

## 5. Colour is never the canonical meaning

There is **no colour, hue, saturation, brightness, opacity, palette, gradient, texture, material, shader, glow, shade, tint or chroma field anywhere in the public surface.** Presentation tiers are named for how much a drawing *discloses* — `withheld`, `minimal`, `declared` — never for how it looks.

The reasoning: if colour carried the meaning, two renderers with different palettes would disagree about what the system is claiming. That is exactly the coupling this phase forbids. A renderer may pick any colour it likes; what it may not do is let the colour be the thing that means `current`.

The audit that enforces this reads the **surface**, not the documentation. Scanning the raw `.d.ts` flagged this module's own "no colour, no hue" comment — the same false-positive class 28C hit with the word "three" — so comments are stripped first, with a test asserting the stripper actually removes them and the stripped surface still contains real declarations.

## 6. Selection is never permission

`refuseVisualSelectionToPermission()` refuses for every input, including seven distinct intents that each ask for something specific: admit a peer, authorize a route, grant capability, promote a forwarder to origin, mark a fact current, spawn a worker, restore previous state. Its result carries `conferredAuthority`, `admittedPeer`, `authorizedRoute` and `mutatedRuntimeState`, all structurally `false`.

## 7. The eight promotions — and an honest correction

`GETIG_VISUAL_FORBIDDEN_PROMOTIONS` lists all eight the prompt requires be prevented, each naming the value a renderer would need and **which layer actually prevents it**.

An earlier draft of this gate asserted that every promotion was prevented by the target value being absent from every vocabulary. **That was false, and a test disproved it.** `origin` is a legitimate route role and `current` is a legitimate freshness; both exist by design. Only four of the eight are prevented by absence:

| Promotion | `from` | `strengthened_value` | Actually prevented by |
|---|---|---|---|
| `unknown_to_trusted` | `unknown` | `trusted` | `value_absent` |
| `claim_to_granted` | `claim` | `granted` | `value_absent` |
| `observed_edge_to_admitted` | `not_admitted` | `admitted_by_inference` | `value_absent` |
| `route_to_authorized` | `planned` | `authorized` | `value_absent` |
| `forwarder_to_origin` | `forwarder` | `origin` | **`axis_non_collapsible`** — the value exists; the axis may never be collapsed |
| `stale_to_current` | `stale` | `current` | **`permitted_tier_ceiling`** — the value exists but ranks higher, and a stale token's permitted tiers exclude `declared` |
| `conflict_to_hidden` | `conflict_visible` | `conflict_suppressed` | `value_absent` **and** `axis_non_collapsible` |
| `observer_view_to_global_truth` | `known` | `global_truth` | `value_absent` **and** `structural_zero` (`globalTruth: false`) |

The suite verifies each row against the mechanism it claims, and includes a test that pins the correction itself: it asserts `origin` and `current` **are** in the vocabularies and that their rows do **not** claim absence. A blanket assurance would have been the same kind of false claim this gate exists to catch.

Two earlier rows were also wrong in their `from` values — `local_view` is not a `knowledge` value, and `observed` is not an `admission` value — so the table named sources that did not exist. Both are corrected to real values (`known`, `not_admitted`).

## 8. Bounded, deterministic, frozen

`maxTokensPerMapping: 4096`, `maxIdChars: 128`. Tokens are sorted by `tokenId` using code-unit comparison — never `localeCompare`, which would make `mappingHash` machine-dependent. The mapping and every token are frozen. An over-large frame is refused rather than truncated. Refusals return `mapping: null` or `plan: null`; no partial output escapes.

## 9. Refusals — all eight reachable

Every code in `GETIG_VISUAL_REFUSAL_CODES` is driven by a real input and asserted to be the code that came back:

`refused_mapping_frame_invalid` · `refused_mapping_unknown_axis` · `refused_mapping_unknown_value` · `refused_mapping_unknown_subject` · `refused_mapping_tier_unknown` · `refused_mapping_strengthening` · `refused_mapping_suppression` · `refused_mapping_selection_not_permission`

## 10. Non-claims

- Nothing was rendered. No WebGPU, no Three.js, no graphics backend of any kind.
- No geometry, layout, camera, mesh or draw call exists here. This module produces statements, not pictures.
- No semantic claim is strengthened, and no renderer can strengthen one through this API.
- No conflict is resolved, no observer preferred, no authority conferred, no state mutated.
- No dependency added; the lockfile is byte-identical.
- No other gate executed.

## 11. Debt

None new. Carried forward unchanged: D-26-1, D-26-2, D-26-3, D-26-4.

## 12. Defects found and corrected during this gate

1. **Unterminated template literal** — a botched edit dropped a closing backtick on the origin route-role `emit` call. The file failed to parse with 20+ cascading `TS1005` errors pointing at lines that were themselves correct. Found by reading line lengths against reported column numbers.
2. **The promotion table's `prevented_by` claim was absent entirely** — the first version asserted blanket absence, which was false for `forwarder→origin` and `stale→current`.
3. **Two rows named `from` values that do not exist** — `local_view` on the `knowledge` axis, `observed` on the `admission` axis.
4. **The colour audit matched its own documentation** — the raw `.d.ts` contains this gate's "no colour, no hue" comment. Fixed by stripping comments before scanning, with a self-test for the stripper.
5. **A test assumed emission order for role tokens** — the mapping correctly sorts by `tokenId`, so the assertion was wrong, not the code. Corrected to assert both the sorted order and the set.
6. **The partition token could never fire on real data.** 28A's `GetigFrame` has NO partition collection — its members are entities, relations, events, conflicts, refusals, routes and proposal flows — and 27H names partition records `reconciliationId`, not `partitionId`. The first version read `frame.partitions[].partitionId`, which is always empty for a real frame, so partitions silently produced no tokens while the documentation claimed they were emitted for every partition. Partitions are now supplied as evidence, accepting either field name, and refused rather than dropped when neither is usable. **This bug was invisible to the suite because no test covered partition emission** — the gap and the bug hid each other.

Item 6 was found by the final completion check, not by the suite: **the missing test and the dead code hid each other**. Three partition tests were added rather than the documentation being softened to match the broken behaviour.

Items 2, 3 and 4 were caught by audits written to catch exactly that class of overclaim. Item 1 was caught by refusing to believe an error report that pointed at obviously-correct lines.