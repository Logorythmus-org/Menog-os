# PHASE 28E — Observer-Relative World Views Contract

Gate: 28E · Verdict: **28E_PASS**
Mode: MULTI-VIEW / NO GLOBAL TRUTH SYNTHESIS / ATTRIBUTED / ZERO-AUTHORITY / RENDERER-NEUTRAL / LOCAL-ONLY / READ-ONLY / NO GIT / NO PUBLICATION
Schema version: `menog-getig-view/v0`
Central laws: **OBSERVER_VIEW != GLOBAL_TRUTH** · **RECONCILIATION != CONSENSUS**

Source: `packages/durable-state/src/getigObserverViews.ts` (30,698 B · 700 L · `4580c9d97f7bb3ef`)
Tests: `tests/unit/getig-observer-views.test.ts` (75 tests · 41,995 B · 813 L · `9f3ed8e155021804`)

---

## 1. What this gate does

Three builders and one guard that can only refuse.

| Export | Purpose |
|---|---|
| `buildGetigObserverView(input)` | Records ONE observer's account of one runtime in one epoch. |
| `compareGetigObserverViews({left, right})` | Reports where two accounts differ, with attribution, and no winner. |
| `buildGetigMultiView(input)` | Holds several observers' views side by side with every pairwise comparison. |
| `refuseGlobalTruthSynthesis(observerIds, label?)` | The ONLY synthesis-adjacent export. It cannot succeed. |

Two helpers, `getigVisualSemanticRank`'s 28E counterpart included in spirit as `ObserverFact` fields, keep the ranking arithmetic inspectable: every comparison entry carries `freshnessDecidesNothing` and `terminalResurrectionBlocked` as data.

## 2. Mandatory context

A view without an observer, a runtime and an epoch is not a view — it is a shape that could be mistaken for one. All three are required, and each is separately refused:

| Missing | Refusal |
|---|---|
| `viewId` | `refused_view_context_incomplete` |
| `observerId` (or empty) | `refused_view_context_incomplete` |
| `observerKind` outside the closed two | `refused_view_context_incomplete` |
| `runtimeId` (or empty) | `refused_view_context_incomplete` |
| `epochId` (or empty) | `refused_view_context_incomplete` |

Two further cross-checks stop a mis-attributed view being built at all:

- the frame's own `observer.observerId` must equal the view's `observerId`, or every fact's attribution would be a lie;
- the frame's `epochId` must equal the view's `epochId`.

And comparisons across worlds are refused outright: `refused_compare_cross_runtime`, `refused_compare_cross_epoch`. Two views from different epochs describe different worlds entirely, and averaging them would be meaningless rather than merely wrong.

## 3. No winner, ever

Picking a winner needs evidence. "A is more recent than B" is not that evidence.

- `ViewComparison.winnerDeclared` is a structural `false`. There is no parameter and no code path that sets it.
- `consensusAsserted` and `isGlobalTruth` likewise.
- The suite asserts that **no comparison field carries a ranking value**: any field whose name mentions winner, consensus, resolution, verdict, global truth or authority must hold `false` or `"none"`, and no field may be named `correctObserver`, `preferredObserver`, `authoritativeObserver`, `resolution` or `verdict`.
- `refuseGlobalTruthSynthesis()` refuses for every input shape, and its explanation names both central laws.

### The upstream-evidence exception, and why it is not implemented here

The prompt permits a winner "unless upstream governed evidence explicitly supplies one". That is **deliberately not implemented**. Adjudicating on governed evidence is a later gate's job, and implementing it here would put a decision path in the one module whose whole purpose is to have none.

What the module does instead is refuse to *pretend the exception was checked*: `governedResolutionSupplied` is a structural `false` on every comparison. A reader can therefore see that no adjudication was performed, rather than inferring that one was considered and found unnecessary. Those are very different claims, and only the first is true.

## 4. Absence is not disagreement

This is the distinction most likely to be got wrong, in both directions.

| Situation | Classification | Why |
|---|---|---|
| both observers state the same kind | `agreement` | — |
| both state a kind, and they differ | `value_differs` → **disagreement** | two accounts, both known, both different |
| one side did not mention the subject | `left_absent` / `right_absent` → **unknown difference** | we have one account, not two |
| one side stated nothing about the subject | `left_unknown` / `right_unknown` → **unknown difference** | present but silent is not a competing claim |
| one says `retired`, the other `observed` | `terminal_vs_live` → **disagreement**, barrier raised | see §5 |

Manufacturing **conflict** out of a gap is the exact mirror of manufacturing **consensus** out of a gap. Both are inventions, and this gate refuses both. Unknown differences are kept out of the `disagreements` array entirely, and a test asserts they never appear in both.

## 5. Terminal facts cannot be visually resurrected — without adjudicating

When one observer reports a subject `retired` and another reports it `observed`:

1. the divergence is reported as a disagreement, attributed to both;
2. `terminalResurrectionBlocked: true` is set on the entry;
3. the subject id is added to `comparison.terminalBarriers`, and up to `multiView.terminalBarrierSubjects`;
4. `multiView.terminalResurrected` is structural `false`;
5. **and no winner is declared, no consensus asserted, and neither side called true.**

Blocking resurrection is not adjudicating. The retired account is not declared correct and the observed account is not declared wrong; the pair simply refuses to collapse. `quarantined` is deliberately **not** terminal — a quarantined thing may yet be released — but it IS barred from resurrection, because a quarantined fact still may not be presented as healthy. That is a display law, not a truth claim.

## 6. Freshness and time decide nothing

`ComparisonEntry.freshnessDecidesNothing` is a structural `true` on every entry. Freshness is carried onto the fact for display, but:

- two observers whose freshness differs and whose kind matches are an **agreement**, not a disagreement;
- two observers whose kind differs are a **disagreement** regardless of which is fresher.

## 7. Side-by-side, deterministic, bounded

`buildGetigMultiView()` sorts views by `observerId`, so a caller handing them over in any order gets byte-identical output — asserted for three observers across three orderings, including the exact `JSON.stringify` equality of the whole multi-view. Every pair is compared exactly once. The same observer appearing twice is refused: two views from one observer are one account, and showing it twice would imply two independent opinions.

Ordering uses code-unit comparison, never `localeCompare`, so `viewHash` and `comparisonHash` cannot become machine-dependent.

| Bound | Value |
|---|---|
| `maxFactsPerView` | 1,024 |
| `maxViewsPerMultiView` | 16 |
| `maxComparisonEntries` | 2,048 |
| `maxIdChars` | 128 |

Views, facts, comparisons, entries and the multi-view are all frozen. Refusals return `view: null` / `comparison: null` / `multiView: null`; no partial output escapes.

## 8. Refusals — all nine reachable

Every code in `GETIG_VIEW_REFUSAL_CODES` is driven by a real input and asserted to be the code that came back. The suite and the independent probe both fail if any becomes unreachable.

`refused_view_context_incomplete` · `refused_view_frame_invalid` · `refused_view_unknown_subject` · `refused_compare_not_a_view` · `refused_compare_cross_runtime` · `refused_compare_cross_epoch` · `refused_multiview_input_invalid` · `refused_multiview_duplicate_observer` · `refused_synthesis_not_permitted`

## 9. Non-claims

- No consensus, no global truth, no reconciliation, no winner, no vote, no merge.
- No conflict resolved and no observer preferred.
- No terminal fact resurrected.
- No rendering, no colour, no style field, no graphics dependency.
- No execution, network, Policy, isolation or process path.
- No dependency added; the lockfile is byte-identical.
- The upstream-evidence adjudication exception is **not** implemented and **not** claimed.
- D-26-1 remains open; nothing here is physical-LAN validation.

## 10. Debt

None new. Carried forward unchanged: D-26-1, D-26-2, D-26-3, D-26-4.

## 11. Defects found and corrected during this gate

1. **`refused_view_unknown_subject` was unreachable.** The first version silently `return`ed on a subject with no usable id, so the code existed in the vocabulary and nothing could produce it — the same vacuous-vocabulary defect found at 28C. A record with no usable id is a *malformed subject*, not an absent one, and silently dropping it also left a view that looked complete and was not. It is now refused.
2. **Two probe expectations were wrong, not the module.** `left_absent` correctly means "absent from the left view", and a cross-epoch fixture hardcoded the epoch into the frame so the view builder (rightly) refused it and there was nothing left to compare. Both fixtures were corrected; the module was not changed to match a bad test.
3. **An audit was too crude and had to be made precise.** The "no field could rank observers" check originally forbade any field *name* containing `resolution`, which flagged `governedResolutionSupplied` — itself a guarantee of `false`. The check now asserts the real invariant: any such field must hold a structural zero (`false` or `"none"`), never a name, a score or a `true`.
4. **A test used a kind 28A does not have.** `observed_node` is not in 28A's entity vocabulary, so the "two real 28A frames" integration test was refused by 28A before 28E saw it. Corrected to `agent`, which is real. Worth noting: the refusal came from 28A doing its job, not from a defect.

6. **A quarantined-vs-observed difference was reported as an AGREEMENT.** The comparison derived its verdict from `statedKind` alone, so two observers naming the same kind while disagreeing about lifecycle — one `quarantined`, one `observed` — produced no entry at all. That is the worst failure this gate can have: it hides a real difference rather than inventing one, and it silently passed every test that existed. Lifecycle is now compared separately (`lifecycle_differs`), and `quarantined` is barred from resurrection alongside `retired`. Five tests added, covering the case that was previously invisible.

Item 1 was caught by the independent probe against `dist/`. Items 2–5 were caught by the suite's first run.