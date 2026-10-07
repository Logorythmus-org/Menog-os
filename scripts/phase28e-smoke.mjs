/**
 * PHASE 28E — out-of-suite smoke check against the BUILT artefact.
 *
 * Development probe, not a gate test. It exists so 28E behaviour can be shown
 * against `dist/` rather than only inside a suite that could be masking a stale
 * build. Two defects in earlier gates — a blanket "absence" claim at 28D and a
 * dead partition token — were caught by exactly this kind of independent run.
 */
import {
  buildGetigObserverView,
  compareGetigObserverViews,
  buildGetigMultiView,
  refuseGlobalTruthSynthesis,
  GETIG_VIEW_REFUSAL_CODES,
  GETIG_VIEW_DIVERGENCE_KINDS,
  GETIG_VIEW_LIFECYCLES,
  GETIG_VIEW_BOUNDS,
} from "../packages/durable-state/dist/index.js";

let failures = 0;
const check = (name, ok, observed) => {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ->  ${observed}`);
};

const hex = (d) => String(d).repeat(64);
const EPOCH = "epoch-28e";
const RUNTIME = "runtime-local-1";

const ent = (visibleId, over = {}) => ({
  visibleId, kind: "runtime_node", label: `l-${visibleId}`, isRuntimeObject: false, grant: "none",
  freshness: "current", lifecycle: "observed", provenanceRefs: [], representsRuntimeId: null, ...over,
});

const frameOf = (observerId, visibleHash, over = {}, epochId = EPOCH) => ({
  schemaVersion: "menog-getig/v0", frameId: `frame-${observerId}`, observer: observerFor(observerId), epochId,
  asOfEpochMs: 1_700_000_000_000, sourceProjectionHash: hex("a"), canonicalVisibleHash: hex(visibleHash),
  entities: [], relations: [], events: [], conflicts: [], refusals: [], routes: [], proposalFlows: [],
  authority: "none", controlPlane: "none", readOnly: true, replaySemantics: "visual_only_not_executable",
  globalTruth: false, visibleCapabilities: [], ...over,
});

const observerFor = (observerId, observerKind = "local_runtime") => ({ observerId, observerKind, epochId: EPOCH, isGlobalTruth: false });

const view = (viewId, observerId, visibleHash, entities, over = {}) =>
  buildGetigObserverView({ viewId, observerId, observerKind: "local_runtime", runtimeId: RUNTIME, epochId: EPOCH, frame: frameOf(observerId, visibleHash, { entities, ...over }) });

// ── single observer view ─────────────────────────────────────────────────────
const a = view("view-a", "obs-a", "1", [ent("n1"), ent("n2")]);
check("single observer view builds", a.ok, a.ok ? `${a.view.factCount} facts` : a.explanation);
if (a.ok) {
  check("view carries mandatory context",
    a.view.observerId === "obs-a" && a.view.runtimeId === RUNTIME && a.view.epochId === EPOCH,
    `${a.view.observerId}/${a.view.runtimeId}/${a.view.epochId}`);
  check("view denies global truth and consensus",
    a.view.isGlobalTruth === false && a.view.assertsConsensus === false && a.view.authority === "none");
  check("every fact is attributed", a.view.facts.every((f) => f.attributedToObserverId === "obs-a" && f.isGrant === false));
  check("view is deterministic", view("view-a", "obs-a", "1", [ent("n1"), ent("n2")]).view.viewHash === a.view.viewHash);
}

// ── contradictory observations ───────────────────────────────────────────────
const b = view("view-b", "obs-b", "2", [ent("n1"), ent("n2", { kind: "observed_node" })]);
const cmp = compareGetigObserverViews({ left: a.view, right: b.view });
check("comparison builds", cmp.ok, cmp.ok ? `d=${cmp.comparison.summary.disagreementCount}` : cmp.explanation);
if (cmp.ok) {
  const c = cmp.comparison;
  check("contradictory observations are a DISAGREEMENT", c.summary.disagreementCount === 1 && c.summary.agreementCount === 1,
    JSON.stringify(c.summary));
  check("no winner, no consensus, no global truth",
    c.winnerDeclared === false && c.consensusAsserted === false && c.isGlobalTruth === false
    && c.governedResolutionSupplied === false);
  check("freshness decides nothing", c.disagreements.every((e) => e.freshnessDecidesNothing === true));
}

// ── absence is NOT disagreement ──────────────────────────────────────────────
const onlyA = view("view-a", "obs-a", "3", [ent("n1")]);
const onlyB = view("view-b", "obs-b", "4", [ent("n1"), ent("n9")]);
const gap = compareGetigObserverViews({ left: onlyA.view, right: onlyB.view });
check("a subject only one observer saw is an UNKNOWN difference, not a disagreement",
  gap.ok && gap.comparison.summary.disagreementCount === 0 && gap.comparison.summary.unknownDifferenceCount === 1,
  gap.ok ? JSON.stringify(gap.comparison.summary) : gap.refusal);
if (gap.ok) {
  check("and it is classified as absent-from-left", gap.comparison.unknownDifferences[0].divergenceKind === "left_absent",
    gap.comparison.unknownDifferences[0].divergenceKind);
}

// ── stale vs current: freshness must not decide ──────────────────────────────
const staleA = view("view-a", "obs-a", "5", [ent("n1", { freshness: "stale", kind: "runtime_node" })]);
const freshB = view("view-b", "obs-b", "6", [ent("n1", { freshness: "current", kind: "observed_node" })]);
const sf = compareGetigObserverViews({ left: staleA.view, right: freshB.view });
check("stale-vs-current still disagrees on kind, and freshness decides nothing",
  sf.ok && sf.comparison.summary.disagreementCount === 1 && sf.comparison.disagreements[0].freshnessDecidesNothing === true,
  sf.ok ? JSON.stringify(sf.comparison.summary) : sf.refusal);

// ── terminal vs observed ─────────────────────────────────────────────────────
const termA = view("view-a", "obs-a", "7", [ent("n1", { lifecycle: "retired" })]);
const liveB = view("view-b", "obs-b", "8", [ent("n1", { lifecycle: "observed" })]);
const tv = compareGetigObserverViews({ left: termA.view, right: liveB.view });
check("terminal vs live is a disagreement with the resurrection barrier set",
  tv.ok && tv.comparison.summary.disagreementCount === 1
  && tv.comparison.disagreements[0].terminalResurrectionBlocked === true,
  tv.ok ? tv.comparison.disagreements[0].divergenceKind : tv.refusal);
check("terminal fact is marked terminal in the view that reports it",
  termA.ok && termA.view.facts[0].isTerminal === true && liveB.ok && liveB.view.facts[0].isTerminal === false,
  termA.ok ? `A terminal=${termA.view.facts[0].isTerminal} B terminal=${liveB.view.facts[0].isTerminal}` : "n/a");

// ── unknown vs known ─────────────────────────────────────────────────────────
const unkA = view("view-a", "obs-a", "9", [{ ...ent("n1"), kind: undefined }]);
const knoB = view("view-b", "obs-b", "a", [ent("n1")]);
const uk = compareGetigObserverViews({ left: unkA.view, right: knoB.view });
check("unknown-vs-known is an UNKNOWN difference, not a disagreement",
  uk.ok && uk.comparison.summary.disagreementCount === 0 && uk.comparison.summary.unknownDifferenceCount === 1,
  uk.ok ? JSON.stringify(uk.comparison.summary) : uk.refusal);

// ── partition / rejoin, and shuffled observer order ──────────────────────────
const p1 = view("view-a", "obs-a", "b", [ent("n1"), ent("shared")]);
const p2 = view("view-b", "obs-b", "c", [ent("n1"), ent("shared")]);
const before = buildGetigMultiView({ multiViewId: "mv-1", runtimeId: RUNTIME, epochId: EPOCH, views: [p1.view, p2.view] });
const shuffled = buildGetigMultiView({ multiViewId: "mv-1", runtimeId: RUNTIME, epochId: EPOCH, views: [p2.view, p1.view] });
check("multi-view builds", before.ok, before.ok ? `${before.multiView.viewCount} views, ${before.multiView.comparisons.length} comparisons` : before.explanation);
check("shuffled observer order is byte-identical",
  before.ok && shuffled.ok && JSON.stringify(before.multiView) === JSON.stringify(shuffled.multiView),
  before.ok ? JSON.stringify(before.multiView.observerIds) : "n/a");
check("multi-view asserts no synthesis and no resurrection",
  before.ok && before.multiView.synthesizesGlobalTruth === false && before.multiView.terminalResurrected === false
  && before.multiView.authority === "none" && before.multiView.readOnly === true);

// ── mandatory context ────────────────────────────────────────────────────────
const noObserver = buildGetigObserverView({ viewId: "v", runtimeId: RUNTIME, epochId: EPOCH, frame: frameOf("obs-a", "d") });
const noRuntime = buildGetigObserverView({ viewId: "v", observerId: "obs-a", observerKind: "local_runtime", epochId: EPOCH, frame: frameOf("obs-a", "d") });
const noEpoch = buildGetigObserverView({ viewId: "v", observerId: "obs-a", observerKind: "local_runtime", runtimeId: RUNTIME, frame: frameOf("obs-a", "d") });
const badKind = buildGetigObserverView({ viewId: "v", observerId: "obs-a", observerKind: "oracle", runtimeId: RUNTIME, epochId: EPOCH, frame: frameOf("obs-a", "d") });
for (const [n, d] of [["no observerId", noObserver], ["no runtimeId", noRuntime], ["no epochId", noEpoch], ["unknown observerKind", badKind]]) {
  check(`refuses: ${n}`, !d.ok && d.refusal === "refused_view_context_incomplete", d.ok ? "BUILT" : d.refusal);
}

// ── cross-runtime / cross-epoch ──────────────────────────────────────────────
const otherRuntime = buildGetigObserverView({ viewId: "v-x", observerId: "obs-x", observerKind: "local_runtime", runtimeId: "runtime-other", epochId: EPOCH, frame: frameOf("obs-x", "e") });
// The FRAME must carry the same epoch as the view, or the view builder (rightly)
// refuses it and there is nothing left to compare.
const otherEpoch = buildGetigObserverView({ viewId: "v-y", observerId: "obs-y", observerKind: "local_runtime", runtimeId: RUNTIME, epochId: "epoch-other", frame: frameOf("obs-y", "f", {}, "epoch-other") });
check("a view from another epoch builds fine on its own", otherEpoch.ok, otherEpoch.ok ? otherEpoch.view.epochId : otherEpoch.refusal);
const cr = compareGetigObserverViews({ left: a.view, right: otherRuntime.ok ? otherRuntime.view : {} });
check("refuses a cross-runtime comparison", !cr.ok && cr.refusal === "refused_compare_cross_runtime", cr.ok ? "built" : cr.refusal);
const ce = compareGetigObserverViews({ left: a.view, right: otherEpoch.ok ? otherEpoch.view : {} });
check("refuses a cross-epoch comparison", !ce.ok && ce.refusal === "refused_compare_cross_epoch", ce.ok ? "built" : ce.refusal);

// ── multi-view refusals ──────────────────────────────────────────────────────
const dup = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [a.view, a.view] });
check("refuses the same observer twice", !dup.ok && dup.refusal === "refused_multiview_duplicate_observer", dup.ok ? "built" : dup.refusal);
const empty = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [] });
check("refuses an empty view set", !empty.ok && empty.refusal === "refused_multiview_input_invalid", empty.ok ? "built" : empty.refusal);
const tooMany = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: Array.from({ length: GETIG_VIEW_BOUNDS.maxViewsPerMultiView + 1 }, (_, i) => ({ ...a.view, viewId: `v${i}`, observerId: `o${i}` })) });
check("refuses more views than the bound", !tooMany.ok && tooMany.refusal === "refused_multiview_input_invalid", tooMany.ok ? "built" : tooMany.refusal);
const notView = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [{ nope: true }] });
check("refuses something that is not a view", !notView.ok && notView.refusal === "refused_compare_not_a_view", notView.ok ? "built" : notView.refusal);
const badCmp = compareGetigObserverViews({ left: { facts: "no" }, right: a.view });
check("refuses comparing something that is not a view", !badCmp.ok && badCmp.refusal === "refused_compare_not_a_view", badCmp.ok ? "built" : badCmp.refusal);

// ── malformed frame / subject refusals ───────────────────────────────────────
const badFrame = buildGetigObserverView({ viewId: "v", observerId: "obs-a", observerKind: "local_runtime", runtimeId: RUNTIME, epochId: EPOCH, frame: null });
check("refuses a non-object frame", !badFrame.ok && badFrame.refusal === "refused_view_frame_invalid", badFrame.ok ? "built" : badFrame.refusal);
const wrongObserver = buildGetigObserverView({
  viewId: "v", observerId: "obs-a", observerKind: "local_runtime", runtimeId: RUNTIME, epochId: EPOCH,
  frame: frameOf("obs-OTHER", "1"),
});
check("refuses a frame attributed to a different observer",
  !wrongObserver.ok && wrongObserver.refusal === "refused_view_frame_invalid", wrongObserver.ok ? "built" : wrongObserver.refusal);
const noSubjectId = buildGetigObserverView({
  viewId: "v", observerId: "obs-a", observerKind: "local_runtime", runtimeId: RUNTIME, epochId: EPOCH,
  frame: frameOf("obs-a", "1", { entities: [{ kind: "runtime_node", lifecycle: "observed" }] }),
});
check("refuses a subject with no usable id rather than silently dropping it",
  !noSubjectId.ok && noSubjectId.refusal === "refused_view_unknown_subject", noSubjectId.ok ? `built with ${noSubjectId.view.factCount} facts` : noSubjectId.refusal);

// ── the synthesis guard ──────────────────────────────────────────────────────
const syn = refuseGlobalTruthSynthesis(["obs-a", "obs-b", "obs-c"], "the truth");
check("synthesis always refuses, whoever is asked", !syn.ok && syn.refusal === "refused_synthesis_not_permitted"
  && syn.winnerDeclared === false && syn.consensusAsserted === false && syn.isGlobalTruth === false,
  syn.refusal);
check("synthesis refuses for every input shape",
  refuseGlobalTruthSynthesis([]).ok === false && refuseGlobalTruthSynthesis(null).ok === false
  && refuseGlobalTruthSynthesis([1, 2]).observerCount === 0);

// ── every declared refusal code reachable ────────────────────────────────────
const produced = new Set([
  noObserver, noRuntime, noEpoch, badKind, cr, ce, dup, empty, tooMany, notView, badCmp,
  badFrame, wrongObserver, noSubjectId, syn,
].filter((d) => d.ok === false).map((d) => d.refusal));
const missing = [...GETIG_VIEW_REFUSAL_CODES].filter((c) => !produced.has(c));
check("every declared refusal code is reachable", missing.length === 0,
  missing.length === 0 ? `all ${GETIG_VIEW_REFUSAL_CODES.length} produced` : `unreachable: ${missing.join(", ")}`);

// ── vocabulary sanity ────────────────────────────────────────────────────────
check("lifecycle vocabulary has a terminal state",
  GETIG_VIEW_LIFECYCLES.includes("retired") && GETIG_VIEW_LIFECYCLES.includes("quarantined") && GETIG_VIEW_LIFECYCLES.includes("observed"));
check("divergence kinds are closed and distinct",
  new Set(GETIG_VIEW_DIVERGENCE_KINDS).size === GETIG_VIEW_DIVERGENCE_KINDS.length);

console.log(`\n28E smoke: ${failures === 0 ? "ALL PASS" : `${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);