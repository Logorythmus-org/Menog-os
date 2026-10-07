/**
 * PHASE 28E — OBSERVER-RELATIVE WORLD VIEWS
 * (MULTI-VIEW / NO GLOBAL TRUTH SYNTHESIS / ATTRIBUTED / ZERO-AUTHORITY)
 *
 * The prompt names six scenarios. Each has its own block below, and each is
 * driven through the real code path rather than asserted in prose:
 *
 *   contradictory observations · stale-vs-current · terminal-vs-observed ·
 *   unknown-vs-known · partition/rejoin · shuffled observer order
 *
 * Three distinctions carry most of the weight, and each has a block of its own:
 *
 *   · NO WINNER. `winnerDeclared` is structural `false`. There is no parameter
 *     and no code path that sets it, and a fresher account is not a truer one.
 *   · ABSENCE IS NOT DISAGREEMENT. One observer not mentioning a subject is an
 *     UNKNOWN difference. Manufacturing conflict out of a gap is the mirror
 *     image of manufacturing consensus out of a gap.
 *   · TERMINAL IS NOT RESURRECTABLE. Blocking resurrection is not adjudicating:
 *     the retired account is neither declared true nor the live one false.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildGetigObserverView,
  compareGetigObserverViews,
  buildGetigMultiView,
  refuseGlobalTruthSynthesis,
  buildGetigFrame,
  GETIG_VIEW_KNOWLEDGE,
  GETIG_VIEW_LIFECYCLES,
  GETIG_VIEW_FRESHNESS,
  GETIG_VIEW_DIVERGENCE_KINDS,
  GETIG_VIEW_OBSERVER_KINDS,
  GETIG_VIEW_REFUSAL_CODES,
  GETIG_VIEW_BOUNDS,
  GETIG_VIEW_SCHEMA_VERSION,
  type GetigObserverView,
  type ViewComparison,
  type GetigFrameInput,
} from "../../packages/durable-state/dist/index.js";

const SRC_PATH = join(process.cwd(), "packages", "durable-state", "src", "getigObserverViews.ts");
const DTS_PATH = join(process.cwd(), "packages", "durable-state", "dist", "getigObserverViews.d.ts");
const HEX64 = /^[0-9a-f]{64}$/;
const NOW = 1_700_000_000_000;
const EPOCH = "epoch-28e";
const RUNTIME = "runtime-local-1";

function readSourceOrThrow(path: string): string {
  const text = readFileSync(path, "utf8");
  if (text.length === 0) throw new Error(`audit input is empty: ${path}`);
  return text;
}

const hex = (d: string) => d.repeat(64);

const ent = (visibleId: string, over: Record<string, unknown> = {}) => ({
  visibleId,
  kind: "runtime_node" as const,
  label: `label-${visibleId}`,
  isRuntimeObject: false as const,
  grant: "none" as const,
  freshness: "current" as const,
  lifecycle: "observed" as const,
  provenanceRefs: [],
  representsRuntimeId: null,
  ...over,
});

const frameOf = (observerId: string, visibleDigit: string, over: Record<string, unknown> = {}, epochId = EPOCH) => ({
  schemaVersion: "menog-getig/v0",
  frameId: `frame-${observerId}`,
  observer: { observerId, observerKind: "local_runtime" as const, epochId, isGlobalTruth: false as const },
  epochId,
  asOfEpochMs: NOW,
  sourceProjectionHash: hex("a"),
  canonicalVisibleHash: hex(visibleDigit),
  entities: [] as unknown[],
  relations: [] as unknown[],
  events: [] as unknown[],
  conflicts: [] as unknown[],
  refusals: [] as unknown[],
  routes: [] as unknown[],
  proposalFlows: [] as unknown[],
  authority: "none",
  controlPlane: "none",
  readOnly: true,
  replaySemantics: "visual_only_not_executable" as const,
  globalTruth: false as const,
  visibleCapabilities: [] as string[],
  ...over,
});

const viewInput = (viewId: string, observerId: string, frame: unknown, over: Record<string, unknown> = {}) =>
  ({ viewId, observerId, observerKind: "local_runtime", runtimeId: RUNTIME, epochId: EPOCH, frame, ...over }) as never;

function builtView(viewId: string, observerId: string, visibleDigit: string, entities: unknown[], over: Record<string, unknown> = {}): GetigObserverView {
  const decision = buildGetigObserverView(viewInput(viewId, observerId, frameOf(observerId, visibleDigit, { entities }, (over.epochId as string) ?? EPOCH), over));
  if (!decision.ok) throw new Error(`expected a built view, got ${decision.refusal}: ${decision.explanation}`);
  return decision.view;
}

function builtComparison(left: unknown, right: unknown): ViewComparison {
  const decision = compareGetigObserverViews({ left, right } as never);
  if (!decision.ok) throw new Error(`expected a built comparison, got ${decision.refusal}: ${decision.explanation}`);
  return decision.comparison;
}

const kindsOf = (entries: readonly { divergenceKind: string }[]) => entries.map((e) => e.divergenceKind);

// ── mandatory context ────────────────────────────────────────────────────────

describe("28E — observer, runtime and epoch context is mandatory", () => {
  const frame = frameOf("obs-a", "1");
  const cases: readonly [string, Record<string, unknown>, string][] = [
    ["no viewId", { observerId: "obs-a" }, "refused_view_context_incomplete"],
    ["no observerId", { runtimeId: RUNTIME, epochId: EPOCH }, "refused_view_context_incomplete"],
    ["no runtimeId", { observerId: "obs-a", epochId: EPOCH }, "refused_view_context_incomplete"],
    ["no epochId", { observerId: "obs-a", runtimeId: RUNTIME }, "refused_view_context_incomplete"],
    ["unknown observerKind", { observerId: "obs-a", runtimeId: RUNTIME, epochId: EPOCH, observerKind: "oracle" }, "refused_view_context_incomplete"],
    ["empty observerId", { observerId: "", runtimeId: RUNTIME, epochId: EPOCH }, "refused_view_context_incomplete"],
    ["empty runtimeId", { observerId: "obs-a", runtimeId: "", epochId: EPOCH }, "refused_view_context_incomplete"],
    ["empty epochId", { observerId: "obs-a", runtimeId: RUNTIME, epochId: "" }, "refused_view_context_incomplete"],
  ];
  for (const [name, over, expected] of cases) {
    it(`refuses: ${name}`, () => {
      const decision = buildGetigObserverView({ viewId: "v", observerKind: "local_runtime", frame, ...over } as never);
      expect(decision.ok).toBe(false);
      if (decision.ok) return;
      expect(decision.refusal).toBe(expected);
      expect(decision.view).toBeNull();
    });
  }

  it("carries all three on a built view", () => {
    const v = builtView("v", "obs-a", "1", [ent("n1")]);
    expect(v.observerId).toBe("obs-a");
    expect(v.runtimeId).toBe(RUNTIME);
    expect(v.epochId).toBe(EPOCH);
    expect(v.observerKind).toBe("local_runtime");
  });

  it("refuses a frame attributed to a different observer, rather than mis-attributing its facts", () => {
    const decision = buildGetigObserverView(viewInput("v", "obs-a", frameOf("obs-b", "1")));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_view_frame_invalid");
  });

  it("refuses a frame from a different epoch", () => {
    const decision = buildGetigObserverView(viewInput("v", "obs-a", frameOf("obs-a", "1", {}, "epoch-other")));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_view_frame_invalid");
  });

  it("refuses a malformed subject rather than silently dropping it", () => {
    const decision = buildGetigObserverView(viewInput("v", "obs-a", frameOf("obs-a", "1", { entities: [{ kind: "runtime_node" }] })));
    expect(decision.ok).toBe(false);
    // A view that quietly omitted a subject would look complete and not be.
    if (!decision.ok) expect(decision.refusal).toBe("refused_view_unknown_subject");
  });
});

// ── single observer view ─────────────────────────────────────────────────────

describe("28E — single observer view", () => {
  it("builds deterministically from the same frame", () => {
    const a = builtView("v", "obs-a", "1", [ent("n1"), ent("n2")]);
    const b = builtView("v", "obs-a", "1", [ent("n1"), ent("n2")]);
    expect(a.viewHash).toBe(b.viewHash);
    expect(a.viewHash).toMatch(HEX64);
  });

  it("is insensitive to the order subjects arrive in", () => {
    const a = builtView("v", "obs-a", "1", [ent("n1"), ent("n2"), ent("n3")]);
    const b = builtView("v", "obs-a", "1", [ent("n3"), ent("n1"), ent("n2")]);
    expect(a.viewHash).toBe(b.viewHash);
    expect(a.facts.map((f) => f.factId)).toEqual(b.facts.map((f) => f.factId));
  });

  it("gives a different observer a different view hash", () => {
    const a = builtView("v", "obs-a", "1", [ent("n1")]);
    const b = builtView("v", "obs-b", "1", [ent("n1")]);
    expect(a.viewHash).not.toBe(b.viewHash);
    expect(a.builtFromVisibleHash).toBe(b.builtFromVisibleHash);
  });

  it("freezes the view and every fact", () => {
    const v = builtView("v", "obs-a", "1", [ent("n1")]);
    expect(Object.isFrozen(v)).toBe(true);
    expect(Object.isFrozen(v.facts)).toBe(true);
    expect(Object.isFrozen(v.facts[0])).toBe(true);
  });

  it("attributes every fact and grants nothing", () => {
    const v = builtView("v", "obs-a", "1", [ent("n1"), ent("n2")]);
    for (const fact of v.facts) {
      expect(fact.attributedToObserverId).toBe("obs-a");
      expect(fact.isGrant).toBe(false);
    }
  });

  it("pins its structural zeros", () => {
    const v = builtView("v", "obs-a", "1", [ent("n1")]);
    expect(v.schemaVersion).toBe(GETIG_VIEW_SCHEMA_VERSION);
    expect(v.isGlobalTruth).toBe(false);
    expect(v.assertsConsensus).toBe(false);
    expect(v.authority).toBe("none");
    expect(v.readOnly).toBe(true);
    expect(v.bounded).toBe(true);
  });

  it("records an account with no stated kind as unknown, which is not the same as absent", () => {
    const v = builtView("v", "obs-a", "1", [{ ...ent("n1"), kind: undefined }]);
    expect(v.facts[0]!.knowledge).toBe("unknown");
    expect(v.facts[0]!.statedKind).toBeNull();
    expect(v.factCount).toBe(1);
  });
});

// ── scenario: contradictory observations ─────────────────────────────────────

describe("28E — contradictory observations", () => {
  it("reports a disagreement when two observers state different kinds", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1"), ent("n2")]);
    const b = builtView("v-b", "obs-b", "2", [ent("n1"), ent("n2", { kind: "observed_node" })]);
    const c = builtComparison(a, b);
    expect(c.summary.disagreementCount).toBe(1);
    expect(c.summary.agreementCount).toBe(1);
    expect(kindsOf(c.disagreements)).toEqual(["value_differs"]);
  });

  it("attributes the disagreement to both observers, with both statements intact", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1")]);
    const b = builtView("v-b", "obs-b", "2", [ent("n1", { kind: "observed_node" })]);
    const c = builtComparison(a, b);
    expect(c.leftObserverId).toBe("obs-a");
    expect(c.rightObserverId).toBe("obs-b");
    expect(c.disagreements[0]!.leftStatedKind).toBe("runtime_node");
    expect(c.disagreements[0]!.rightStatedKind).toBe("observed_node");
  });

  it("never declares a winner, a consensus, or a global truth", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1")]);
    const b = builtView("v-b", "obs-b", "2", [ent("n1", { kind: "observed_node" })]);
    const c = builtComparison(a, b);
    expect(c.winnerDeclared).toBe(false);
    expect(c.consensusAsserted).toBe(false);
    expect(c.isGlobalTruth).toBe(false);
    // No upstream governed resolution was supplied or acted upon, and the
    // output says so rather than leaving a reader to infer it.
    expect(c.governedResolutionSupplied).toBe(false);
    expect(c.authority).toBe("none");
    expect(c.readOnly).toBe(true);
    expect(c.bounded).toBe(true);
  });

  it("exposes no field that could rank observers or resolve a difference", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1")]);
    const b = builtView("v-b", "obs-b", "2", [ent("n1", { kind: "agent" })]);
    const c = builtComparison(a, b) as unknown as Record<string, unknown>;
    // Naming a field after a guarantee is fine — `winnerDeclared: false` IS the
    // guarantee. What must not exist is a field whose value NAMES an observer as
    // the right one, or whose value is anything but a structural `false`.
    for (const [key, value] of Object.entries(c)) {
      const k = key.toLowerCase();
      const mentions = ["winner", "consensus", "resolution", "verdict", "globaltruth", "authority", "correct", "preferred", "trustedobserver"];
      if (!mentions.some((m) => k.includes(m))) continue;
      // A structural zero may be spelled `false` or `"none"`; both are the same
      // promise. Anything else — a name, a score, a boolean true — would be a
      // ranking, and that is what must not exist.
      expect(["none", false], `"${key}" carries a ranking value: ${String(value)}`).toContain(value);
    }
    // And no field may hold an observer id in a slot that reads like a verdict.
    for (const forbidden of ["correctObserver", "preferredObserver", "authoritativeObserver", "resolution", "verdict"]) {
      expect(Object.prototype.hasOwnProperty.call(c, forbidden), `comparison exposes "${forbidden}"`).toBe(false);
    }
  });

  it("reports an observer agreeing with itself as all agreement", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1"), ent("n2")]);
    const c = builtComparison(a, a);
    expect(c.summary.disagreementCount).toBe(0);
    expect(c.summary.agreementCount).toBe(2);
  });
});

// ── scenario: stale-vs-current ───────────────────────────────────────────────

describe("28E — stale vs current: freshness and time decide nothing", () => {
  it("still reports the disagreement when only freshness and time differ in kind", () => {
    const stale = builtView("v-a", "obs-a", "1", [ent("n1", { freshness: "stale", kind: "runtime_node" })]);
    const fresh = builtView("v-b", "obs-b", "2", [ent("n1", { freshness: "current", kind: "observed_node" })]);
    const c = builtComparison(stale, fresh);
    expect(c.summary.disagreementCount).toBe(1);
    expect(c.disagreements[0]!.freshnessDecidesNothing).toBe(true);
  });

  it("does not prefer the fresher observer when both state the same kind", () => {
    const stale = builtView("v-a", "obs-a", "1", [ent("n1", { freshness: "stale" })]);
    const fresh = builtView("v-b", "obs-b", "2", [ent("n1", { freshness: "current" })]);
    const c = builtComparison(stale, fresh);
    expect(c.summary.agreementCount).toBe(1);
    expect(c.summary.disagreementCount).toBe(0);
    expect(c.winnerDeclared).toBe(false);
  });

  it("carries freshness onto the comparison entry without letting it rank", () => {
    const stale = builtView("v-a", "obs-a", "1", [ent("n1", { freshness: "stale" })]);
    const fresh = builtView("v-b", "obs-b", "2", [ent("n1", { freshness: "current" })]);
    const c = builtComparison(stale, fresh);
    expect(c.agreements[0]!.freshnessDecidesNothing).toBe(true);
  });
});

// ── scenario: terminal-vs-observed ───────────────────────────────────────────

describe("28E — terminal vs observed: a terminal fact cannot be visually resurrected", () => {
  it("marks the retired account terminal and the live one not", () => {
    const retired = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "retired" })]);
    const live = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "observed" })]);
    expect(retired.facts[0]!.isTerminal).toBe(true);
    expect(live.facts[0]!.isTerminal).toBe(false);
  });

  it("reports the divergence and sets the resurrection barrier", () => {
    const retired = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "retired" })]);
    const live = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "observed" })]);
    const c = builtComparison(retired, live);
    expect(c.summary.disagreementCount).toBe(1);
    expect(c.disagreements[0]!.terminalResurrectionBlocked).toBe(true);
    expect(c.terminalBarriers).toEqual(["entities:n1"]);
  });

  it("declares no winner even while blocking resurrection", () => {
    const retired = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "retired" })]);
    const live = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "observed" })]);
    const c = builtComparison(retired, live);
    // Blocking resurrection is not adjudicating: neither side is declared true.
    expect(c.winnerDeclared).toBe(false);
    expect(c.consensusAsserted).toBe(false);
    expect(c.disagreements[0]!.leftLifecycle).toBe("retired");
    expect(c.disagreements[0]!.rightLifecycle).toBe("observed");
  });

  it("treats quarantined as non-terminal but barred from resurrection", () => {
    const quarantined = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "quarantined" })]);
    expect(quarantined.facts[0]!.isTerminal).toBe(false);
    expect(quarantined.facts[0]!.isBarred).toBe(true);
    expect(quarantined.facts[0]!.lifecycle).toBe("quarantined");
  });

  it("reports a quarantined-vs-observed difference as a disagreement, not an agreement", () => {
    // Both observers state the SAME kind here. Comparing only the kind made this
    // an "agreement", which hides a real difference — the worst failure mode
    // available to this gate.
    const quarantined = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "quarantined" })]);
    const live = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "observed" })]);
    const c = builtComparison(quarantined, live);
    expect(c.summary.disagreementCount).toBe(1);
    expect(c.summary.agreementCount).toBe(0);
    expect(kindsOf(c.disagreements)).toEqual(["lifecycle_differs"]);
    expect(c.disagreements[0]!.leftLifecycle).toBe("quarantined");
    expect(c.disagreements[0]!.rightLifecycle).toBe("observed");
  });

  it("blocks resurrection of a quarantined fact, not only a retired one", () => {
    const quarantined = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "quarantined" })]);
    const live = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "observed" })]);
    const c = builtComparison(quarantined, live);
    expect(c.disagreements[0]!.terminalResurrectionBlocked).toBe(true);
    expect(c.terminalBarriers).toEqual(["entities:n1"]);
  });

  it("raises the quarantined barrier through a multi-view", () => {
    const quarantined = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "quarantined" })]);
    const live = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "observed" })]);
    const decision = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [quarantined, live] });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.multiView.terminalBarrierSubjects).toEqual(["entities:n1"]);
    expect(decision.multiView.terminalResurrected).toBe(false);
  });

  it("does not bar a difference between two unbarred lifecycles", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "observed" })]);
    const b = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "observed" })]);
    const c = builtComparison(a, b);
    expect(c.terminalBarriers).toEqual([]);
    expect(c.agreements[0]!.terminalResurrectionBlocked).toBe(false);
  });

  it("raises the barrier in a multi-view containing a retired and a live account", () => {
    const retired = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "retired" })]);
    const live = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "observed" })]);
    const decision = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [retired, live] });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.multiView.terminalBarrierSubjects).toEqual(["entities:n1"]);
    expect(decision.multiView.terminalResurrected).toBe(false);
  });
});

// ── scenario: unknown vs known ───────────────────────────────────────────────

describe("28E — unknown vs known", () => {
  it("is an UNKNOWN difference, never a disagreement", () => {
    const unknown = builtView("v-a", "obs-a", "1", [{ ...ent("n1"), kind: undefined }]);
    const known = builtView("v-b", "obs-b", "2", [ent("n1")]);
    const c = builtComparison(unknown, known);
    expect(c.summary.disagreementCount).toBe(0);
    expect(c.summary.unknownDifferenceCount).toBe(1);
    expect(kindsOf(c.unknownDifferences)).toEqual(["left_unknown"]);
  });

  it("does not count a subject only one observer saw as a disagreement", () => {
    // Absence is not ignorance and is certainly not conflict. Manufacturing
    // disagreement out of a gap is the mirror of manufacturing consensus.
    const a = builtView("v-a", "obs-a", "1", [ent("n1")]);
    const b = builtView("v-b", "obs-b", "2", [ent("n1"), ent("n9")]);
    const c = builtComparison(a, b);
    expect(c.summary.disagreementCount).toBe(0);
    expect(c.summary.unknownDifferenceCount).toBe(1);
    expect(kindsOf(c.unknownDifferences)).toEqual(["left_absent"]);
  });

  it("reports the right-side absence symmetrically", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1"), ent("n9")]);
    const b = builtView("v-b", "obs-b", "2", [ent("n1")]);
    expect(kindsOf(builtComparison(a, b).unknownDifferences)).toEqual(["right_absent"]);
  });

  it("keeps unknown differences out of the disagreement list entirely", () => {
    const unknown = builtView("v-a", "obs-a", "1", [{ ...ent("n1"), kind: undefined }]);
    const known = builtView("v-b", "obs-b", "2", [ent("n1"), ent("n9")]);
    const c = builtComparison(unknown, known);
    const inDisagreements = c.disagreements.map((e) => e.subjectVisibleId);
    for (const entry of c.unknownDifferences) expect(inDisagreements).not.toContain(entry.subjectVisibleId);
  });
});

// ── scenario: partition / rejoin ─────────────────────────────────────────────

describe("28E — partition and rejoin", () => {
  it("shows a partitioned peer disagreeing, without deciding who is right", () => {
    // During a partition the two observers see different worlds. After a rejoin
    // they may still differ, because nothing here performs reconciliation.
    const duringPartition = builtComparison(
      builtView("v-a", "obs-a", "1", [ent("n1"), ent("n2")]),
      builtView("v-b", "obs-b", "2", [ent("n1")]),
    );
    expect(duringPartition.summary.disagreementCount).toBe(0);
    expect(duringPartition.summary.unknownDifferenceCount).toBe(1);

    const afterRejoin = builtComparison(
      builtView("v-a", "obs-a", "3", [ent("n1"), ent("n2")]),
      builtView("v-b", "obs-b", "4", [ent("n1"), ent("n2", { kind: "observed_node" })]),
    );
    expect(afterRejoin.summary.disagreementCount).toBe(1);
    expect(afterRejoin.consensusAsserted).toBe(false);
  });

  it("never reports a rejoin as consensus", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1"), ent("n2")]);
    const b = builtView("v-b", "obs-b", "2", [ent("n1"), ent("n2")]);
    const c = builtComparison(a, b);
    expect(c.summary.agreementCount).toBe(2);
    // Two observers agreeing is not consensus; it is two accounts that match.
    expect(c.consensusAsserted).toBe(false);
    expect(c.isGlobalTruth).toBe(false);
  });

  it("keeps a retired fact retired across a rejoin", () => {
    const before = builtView("v-a", "obs-a", "1", [ent("n1", { lifecycle: "retired" })]);
    const after = builtView("v-b", "obs-b", "2", [ent("n1", { lifecycle: "retired" })]);
    const c = builtComparison(before, after);
    expect(c.terminalBarriers).toEqual([]);
    expect(after.facts[0]!.isTerminal).toBe(true);
  });
});

// ── scenario: shuffled observer order ────────────────────────────────────────

describe("28E — shuffled observer order", () => {
  const a = () => builtView("v-a", "obs-a", "1", [ent("n1"), ent("n2")]);
  const b = () => builtView("v-b", "obs-b", "2", [ent("n1"), ent("n2", { kind: "observed_node" })]);
  const c = () => builtView("v-c", "obs-c", "3", [ent("n1"), ent("n9")]);

  it("produces a byte-identical multi-view whatever order the views arrive in", () => {
    const forwards = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [a(), b(), c()] });
    const backwards = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [c(), b(), a()] });
    const middle = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [b(), a(), c()] });
    expect(forwards.ok && backwards.ok && middle.ok).toBe(true);
    if (!forwards.ok || !backwards.ok || !middle.ok) return;
    expect(JSON.stringify(forwards.multiView)).toBe(JSON.stringify(backwards.multiView));
    expect(JSON.stringify(forwards.multiView)).toBe(JSON.stringify(middle.multiView));
  });

  it("sorts observers by id so the order is a function of content, not of arrival", () => {
    const decision = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [c(), a(), b()] });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.multiView.observerIds).toEqual(["obs-a", "obs-b", "obs-c"]);
  });

  it("compares every pair exactly once", () => {
    const decision = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [a(), b(), c()] });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.multiView.comparisons).toHaveLength(3);
    const pairs = decision.multiView.comparisons.map((x) => `${x.leftObserverId}|${x.rightObserverId}`).sort();
    expect(pairs).toEqual(["obs-a|obs-b", "obs-a|obs-c", "obs-b|obs-c"]);
  });

  it("refuses the same observer appearing twice", () => {
    const decision = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [a(), a()] });
    expect(decision.ok).toBe(false);
    // Two views from one observer are one account, and showing it twice would
    // imply two independent opinions.
    if (!decision.ok) expect(decision.refusal).toBe("refused_multiview_duplicate_observer");
  });

  it("pins the multi-view's structural zeros", () => {
    const decision = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [a(), b()] });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.multiView.synthesizesGlobalTruth).toBe(false);
    expect(decision.multiView.terminalResurrected).toBe(false);
    expect(decision.multiView.authority).toBe("none");
    expect(decision.multiView.readOnly).toBe(true);
    expect(decision.multiView.bounded).toBe(true);
  });
});

// ── the synthesis guard ──────────────────────────────────────────────────────

describe("28E — several views never become one truth", () => {
  it("refuses to synthesise, whoever is asked and however many agree", () => {
    const result = refuseGlobalTruthSynthesis(["obs-a", "obs-b", "obs-c"], "the global view");
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe("refused_synthesis_not_permitted");
    expect(result.winnerDeclared).toBe(false);
    expect(result.consensusAsserted).toBe(false);
    expect(result.isGlobalTruth).toBe(false);
    expect(result.observerCount).toBe(3);
  });

  it("refuses for every input shape", () => {
    expect(refuseGlobalTruthSynthesis([]).ok).toBe(false);
    expect(refuseGlobalTruthSynthesis(null as never).ok).toBe(false);
    expect(refuseGlobalTruthSynthesis([1, 2] as never).observerCount).toBe(0);
    expect(refuseGlobalTruthSynthesis(["a"], "vote for a").ok).toBe(false);
  });

  it("names both central laws in its explanation", () => {
    const explanation = refuseGlobalTruthSynthesis(["a"]).explanation;
    expect(explanation).toContain("OBSERVER_VIEW != GLOBAL_TRUTH");
    expect(explanation).toContain("RECONCILIATION != CONSENSUS");
  });
});

// ── refusals ─────────────────────────────────────────────────────────────────

describe("28E — refusals", () => {
  it("refuses a comparison across different runtimes", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1")]);
    const other = buildGetigObserverView(viewInput("v-x", "obs-x", frameOf("obs-x", "2"), { runtimeId: "runtime-other" }));
    expect(other.ok).toBe(true);
    if (!other.ok) return;
    const decision = compareGetigObserverViews({ left: a, right: other.view });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_compare_cross_runtime");
  });

  it("refuses a comparison across different epochs", () => {
    const a = builtView("v-a", "obs-a", "1", [ent("n1")]);
    const other = buildGetigObserverView(viewInput("v-y", "obs-y", frameOf("obs-y", "2", {}, "epoch-other"), { epochId: "epoch-other" }));
    expect(other.ok).toBe(true);
    if (!other.ok) return;
    const decision = compareGetigObserverViews({ left: a, right: other.view });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_compare_cross_epoch");
  });

  it("refuses to compare something that is not a view", () => {
    for (const bad of [null, undefined, 42, "view", {}, { facts: "no" }, { facts: [], viewId: "v" }]) {
      const decision = compareGetigObserverViews({ left: bad, right: bad });
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_compare_not_a_view");
    }
  });

  it("refuses an empty or over-large view set", () => {
    const empty = buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [] });
    expect(empty.ok).toBe(false);
    if (!empty.ok) expect(empty.refusal).toBe("refused_multiview_input_invalid");
    const base = builtView("v", "obs-a", "1", [ent("n1")]);
    const tooMany = buildGetigMultiView({
      multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH,
      views: Array.from({ length: GETIG_VIEW_BOUNDS.maxViewsPerMultiView + 1 }, (_, i) => ({ ...base, viewId: `v${i}`, observerId: `o${i}` })),
    });
    expect(tooMany.ok).toBe(false);
    if (!tooMany.ok) expect(tooMany.refusal).toBe("refused_multiview_input_invalid");
  });

  it("refuses a view belonging to another runtime or epoch", () => {
    const base = builtView("v", "obs-a", "1", [ent("n1")]);
    const decision = buildGetigMultiView({ multiViewId: "mv", runtimeId: "runtime-other", epochId: EPOCH, views: [base] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_multiview_input_invalid");
  });

  it("exposes no partial output on refusal", () => {
    const bad = buildGetigObserverView(viewInput("v", "obs-a", frameOf("obs-a", "1", { entities: [{ kind: "x" }] })));
    expect(bad.ok).toBe(false);
    if (!bad.ok) {
      expect(Object.prototype.hasOwnProperty.call(bad, "view")).toBe(true);
      expect(bad.view).toBeNull();
      expect(bad.explanation).not.toBe(bad.refusal);
    }
    const badCmp = compareGetigObserverViews({ left: null, right: null });
    expect(badCmp.ok).toBe(false);
    if (!badCmp.ok) expect(badCmp.comparison).toBeNull();
  });

  it("bounds the fact count", () => {
    const many = Array.from({ length: GETIG_VIEW_BOUNDS.maxFactsPerView + 1 }, (_, i) => ent(`n${i}`));
    const decision = buildGetigObserverView(viewInput("v", "obs-a", frameOf("obs-a", "1", { entities: many })));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_view_frame_invalid");
  });
});

// ── law audits ───────────────────────────────────────────────────────────────

describe("28E — law audit: every declared refusal code is reachable", () => {
  it("drives all nine codes from real inputs and gets each one back", () => {
    const produced = new Map<string, string>();
    const record = (name: string, d: { ok: boolean; refusal?: string }) => {
      if (!d.ok) produced.set(d.refusal!, name);
    };
    const frame = frameOf("obs-a", "1");
    const ok = () => builtView("v", "obs-a", "1", [ent("n1")]);

    record("no observerId", buildGetigObserverView(viewInput("v", undefined as never, frame)));
    record("bad frame", buildGetigObserverView(viewInput("v", "obs-a", null)));
    record("bad subject", buildGetigObserverView(viewInput("v", "obs-a", frameOf("obs-a", "1", { entities: [{ kind: "x" }] }))));
    const otherRuntime = buildGetigObserverView(viewInput("v-x", "obs-x", frameOf("obs-x", "2"), { runtimeId: "runtime-other" }));
    record("cross runtime", compareGetigObserverViews({ left: ok(), right: otherRuntime.ok ? otherRuntime.view : {} }));
    const otherEpoch = buildGetigObserverView(viewInput("v-y", "obs-y", frameOf("obs-y", "2", {}, "epoch-other"), { epochId: "epoch-other" }));
    record("cross epoch", compareGetigObserverViews({ left: ok(), right: otherEpoch.ok ? otherEpoch.view : {} }));
    record("not a view", buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [{ nope: true }] }));
    record("bad input", buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [] }));
    record("duplicate", buildGetigMultiView({ multiViewId: "mv", runtimeId: RUNTIME, epochId: EPOCH, views: [ok(), ok()] }));
    record("synthesis", refuseGlobalTruthSynthesis(["obs-a"]));

    const unreachable = GETIG_VIEW_REFUSAL_CODES.filter((c) => !produced.has(c));
    expect(unreachable, `refusal codes no input can produce: ${unreachable.join(", ")}`).toEqual([]);
    expect(produced.size).toBe(GETIG_VIEW_REFUSAL_CODES.length);
  });

  it("has no duplicate refusal codes", () => {
    expect(new Set(GETIG_VIEW_REFUSAL_CODES).size).toBe(GETIG_VIEW_REFUSAL_CODES.length);
  });
});

describe("28E — law audit: no execution, network, renderer or policy path", () => {
  const FORBIDDEN_CAPABILITY = [
    "child_process", "node:child_process", "execSync", "spawnSync", "node:worker_threads",
    "node:net", "node:http", "node:fs", "WebGPU", "GPUDevice", "three.js", "@babylonjs",
    "playcanvas", "requestAnimationFrame", "eval(", "new Function", "@menog/policy", "@menog/runtime-linux",
  ] as const;

  const scan = (text: string): string[] => {
    const lower = text.toLowerCase();
    return FORBIDDEN_CAPABILITY.filter((token) => {
      const t = token.toLowerCase();
      if (/^[a-z0-9_]+$/.test(t)) return new RegExp(`\\b${t}\\b`).test(lower);
      return lower.includes(t);
    });
  };

  it("the capability scan actually detects a planted violation", () => {
    expect(scan("const cp = require('node:child_process')")).toEqual(["child_process", "node:child_process"]);
    expect(scan("import { evaluate } from '@menog/policy'")).toEqual(["@menog/policy"]);
    expect(scan("adapter = new GPUDevice()")).toEqual(["GPUDevice"]);
    expect(scan("the three axes are ordered")).toEqual([]);
  });

  it("finds no execution, network, renderer or policy capability in the source", () => {
    const found = scan(readSourceOrThrow(SRC_PATH));
    expect(found, `forbidden capabilities present: ${found.join(", ")}`).toEqual([]);
  });

  it("reports a non-empty audit input so the scan cannot pass vacuously", () => {
    const text = readSourceOrThrow(SRC_PATH);
    expect(text.length).toBeGreaterThan(2_000);
    expect(text).toContain("buildGetigObserverView");
    expect(text).toContain("refuseGlobalTruthSynthesis");
  });

  it("exports no mutating or executing function", () => {
    const decls = readSourceOrThrow(DTS_PATH);
    const exported = [...decls.matchAll(/export declare (?:function|const) (\w+)/g)].map((m) => m[1]!);
    expect(exported.length).toBeGreaterThan(0);
    const mutating = exported.filter((n) =>
      /^(apply|mutate|set|update|write|delete|remove|insert|patch|put|merge|synthesise|synthesize|resolve|adjudicate|elect|vote)$/i.test(n),
    );
    // `refuseGlobalTruthSynthesis` is allowed: it starts with `refuse` and can
    // only refuse, which is the whole point of it.
    expect(mutating, `mutating/synthesising exports present: ${mutating.join(", ")}`).toEqual([]);
  });

  it("names no colour or styling token in the emitted surface", () => {
    const surface = readSourceOrThrow(DTS_PATH).replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
    expect(surface.length).toBeGreaterThan(500);
    const found = ["color", "colour", "hue", "saturation", "palette", "gradient", "material", "shader"]
      .filter((t) => new RegExp(`\\b${t}\\b`, "i").test(surface));
    expect(found, `presentation tokens present: ${found.join(", ")}`).toEqual([]);
  });
});

describe("28E — law audit: closed vocabularies", () => {
  it("declares a terminal lifecycle state", () => {
    expect(GETIG_VIEW_LIFECYCLES).toEqual(["unknown", "retired", "quarantined", "observed"]);
  });

  it("has no duplicate entries in any vocabulary", () => {
    for (const v of [GETIG_VIEW_KNOWLEDGE, GETIG_VIEW_LIFECYCLES, GETIG_VIEW_FRESHNESS, GETIG_VIEW_DIVERGENCE_KINDS, GETIG_VIEW_OBSERVER_KINDS]) {
      expect(new Set(v).size).toBe(v.length);
    }
  });

  it("only ever emits values from the closed vocabularies", () => {
    const v = builtView("v", "obs-a", "1", [ent("n1", { lifecycle: "retired" }), ent("n2", { freshness: "stale" })]);
    for (const fact of v.facts) {
      expect(GETIG_VIEW_LIFECYCLES).toContain(fact.lifecycle);
      expect(GETIG_VIEW_FRESHNESS).toContain(fact.freshness);
      expect(GETIG_VIEW_KNOWLEDGE).toContain(fact.knowledge);
    }
  });

  it("falls back to unknown for an unrecognised vocabulary value rather than passing it through", () => {
    const v = builtView("v", "obs-a", "1", [{ ...ent("n1"), lifecycle: "extremely_fresh", freshness: "rather_fresh" }]);
    expect(v.facts[0]!.lifecycle).toBe("unknown");
    expect(v.facts[0]!.freshness).toBe("unknown");
  });

  it("separates absence, ignorance and disagreement in the closed kind vocabulary", () => {
    for (const kind of ["left_absent", "right_absent", "left_unknown", "right_unknown", "value_differs", "lifecycle_differs", "terminal_vs_live", "agreement"]) {
      expect(GETIG_VIEW_DIVERGENCE_KINDS).toContain(kind);
    }
  });

  it("marks retired and quarantined barred, and nothing else", () => {
    const barred = (lifecycle: string) =>
      builtView("v", "obs-a", "1", [ent("n1", { lifecycle })]).facts[0]!.isBarred;
    expect(barred("retired")).toBe(true);
    expect(barred("quarantined")).toBe(true);
    expect(barred("observed")).toBe(false);
    expect(barred("unknown")).toBe(false);
  });
});

// ── integration ──────────────────────────────────────────────────────────────

describe("28E — integration with real 28A frames", () => {
  const observer = { observerId: "obs-a", observerKind: "local_runtime" as const, epochId: EPOCH, isGlobalTruth: false as const };

  function realFrame28a(frameId: string, observerId: string, entities: GetigFrameInput["entities"]): GetigFrameInput {
    return { frameId, observer: { ...observer, observerId }, epochId: EPOCH, asOfEpochMs: NOW, sourceProjectionHash: hex("1"), entities } as GetigFrameInput;
  }

  function frame28a(frameId: string, observerId: string, entities: GetigFrameInput["entities"]) {
    const decision = buildGetigFrame(realFrame28a(frameId, observerId, entities));
    if (!decision.ok) throw new Error(`28A refused: ${decision.refusal}`);
    return decision.frame;
  }

  it("builds two real 28A views and compares them", () => {
    const a = buildGetigObserverView(viewInput("v-a", "obs-a", frame28a("frame-a", "obs-a", [ent("n1"), ent("n2")])));
    // `agent` is a real 28A entity kind; `observed_node` is not, and using it
    // would make 28A refuse the frame before 28E ever saw it.
    const b = buildGetigObserverView(viewInput("v-b", "obs-b", frame28a("frame-b", "obs-b", [ent("n1"), ent("n2", { kind: "agent" })])));
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    const c = builtComparison(a.view, b.view);
    expect(c.summary.disagreementCount).toBe(1);
    expect(c.winnerDeclared).toBe(false);
  });

  it("carries a real 28A frame's own visible hash into the view", () => {
    const f = frame28a("frame-a", "obs-a", [ent("n1")]);
    const v = buildGetigObserverView(viewInput("v-a", "obs-a", f));
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    expect(v.view.builtFromFrameId).toBe("frame-a");
    expect(v.view.builtFromVisibleHash).toBe(f.canonicalVisibleHash);
  });

  it("refuses a real 28A frame whose observer does not match the view's", () => {
    const f = frame28a("frame-a", "obs-a", [ent("n1")]);
    const decision = buildGetigObserverView(viewInput("v-b", "obs-b", f));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_view_frame_invalid");
  });

  it("still refuses to synthesise after building real views", () => {
    const a = buildGetigObserverView(viewInput("v-a", "obs-a", frame28a("frame-a", "obs-a", [ent("n1")])));
    const b = buildGetigObserverView(viewInput("v-b", "obs-b", frame28a("frame-b", "obs-b", [ent("n1")])));
    if (!a.ok || !b.ok) throw new Error("expected built views");
    expect(refuseGlobalTruthSynthesis([a.view.observerId, b.view.observerId]).ok).toBe(false);
  });
});