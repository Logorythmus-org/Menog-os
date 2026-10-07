/**
 * PHASE 29F — TEMPORAL RENDERING & ANIMATION — REGRESSION SUITE
 *
 * MODE: PRESENTATION TRANSITIONS ONLY / NO GPU / NO RUNTIME / NO DEPENDENCY.
 *
 * Central laws under test:
 *   ANIMATION != LIVE EXECUTION
 *   VISUAL_REPLAY != EXECUTABLE_REPLAY
 *
 * One describe block per pack requirement, so a failure names the law it broke:
 *   1. historical / observed_transition / interpolated_presentation / unknown classes
 *   2. interpolation creates no evidence
 *   3. unknown temporal order stays unknown
 *   4. no invented causality
 *   5. playback never resumes runtime
 *   6. animation cannot mutate GETIG/runtime
 *   7. deterministic transition plan
 *   8. bounded resources
 *   9. repaired real route anchors only
 *  10. no semantic rank strengthening
 *
 * The suite runs on the REAL frozen Phase-28 chain (28J scenario frames), not
 * on fixtures alone: the happy path must work over evidence that already
 * exists on disk. Synthetic frames are used only where the test needs an input
 * the frozen chain deliberately cannot produce (129 frames, 513 subjects,
 * synthetic route anchors) — and each such case asserts a REFUSAL, never a
 * successful plan over fake history.
 *
 * Every code in GETIG_TRANSITION_REFUSAL_CODES is driven from a real input and
 * compared as a SET against the vocabulary — a code nobody can reach, or a
 * behaviour with no code, both fail.
 */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  GETIG_DIFF_CLASSES,
  GETIG_FORBIDDEN_DIFF_FIELDS,
  GETIG_TRANSITION_BOUNDS,
  GETIG_TRANSITION_CLASSES,
  GETIG_TRANSITION_FORBIDDEN_PLAN_FIELDS,
  GETIG_TRANSITION_REFUSAL_CODES,
  GETIG_TRANSITION_STEP_KINDS,
  PHASE29F_FORBIDDEN_TOKENS,
  buildGetigFrameSequence,
  diffGetigFrames,
  planGetigTransitions,
  refuseTransitionPlaybackResume,
  refuseTransitionRuntimeMutation,
  runGetigEndToEndScenario,
  type GetigTransitionPlan,
  type GetigTransitionStep,
} from "../../packages/durable-state/src/index.js";
import * as plannerSurface from "../../packages/durable-state/src/temporalTransitionPlanner.js";
import { canonicalHash } from "../../packages/durable-state/src/canonical.js";

// ── the REAL frozen chain ─────────────────────────────────────────────────────

const scenario = runGetigEndToEndScenario();
if (!scenario.ok) throw new Error(`frozen Phase-28 scenario refused: ${scenario.refusal}`);
const FRAME = scenario.scenario.frame;
const LATER = scenario.scenario.frameLater;
const OBSERVER = FRAME.observer.observerId;
const EPOCH = FRAME.epochId;

type InputOver = Record<string, unknown>;
const baseInput = (over: InputOver = {}): Record<string, unknown> => ({
  planId: "plan-29f",
  sequenceId: "seq-29f",
  observerId: OBSERVER,
  epochId: EPOCH,
  orderingBasis: "observed_order",
  frames: [FRAME, LATER],
  interpolation: { enabled: false, stepsPerTransition: 0 },
  ...over,
});

const planOf = (over: InputOver = {}): GetigTransitionPlan => {
  const d = planGetigTransitions(baseInput(over));
  if (!d.ok) throw new Error(`expected a plan, got ${d.refusal}: ${d.explanation}`);
  return d.plan;
};

const refusalOf = (over: InputOver = {}): { refusal: string; explanation: string; upstreamRefusal: string | null } => {
  const d = planGetigTransitions(baseInput(over));
  if (d.ok) throw new Error(`expected a refusal, got a plan with ${d.plan.stepCount} steps`);
  return { refusal: d.refusal, explanation: d.explanation, upstreamRefusal: d.upstreamRefusal };
};

const hex64 = (seed: string): string => createHash("sha256").update(seed).digest("hex");

/** A frame-shaped input the 28C sequence builder accepts. NOT a real 28A frame. */
const syntheticFrame = (id: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  frameId: id,
  asOfEpochMs: 1_700_000_000_000,
  canonicalVisibleHash: hex64(`${id}:vis`),
  sourceProjectionHash: hex64(`${id}:src`),
  epochId: EPOCH,
  observer: { observerId: OBSERVER },
  ...extra,
});

const syntheticFrames = (count: number): Record<string, unknown>[] =>
  Array.from({ length: count }, (_, i) => syntheticFrame(`f${i}`));

const holds = (plan: GetigTransitionPlan): GetigTransitionStep[] =>
  plan.steps.filter((s) => s.stepClass === "historical");

/** Every key that appears anywhere in a JSON value — for forbidden-field scans. */
const collectKeys = (value: unknown, out: Set<string> = new Set()): Set<string> => {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, out);
  } else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      out.add(k);
      collectKeys(v, out);
    }
  }
  return out;
};

// ── source scanner (comments and string literals stripped, 29E technique) ─────

const stripLiterals = (src: string): string => {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i += 1;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") i += 1;
        i += 1;
      }
      i += 1;
      out += '""';
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
};

const MODULE_SRC = readFileSync(
  new URL("../../packages/durable-state/src/temporalTransitionPlanner.ts", import.meta.url),
  "utf8",
);
const MODULE_CODE = stripLiterals(MODULE_SRC);

// plans used across blocks (built once: they are pure functions of frozen input)
const OBSERVED = planOf({ interpolation: { enabled: true, stepsPerTransition: 3 } });
const PLAIN = planOf();
const UNKNOWN = planOf({ orderingBasis: "unknown" });

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-1 — historical / observed_transition / interpolated_presentation / unknown classes", () => {
  it("the class vocabulary is exactly the four the pack requires", () => {
    expect([...GETIG_TRANSITION_CLASSES]).toEqual([
      "historical",
      "observed_transition",
      "interpolated_presentation",
      "unknown",
    ]);
  });

  it("every step of every plan is one of the four classes and one of the three kinds", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      for (const step of plan.steps) {
        expect([...GETIG_TRANSITION_CLASSES]).toContain(step.stepClass);
        expect([...GETIG_TRANSITION_STEP_KINDS]).toContain(step.kind);
      }
    }
  });

  it("classCounts covers exactly the four classes and sums to stepCount", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      expect(Object.keys(plan.classCounts).sort()).toEqual([...GETIG_TRANSITION_CLASSES].sort());
      const sum = GETIG_TRANSITION_CLASSES.reduce((acc, c) => acc + plan.classCounts[c], 0);
      expect(sum).toBe(plan.stepCount);
      expect(plan.steps.length).toBe(plan.stepCount);
    }
  });

  it("the frozen observed plan exercises historical + observed_transition + interpolated_presentation", () => {
    expect(OBSERVED.classCounts.historical).toBe(2);
    expect(OBSERVED.classCounts.observed_transition).toBe(1);
    expect(OBSERVED.classCounts.interpolated_presentation).toBe(3);
    expect(OBSERVED.classCounts.unknown).toBe(0);
  });

  it("an unknown-order plan exercises the unknown class", () => {
    expect(UNKNOWN.classCounts.unknown).toBe(1);
    expect(UNKNOWN.classCounts.observed_transition).toBe(0);
    expect(UNKNOWN.classCounts.interpolated_presentation).toBe(0);
  });

  it("kind and class agree: holds are historical, transitions are observed or unknown, interpolations are interpolated_presentation", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      for (const step of plan.steps) {
        if (step.kind === "hold") expect(step.stepClass).toBe("historical");
        if (step.kind === "interpolated") expect(step.stepClass).toBe("interpolated_presentation");
        if (step.kind === "transition") {
          expect(step.stepClass === "observed_transition" || step.stepClass === "unknown").toBe(true);
        }
      }
    }
    const observedKinds = OBSERVED.steps.map((s) => s.kind).join(",");
    expect(observedKinds).toBe("hold,transition,interpolated,interpolated,interpolated,hold");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-2 — interpolation creates no evidence", () => {
  const interpolated = OBSERVED.steps.filter((s) => s.kind === "interpolated");

  it("every interpolated step carries NULL evidence — literal types, not conventions", () => {
    expect(interpolated.length).toBe(3);
    for (const step of interpolated) {
      if (step.kind !== "interpolated") throw new Error("unreachable");
      expect(step.observedVisibleHash).toBeNull();
      expect(step.sourceProjectionHash).toBeNull();
      expect(step.diff).toBeNull();
      expect(step.createsEvidence).toBe(false);
      expect(step.evidenceCreated).toBeNull();
    }
  });

  it("an interpolated step owns no frame id and no content hash of its own", () => {
    for (const step of interpolated) {
      const keys = Object.keys(step);
      expect(keys).not.toContain("frameId");
      expect(keys).not.toContain("canonicalVisibleHash");
      expect(keys).not.toContain("asOfEpochMs");
      expect(keys).not.toContain("position");
      // References to the ENDPOINTS are metadata, not observations.
      expect(keys).toContain("fromFrameId");
      expect(keys).toContain("toFrameId");
    }
  });

  it("fractions are exact rationals 1/k .. k/k — no floats, no rounding", () => {
    const fractions = interpolated.map((s) => (s.kind === "interpolated" ? s.fraction : null));
    expect(fractions).toEqual([
      { numerator: 1, denominator: 3 },
      { numerator: 2, denominator: 3 },
      { numerator: 3, denominator: 3 },
    ]);
  });

  it("the plan states interpolationCreatesEvidence: false once, at the top", () => {
    expect(OBSERVED.interpolationCreatesEvidence).toBe(false);
    expect(PLAIN.interpolationCreatesEvidence).toBe(false);
    expect(UNKNOWN.interpolationCreatesEvidence).toBe(false);
  });

  it("the interpolated count is exactly (frames-1) x stepsPerTransition", () => {
    const k = 5;
    const plan = planOf({ interpolation: { enabled: true, stepsPerTransition: k } });
    expect(plan.classCounts.interpolated_presentation).toBe(1 * k);
    expect(plan.interpolation).toEqual({ enabled: true, stepsPerTransition: k });
  });

  it("with interpolation disabled the plan says stepsPerTransition 0", () => {
    expect(PLAIN.interpolation).toEqual({ enabled: false, stepsPerTransition: 0 });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-3 — unknown temporal order stays unknown", () => {
  it("the plan carries the unknown basis and temporalOrderEstablished false", () => {
    expect(UNKNOWN.orderingBasis).toBe("unknown");
    expect(UNKNOWN.temporalOrderEstablished).toBe(false);
  });

  it("NO step is an observed_transition and NO step is interpolated", () => {
    expect(UNKNOWN.classCounts.observed_transition).toBe(0);
    expect(UNKNOWN.classCounts.interpolated_presentation).toBe(0);
    expect(UNKNOWN.steps.some((s) => s.stepClass === "observed_transition")).toBe(false);
    expect(UNKNOWN.steps.some((s) => s.stepClass === "interpolated_presentation")).toBe(false);
  });

  it("EVERY step — including holds — says temporalOrderEstablished false", () => {
    for (const step of UNKNOWN.steps) expect(step.temporalOrderEstablished).toBe(false);
  });

  it("asking to interpolate across an unknown order is REFUSED, not silently downgraded", () => {
    const r = refusalOf({ orderingBasis: "unknown", interpolation: { enabled: true, stepsPerTransition: 3 } });
    expect(r.refusal).toBe("refused_transition_interpolation_requires_observed_order");
    expect(r.explanation).toContain("unknown order stays unknown");
  });

  it("shuffled supplied order is NOT re-sorted into a pretended chronology", () => {
    const shuffled = planOf({ orderingBasis: "unknown", frames: [LATER, FRAME] });
    const shuffledIds = holds(shuffled).map((s) => (s.kind === "hold" ? s.frameId : ""));
    expect(shuffledIds).toEqual([LATER.frameId, FRAME.frameId]);
    // Same under observed_order: positions are as supplied, never sorted.
    const observedShuffled = planOf({ frames: [LATER, FRAME] });
    expect(holds(observedShuffled).map((s) => (s.kind === "hold" ? s.frameId : ""))).toEqual([
      LATER.frameId,
      FRAME.frameId,
    ]);
    expect(observedShuffled.steps.map((s) => s.stepIndex)).toEqual([0, 1, 2]);
  });

  it("an unknown-order ordering basis is not accepted from an unknown vocabulary member", () => {
    const r = refusalOf({ orderingBasis: "sort_of_chronological" });
    expect(r.refusal).toBe("refused_transition_input_invalid");
    expect(r.explanation).toContain("refusing rather than guessing an order");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-4 — no invented causality", () => {
  it("no key of a real plan (recursively) is a forbidden causal or promotion field", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      const keys = collectKeys(plan);
      const hits = [...keys].filter((k) =>
        (GETIG_TRANSITION_FORBIDDEN_PLAN_FIELDS as readonly string[]).includes(k),
      );
      expect(hits, `forbidden keys found in plan: ${hits.join(", ")}`).toEqual([]);
    }
  });

  it("the plan's causal list is 28C's list, reused — not a re-declared subset", () => {
    for (const field of GETIG_FORBIDDEN_DIFF_FIELDS) {
      expect([...GETIG_TRANSITION_FORBIDDEN_PLAN_FIELDS]).toContain(field);
    }
  });

  it("causalityClaimed is false on the plan and on every step", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      expect(plan.causalityClaimed).toBe(false);
      for (const step of plan.steps) expect(step.causalityClaimed).toBe(false);
    }
  });

  it("the carried diff reports WHAT differs and nothing about WHY", () => {
    const observedStep = OBSERVED.steps.find((s) => s.stepClass === "observed_transition");
    if (!observedStep || observedStep.kind !== "transition") throw new Error("no observed step");
    expect(observedStep.diff.causalityClaimed).toBe(false);
    for (const entry of observedStep.diff.entries) {
      expect(entry.classes.length).toBeGreaterThan(0);
      for (const c of entry.classes) expect([...GETIG_DIFF_CLASSES]).toContain(c);
    }
    const diffKeys = collectKeys(observedStep.diff);
    for (const field of GETIG_FORBIDDEN_DIFF_FIELDS) expect(diffKeys.has(field)).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-5 — playback never resumes runtime", () => {
  it("the playback guard can only refuse, under any input", () => {
    for (const id of ["plan-1", "", "x".repeat(500), "💥", 42 as unknown as string]) {
      const r = refuseTransitionPlaybackResume(id);
      expect(r.ok).toBe(false);
      expect(r.code).toBe("playback_refused");
      expect(r.refusal).toBe("refused_transition_playback_not_permitted");
      expect(r.resumedRuntimeState).toBe(false);
      expect(r.restoredRuntimeState).toBe(false);
      expect(r.explanation).toContain("ANIMATION != LIVE EXECUTION");
      expect([...GETIG_TRANSITION_REFUSAL_CODES]).toContain(r.refusal);
    }
  });

  it("the plan states playbackResumesRuntime false and restoresRuntimeState false", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      expect(plan.playbackResumesRuntime).toBe(false);
      expect(plan.restoresRuntimeState).toBe(false);
      expect(plan.replaySemantics).toBe("visual_history_not_executable");
    }
  });

  it("no step offers a resume surface", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      for (const step of plan.steps) {
        expect(Object.keys(step)).not.toContain("resumesRuntimeState");
        expect(Object.keys(step)).not.toContain("restoresState");
        expect(Object.keys(step)).not.toContain("applyTo");
      }
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-6 — animation cannot mutate GETIG/runtime (and contains no execution surface)", () => {
  it("the mutation guard can only refuse, under any input", () => {
    for (const id of ["plan-1", "", 7 as unknown as string]) {
      const r = refuseTransitionRuntimeMutation(id);
      expect(r.ok).toBe(false);
      expect(r.code).toBe("mutation_refused");
      expect(r.refusal).toBe("refused_transition_runtime_mutation_not_permitted");
      expect(r.mutatedGetig).toBe(false);
      expect(r.mutatedRuntime).toBe(false);
      expect([...GETIG_TRANSITION_REFUSAL_CODES]).toContain(r.refusal);
    }
  });

  it("the plan's structural zeros: no control plane, no authority, no execution", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      expect(plan.mutatesGetig).toBe(false);
      expect(plan.mutatesRuntime).toBe(false);
      expect(plan.animationIsLiveExecution).toBe(false);
      expect(plan.authority).toBe("none");
      expect(plan.controlPlane).toBe(false);
      expect(plan.readOnly).toBe(true);
      expect(plan.executionAuthorized).toBe(false);
      expect(plan.strengthensSemanticRank).toBe(false);
      for (const step of plan.steps) {
        expect(step.mutates).toBe(false);
        expect(step.authority).toBe("none");
        expect(step.presentationOnly).toBe(true);
      }
    }
  });

  it("the module exports EXACTLY one planner and two always-refusing guards — no apply/step/tick exists", () => {
    const fnNames = Object.entries(plannerSurface)
      .filter(([, v]) => typeof v === "function")
      .map(([k]) => k)
      .sort();
    expect(fnNames).toEqual(
      ["planGetigTransitions", "refuseTransitionPlaybackResume", "refuseTransitionRuntimeMutation"].sort(),
    );
  });

  it("the module's CODE contains no GPU token, animation driver, clock or randomness", () => {
    for (const token of PHASE29F_FORBIDDEN_TOKENS) {
      expect(MODULE_CODE, `module code must not contain "${token}"`).not.toContain(token);
    }
  });

  it("POSITIVE CONTROL: the token scan fires on a token really present in code", () => {
    const planted = "const x = { createRenderPipeline: 1 }; requestAnimationFrame(loop);";
    const hits = PHASE29F_FORBIDDEN_TOKENS.filter((t) => stripLiterals(planted).includes(t));
    expect(hits).toContain("createRenderPipeline");
    expect(hits).toContain("requestAnimationFrame");
  });

  it("POSITIVE CONTROL: comments alone must NOT trip the scan", () => {
    const commentOnly = "// never call navigator.gpu, setTimeout or Date.now here\nconst a = 1;\n";
    expect(PHASE29F_FORBIDDEN_TOKENS.filter((t) => stripLiterals(commentOnly).includes(t))).toEqual([]);
  });

  it("POSITIVE CONTROL: string literals alone must NOT trip the scan", () => {
    const literalOnly = 'const s = "queue.submit draw( Math.random";';
    expect(PHASE29F_FORBIDDEN_TOKENS.filter((t) => stripLiterals(literalOnly).includes(t))).toEqual([]);
  });

  it("the plan objects are frozen — an animation instruction cannot be edited after the fact", () => {
    expect(Object.isFrozen(OBSERVED)).toBe(true);
    expect(Object.isFrozen(OBSERVED.steps)).toBe(true);
    for (const step of OBSERVED.steps) expect(Object.isFrozen(step)).toBe(true);
    expect(Object.isFrozen(OBSERVED.routeAnchors)).toBe(true);
    expect(Object.isFrozen(OBSERVED.classCounts)).toBe(true);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-7 — deterministic transition plan", () => {
  it("the same input yields the same planHash and byte-identical JSON", () => {
    const again = planOf({ interpolation: { enabled: true, stepsPerTransition: 3 } });
    expect(again.planHash).toBe(OBSERVED.planHash);
    expect(JSON.stringify(again)).toBe(JSON.stringify(OBSERVED));
  });

  it("planHash is the canonical hash of the plan minus its own hash", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      const { planHash, ...rest } = plan;
      expect(canonicalHash(rest)).toBe(planHash);
      expect(planHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("a different input yields a different hash — the hash is not a constant", () => {
    const other = planOf({ planId: "plan-other" });
    expect(other.planHash).not.toBe(PLAIN.planHash);
    const otherFrames = planOf({ frames: [FRAME] });
    expect(otherFrames.planHash).not.toBe(PLAIN.planHash);
    const otherK = planOf({ interpolation: { enabled: true, stepsPerTransition: 4 } });
    expect(otherK.planHash).not.toBe(OBSERVED.planHash);
  });

  it("the sequence identity is the input's, not the plan's: it matches an independent 28C build", () => {
    const independent = buildGetigFrameSequence({
      sequenceId: "seq-29f",
      observerId: OBSERVER,
      epochId: EPOCH,
      orderingBasis: "observed_order",
      frames: [FRAME, LATER],
    });
    if (!independent.ok) throw new Error("independent sequence refused");
    expect(PLAIN.sequenceIdentity).toBe(independent.sequence.sequenceIdentity);
    expect(independent.sequence.sequenceIdentity).not.toBe(PLAIN.planHash);
  });

  it("the observed step carries 28C's diff VERBATIM (recomputed independently)", () => {
    const independent = diffGetigFrames(FRAME, LATER);
    if (!independent.ok) throw new Error("independent diff refused");
    const observedStep = OBSERVED.steps.find((s) => s.stepClass === "observed_transition");
    if (!observedStep || observedStep.kind !== "transition") throw new Error("no observed step");
    expect(JSON.stringify(observedStep.diff)).toBe(JSON.stringify(independent.diff));
  });

  it("an empty frame list plans an empty, valid, deterministic plan", () => {
    const empty = planOf({ frames: [] });
    expect(empty.stepCount).toBe(0);
    expect(empty.frameCount).toBe(0);
    expect(empty.classCounts).toEqual({
      historical: 0,
      observed_transition: 0,
      interpolated_presentation: 0,
      unknown: 0,
    });
    const emptyAgain = planOf({ frames: [] });
    expect(emptyAgain.planHash).toBe(empty.planHash);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-8 — bounded resources (overflow refuses, never truncates)", () => {
  it("more frames than the plan bound refuses", () => {
    const r = refusalOf({
      frames: syntheticFrames(GETIG_TRANSITION_BOUNDS.maxFramesPerPlan + 1),
      interpolation: { enabled: false, stepsPerTransition: 0 },
    });
    expect(r.refusal).toBe("refused_transition_bound_exceeded");
    expect(r.explanation).toContain("exceeds the plan bound");
  });

  it("interpolation wider than the per-transition bound refuses", () => {
    const r = refusalOf({
      interpolation: { enabled: true, stepsPerTransition: GETIG_TRANSITION_BOUNDS.maxInterpolationStepsPerTransition + 1 },
    });
    expect(r.refusal).toBe("refused_transition_bound_exceeded");
  });

  it("the predicted TOTAL step count refuses BEFORE building (n=128, k=63 exceeds 8192)", () => {
    const r = refusalOf({
      frames: syntheticFrames(128),
      interpolation: { enabled: true, stepsPerTransition: 63 },
    });
    expect(r.refusal).toBe("refused_transition_bound_exceeded");
    expect(r.explanation).toContain("steps, exceeding the bound");
    // 128 + 127 + 127*63 = 8256 > 8192 — the arithmetic, spelled out.
    expect(128 + 127 + 127 * 63).toBeGreaterThan(GETIG_TRANSITION_BOUNDS.maxStepsPerPlan);
  });

  it("one step under the bound still BUILDS: n=128, k=62 = 8129 steps, fully accounted", () => {
    const plan = planOf({
      frames: syntheticFrames(128),
      interpolation: { enabled: true, stepsPerTransition: 62 },
    });
    expect(plan.stepCount).toBe(8129);
    expect(plan.classCounts).toEqual({
      historical: 128,
      observed_transition: 127,
      interpolated_presentation: 127 * 62,
      unknown: 0,
    });
    expect(plan.stepCount).toBeLessThanOrEqual(GETIG_TRANSITION_BOUNDS.maxStepsPerPlan);
  });

  it("more unique route chains than the route bound refuses", () => {
    const frames = Array.from({ length: 128 }, (_, i) =>
      syntheticFrame(`f${i}`, {
        routes: Array.from({ length: 5 }, (_, j) => ({
          routeId: `r${i}-${j}`,
          originVisibleId: "n1",
          forwarderVisibleIds: ["n2"],
          destinationVisibleId: "n3",
        })),
      }),
    );
    const r = refusalOf({ frames });
    expect(r.refusal).toBe("refused_transition_bound_exceeded");
    expect(r.explanation).toContain("unique route chains");
  });

  it("malformed input refuses with refused_transition_input_invalid (never a partial plan)", () => {
    for (const raw of [
      null,
      "plan",
      42,
      {},
      { planId: "p" },
      baseInput({ sequenceId: "" }),
      baseInput({ observerId: undefined }),
      baseInput({ interpolation: undefined }),
      baseInput({ interpolation: { enabled: "yes", stepsPerTransition: 3 } }),
      baseInput({ interpolation: { enabled: true, stepsPerTransition: -1 } }),
      baseInput({ interpolation: { enabled: true, stepsPerTransition: 2.5 } }),
      baseInput({ interpolation: { enabled: true, stepsPerTransition: 0 } }),
      baseInput({ interpolation: { enabled: false, stepsPerTransition: 3 } }),
      baseInput({ frames: "not-an-array" }),
    ]) {
      const d = planGetigTransitions(raw);
      expect(d.ok, `expected refusal for ${JSON.stringify(raw)?.slice(0, 60)}`).toBe(false);
      if (d.ok) continue;
      expect(d.refusal).toBe("refused_transition_input_invalid");
      expect(d.plan).toBeNull();
      expect(d.explanation).toContain("no partial plan was produced");
    }
  });

  it("every refusal exposes NO partial plan and says so", () => {
    for (const r of [
      refusalOf({ frames: syntheticFrames(200) }),
      refusalOf({ orderingBasis: "unknown", interpolation: { enabled: true, stepsPerTransition: 2 } }),
      refusalOf({ frames: [FRAME, FRAME] }),
    ]) {
      expect(r.refusal).toMatch(/^refused_transition_/);
      expect(r.explanation).toContain("no partial plan was produced");
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-9 — repaired real route anchors only (29D-OBS-2 / 29R1 honoured)", () => {
  it("the frozen plan validates the REAL chain: route root -> origin -> forwarder -> destination", () => {
    expect(OBSERVED.routeAnchors.policy).toBe("repaired_real_only");
    expect(OBSERVED.routeAnchors.uniqueChains).toBe(1);
    expect(OBSERVED.routeAnchors.anchorsChecked).toBe(6); // 3 anchors x 2 frames
    const chain = OBSERVED.routeAnchors.chains[0];
    expect(chain).toBeDefined();
    if (!chain) return;
    expect(chain.routeId).toBe("route-28j-1");
    expect([...chain.anchorChain]).toEqual(["node-local", "node-relay", "node-remote"]);
    expect(chain.hopCount).toBe(2);
  });

  it("no plan output anywhere uses the synthetic route: namespace", () => {
    const json = JSON.stringify(OBSERVED);
    expect(json).not.toMatch(/route:(origin|forwarder|destination)/);
    for (const chain of OBSERVED.routeAnchors.chains) {
      expect(chain.routeId.startsWith("route:")).toBe(false);
      for (const anchor of chain.anchorChain) expect(anchor.startsWith("route:")).toBe(false);
    }
  });

  it("a synthetic anchor in an input frame REFUSES the whole plan", () => {
    const r = refusalOf({
      frames: [
        syntheticFrame("fa", {
          routes: [
            {
              routeId: "route-1",
              originVisibleId: "route:origin",
              forwarderVisibleIds: [],
              destinationVisibleId: "node-b",
            },
          ],
        }),
      ],
    });
    expect(r.refusal).toBe("refused_transition_route_anchor_synthetic");
    expect(r.explanation).toContain("route:origin");
  });

  it("a synthetic route ROOT also refuses", () => {
    const r = refusalOf({
      frames: [
        syntheticFrame("fa", {
          routes: [
            {
              routeId: "route:forwarder",
              originVisibleId: "node-a",
              forwarderVisibleIds: [],
              destinationVisibleId: "node-b",
            },
          ],
        }),
      ],
    });
    expect(r.refusal).toBe("refused_transition_route_anchor_synthetic");
  });

  it("a missing/unusable anchor refuses — a dropped route never becomes a silent gap", () => {
    for (const broken of [
      { originVisibleId: "", forwarderVisibleIds: [], destinationVisibleId: "node-b" },
      { forwarderVisibleIds: [], destinationVisibleId: "node-b" },
      { originVisibleId: "node-a", forwarderVisibleIds: "node-f", destinationVisibleId: "node-b" },
      { originVisibleId: "node-a", forwarderVisibleIds: [] },
      { originVisibleId: "node-a", forwarderVisibleIds: [], destinationVisibleId: 42 },
    ]) {
      const r = refusalOf({
        frames: [syntheticFrame("fa", { routes: [{ routeId: "r1", ...broken }] })],
      });
      expect(r.refusal).toBe("refused_transition_route_anchor_unresolved");
    }
  });

  it("a malformed routes collection refuses rather than being skipped", () => {
    const r = refusalOf({ frames: [syntheticFrame("fa", { routes: "not-an-array" })] });
    expect(r.refusal).toBe("refused_transition_route_anchor_unresolved");
    const r2 = refusalOf({ frames: [syntheticFrame("fa", { routes: [{ nope: true }] })] });
    expect(r2.refusal).toBe("refused_transition_route_anchor_unresolved");
  });

  it("identical chains across frames deduplicate; different chains stay separate", () => {
    expect(OBSERVED.routeAnchors.uniqueChains).toBe(1);
    const diverged = planOf({
      frames: [
        FRAME,
        {
          ...LATER,
          routes: [
            {
              ...LATER.routes[0],
              destinationVisibleId: "node-elsewhere",
            },
          ],
        },
      ],
    });
    expect(diverged.routeAnchors.uniqueChains).toBe(2);
    expect(diverged.routeAnchors.anchorsChecked).toBe(6);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-10 — no semantic rank strengthening", () => {
  it("no plan contains a semanticRank or rank-promotion field anywhere (recursively)", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      const keys = collectKeys(plan);
      expect(keys.has("semanticRank")).toBe(false);
      expect(keys.has("promotedRank")).toBe(false);
      expect(keys.has("rankStrengthened")).toBe(false);
      expect(keys.has("semanticRankOverride")).toBe(false);
      expect(keys.has("presentedValue")).toBe(false);
      expect(keys.has("semanticValue")).toBe(false);
    }
  });

  it("the plan's own JSON does not even contain the WORD semanticRank", () => {
    expect(JSON.stringify(OBSERVED)).not.toContain("semanticRank");
    expect(JSON.stringify(UNKNOWN)).not.toContain("semanticRank");
  });

  it("every step and the plan declare strengthensSemanticRank false", () => {
    for (const plan of [OBSERVED, PLAIN, UNKNOWN]) {
      expect(plan.strengthensSemanticRank).toBe(false);
      for (const step of plan.steps) expect(step.strengthensSemanticRank).toBe(false);
    }
  });

  it("interpolated steps carry no semantic value to promote", () => {
    const interpolated = OBSERVED.steps.filter((s) => s.kind === "interpolated");
    for (const step of interpolated) {
      const keys = Object.keys(step);
      expect(keys).not.toContain("semanticValue");
      expect(keys).not.toContain("presentedValue");
      expect(keys).not.toContain("tier");
      expect(keys).not.toContain("semanticRank");
    }
  });

  it("carried diff classes stay inside 28C's closed vocabulary — no new strength available", () => {
    const observedStep = OBSERVED.steps.find((s) => s.stepClass === "observed_transition");
    if (!observedStep || observedStep.kind !== "transition") throw new Error("no observed step");
    for (const entry of observedStep.diff.entries) {
      for (const c of entry.classes) expect([...GETIG_DIFF_CLASSES]).toContain(c);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29F-R — every declared refusal code is reachable from a real input (set equality)", () => {
  it("driven codes === declared codes: nothing unreachable, nothing undeclared", () => {
    const driven = new Set<string>();

    // refused_transition_input_invalid
    const nullInput = planGetigTransitions(null);
    expect(nullInput.ok).toBe(false);
    if (!nullInput.ok) driven.add(nullInput.refusal);

    // refused_transition_bound_exceeded
    const bound = refusalOf({ frames: syntheticFrames(129) });
    expect(bound.refusal).toBe("refused_transition_bound_exceeded");
    driven.add(bound.refusal);

    // refused_transition_interpolation_requires_observed_order
    const interp = refusalOf({
      orderingBasis: "unknown",
      interpolation: { enabled: true, stepsPerTransition: 2 },
    });
    expect(interp.refusal).toBe("refused_transition_interpolation_requires_observed_order");
    driven.add(interp.refusal);

    // refused_transition_sequence_refused (upstream 28C duplicate frame)
    const dup = refusalOf({ frames: [FRAME, FRAME] });
    expect(dup.refusal).toBe("refused_transition_sequence_refused");
    expect(dup.upstreamRefusal).toBe("refused_sequence_duplicate_frame");
    driven.add(dup.refusal);

    // refused_transition_diff_refused (upstream 28C retention bound: 513 > 512)
    const many = (tag: string): Record<string, unknown> =>
      syntheticFrame(`big-${tag}`, {
        entities: Array.from({ length: 513 }, (_, i) => ({ visibleId: `e${i}` })),
      });
    const bigDiff = refusalOf({ frames: [many("a"), many("b")] });
    expect(bigDiff.refusal).toBe("refused_transition_diff_refused");
    expect(bigDiff.upstreamRefusal).toBe("refused_sequence_retention_bound");
    driven.add(bigDiff.refusal);

    // refused_transition_route_anchor_synthetic
    const synth = refusalOf({
      frames: [
        syntheticFrame("fa", {
          routes: [
            { routeId: "r1", originVisibleId: "route:destination", forwarderVisibleIds: [], destinationVisibleId: "n2" },
          ],
        }),
      ],
    });
    expect(synth.refusal).toBe("refused_transition_route_anchor_synthetic");
    driven.add(synth.refusal);

    // refused_transition_route_anchor_unresolved
    const unres = refusalOf({
      frames: [
        syntheticFrame("fa", {
          routes: [{ routeId: "r1", originVisibleId: "", forwarderVisibleIds: [], destinationVisibleId: "n2" }],
        }),
      ],
    });
    expect(unres.refusal).toBe("refused_transition_route_anchor_unresolved");
    driven.add(unres.refusal);

    // refused_transition_playback_not_permitted
    const play = refuseTransitionPlaybackResume("p");
    expect(play.ok).toBe(false);
    driven.add(play.refusal);

    // refused_transition_runtime_mutation_not_permitted
    const mut = refuseTransitionRuntimeMutation("p");
    expect(mut.ok).toBe(false);
    driven.add(mut.refusal);

    expect([...driven].sort()).toEqual([...GETIG_TRANSITION_REFUSAL_CODES].sort());
  });

  it("the two guards refuse BEFORE any plan exists — they take no plan at all", () => {
    expect(refuseTransitionPlaybackResume("any").refusal).toBe(
      "refused_transition_playback_not_permitted",
    );
    expect(refuseTransitionRuntimeMutation("any").refusal).toBe(
      "refused_transition_runtime_mutation_not_permitted",
    );
  });
});
