/**
 * PHASE 29F — TEMPORAL RENDERING & ANIMATION
 * (TRANSITION PLANNING ONLY / PRESENTATION / NO EXECUTION)
 *
 * CENTRAL LAWS:
 *   ANIMATION != LIVE EXECUTION
 *   VISUAL_REPLAY != EXECUTABLE_REPLAY
 *
 * ── WHAT THIS MODULE IS ──────────────────────────────────────────────────────
 *
 * A bounded, deterministic planner that turns Phase-28 temporal frames and
 * their semantic diffs into an ordered PRESENTATION plan: which observed frame
 * is held, which observed change is shown, which in-between pictures are
 * synthesised purely for smooth display, and where the temporal order is not
 * known. A plan is a DESCRIPTION of what a viewer may show, in order. It runs
 * nothing, allocates nothing, draws nothing and changes nothing.
 *
 * ── WHY THE FOUR CLASSES ARE CLOSED AND LOAD-BEARING ─────────────────────────
 *
 *   · `historical`               — a HOLD of one observed frame. Its content
 *     was seen; the class claims nothing about what came before or after.
 *   · `observed_transition`      — the change between two adjacent OBSERVED
 *     frames in a sequence whose ordering basis is `observed_order`. It carries
 *     28C's diff VERBATIM: WHAT differs, never WHY, never "A caused B".
 *   · `interpolated_presentation`— an in-between picture synthesised only to
 *     make movement smooth. It creates NO evidence: no frame id, no visible
 *     hash, no source hash, no diff. An interpolated step cannot be cited as an
 *     observation of anything, because nothing was observed to produce it.
 *   · `unknown`                  — a step whose temporal placement could not be
 *     established (the sequence's ordering basis is `unknown`). Positions are
 *     exactly as supplied; no chronology is asserted; no interpolation is
 *     emitted across an unknown order, and asking for one is REFUSED.
 *
 * "Unknown stays unknown" is enforced structurally, not by convention: the
 * planner refuses `interpolation.enabled` when the ordering basis is not
 * `observed_order`, so there is no input that produces a smoothly moving
 * picture between frames whose order nobody established. Sorting frames to
 * make the animation look right would manufacture a history; positions are
 * therefore carried through exactly as 28C recorded them.
 *
 * ── WHY INTERPOLATION CAN NEVER BECOME EVIDENCE ──────────────────────────────
 *
 * An interpolated step's observable fields are `observedVisibleHash: null`,
 * `sourceProjectionHash: null`, `diff: null`, `evidenceCreated: null` and
 * `createsEvidence: false` — literal types, not conventions. It references its
 * two endpoint frames (references are metadata) but owns no content hash of its
 * own, so no downstream reader can mistake a generated picture for a recorded
 * one. The plan itself states `interpolationCreatesEvidence: false` once, at the
 * top, where a reader cannot miss it.
 *
 * ── WHY NO CAUSALITY CAN BE INVENTED ────────────────────────────────────────
 *
 * Every step carries `causalityClaimed: false`, and `GETIG_TRANSITION_FORBIDDEN_PLAN_FIELDS`
 * names the causal vocabulary (28C's list, reused rather than re-declared, plus
 * rank-promotion names). The suite scans the KEYS of a real plan against that
 * list — the law is checked against output, not against this comment.
 *
 * ── WHY PLAYBACK AND ANIMATION CANNOT TOUCH THE RUNTIME ──────────────────────
 *
 * The module exposes exactly three functions: the planner, and two guards that
 * can only REFUSE (`refuseTransitionPlaybackResume`,
 * `refuseTransitionRuntimeMutation`). There is no apply/commit/step/tick
 * function, no store import, no clock, no randomness and no GPU surface. The
 * refusal vocabulary itself says so: the two guard codes are DECLARED so the
 * laws "playback never resumes runtime" and "animation cannot mutate GETIG or
 * the runtime" are testable as reachable refusals rather than absent code.
 *
 * ── WHY ROUTE ANCHORS MUST BE THE REPAIRED REAL ONES ─────────────────────────
 *
 * 29D-OBS-2 was the defect where route endpoints were synthetic `route:<role>`
 * names binding to no drawable primitive; 29R1 repaired the compiler to derive
 * endpoints from the real chain (route root -> origin -> forwarder ->
 * destination). This planner honours that repair by ACCEPTING ONLY REAL
 * ANCHORS: any anchor (or route root) in the `route:` namespace is refused
 * (`refused_transition_route_anchor_synthetic`), and a route with a missing or
 * unusable anchor is refused (`refused_transition_route_anchor_unresolved`)
 * rather than skipped — a silently dropped route in an animation is how a
 * viewer ends up watching a journey that the evidence never showed. The plan
 * records the real chains it validated under `routeAnchors`, with policy
 * `repaired_real_only`.
 *
 * ── DETERMINISM AND BOUNDS ───────────────────────────────────────────────────
 *
 * The plan is a pure function of its input: no clock (`Date.now`,
 * `performance.now`), no randomness (`Math.random`) and no animation frame
 * callback (`requestAnimationFrame`) appear anywhere in the code. `planHash`
 * is 28A/22A's canonical hash over the plan minus its own hash, so the same
 * input yields the same hash on any machine. Every quantity is bounded before
 * it is built — frames, interpolation width, total steps, unique route chains —
 * and a bound that would be exceeded REFUSES the whole plan. There is no
 * truncation knob, because a truncated plan that still plays is a plan that
 * silently skipped part of the history.
 *
 * NO GPU TOKEN, NO ANIMATION DRIVER, NO STORE, NO CLOCK in this file; the
 * forbidden-token list below is scanned against the code (comments and string
 * literals stripped) by the suite.
 */

import { canonicalHash } from "./canonical.js";
import {
  GETIG_FORBIDDEN_DIFF_FIELDS,
  GETIG_SEQUENCE_ORDERING_BASES,
  buildGetigFrameSequence,
  diffGetigFrames,
  type GetigSequenceOrderingBasis,
  type SemanticDiff,
} from "./getigTemporalFrames.js";

// ── closed vocabularies ──────────────────────────────────────────────────────

/**
 * The four presentation classes. Closed: an unknown class fails CLOSED at the
 * type level, and the plan's `classCounts` can only speak these four words.
 */
export const GETIG_TRANSITION_CLASSES = Object.freeze([
  "historical",
  "observed_transition",
  "interpolated_presentation",
  "unknown",
] as const);
export type GetigTransitionClass = (typeof GETIG_TRANSITION_CLASSES)[number];

/** The three structural kinds of presentation step. */
export const GETIG_TRANSITION_STEP_KINDS = Object.freeze([
  "hold",
  "transition",
  "interpolated",
] as const);
export type GetigTransitionStepKind = (typeof GETIG_TRANSITION_STEP_KINDS)[number];

/**
 * 29F's refusals. Every code here is driven from a real input by the suite —
 * a declared code no input can produce would be worse than no code at all.
 */
export const GETIG_TRANSITION_REFUSAL_CODES = Object.freeze([
  "refused_transition_input_invalid",
  "refused_transition_bound_exceeded",
  "refused_transition_interpolation_requires_observed_order",
  "refused_transition_sequence_refused",
  "refused_transition_diff_refused",
  "refused_transition_route_anchor_synthetic",
  "refused_transition_route_anchor_unresolved",
  "refused_transition_playback_not_permitted",
  "refused_transition_runtime_mutation_not_permitted",
] as const);
export type GetigTransitionRefusalCode = (typeof GETIG_TRANSITION_REFUSAL_CODES)[number];

/**
 * Field names that would make a plan output a causal claim or a semantic-rank
 * promotion. 28C's causal list is IMPORTED (reused, not re-declared) and
 * extended with the rank-promotion names this gate must never emit. The suite
 * walks the keys of a real plan against this list.
 */
export const GETIG_TRANSITION_FORBIDDEN_PLAN_FIELDS = Object.freeze([
  ...GETIG_FORBIDDEN_DIFF_FIELDS,
  "semanticRank",
  "semanticRankOverride",
  "promotedRank",
  "rankStrengthened",
  "newEvidence",
  "evidenceContent",
] as const);
export type GetigTransitionForbiddenPlanField =
  (typeof GETIG_TRANSITION_FORBIDDEN_PLAN_FIELDS)[number];

/** Explicit bounds. A bound that would be exceeded REFUSES; nothing truncates. */
export const GETIG_TRANSITION_BOUNDS = Object.freeze({
  maxFramesPerPlan: 128,
  maxInterpolationStepsPerTransition: 64,
  maxStepsPerPlan: 8192,
  maxRouteAnchorChains: 512,
  maxIdChars: 128,
});
export type GetigTransitionBounds = typeof GETIG_TRANSITION_BOUNDS;

export const GETIG_TRANSITION_SCHEMA_VERSION =
  "menog-temporal-transition/v0" as const;

/**
 * Tokens that would mean this planner ran something: GPU creation/submission,
 * an animation driver, a clock, or randomness. Exported so the suite can scan
 * this file's CODE (comments and string literals stripped) for their absence —
 * and can plant one to prove the scanner fires.
 */
export const PHASE29F_FORBIDDEN_TOKENS = Object.freeze([
  "navigator",
  "requestAdapter",
  "requestDevice",
  "createBuffer",
  "createTexture",
  "createRenderPipeline",
  "createCommandEncoder",
  "queue.submit",
  "draw(",
  "dispatchWorkgroups",
  "copyTextureToBuffer",
  "mapAsync",
  "requestAnimationFrame",
  "setInterval",
  "setTimeout",
  "Date.now",
  "Math.random",
  "performance.now",
] as const);

// ── the shapes ───────────────────────────────────────────────────────────────

/** Documentation of the planner's input. The function itself takes `unknown`
 *  and validates fail-closed — the type never certifies caller input. */
export interface TransitionPlanInput {
  readonly planId: string;
  readonly sequenceId: string;
  readonly observerId: string;
  readonly epochId: string;
  readonly orderingBasis: GetigSequenceOrderingBasis;
  readonly frames: readonly unknown[];
  readonly interpolation: {
    readonly enabled: boolean;
    /** Must be 0 when `enabled` is false. Beyond the bound: refused. */
    readonly stepsPerTransition: number;
  };
}

interface TransitionStepBase {
  readonly stepIndex: number;
  /** `step:<i>:<detail>` — a pure function of position, never random. */
  readonly stepId: string;
  readonly kind: GetigTransitionStepKind;
  readonly stepClass: GetigTransitionClass;
  /**
   * Whether this step's placement in the plan means anything as TIME. False
   * for EVERY step when the ordering basis is `unknown` — including holds,
   * because with no established order there is no "when" for anything.
   */
  readonly temporalOrderEstablished: boolean;
  /** A step is a presentation instruction. It performs nothing. */
  readonly presentationOnly: true;
  readonly causalityClaimed: false;
  readonly strengthensSemanticRank: false;
  readonly mutates: false;
  readonly authority: "none";
}

/** A HOLD: one observed frame, shown as itself. */
export interface HistoricalHoldStep extends TransitionStepBase {
  readonly kind: "hold";
  readonly stepClass: "historical";
  readonly frameId: string;
  readonly position: number;
  readonly canonicalVisibleHash: string;
  readonly sourceProjectionHash: string;
  readonly asOfEpochMs: number;
}

/** The observed change between two adjacent frames of an ordered sequence. */
export interface ObservedTransitionStep extends TransitionStepBase {
  readonly kind: "transition";
  readonly stepClass: "observed_transition";
  readonly temporalOrderEstablished: true;
  readonly fromFrameId: string;
  readonly toFrameId: string;
  readonly fromPosition: number;
  readonly toPosition: number;
  /** 28C's diff, verbatim. WHAT differs — never why, never "caused by". */
  readonly diff: SemanticDiff;
}

/**
 * A synthesised in-between picture. The NULLS ARE THE LAW: this step owns no
 * observation, so nothing here can be quoted as evidence of anything.
 */
export interface InterpolatedPresentationStep extends TransitionStepBase {
  readonly kind: "interpolated";
  readonly stepClass: "interpolated_presentation";
  readonly temporalOrderEstablished: true;
  readonly fromFrameId: string;
  readonly toFrameId: string;
  /** Exact rational — never a float, never rounded, never locale-formatted. */
  readonly fraction: {
    readonly numerator: number;
    readonly denominator: number;
  };
  readonly observedVisibleHash: null;
  readonly sourceProjectionHash: null;
  readonly diff: null;
  readonly createsEvidence: false;
  readonly evidenceCreated: null;
}

/** A step between frames whose temporal relationship could not be established. */
export interface UnknownTransitionStep extends TransitionStepBase {
  readonly kind: "transition";
  readonly stepClass: "unknown";
  readonly temporalOrderEstablished: false;
  readonly fromFrameId: string;
  readonly toFrameId: string;
  readonly fromPosition: number;
  readonly toPosition: number;
  /**
   * The observed WHAT-differs may still be reported — 28C's diff is an
   * observation, not a chronology — but the step's class says the temporal
   * relationship between these frames is UNKNOWN, and says it first.
   */
  readonly diff: SemanticDiff | null;
}

export type GetigTransitionStep =
  | HistoricalHoldStep
  | ObservedTransitionStep
  | InterpolatedPresentationStep
  | UnknownTransitionStep;

/** One validated real route chain, in chain order: origin -> forwarders -> destination. */
export interface RouteAnchorChain {
  readonly routeId: string;
  readonly anchorChain: readonly string[];
  /** Number of hops: anchors minus one. */
  readonly hopCount: number;
}

export interface RouteAnchorReport {
  /** The only policy this planner accepts: 29R1's repaired real anchors. */
  readonly policy: "repaired_real_only";
  readonly uniqueChains: number;
  readonly anchorsChecked: number;
  readonly chains: readonly RouteAnchorChain[];
}

export interface GetigTransitionPlan {
  readonly schemaVersion: typeof GETIG_TRANSITION_SCHEMA_VERSION;
  readonly planId: string;
  readonly sequenceId: string;
  readonly observerId: string;
  readonly epochId: string;
  readonly orderingBasis: GetigSequenceOrderingBasis;
  readonly temporalOrderEstablished: boolean;
  /** The THIRD identity of the underlying 28C sequence, carried through. */
  readonly sequenceIdentity: string;
  readonly frameCount: number;
  readonly interpolation: {
    readonly enabled: boolean;
    /** 0 whenever interpolation did not run. */
    readonly stepsPerTransition: number;
  };
  readonly steps: readonly GetigTransitionStep[];
  readonly stepCount: number;
  readonly classCounts: Readonly<Record<GetigTransitionClass, number>>;
  readonly routeAnchors: RouteAnchorReport;
  readonly planHash: string;
  // ── the laws, stated once where a reader cannot miss them ──
  readonly replaySemantics: "visual_history_not_executable";
  readonly animationIsLiveExecution: false;
  readonly playbackResumesRuntime: false;
  readonly restoresRuntimeState: false;
  readonly mutatesGetig: false;
  readonly mutatesRuntime: false;
  readonly interpolationCreatesEvidence: false;
  readonly causalityClaimed: false;
  readonly strengthensSemanticRank: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly executionAuthorized: false;
}

// ── decisions ────────────────────────────────────────────────────────────────

export type TransitionPlanBuilt = {
  readonly ok: true;
  readonly code: "transition_plan_built";
  readonly plan: GetigTransitionPlan;
};

export type TransitionPlanRefused = {
  readonly ok: false;
  readonly code: "transition_plan_refused";
  readonly refusal: GetigTransitionRefusalCode;
  readonly explanation: string;
  /** The upstream 28C refusal code when this refusal pass-throughs one. */
  readonly upstreamRefusal: string | null;
  /** Fail-closed: a refusal exposes no partial plan. */
  readonly plan: null;
};

export type TransitionPlanDecision = TransitionPlanBuilt | TransitionPlanRefused;

// ── helpers ──────────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= GETIG_TRANSITION_BOUNDS.maxIdChars
  );
}

/**
 * The synthetic anchor namespace 29D-OBS-2 emitted and 29R1 repaired. Real
 * anchors are plain subject ids (node-local, ...); the `route:` namespace
 * names a ROLE, not a primitive, so it can never be an anchor here.
 */
const SYNTHETIC_ROUTE_ANCHOR = /^route:/;

const EMPTY_CLASS_COUNTS = (): Record<GetigTransitionClass, number> => ({
  historical: 0,
  observed_transition: 0,
  interpolated_presentation: 0,
  unknown: 0,
});

// ── the ONE planner ──────────────────────────────────────────────────────────

/**
 * Build a bounded, deterministic presentation plan from Phase-28 frames.
 *
 * Fail-closed throughout: any refusal returns `plan: null` and names its code.
 * The four pack laws this function must uphold are structural:
 * interpolation emits null evidence, unknown order refuses interpolation,
 * diffs are carried verbatim (no causal field exists in the step shape), and
 * route anchors must be real or the whole plan is refused.
 */
export function planGetigTransitions(input: unknown): TransitionPlanDecision {
  const refuse = (
    refusal: GetigTransitionRefusalCode,
    detail: string,
    upstreamRefusal: string | null = null,
  ): TransitionPlanRefused => ({
    ok: false,
    code: "transition_plan_refused",
    refusal,
    explanation: `the transition plan was refused and no partial plan was produced: ${detail}`,
    upstreamRefusal,
    plan: null,
  });

  // ── 1. input shape ──
  if (!isRecord(input)) {
    return refuse("refused_transition_input_invalid", "the planner input must be an object");
  }
  if (!isId(input.planId)) {
    return refuse("refused_transition_input_invalid", "planId is missing or over-long");
  }
  if (!isId(input.sequenceId)) {
    return refuse("refused_transition_input_invalid", "sequenceId is missing or over-long");
  }
  if (!isId(input.observerId)) {
    return refuse("refused_transition_input_invalid", "observerId is missing or over-long");
  }
  if (!isId(input.epochId)) {
    return refuse("refused_transition_input_invalid", "epochId is missing or over-long");
  }
  const orderingBasis = input.orderingBasis;
  if (!(GETIG_SEQUENCE_ORDERING_BASES as readonly string[]).includes(String(orderingBasis))) {
    return refuse(
      "refused_transition_input_invalid",
      `"${String(orderingBasis)}" is not an ordering basis; refusing rather than guessing an order`,
    );
  }
  const framesRaw: unknown = input.frames;
  if (!Array.isArray(framesRaw)) {
    return refuse("refused_transition_input_invalid", "frames must be an array");
  }
  const frames: unknown[] = framesRaw;

  // ── 2. bounds, checked BEFORE anything is built ──
  if (frames.length > GETIG_TRANSITION_BOUNDS.maxFramesPerPlan) {
    return refuse(
      "refused_transition_bound_exceeded",
      `${frames.length} frames exceeds the plan bound of ${GETIG_TRANSITION_BOUNDS.maxFramesPerPlan}`,
    );
  }

  // ── 3. interpolation request ──
  const interp = input.interpolation;
  if (!isRecord(interp)) {
    return refuse("refused_transition_input_invalid", "interpolation must be an object");
  }
  if (typeof interp.enabled !== "boolean") {
    return refuse("refused_transition_input_invalid", "interpolation.enabled must be a boolean");
  }
  const k = interp.stepsPerTransition;
  if (typeof k !== "number" || !Number.isInteger(k) || k < 0) {
    return refuse(
      "refused_transition_input_invalid",
      "interpolation.stepsPerTransition must be a non-negative integer",
    );
  }
  if (interp.enabled && k === 0) {
    return refuse(
      "refused_transition_input_invalid",
      "interpolation is enabled but stepsPerTransition is 0",
    );
  }
  if (!interp.enabled && k !== 0) {
    return refuse(
      "refused_transition_input_invalid",
      "interpolation.stepsPerTransition must be 0 when interpolation is disabled",
    );
  }
  if (k > GETIG_TRANSITION_BOUNDS.maxInterpolationStepsPerTransition) {
    return refuse(
      "refused_transition_bound_exceeded",
      `${k} interpolation steps exceeds the per-transition bound of ${GETIG_TRANSITION_BOUNDS.maxInterpolationStepsPerTransition}`,
    );
  }

  const established = orderingBasis === "observed_order";
  // The law "unknown temporal order stays unknown" as a REFUSAL: you cannot
  // ask for synthesised in-between pictures between frames nobody ordered.
  if (interp.enabled && !established) {
    return refuse(
      "refused_transition_interpolation_requires_observed_order",
      "interpolation was requested but the ordering basis is not observed_order; an unknown order stays unknown and is never smoothed over",
    );
  }

  const n = frames.length;
  const predictedSteps =
    n === 0
      ? 0
      : established
        ? n + (n - 1) + (interp.enabled ? (n - 1) * k : 0)
        : n + (n - 1);
  if (predictedSteps > GETIG_TRANSITION_BOUNDS.maxStepsPerPlan) {
    return refuse(
      "refused_transition_bound_exceeded",
      `the plan would contain ${predictedSteps} steps, exceeding the bound of ${GETIG_TRANSITION_BOUNDS.maxStepsPerPlan}`,
    );
  }

  // ── 4. route anchors: REAL ones only (29R1's repair honoured here) ──
  const chainByKey = new Map<string, RouteAnchorChain>();
  let anchorsChecked = 0;
  for (let i = 0; i < frames.length; i += 1) {
    const frame: unknown = frames[i];
    if (!isRecord(frame)) continue; // the sequence builder refuses this below
    const routes: unknown = frame.routes;
    if (routes === undefined) continue; // a frame without routes carries no anchors
    if (!Array.isArray(routes)) {
      return refuse(
        "refused_transition_route_anchor_unresolved",
        `frames[${i}].routes is not an array`,
      );
    }
    for (let r = 0; r < routes.length; r += 1) {
      const route: unknown = routes[r];
      if (!isRecord(route)) {
        return refuse(
          "refused_transition_route_anchor_unresolved",
          `frames[${i}].routes[${r}] is not a route`,
        );
      }
      if (!isId(route.routeId)) {
        return refuse(
          "refused_transition_route_anchor_unresolved",
          `frames[${i}].routes[${r}] has no usable routeId`,
        );
      }
      if (SYNTHETIC_ROUTE_ANCHOR.test(route.routeId)) {
        return refuse(
          "refused_transition_route_anchor_synthetic",
          `route root "${route.routeId}" uses the synthetic route: namespace, which names a role rather than a drawable primitive`,
        );
      }
      const forwarders: unknown = route.forwarderVisibleIds;
      if (!Array.isArray(forwarders)) {
        return refuse(
          "refused_transition_route_anchor_unresolved",
          `frames[${i}].routes[${r}] has no usable forwarderVisibleIds`,
        );
      }
      // origin -> forwarders -> destination: 29R1's chain, by field structure.
      const anchors: unknown[] = [route.originVisibleId, ...forwarders, route.destinationVisibleId];
      for (let a = 0; a < anchors.length; a += 1) {
        const anchor: unknown = anchors[a];
        if (typeof anchor === "string" && SYNTHETIC_ROUTE_ANCHOR.test(anchor)) {
          return refuse(
            "refused_transition_route_anchor_synthetic",
            `anchor "${anchor}" of route "${route.routeId}" is synthetic; only 29R1's repaired real anchors are accepted`,
          );
        }
        if (!isId(anchor)) {
          return refuse(
            "refused_transition_route_anchor_unresolved",
            `anchor at index ${a} of route "${route.routeId}" in frames[${i}] is missing or unusable`,
          );
        }
      }
      anchorsChecked += anchors.length;
      const key = JSON.stringify([route.routeId, anchors]);
      if (!chainByKey.has(key)) {
        chainByKey.set(key, {
          routeId: route.routeId,
          anchorChain: Object.freeze([...(anchors as string[])]),
          hopCount: anchors.length - 1,
        });
        Object.freeze(chainByKey.get(key));
      }
      if (chainByKey.size > GETIG_TRANSITION_BOUNDS.maxRouteAnchorChains) {
        return refuse(
          "refused_transition_bound_exceeded",
          `more than ${GETIG_TRANSITION_BOUNDS.maxRouteAnchorChains} unique route chains across the plan's frames`,
        );
      }
    }
  }

  // ── 5. the 28C sequence, upstream and authoritative ──
  const sequenceDecision = buildGetigFrameSequence({
    sequenceId: input.sequenceId,
    observerId: input.observerId,
    epochId: input.epochId,
    orderingBasis: orderingBasis as GetigSequenceOrderingBasis,
    frames,
  });
  if (!sequenceDecision.ok) {
    return refuse(
      "refused_transition_sequence_refused",
      sequenceDecision.explanation,
      sequenceDecision.refusal,
    );
  }
  const sequence = sequenceDecision.sequence;

  // ── 6. steps, in the order the frames were SUPPLIED ──
  const steps: GetigTransitionStep[] = [];
  const classCounts = EMPTY_CLASS_COUNTS();
  const push = (step: GetigTransitionStep): void => {
    steps.push(Object.freeze(step));
    classCounts[step.stepClass] += 1;
  };

  const entries = sequence.entries;
  for (const [i, entry] of entries.entries()) {
    // HOLD — the observed frame, shown as itself.
    push({
      stepIndex: steps.length,
      stepId: `step:${i}:hold`,
      kind: "hold",
      stepClass: "historical",
      temporalOrderEstablished: entry.temporalOrderEstablished,
      presentationOnly: true,
      causalityClaimed: false,
      strengthensSemanticRank: false,
      mutates: false,
      authority: "none",
      frameId: entry.frameId,
      position: entry.position,
      canonicalVisibleHash: entry.canonicalVisibleHash,
      sourceProjectionHash: entry.sourceProjectionHash,
      asOfEpochMs: entry.asOfEpochMs,
    });

    if (i + 1 >= entries.length) continue;
    const next = entries[i + 1];
    const from: unknown = frames[i];
    const to: unknown = frames[i + 1];
    if (next === undefined || !isRecord(from) || !isRecord(to)) {
      return refuse(
        "refused_transition_input_invalid",
        "frames changed shape after sequence construction",
      );
    }

    const diffDecision = diffGetigFrames(from, to);
    if (!diffDecision.ok) {
      return refuse(
        "refused_transition_diff_refused",
        diffDecision.explanation,
        diffDecision.refusal,
      );
    }
    const diff = diffDecision.diff;
    // Deep-freeze the fresh diff so a step cannot be edited after the fact.
    for (const diffEntry of diff.entries) Object.freeze(diffEntry);

    if (established) {
      // OBSERVED TRANSITION — 28C's diff, verbatim, between adjacent frames.
      push({
        stepIndex: steps.length,
        stepId: `step:${i}:to:${i + 1}`,
        kind: "transition",
        stepClass: "observed_transition",
        temporalOrderEstablished: true,
        presentationOnly: true,
        causalityClaimed: false,
        strengthensSemanticRank: false,
        mutates: false,
        authority: "none",
        fromFrameId: entry.frameId,
        toFrameId: next.frameId,
        fromPosition: entry.position,
        toPosition: next.position,
        diff,
      });

      // INTERPOLATED PRESENTATION — display-only, evidence-free, exact rationals.
      if (interp.enabled) {
        for (let j = 1; j <= k; j += 1) {
          push({
            stepIndex: steps.length,
            stepId: `step:${i}:interp:${j}`,
            kind: "interpolated",
            stepClass: "interpolated_presentation",
            temporalOrderEstablished: true,
            presentationOnly: true,
            causalityClaimed: false,
            strengthensSemanticRank: false,
            mutates: false,
            authority: "none",
            fromFrameId: entry.frameId,
            toFrameId: next.frameId,
            fraction: Object.freeze({ numerator: j, denominator: k }),
            observedVisibleHash: null,
            sourceProjectionHash: null,
            diff: null,
            createsEvidence: false,
            evidenceCreated: null,
          });
        }
      }
    } else {
      // UNKNOWN — order not established: the step says so, and says it first.
      push({
        stepIndex: steps.length,
        stepId: `step:${i}:to:${i + 1}`,
        kind: "transition",
        stepClass: "unknown",
        temporalOrderEstablished: false,
        presentationOnly: true,
        causalityClaimed: false,
        strengthensSemanticRank: false,
        mutates: false,
        authority: "none",
        fromFrameId: entry.frameId,
        toFrameId: next.frameId,
        fromPosition: entry.position,
        toPosition: next.position,
        diff,
      });
    }
  }

  // Belt and braces: the count was predicted, and is re-checked after the
  // build so a future edit that miscalculates fails closed instead of shipping.
  if (steps.length > GETIG_TRANSITION_BOUNDS.maxStepsPerPlan) {
    return refuse(
      "refused_transition_bound_exceeded",
      `the plan contains ${steps.length} steps, exceeding the bound of ${GETIG_TRANSITION_BOUNDS.maxStepsPerPlan}`,
    );
  }

  const routeChains = [...chainByKey.values()];
  const base = {
    schemaVersion: GETIG_TRANSITION_SCHEMA_VERSION,
    planId: input.planId,
    sequenceId: input.sequenceId,
    observerId: input.observerId,
    epochId: input.epochId,
    orderingBasis: orderingBasis as GetigSequenceOrderingBasis,
    temporalOrderEstablished: established,
    sequenceIdentity: sequence.sequenceIdentity,
    frameCount: sequence.frameCount,
    interpolation: Object.freeze({
      enabled: interp.enabled === true,
      stepsPerTransition: interp.enabled ? k : 0,
    }),
    steps: Object.freeze(steps),
    stepCount: steps.length,
    classCounts: Object.freeze({ ...classCounts }),
    routeAnchors: Object.freeze({
      policy: "repaired_real_only" as const,
      uniqueChains: routeChains.length,
      anchorsChecked,
      chains: Object.freeze(routeChains),
    }),
    replaySemantics: "visual_history_not_executable" as const,
    animationIsLiveExecution: false as const,
    playbackResumesRuntime: false as const,
    restoresRuntimeState: false as const,
    mutatesGetig: false as const,
    mutatesRuntime: false as const,
    interpolationCreatesEvidence: false as const,
    causalityClaimed: false as const,
    strengthensSemanticRank: false as const,
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    executionAuthorized: false as const,
  };
  // The plan's own hash never includes itself (22A discipline).
  const planHash = canonicalHash(base);

  return {
    ok: true,
    code: "transition_plan_built",
    plan: Object.freeze({ ...base, planHash }),
  };
}

// ── the two always-refusing guards ───────────────────────────────────────────

/**
 * Playback NEVER resumes runtime state.
 *
 * The only navigation-adjacent export of this module, and it cannot succeed
 * under any input. Watching an animation play selects which visible frames are
 * LOOKED AT, in order. That is a read. Re-entering runtime state is not a
 * read, and no code path here could attempt it — the guard exists so the law
 * is TESTABLE rather than merely absent.
 */
export function refuseTransitionPlaybackResume(planId: string): {
  readonly ok: false;
  readonly code: "playback_refused";
  readonly refusal: "refused_transition_playback_not_permitted";
  readonly explanation: string;
  readonly planId: string;
  readonly resumedRuntimeState: false;
  readonly restoredRuntimeState: false;
} {
  return {
    ok: false,
    code: "playback_refused",
    refusal: "refused_transition_playback_not_permitted",
    explanation:
      "playing a transition plan selects which visible frames are LOOKED AT and in what order; it never restores, resumes or re-enters runtime state. ANIMATION != LIVE EXECUTION and VISUAL_REPLAY != EXECUTABLE_REPLAY.",
    planId: typeof planId === "string" ? planId : "",
    resumedRuntimeState: false,
    restoredRuntimeState: false,
  };
}

/**
 * Animation CANNOT mutate GETIG or the runtime.
 *
 * The second always-refusing guard. A plan is a description; there is no
 * apply/commit/step/tick function in this module, no store import and no
 * dispatch surface, so nothing could carry an animated frame into state. The
 * guard gives the law an exit code the suite can drive.
 */
export function refuseTransitionRuntimeMutation(planId: string): {
  readonly ok: false;
  readonly code: "mutation_refused";
  readonly refusal: "refused_transition_runtime_mutation_not_permitted";
  readonly explanation: string;
  readonly planId: string;
  readonly mutatedGetig: false;
  readonly mutatedRuntime: false;
} {
  return {
    ok: false,
    code: "mutation_refused",
    refusal: "refused_transition_runtime_mutation_not_permitted",
    explanation:
      "a transition plan is a presentation description; applying it to GETIG or to the runtime is not permitted. This module exposes no mutation function, no store, no dispatch and no GPU surface, so an animated frame can never become a durable one.",
    planId: typeof planId === "string" ? planId : "",
    mutatedGetig: false,
    mutatedRuntime: false,
  };
}
