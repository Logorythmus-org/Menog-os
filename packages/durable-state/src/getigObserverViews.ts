/**
 * PHASE 28E — OBSERVER-RELATIVE WORLD VIEWS
 * (MULTI-VIEW / NO GLOBAL TRUTH SYNTHESIS / ATTRIBUTED / ZERO-AUTHORITY)
 *
 * CENTRAL LAWS:
 *   OBSERVER_VIEW != GLOBAL_TRUTH
 *   RECONCILIATION != CONSENSUS
 *
 * Two observers can see the same runtime differently. That is the normal case,
 * not an error to be smoothed over. This module holds several observers' views
 * side by side, compares them, and reports every disagreement WITH ITS
 * ATTRIBUTION — while refusing, always, to say which observer is right.
 *
 * ── WHY NO WINNER ───────────────────────────────────────────────────────────
 *
 * Picking a winner needs evidence. "A is more recent than B" is not that
 * evidence: a fresher observation is not a truer one, and time alone decides
 * nothing here. So:
 *
 *   · `compareGetigObserverViews()` emits `winnerDeclared: false` structurally.
 *     There is no field to set and no code path that picks one.
 *   · `refuseGlobalTruthSynthesis()` is the ONLY synthesis-adjacent export and
 *     it cannot succeed under any input.
 *
 * The one exception the prompt names — "unless upstream governed evidence
 * explicitly supplies one" — is not implemented here, and that is deliberate.
 * Acting on such evidence is adjudication, which is a later gate's job and not
 * this one's. What this gate does is refuse to pretend the exception was
 * checked: `governedResolutionSupplied` is a structural `false` on every
 * comparison, so a reader can see that no adjudication was performed rather
 * than inferring that one was considered and found unnecessary.
 *
 * ── ABSENCE IS NOT DISAGREEMENT ──────────────────────────────────────────────
 *
 * If observer A does not mention a subject, that is an UNKNOWN DIFFERENCE, not
 * a disagreement. A disagreement is two observers both saying something known
 * and saying different things. Collapsing the two would manufacture conflict
 * out of a gap — which is the mirror image of manufacturing consensus out of a
 * gap, and just as wrong.
 *
 * ── TERMINAL FACTS CANNOT BE VISUALLY RESURRECTED ───────────────────────────
 *
 * Blocking resurrection is NOT adjudicating. When one observer reports a
 * subject `retired` and another reports it `observed`, this module reports the
 * divergence, attributes both sides, declares no winner, and marks the subject
 * as barred so no downstream display can present it as live. The retired
 * account is not declared TRUE and the observed account is not declared FALSE —
 * the pair simply refuses to collapse.
 *
 * `quarantined` is barred alongside `retired`. It is not terminal — a
 * quarantined thing may yet be released — but a quarantined fact still may not
 * be presented as healthy, and that is a display law rather than a truth claim.
 *
 * ── MANDATORY CONTEXT ───────────────────────────────────────────────────────
 *
 * A view without an observer, a runtime and an epoch is not a view; it is a
 * shape that could be mistaken for one. All three are required, and views from
 * different epochs or runtimes cannot be compared at all.
 */

import { canonicalHash } from "./canonical.js";

// ── closed vocabularies ──────────────────────────────────────────────────────

export const GETIG_VIEW_KNOWLEDGE = Object.freeze(["unknown", "known"] as const);
export type GetigViewKnowledge = (typeof GETIG_VIEW_KNOWLEDGE)[number];

/** `retired` is TERMINAL: a retired fact is never visually resurrected. */
export const GETIG_VIEW_LIFECYCLES = Object.freeze(["unknown", "retired", "quarantined", "observed"] as const);
export type GetigViewLifecycle = (typeof GETIG_VIEW_LIFECYCLES)[number];

export const GETIG_VIEW_FRESHNESS = Object.freeze(["unknown", "stale", "current"] as const);
export type GetigViewFreshness = (typeof GETIG_VIEW_FRESHNESS)[number];

/**
 * How two observers' accounts of one subject relate. Deliberately closed and
 * deliberately NOT a quality ranking: none of these values means "more true".
 */
export const GETIG_VIEW_DIVERGENCE_KINDS = Object.freeze([
  "agreement",
  "value_differs",
  "lifecycle_differs",
  "left_unknown",
  "right_unknown",
  "left_absent",
  "right_absent",
  "terminal_vs_live",
] as const);
export type GetigViewDivergenceKind = (typeof GETIG_VIEW_DIVERGENCE_KINDS)[number];

/** Observer context is mandatory and closed. */
export const GETIG_VIEW_OBSERVER_KINDS = Object.freeze(["local_runtime", "remote_runtime"] as const);
export type GetigViewObserverKind = (typeof GETIG_VIEW_OBSERVER_KINDS)[number];

export const GETIG_VIEW_REFUSAL_CODES = Object.freeze([
  "refused_view_context_incomplete",
  "refused_view_frame_invalid",
  "refused_view_unknown_subject",
  "refused_compare_not_a_view",
  "refused_compare_cross_runtime",
  "refused_compare_cross_epoch",
  "refused_multiview_input_invalid",
  "refused_multiview_duplicate_observer",
  "refused_synthesis_not_permitted",
] as const);
export type GetigViewRefusalCode = (typeof GETIG_VIEW_REFUSAL_CODES)[number];

export const GETIG_VIEW_BOUNDS = Object.freeze({
  maxFactsPerView: 1_024,
  maxViewsPerMultiView: 16,
  maxComparisonEntries: 2_048,
  maxIdChars: 128,
});

export const GETIG_VIEW_SCHEMA_VERSION = "menog-getig-view/v0" as const;

// ── the shapes ───────────────────────────────────────────────────────────────

/** One subject as ONE observer accounts for it. Never a fact in general. */
export interface ObserverFact {
  readonly factId: string;
  readonly subjectVisibleId: string;
  readonly subjectCollection: string;
  /** What this observer says the thing IS. `null` means it did not say. */
  readonly statedKind: string | null;
  readonly lifecycle: GetigViewLifecycle;
  readonly freshness: GetigViewFreshness;
  readonly knowledge: GetigViewKnowledge;
  /** True when this observer's account is terminal. Never overridden. */
  readonly isTerminal: boolean;
  /**
   * True when this observer's account may not be visually resurrected: `retired`
   * is terminal, and `quarantined` is barred alongside it. Neither may be
   * presented as live on the strength of another observer's account.
   */
  readonly isBarred: boolean;
  /** Structural: an account of a thing is not a grant of anything. */
  readonly isGrant: false;
  /** Law: every disagreement must be attributable. */
  readonly attributedToObserverId: string;
}

export interface GetigObserverView {
  readonly schemaVersion: typeof GETIG_VIEW_SCHEMA_VERSION;
  readonly viewId: string;
  /** All three are MANDATORY. A view without them is refused. */
  readonly observerId: string;
  readonly observerKind: GetigViewObserverKind;
  readonly runtimeId: string;
  readonly epochId: string;
  readonly builtFromFrameId: string;
  readonly builtFromVisibleHash: string;
  readonly facts: readonly ObserverFact[];
  readonly factCount: number;
  readonly viewHash: string;
  /** OBSERVER_VIEW != GLOBAL_TRUTH. Structural, not a value to set. */
  readonly isGlobalTruth: false;
  readonly assertsConsensus: false;
  readonly authority: "none";
  readonly readOnly: true;
  readonly bounded: true;
}

export interface ComparisonEntry {
  readonly subjectVisibleId: string;
  readonly subjectCollection: string;
  readonly divergenceKind: GetigViewDivergenceKind;
  readonly leftStatedKind: string | null;
  readonly rightStatedKind: string | null;
  readonly leftLifecycle: GetigViewLifecycle | null;
  readonly rightLifecycle: GetigViewLifecycle | null;
  /**
   * True where one side is terminal and the other is not. A downstream display
   * must not present such a subject as live on the strength of the other side.
   */
  readonly terminalResurrectionBlocked: boolean;
  /** Structural: a fresher account is not a truer one. */
  readonly freshnessDecidesNothing: true;
}

export interface ViewComparison {
  readonly schemaVersion: typeof GETIG_VIEW_SCHEMA_VERSION;
  readonly leftViewId: string;
  readonly rightViewId: string;
  readonly leftObserverId: string;
  readonly rightObserverId: string;
  readonly runtimeId: string;
  readonly epochId: string;
  readonly agreements: readonly ComparisonEntry[];
  readonly disagreements: readonly ComparisonEntry[];
  readonly unknownDifferences: readonly ComparisonEntry[];
  readonly summary: {
    readonly agreementCount: number;
    readonly disagreementCount: number;
    readonly unknownDifferenceCount: number;
  };
  readonly terminalBarriers: readonly string[];
  /** The central law, as data. There is no field to set and no way to set one. */
  readonly winnerDeclared: false;
  /** RECONCILIATION != CONSENSUS. Comparing is not agreeing. */
  readonly consensusAsserted: false;
  readonly isGlobalTruth: false;
  /** No upstream governed resolution was supplied or acted upon here. */
  readonly governedResolutionSupplied: false;
  readonly authority: "none";
  readonly readOnly: true;
  readonly bounded: true;
}

export interface GetigMultiView {
  readonly schemaVersion: typeof GETIG_VIEW_SCHEMA_VERSION;
  readonly multiViewId: string;
  readonly runtimeId: string;
  readonly epochId: string;
  /** Sorted by observerId, so shuffled input yields identical output. */
  readonly observerIds: readonly string[];
  readonly views: readonly GetigObserverView[];
  readonly viewCount: number;
  readonly comparisons: readonly ViewComparison[];
  /** Subjects where a terminal account meets a live one. */
  readonly terminalBarrierSubjects: readonly string[];
  /** Structural: no terminal fact was resurrected anywhere in this display. */
  readonly terminalResurrected: false;
  readonly synthesizesGlobalTruth: false;
  readonly authority: "none";
  readonly readOnly: true;
  readonly bounded: true;
}

// ── decisions ────────────────────────────────────────────────────────────────

export type ViewBuilt = { readonly ok: true; readonly code: "observer_view_built"; readonly view: GetigObserverView };
export type ViewRefused = {
  readonly ok: false;
  readonly code: "observer_view_refused";
  readonly refusal: GetigViewRefusalCode;
  readonly explanation: string;
  readonly view: null;
};
export type ViewDecision = ViewBuilt | ViewRefused;

export type ComparisonBuilt = { readonly ok: true; readonly code: "observer_views_compared"; readonly comparison: ViewComparison };
export type ComparisonRefused = {
  readonly ok: false;
  readonly code: "observer_view_comparison_refused";
  readonly refusal: GetigViewRefusalCode;
  readonly explanation: string;
  readonly comparison: null;
};
export type ComparisonDecision = ComparisonBuilt | ComparisonRefused;

export type MultiViewBuilt = { readonly ok: true; readonly code: "multi_view_built"; readonly multiView: GetigMultiView };
export type MultiViewRefused = {
  readonly ok: false;
  readonly code: "multi_view_refused";
  readonly refusal: GetigViewRefusalCode;
  readonly explanation: string;
  readonly multiView: null;
};
export type MultiViewDecision = MultiViewBuilt | MultiViewRefused;

// ── helpers ──────────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= GETIG_VIEW_BOUNDS.maxIdChars;
}

/** Code-unit comparison, never `localeCompare`: a locale-dependent ordering
 *  would make `viewHash` and `comparisonHash` machine-dependent. */
function byKey<T>(items: readonly T[], key: (item: T) => string): T[] {
  return [...items].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
  });
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === "string" && (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
}

// ── the ONE view builder ─────────────────────────────────────────────────────

/**
 * Build ONE observer's view. Observer, runtime and epoch are all mandatory.
 *
 * A subject the frame omits is simply absent from this view. It is NOT recorded
 * as `unknown`, because absence and ignorance are different: absence means
 * this observer did not mention it, and inventing a record would be fabrication.
 */
export function buildGetigObserverView(input: {
  readonly viewId: string;
  readonly observerId: string;
  readonly observerKind: GetigViewObserverKind;
  readonly runtimeId: string;
  readonly epochId: string;
  readonly frame: unknown;
}): ViewDecision {
  const refuse = (refusal: GetigViewRefusalCode, detail: string): ViewRefused => ({
    ok: false,
    code: "observer_view_refused",
    refusal,
    explanation: `the view was refused and no partial view was produced: ${detail}`,
    view: null,
  });

  if (!isRecord(input)) return refuse("refused_view_context_incomplete", "the builder input must be an object");
  if (!isId(input.viewId)) return refuse("refused_view_context_incomplete", "viewId is missing or over-long");
  // Mandatory context. A view without all three could be mistaken for a fact.
  if (!isId(input.observerId)) return refuse("refused_view_context_incomplete", "observerId is mandatory");
  if (!(GETIG_VIEW_OBSERVER_KINDS as readonly string[]).includes(String(input.observerKind))) {
    return refuse("refused_view_context_incomplete", `observerKind "${String(input.observerKind)}" is not a known observer kind`);
  }
  if (!isId(input.runtimeId)) return refuse("refused_view_context_incomplete", "runtimeId is mandatory");
  if (!isId(input.epochId)) return refuse("refused_view_context_incomplete", "epochId is mandatory");

  const frame = input.frame;
  if (!isRecord(frame)) return refuse("refused_view_frame_invalid", "the frame must be an object");
  if (!isId(frame.frameId)) return refuse("refused_view_frame_invalid", "frame.frameId is required");
  // The frame's own observer must be the observer being recorded, or the
  // attribution on every fact would be a lie.
  if (!isRecord(frame.observer) || frame.observer.observerId !== input.observerId) {
    return refuse("refused_view_frame_invalid", "frame.observer.observerId does not match the view's observer");
  }
  if (frame.epochId !== input.epochId) {
    return refuse("refused_view_frame_invalid", "frame.epochId does not match the view's epoch");
  }

  const facts: ObserverFact[] = [];

  const add = (collection: string, idKey: string, kindKey: string, item: Record<string, unknown>): boolean => {
    const subjectVisibleId = item[idKey];
    // A record with no usable id is a MALFORMED subject, not an absent one, and
    // it is refused rather than skipped. Silently dropping it would leave a
    // view that looks complete and is not — and it would make this refusal
    // code unreachable, which is worse than not having it.
    if (!isId(subjectVisibleId)) return false;
    const lifecycle = oneOf(item.lifecycle, GETIG_VIEW_LIFECYCLES, "unknown");
    const rawKind = item[kindKey];
    const statedKind = typeof rawKind === "string" && rawKind.length > 0 ? rawKind : null;
    facts.push(
      Object.freeze({
        factId: `${collection}:${subjectVisibleId}`,
        subjectVisibleId,
        subjectCollection: collection,
        statedKind,
        lifecycle,
        freshness: oneOf(item.freshness, GETIG_VIEW_FRESHNESS, "unknown"),
        // An account with no stated kind is `unknown` — it is present but says
        // nothing. That is different from the subject being absent.
        knowledge: statedKind === null ? "unknown" : "known",
        isTerminal: lifecycle === "retired",
        isBarred: lifecycle === "retired" || lifecycle === "quarantined",
        isGrant: false,
        attributedToObserverId: input.observerId,
      }),
    );
    return true;
  };

  const itemsOf = (key: string): readonly Record<string, unknown>[] => {
    const raw = frame[key];
    if (!Array.isArray(raw)) return [];
    return raw.filter(isRecord);
  };

  const COLLECTIONS: readonly (readonly [string, string, string])[] = [
    ["entities", "visibleId", "kind"],
    ["relations", "relationId", "kind"],
    ["events", "eventId", "kind"],
    ["routes", "routeId", "kind"],
    ["proposalFlows", "proposalId", "kind"],
  ];
  for (const [collection, idKey, kindKey] of COLLECTIONS) {
    for (const item of itemsOf(collection)) {
      if (!add(collection, idKey, kindKey, item)) {
        return refuse("refused_view_unknown_subject", `a ${collection} record has no usable ${idKey}`);
      }
    }
  }

  if (facts.length > GETIG_VIEW_BOUNDS.maxFactsPerView) {
    return refuse("refused_view_frame_invalid", `${facts.length} facts exceeds the bound of ${GETIG_VIEW_BOUNDS.maxFactsPerView}`);
  }

  const ordered = byKey(facts, (f) => f.factId);
  const context = {
    viewId: input.viewId,
    observerId: input.observerId,
    observerKind: input.observerKind,
    runtimeId: input.runtimeId,
    epochId: input.epochId,
  };

  return {
    ok: true,
    code: "observer_view_built",
    view: Object.freeze({
      schemaVersion: GETIG_VIEW_SCHEMA_VERSION,
      ...context,
      builtFromFrameId: frame.frameId,
      builtFromVisibleHash: typeof frame.canonicalVisibleHash === "string" ? frame.canonicalVisibleHash : "",
      facts: Object.freeze(ordered),
      factCount: ordered.length,
      viewHash: canonicalHash({
        schemaVersion: GETIG_VIEW_SCHEMA_VERSION,
        ...context,
        builtFromFrameId: frame.frameId,
        facts: ordered.map((f) => f.factId),
      }),
      isGlobalTruth: false,
      assertsConsensus: false,
      authority: "none",
      readOnly: true,
      bounded: true,
    }),
  };
}

// ── the ONE comparison ───────────────────────────────────────────────────────

/**
 * Compare two observers' accounts of the same runtime and epoch.
 *
 * The result says WHERE they differ and WHO said what. It never says who is
 * right, which is why `winnerDeclared` is structural rather than a parameter.
 */
export function compareGetigObserverViews(input: {
  readonly left: unknown;
  readonly right: unknown;
}): ComparisonDecision {
  const refuse = (refusal: GetigViewRefusalCode, detail: string): ComparisonRefused => ({
    ok: false,
    code: "observer_view_comparison_refused",
    refusal,
    explanation: `the comparison was refused and no partial comparison was produced: ${detail}`,
    comparison: null,
  });

  if (!isRecord(input) || !isRecord(input.left) || !isRecord(input.right)) {
    return refuse("refused_compare_not_a_view", "both sides must be built observer views");
  }
  const left = input.left;
  const right = input.right;
  for (const [label, view] of [["left", left], ["right", right]] as const) {
    if (!Array.isArray(view.facts) || !isId(view.viewId) || !isId(view.observerId)) {
      return refuse("refused_compare_not_a_view", `the ${label} side is not a built observer view`);
    }
  }
  // Views from different runtimes or epochs describe different worlds entirely.
  if (left.runtimeId !== right.runtimeId) {
    return refuse("refused_compare_cross_runtime", `views belong to runtimes "${String(left.runtimeId)}" and "${String(right.runtimeId)}"`);
  }
  if (left.epochId !== right.epochId) {
    return refuse("refused_compare_cross_epoch", `views belong to epochs "${String(left.epochId)}" and "${String(right.epochId)}"`);
  }

  const leftBy = new Map<string, ObserverFact>();
  for (const fact of left.facts as readonly ObserverFact[]) leftBy.set(fact.factId, fact);
  const rightBy = new Map<string, ObserverFact>();
  for (const fact of right.facts as readonly ObserverFact[]) rightBy.set(fact.factId, fact);

  const factIds = byKey([...new Set([...leftBy.keys(), ...rightBy.keys()])], (id) => id);
  if (factIds.length > GETIG_VIEW_BOUNDS.maxComparisonEntries) {
    return refuse("refused_multiview_input_invalid", `${factIds.length} comparison entries exceeds the bound`);
  }

  const agreements: ComparisonEntry[] = [];
  const disagreements: ComparisonEntry[] = [];
  const unknownDifferences: ComparisonEntry[] = [];
  const terminalBarriers: string[] = [];

  for (const factId of factIds) {
    const l = leftBy.get(factId);
    const r = rightBy.get(factId);
    const subject = l ?? r;
    if (!subject) continue;

    let kind: GetigViewDivergenceKind;
    if (!l) kind = "left_absent";
    else if (!r) kind = "right_absent";
    else if (l.knowledge === "unknown" || r.knowledge === "unknown") {
      kind = l.knowledge === "unknown" ? "left_unknown" : "right_unknown";
    } else if (l.isTerminal !== r.isTerminal) {
      kind = "terminal_vs_live";
    } else if (l.lifecycle !== r.lifecycle) {
      // Lifecycle is compared SEPARATELY from kind. Without this, two observers
      // reporting the same kind but different lifecycle — one `quarantined`, one
      // `observed` — were silently reported as an AGREEMENT, which is the worst
      // possible failure here: it hides a real difference rather than inventing
      // one.
      kind = "lifecycle_differs";
    } else if (l.statedKind !== r.statedKind) {
      kind = "value_differs";
    } else kind = "agreement";

    // Terminal AND quarantined facts are barred from resurrection: a subject one
    // side has retired or quarantined must not be presented as live on the
    // strength of the other side's account.
    const barredVsLive = Boolean(
      l && r && (l.isBarred || r.isBarred) && l.lifecycle !== r.lifecycle,
    );
    const entry: ComparisonEntry = Object.freeze({
      subjectVisibleId: subject.subjectVisibleId,
      subjectCollection: subject.subjectCollection,
      divergenceKind: kind,
      leftStatedKind: l ? l.statedKind : null,
      rightStatedKind: r ? r.statedKind : null,
      leftLifecycle: l ? l.lifecycle : null,
      rightLifecycle: r ? r.lifecycle : null,
      terminalResurrectionBlocked: barredVsLive,
      freshnessDecidesNothing: true,
    });

    if (kind === "agreement") agreements.push(entry);
    else if (kind === "value_differs" || kind === "lifecycle_differs" || kind === "terminal_vs_live") {
      disagreements.push(entry);
      if (barredVsLive) terminalBarriers.push(subject.factId);
    } else {
      // Absence and ignorance are UNKNOWN differences, not disagreements.
      // Manufacturing conflict out of a gap is the mirror image of
      // manufacturing consensus out of a gap.
      unknownDifferences.push(entry);
    }
  }

  const identity = {
    leftViewId: String(left.viewId),
    rightViewId: String(right.viewId),
    leftObserverId: String(left.observerId),
    rightObserverId: String(right.observerId),
    runtimeId: String(left.runtimeId),
    epochId: String(left.epochId),
  };

  return {
    ok: true,
    code: "observer_views_compared",
    comparison: Object.freeze({
      schemaVersion: GETIG_VIEW_SCHEMA_VERSION,
      ...identity,
      agreements: Object.freeze(agreements),
      disagreements: Object.freeze(disagreements),
      unknownDifferences: Object.freeze(unknownDifferences),
      summary: Object.freeze({
        agreementCount: agreements.length,
        disagreementCount: disagreements.length,
        unknownDifferenceCount: unknownDifferences.length,
      }),
      terminalBarriers: Object.freeze(terminalBarriers),
      // OBSERVER_VIEW != GLOBAL_TRUTH. RECONCILIATION != CONSENSUS.
      winnerDeclared: false,
      consensusAsserted: false,
      isGlobalTruth: false,
      governedResolutionSupplied: false,
      authority: "none",
      readOnly: true,
      bounded: true,
      comparisonHash: canonicalHash({
        schemaVersion: GETIG_VIEW_SCHEMA_VERSION,
        ...identity,
        agreements: agreements.map((e) => `${e.subjectVisibleId}:${e.divergenceKind}`),
        disagreements: disagreements.map((e) => `${e.subjectVisibleId}:${e.divergenceKind}`),
        unknownDifferences: unknownDifferences.map((e) => `${e.subjectVisibleId}:${e.divergenceKind}`),
      }),
    } as ViewComparison),
  };
}

// ── the ONE multi-view builder ───────────────────────────────────────────────

/**
 * Hold several observers' views side by side, with every pairwise comparison.
 *
 * Views are sorted by observerId, so a caller who hands them over in any order
 * gets byte-identical output. There is no merge, no vote and no combined
 * "answer" — the output is the views themselves plus the differences.
 */
export function buildGetigMultiView(input: {
  readonly multiViewId: string;
  readonly runtimeId: string;
  readonly epochId: string;
  readonly views: readonly unknown[];
}): MultiViewDecision {
  const refuse = (refusal: GetigViewRefusalCode, detail: string): MultiViewRefused => ({
    ok: false,
    code: "multi_view_refused",
    refusal,
    explanation: `the multi-view was refused and no partial multi-view was produced: ${detail}`,
    multiView: null,
  });

  if (!isRecord(input)) return refuse("refused_multiview_input_invalid", "the builder input must be an object");
  if (!isId(input.multiViewId)) return refuse("refused_multiview_input_invalid", "multiViewId is missing or over-long");
  if (!isId(input.runtimeId)) return refuse("refused_multiview_input_invalid", "runtimeId is missing or over-long");
  if (!isId(input.epochId)) return refuse("refused_multiview_input_invalid", "epochId is missing or over-long");
  if (!Array.isArray(input.views) || input.views.length === 0) {
    return refuse("refused_multiview_input_invalid", "views must be a non-empty array");
  }
  if (input.views.length > GETIG_VIEW_BOUNDS.maxViewsPerMultiView) {
    return refuse("refused_multiview_input_invalid", `${input.views.length} views exceeds the bound of ${GETIG_VIEW_BOUNDS.maxViewsPerMultiView}`);
  }

  const views: GetigObserverView[] = [];
  for (const raw of input.views) {
    if (!isRecord(raw) || !Array.isArray(raw.facts) || !isId(raw.viewId) || !isId(raw.observerId)) {
      return refuse("refused_compare_not_a_view", "every view must be a built observer view");
    }
    if (raw.runtimeId !== input.runtimeId || raw.epochId !== input.epochId) {
      return refuse("refused_multiview_input_invalid", `view "${String(raw.viewId)}" does not belong to this runtime and epoch`);
    }
    views.push(raw as unknown as GetigObserverView);
  }

  // One view per observer. Two views from the same observer are the same
  // account, and showing it twice would imply two independent opinions.
  const observerIds = views.map((v) => v.observerId);
  if (new Set(observerIds).size !== observerIds.length) {
    return refuse("refused_multiview_duplicate_observer", `the same observer appears more than once: ${observerIds.join(", ")}`);
  }

  // Sorted, so shuffled input is byte-identical output.
  const ordered = byKey(views, (v) => v.observerId);

  const comparisons: ViewComparison[] = [];
  const barriers = new Set<string>();
  for (let i = 0; i < ordered.length; i += 1) {
    for (let j = i + 1; j < ordered.length; j += 1) {
      const decision = compareGetigObserverViews({ left: ordered[i], right: ordered[j] });
      if (!decision.ok) return refuse(decision.refusal, decision.explanation);
      comparisons.push(decision.comparison);
      for (const barrier of decision.comparison.terminalBarriers) barriers.add(barrier);
    }
  }

  return {
    ok: true,
    code: "multi_view_built",
    multiView: Object.freeze({
      schemaVersion: GETIG_VIEW_SCHEMA_VERSION,
      multiViewId: input.multiViewId,
      runtimeId: input.runtimeId,
      epochId: input.epochId,
      observerIds: Object.freeze(ordered.map((v) => v.observerId)),
      views: Object.freeze(ordered),
      viewCount: ordered.length,
      comparisons: Object.freeze(comparisons),
      terminalBarrierSubjects: Object.freeze([...barriers].sort()),
      // Structural. A terminal account is carried through, never overwritten.
      terminalResurrected: false,
      synthesizesGlobalTruth: false,
      authority: "none",
      readOnly: true,
      bounded: true,
    }),
  };
}

// ── the synthesis guard ──────────────────────────────────────────────────────

/**
 * Several observers' views NEVER become one global truth.
 *
 * This is the only synthesis-adjacent export and it cannot succeed under any
 * input. It exists so the law is testable rather than merely absent: a reader
 * can require that it is the sole such export and that it always refuses.
 */
export function refuseGlobalTruthSynthesis(
  observerIds: readonly string[],
  _requestedLabel?: string,
): {
  readonly ok: false;
  readonly code: "synthesis_refused";
  readonly refusal: "refused_synthesis_not_permitted";
  readonly explanation: string;
  readonly observerCount: number;
  readonly observerIds: readonly string[];
  readonly winnerDeclared: false;
  readonly consensusAsserted: false;
  readonly isGlobalTruth: false;
} {
  const ids = Array.isArray(observerIds) ? observerIds.filter((v): v is string => typeof v === "string") : [];
  return {
    ok: false,
    code: "synthesis_refused",
    refusal: "refused_synthesis_not_permitted",
    explanation:
      "combining several observers' views into one answer is not available here. Agreement between observers is not consensus, and a majority is not truth. OBSERVER_VIEW != GLOBAL_TRUTH; RECONCILIATION != CONSENSUS.",
    observerCount: ids.length,
    observerIds: Object.freeze([...ids]),
    winnerDeclared: false,
    consensusAsserted: false,
    isGlobalTruth: false,
  };
}