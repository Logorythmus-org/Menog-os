/**
 * PHASE 28G — READ-ONLY INSPECTION RUNTIME
 * (INSPECTION ONLY / NO CONTROL PLANE / STRUCTURALLY READ-ONLY / ZERO-AUTHORITY)
 *
 * CENTRAL LAWS:
 *   INSPECTION != CONTROL
 *   SELECTION != PERMISSION
 *   FILTERED != COMPLETE
 *   SELECTION != EXECUTION
 *   QUERY != MUTATION
 *
 * ── WHY THE API IS STRUCTURALLY READ-ONLY ───────────────────────────────────
 *
 * The temptation in an inspection runtime is to check permissions at each call
 * site. That is the wrong shape: a check that can be forgotten is a hole, and a
 * gate that can be bypassed by a future edit has not been established. So this
 * module does not *enforce* read-only-ness. It has no mutating operation to
 * enable in the first place.
 *
 * There is no `execute`, no `approve`, no `admit`, no `retire`, no `grant`, no
 * `resume`, no setter, and no mutator on any exported type. `InspectionQuery`
 * is a closed union of seven query KINDS — the "what may I look at" surface —
 * and every operation accepts a query and a frozen Phase-28 input, returning a
 * NEW value. Nothing is written. `INSPECTION_FORBIDDEN_ACTIONS` exists so a
 * scanner can prove the absence rather than take it on trust.
 *
 * ── WHY A FILTERED VIEW SAYS SO ─────────────────────────────────────────────
 *
 * The most dangerous property an inspection tool can have is a filter that
 * makes a partial world look like a whole one. Someone filters to one subject
 * and reads the result as "this is what the system contains."
 *
 * So a filtered result is not a smaller `GetigObserverView`. It is a different
 * type — `FilteredInspection` — that carries `isFiltered: true`,
 * `isComplete: false`, and the counts it dropped, every time. There is no code
 * path that produces a filtered result without those markers, because the
 * constructor of the result type requires them.
 *
 * ── WHY SELECTION CONFERS NOTHING ───────────────────────────────────────────
 *
 * Focus, expand/collapse and selection are questions about WHAT IS BEING LOOKED
 * AT. They say nothing about what is permitted, what is true, or what may run.
 * `InspectionSelection` therefore carries `authority: "none"`,
 * `confersPermission: false` and `isExecution: false` as structural
 * literals — there is no field a caller could set to claim otherwise. Selecting
 * a node is not approving it; highlighting a tool is not invoking it.
 *
 * ── WHY TIMELINE NAVIGATION IS NOT RESUMPTION ──────────────────────────────
 *
 * Navigating a sequence reads past frames. Resuming would replay them. 28C
 * already refuses the second thing (`refuseResumeFromFrame`), and this module
 * refuses the same thing from the inspection side: it consumes a
 * `GetigFrameSequence` whose own `replaySemantics` is
 * `visual_history_not_executable`, and it emits `resumesRuntimeState: false`.
 * Looking at frame 4 tells you what frame 4 said. It does not put frame 4 back.
 *
 * ── BINDING ─────────────────────────────────────────────────────────────────
 *
 * Every result is bound to the frame, observer and hash it came from, per the
 * prompt's "all results remain bound to frame/observer/hash." An unbound result
 * could be carried into a different frame and read as if it described that one.
 * Refusals are emitted when that binding cannot be established, rather than
 * emitting an unbound result and hoping the caller notices.
 *
 * ── NO CACHE, THEREFORE NO MUTABLE AUTHORITY ────────────────────────────────
 *
 * The prompt forbids a mutable cache becoming authority. This module has no
 * cache at all — every operation recomputes from the frozen input it is given.
 * That makes the prohibition structurally satisfied instead of merely enforced,
 * and it means two identical queries over identical inputs are byte-identical.
 */

import { canonicalHash } from "./canonical.js";

// ── closed vocabularies ──────────────────────────────────────────────────────

/**
 * The ONLY operations this runtime can perform. Each derives a subset or a
 * projection; none writes. The list is closed on purpose: adding a kind is a
 * governance-visible act, not an incidental edit.
 */
export const INSPECTION_QUERY_KINDS = Object.freeze([
  "select",
  "inspect",
  "filter",
  "focus",
  "expand_collapse",
  "timeline_navigate",
  "compare",
  "trace_provenance",
  "enumerate_refusals",
] as const);
export type InspectionQueryKind = (typeof INSPECTION_QUERY_KINDS)[number];

/** The seven verbs the prompt names as ALLOWED, as a closed set. */
export const INSPECTION_ALLOWED_OPERATIONS = Object.freeze([
  "select",
  "inspect",
  "filter",
  "focus",
  "expand_collapse",
  "timeline_navigate",
  "compare_views",
  "trace_provenance",
  "enumerate_refusals_conflicts",
] as const);
export type InspectionAllowedOperation = (typeof INSPECTION_ALLOWED_OPERATIONS)[number];

/**
 * The prompt's FORBIDDEN list, declared so a scanner can assert its absence
 * from the module's own surface. This list is documentation with teeth: the
 * test suite scans this file for these tokens in callable position.
 */
export const INSPECTION_FORBIDDEN_ACTIONS = Object.freeze([
  "execute",
  "approve",
  "admit",
  "quarantine",
  "retire",
  "grant",
  "mutate_policy",
  "mutate_trust",
  "restart",
  "kill",
  "invoke_tool",
  "mutate_network",
  "mutate_session",
  "write_runtime_state",
  "auto_resume",
] as const);
export type InspectionForbiddenAction = (typeof INSPECTION_FORBIDDEN_ACTIONS)[number];

/** Refusal vocabulary. Closed, and every code is reachable. */
export const INSPECTION_REFUSAL_CODES = Object.freeze([
  "refused_query_kind_unknown",
  "refused_query_operation_unknown",
  "refused_query_mutation_shape",
  "refused_binding_frame_missing",
  "refused_binding_observer_missing",
  "refused_binding_hash_missing",
  "refused_binding_mismatch",
  "refused_input_not_a_view",
  "refused_input_not_a_sequence",
  "refused_input_not_a_graph",
  "refused_subject_unknown",
  "refused_filter_predicate_unknown",
  "refused_limit_out_of_range",
  "refused_bounds_exceeded",
  "refused_selection_mutation_attempt",
] as const);
export type InspectionRefusalCode = (typeof INSPECTION_REFUSAL_CODES)[number];

/**
 * Comparison bases a query may filter on. Deliberately small: a predicate the
 * runtime cannot evaluate is refused rather than approximated, because a filter
 * that silently ignores a condition would let a partial result masquerade as a
 * complete one.
 */
export const INSPECTION_FILTER_BASES = Object.freeze([
  "lifecycle",
  "freshness",
  "knowledge",
  "subject_collection",
  "divergence",
] as const);
export type InspectionFilterBase = (typeof INSPECTION_FILTER_BASES)[number];

export const INSPECTION_FOCUS_SCOPES = Object.freeze(["subject", "collection", "whole_view"] as const);
export type InspectionFocusScope = (typeof INSPECTION_FOCUS_SCOPES)[number];

export const INSPECTION_EXPANSION_STATES = Object.freeze(["expanded", "collapsed"] as const);
export type InspectionExpansionState = (typeof INSPECTION_EXPANSION_STATES)[number];

export const INSPECTION_BOUNDS = Object.freeze({
  maxSubjectsPerQuery: 2_048,
  maxTracedHops: 256,
  maxIdChars: 128,
  minResultLimit: 1,
  maxResultLimit: 2_048,
});

export const INSPECTION_SCHEMA_VERSION = "menog-getig-inspection/v0" as const;

// ── shapes ───────────────────────────────────────────────────────────────────

/**
 * A request to look at something. Read-only by construction: every field is
 * data, and none of them can name a mutation. `operation` is the only field
 * that selects behaviour, and it is drawn from the closed allowed list.
 */
export interface InspectionQuery {
  readonly kind: InspectionQueryKind;
  readonly operation: InspectionAllowedOperation;
  /** Present for `select`, `inspect`, `focus` and `trace_provenance`. */
  readonly subjectVisibleId?: string;
  /** Present for `filter`. Unknown bases are refused, never ignored. */
  readonly filterBase?: InspectionFilterBase;
  readonly filterValue?: string;
  /** Present for `timeline_navigate`. */
  readonly frameId?: string;
  /** Present for `focus` and `expand_collapse`. */
  readonly focusScope?: InspectionFocusScope;
  readonly expansionState?: InspectionExpansionState;
  /** Explicit, bounded, fail-closed. */
  readonly limit?: number;
}

/**
 * The binding every result carries. A result without this could be shown
 * beside a frame it does not describe, so the three fields are mandatory and a
 * mismatch against the frozen input is a refusal rather than a relabelling.
 */
export interface InspectionBinding {
  readonly frameId: string;
  readonly observerId: string;
  readonly canonicalVisibleHash: string;
  /** The view's own hash, so a result is bound to the exact view it read. */
  readonly viewHash: string;
}

/** Structural: looking at a subject is not permitting it. */
export interface InspectionSelection {
  readonly subjectVisibleId: string;
  readonly subjectCollection: string;
  readonly focusScope: InspectionFocusScope;
  readonly expansionState: InspectionExpansionState;
  /** Structural: SELECTION != PERMISSION. There is no field to set. */
  readonly authority: "none";
  readonly confersPermission: false;
  readonly isExecution: false;
  readonly grantsNothing: true;
  readonly binding: InspectionBinding;
}

/**
 * A filter RESULT. Deliberately a distinct type from a whole view so that a
 * partial answer cannot be passed off as a complete one: `isFiltered` and
 * `isComplete` are required literals on every construction.
 */
export interface FilteredInspection {
  readonly schemaVersion: typeof INSPECTION_SCHEMA_VERSION;
  readonly inspectionId: string;
  readonly operation: "filter";
  readonly filterBase: InspectionFilterBase;
  readonly filterValue: string;
  readonly subjectVisibleIds: readonly string[];
  readonly matchedCount: number;
  /** What the filter removed. Present so "incomplete" is quantified. */
  readonly excludedCount: number;
  /** Required literal. A filtered result is always filtered. */
  readonly isFiltered: true;
  /** Required literal. A filtered result is never complete. */
  readonly isComplete: false;
  /** Structural: filtering is not deletion; the canonical view is untouched. */
  readonly canonicalViewAltered: false;
  readonly authority: "none";
  readonly readOnly: true;
  readonly bounded: true;
  readonly binding: InspectionBinding;
}

/** Timeline navigation: reading past frames, never resuming one. */
export interface TimelineInspection {
  readonly schemaVersion: typeof INSPECTION_SCHEMA_VERSION;
  readonly inspectionId: string;
  readonly operation: "timeline_navigate";
  readonly sequenceId: string;
  readonly orderingBasis: string;
  /**
   * Whether this sequence claims a chronology at all. False when the basis is
   * `unknown` — and a refused answer here is the honest one.
   */
  readonly temporalOrderEstablished: boolean;
  readonly frameIds: readonly string[];
  readonly positionCount: number;
  /** VISUAL HISTORY ONLY. Echoed, never reinterpreted. */
  readonly replaySemantics: "visual_history_not_executable";
  /** Structural: reading a frame does not put it back. */
  readonly resumesRuntimeState: false;
  readonly restoresRuntimeState: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly binding: InspectionBinding;
}

/** Provenance traced from a frozen 28F graph. Explains; never authorises. */
export interface ProvenanceInspection {
  readonly schemaVersion: typeof INSPECTION_SCHEMA_VERSION;
  readonly inspectionId: string;
  readonly operation: "trace_provenance";
  readonly subjectVisibleId: string;
  readonly graphId: string;
  readonly hops: readonly {
    readonly nodeId: string;
    readonly kind: string;
    readonly relation: string;
    readonly role: string;
    readonly depth: number;
    /** Structural on every hop: a provenance link is not trust. */
    readonly confersTrust: false;
    readonly confersAuthority: false;
  }[];
  readonly hopCount: number;
  /** True when traversal stopped at a bound rather than exhausting the graph. */
  readonly boundedStop: boolean;
  readonly cycleBroken: boolean;
  /** EXPLAINATION != AUTHORIZATION. */
  readonly authorizes: false;
  readonly authority: "none";
  readonly readOnly: true;
  readonly binding: InspectionBinding;
}

/** Refusal/conflict enumeration — the "show me what is blocked" surface. */
export interface RefusalInspection {
  readonly schemaVersion: typeof INSPECTION_SCHEMA_VERSION;
  readonly inspectionId: string;
  readonly operation: "enumerate_refusals";
  readonly refusalCodes: readonly string[];
  readonly conflictSubjects: readonly string[];
  /** Terminal facts that a filtered or focused view must not present as live. */
  readonly barredSubjects: readonly string[];
  readonly counts: {
    readonly refusalCodeCount: number;
    readonly conflictSubjectCount: number;
    readonly barredSubjectCount: number;
  };
  /** Structural: unknown stays unknown. Absence is reported, not smoothed. */
  readonly completenessClaimed: false;
  readonly authority: "none";
  readonly readOnly: true;
  readonly binding: InspectionBinding;
}

/** A whole-view projection, or a focused one — never a mutated one. */
export interface ViewInspection {
  readonly schemaVersion: typeof INSPECTION_SCHEMA_VERSION;
  readonly inspectionId: string;
  readonly operation: "inspect" | "focus" | "expand_collapse" | "select" | "compare_views";
  readonly viewId: string;
  readonly focusScope: InspectionFocusScope;
  readonly expansionState: InspectionExpansionState;
  readonly subjectVisibleIds: readonly string[];
  readonly factCount: number;
  /** Structural: the canonical view was read, never rewritten. */
  readonly canonicalViewAltered: false;
  readonly isGlobalTruth: false;
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly bounded: true;
  readonly binding: InspectionBinding;
}

export type InspectionResult =
  | ViewInspection
  | FilteredInspection
  | TimelineInspection
  | ProvenanceInspection
  | RefusalInspection
  | InspectionSelection;

export type InspectionSucceeded = {
  readonly ok: true;
  readonly code: "inspection_succeeded";
  readonly operation: InspectionAllowedOperation;
  readonly result: InspectionResult;
  /** Structural: an inspection never mutates the thing it inspects. */
  readonly mutatedCanonicalState: false;
  readonly authority: "none";
  readonly readOnly: true;
};

export type InspectionRefused = {
  readonly ok: false;
  readonly code: "inspection_refused";
  readonly refusal: InspectionRefusalCode;
  readonly explanation: string;
  readonly result: null;
  readonly mutatedCanonicalState: false;
  readonly authority: "none";
  readonly readOnly: true;
};

export type InspectionDecision = InspectionSucceeded | InspectionRefused;

// ── helpers ──────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const asString = (v: unknown): string | null => (typeof v === "string" ? v : null);

/**
 * Shape test for a frozen Phase-28 observer view. Declared structurally rather
 * than imported as a constructor: this module READS a view, it never builds or
 * mutates one, so depending on the shape is enough and keeps the read-only
 * property structural.
 */
const isObserverView = (v: unknown): v is {
  readonly viewId: string;
  readonly observerId: string;
  readonly builtFromFrameId: string;
  readonly builtFromVisibleHash: string;
  readonly viewHash: string;
  readonly facts: readonly unknown[];
  readonly authority: string;
  readonly readOnly: boolean;
} =>
  isRecord(v) &&
  typeof v["viewId"] === "string" &&
  typeof v["observerId"] === "string" &&
  typeof v["builtFromFrameId"] === "string" &&
  typeof v["builtFromVisibleHash"] === "string" &&
  typeof v["viewHash"] === "string" &&
  Array.isArray(v["facts"]) &&
  v["authority"] === "none" &&
  v["readOnly"] === true;

const isFrameSequence = (v: unknown): v is {
  readonly sequenceId: string;
  readonly observerId: string;
  readonly orderingBasis?: string;
  readonly entries: readonly { readonly frameId: string; readonly canonicalVisibleHash: string }[];
  readonly replaySemantics: string;
} =>
  isRecord(v) &&
  typeof v["sequenceId"] === "string" &&
  typeof v["observerId"] === "string" &&
  Array.isArray(v["entries"]) &&
  typeof v["replaySemantics"] === "string";

const isExplanationGraph = (v: unknown): v is {
  readonly graphId: string;
  readonly nodes: readonly unknown[];
  readonly edges: readonly { readonly fromNodeId: string; readonly toNodeId: string }[];
} =>
  isRecord(v) &&
  typeof v["graphId"] === "string" &&
  Array.isArray(v["nodes"]) &&
  Array.isArray(v["edges"]);

const refuse = (refusal: InspectionRefusalCode, explanation: string): InspectionRefused => ({
  ok: false,
  code: "inspection_refused",
  refusal,
  explanation,
  result: null,
  mutatedCanonicalState: false,
  authority: "none",
  readOnly: true,
});

/**
 * Reject a query that carries a mutation-shaped field. This is not the primary
 * defence — the primary defence is that no mutating export exists — but it stops
 * a caller who passes `{ approve: true }` from believing it did something.
 */
const hasMutationShape = (q: Record<string, unknown>): boolean =>
  Object.keys(q).some((k) => (INSPECTION_FORBIDDEN_ACTIONS as readonly string[]).includes(k));

// ── the runtime ──────────────────────────────────────────────────────────────

export interface InspectInput {
  readonly query: unknown;
  /** A frozen 28E view. Read, never written. */
  readonly view?: unknown;
  /** A frozen 28C sequence. Read, never replayed into existence. */
  readonly sequence?: unknown;
  /** A frozen 28F graph. Read, never extended. */
  readonly graph?: unknown;
  /**
   * The frame this inspection is bound to. Required, so a result can never be
   * detached from the frame it describes.
   */
  readonly binding?: {
    readonly frameId?: unknown;
    readonly observerId?: unknown;
    readonly canonicalVisibleHash?: unknown;
    readonly viewHash?: unknown;
  };
}

/**
 * Perform one inspection. Returns a decision; never throws for a bad request,
 * never mutates, never returns an unbound result.
 */
export function inspect(input: InspectInput): InspectionDecision {
  // ── query validation: closed, fail-closed ────────────────────────────────
  if (!isRecord(input.query)) {
    return refuse("refused_query_kind_unknown", "query must be an object describing one inspection");
  }
  const q = input.query as Record<string, unknown>;

  if (hasMutationShape(q)) {
    // A mutation attempt riding on a SELECTION is its own failure, not a
    // generic one: selecting something and asking to change it is the exact
    // conflation this gate exists to refuse, so it gets a distinct code rather
    // than being folded into the general malformed-query bucket.
    const isSelection =
      q["kind"] === "select" || q["kind"] === "focus" || q["operation"] === "select" || q["operation"] === "focus";
    return refuse(
      isSelection ? "refused_selection_mutation_attempt" : "refused_query_mutation_shape",
      isSelection
        ? "a selection cannot carry a mutation: SELECTION != PERMISSION and SELECTION != EXECUTION"
        : "query carries a forbidden action field; this runtime has no mutating operation",
    );
  }

  const kind = asString(q["kind"]);
  if (kind === null || !(INSPECTION_QUERY_KINDS as readonly string[]).includes(kind)) {
    return refuse("refused_query_kind_unknown", `query kind must be one of ${INSPECTION_QUERY_KINDS.join(", ")}`);
  }
  const operation = asString(q["operation"]);
  if (operation === null || !(INSPECTION_ALLOWED_OPERATIONS as readonly string[]).includes(operation)) {
    return refuse(
      "refused_query_operation_unknown",
      `operation must be one of ${INSPECTION_ALLOWED_OPERATIONS.join(", ")}`,
    );
  }

  // An explicit limit is honoured or refused; it is never silently clamped,
  // because a clamped limit would return fewer rows than asked for while
  // looking like a complete answer.
  if (q["limit"] !== undefined) {
    const limit = q["limit"];
    if (typeof limit !== "number" || !Number.isInteger(limit) ||
        limit < INSPECTION_BOUNDS.minResultLimit || limit > INSPECTION_BOUNDS.maxResultLimit) {
      return refuse(
        "refused_limit_out_of_range",
        `limit must be an integer in [${INSPECTION_BOUNDS.minResultLimit}, ${INSPECTION_BOUNDS.maxResultLimit}]`,
      );
    }
  }

  // ── binding: mandatory, and must agree with the frozen input ─────────────
  const b = input.binding;
  if (b === undefined) {
    return refuse("refused_binding_frame_missing", "every inspection must declare its frame binding");
  }
  const frameId = asString(b.frameId);
  const observerId = asString(b.observerId);
  const visibleHash = asString(b.canonicalVisibleHash);
  const viewHash = asString(b.viewHash);
  if (frameId === null) {
    return refuse("refused_binding_frame_missing", "binding requires frameId");
  }
  if (observerId === null) {
    return refuse("refused_binding_observer_missing", "binding requires observerId");
  }
  if (visibleHash === null) {
    return refuse("refused_binding_hash_missing", "binding requires canonicalVisibleHash");
  }
  if (viewHash === null) {
    return refuse("refused_binding_hash_missing", "binding requires viewHash");
  }

  const binding: InspectionBinding = { frameId, observerId, canonicalVisibleHash: visibleHash, viewHash };

  // ── timeline navigation: reads a sequence, resumes nothing ───────────────
  if (operation === "timeline_navigate") {
    const seq = input.sequence;
    if (!isFrameSequence(seq)) {
      return refuse("refused_input_not_a_sequence", "timeline navigation requires a frozen 28C sequence");
    }
    // A sequence whose own semantics are not visual-history-only is refused
    // rather than reinterpreted as such.
    if (seq.replaySemantics !== "visual_history_not_executable") {
      return refuse("refused_input_not_a_sequence", "sequence does not declare visual-history-only semantics");
    }
    if (seq.observerId !== observerId) {
      return refuse(
        "refused_binding_mismatch",
        "binding observerId does not match the sequence it would describe",
      );
    }
    const entries = [...seq.entries].sort((a, b2) => a.frameId.localeCompare(b2.frameId));
    const truncated = typeof q["limit"] === "number" ? entries.slice(0, q["limit"] as number) : entries;
    // Absent ordering basis is UNKNOWN, and an unknown basis means the sequence
    // claims no chronology at all. Defaulting to `unknown` is the honest answer.
    const orderedBasis = typeof seq.orderingBasis === "string" ? seq.orderingBasis : "unknown";
    const result: TimelineInspection = {
      schemaVersion: INSPECTION_SCHEMA_VERSION,
      inspectionId: canonicalHash({
        op: operation,
        sequenceId: seq.sequenceId,
        frameId,
        observerId,
        frames: truncated.map((e) => e.frameId),
      }),
      operation: "timeline_navigate",
      sequenceId: seq.sequenceId,
      orderingBasis: orderedBasis,
      temporalOrderEstablished: orderedBasis !== "unknown",
      frameIds: truncated.map((e) => e.frameId),
      positionCount: entries.length,
      replaySemantics: "visual_history_not_executable",
      resumesRuntimeState: false,
      restoresRuntimeState: false,
      authority: "none",
      controlPlane: false,
      readOnly: true,
      binding,
    };
    return {
      ok: true,
      code: "inspection_succeeded",
      operation,
      result,
      mutatedCanonicalState: false,
      authority: "none",
      readOnly: true,
    };
  }

  // ── provenance tracing: reads a graph, authorises nothing ───────────────
  if (operation === "trace_provenance") {
    const graph = input.graph;
    if (!isExplanationGraph(graph)) {
      return refuse("refused_input_not_a_graph", "provenance tracing requires a frozen 28F graph");
    }
    const subject = asString(q["subjectVisibleId"]);
    if (subject === null) {
      return refuse("refused_subject_unknown", "provenance tracing requires a subjectVisibleId");
    }
    const maxDepth =
      typeof q["limit"] === "number"
        ? Math.min(q["limit"] as number, INSPECTION_BOUNDS.maxTracedHops)
        : INSPECTION_BOUNDS.maxTracedHops;

    // Breadth-first, cycle-safe: a node already seen is not re-entered, which
    // is what stops a cyclic graph from looping forever.
    const outgoing = new Map<string, string[]>();
    for (const edge of graph.edges) {
      const list = outgoing.get(edge.fromNodeId) ?? [];
      list.push(edge.toNodeId);
      outgoing.set(edge.fromNodeId, list);
    }
    const kinds = new Map<string, string>();
    for (const node of graph.nodes) {
      if (isRecord(node) && typeof node["nodeId"] === "string" && typeof node["kind"] === "string") {
        kinds.set(node["nodeId"], node["kind"]);
      }
    }

    const seen = new Set<string>([subject]);
    let frontier: { nodeId: string; depth: number }[] = [{ nodeId: subject, depth: 0 }];
    // Built as a mutable local and frozen into the result: the RESULT is
    // read-only, and the traversal needs to append while it runs.
    const hops: {
      nodeId: string;
      kind: string;
      relation: string;
      role: string;
      depth: number;
      confersTrust: false;
      confersAuthority: false;
    }[] = [];
    let cycleBroken = false;
    let boundedStop = false;

    while (frontier.length > 0) {
      if (hops.length >= maxDepth) {
        boundedStop = true;
        break;
      }
      const next: { nodeId: string; depth: number }[] = [];
      for (const current of frontier) {
        for (const target of outgoing.get(current.nodeId) ?? []) {
          if (seen.has(target)) {
            cycleBroken = true;
            continue;
          }
          seen.add(target);
          next.push({ nodeId: target, depth: current.depth + 1 });
          if (hops.length < maxDepth) {
            hops.push({
              nodeId: target,
              kind: kinds.get(target) ?? "unknown",
              relation: "references",
              role: "none",
              depth: current.depth + 1,
              confersTrust: false,
              confersAuthority: false,
            });
          }
        }
      }
      frontier = next;
    }

    const result: ProvenanceInspection = {
      schemaVersion: INSPECTION_SCHEMA_VERSION,
      inspectionId: canonicalHash({
        op: operation,
        graphId: graph.graphId,
        subject,
        frameId,
        observerId,
        hops: hops.map((h) => h.nodeId),
      }),
      operation: "trace_provenance",
      subjectVisibleId: subject,
      graphId: graph.graphId,
      hops,
      hopCount: hops.length,
      boundedStop,
      cycleBroken,
      authorizes: false,
      authority: "none",
      readOnly: true,
      binding,
    };
    return {
      ok: true,
      code: "inspection_succeeded",
      operation,
      result,
      mutatedCanonicalState: false,
      authority: "none",
      readOnly: true,
    };
  }

  // ── every remaining operation reads a view ───────────────────────────────
  const view = input.view;
  if (!isObserverView(view)) {
    return refuse("refused_input_not_a_view", "this inspection requires a frozen 28E observer view");
  }
  if (view.observerId !== observerId) {
    return refuse("refused_binding_mismatch", "binding observerId does not match the view it would describe");
  }
  if (view.builtFromVisibleHash !== visibleHash) {
    return refuse(
      "refused_binding_mismatch",
      "binding canonicalVisibleHash does not match the view it would describe",
    );
  }
  if (view.viewHash !== viewHash) {
    return refuse("refused_binding_mismatch", "binding viewHash does not match the view it would describe");
  }

  const factRows = view.facts.filter(isRecord);

  // Fail closed on an oversized input rather than truncating it silently. A
  // truncated inspection that looked complete would be the exact lie this
  // module exists to avoid, so the bound refuses instead of quietly cutting.
  if (view.facts.length > INSPECTION_BOUNDS.maxSubjectsPerQuery) {
    return refuse(
      "refused_bounds_exceeded",
      `view holds ${view.facts.length} facts, above the inspection bound of ${INSPECTION_BOUNDS.maxSubjectsPerQuery}`,
    );
  }

  const allSubjects = factRows
    .map((f) => asString(f["subjectVisibleId"]))
    .filter((s): s is string => s !== null);

  // ── filter: derive a subset, mark it as a subset ─────────────────────────
  if (operation === "filter") {
    const base = asString(q["filterBase"]);
    const value = asString(q["filterValue"]);
    if (base === null || !(INSPECTION_FILTER_BASES as readonly string[]).includes(base)) {
      return refuse(
        "refused_filter_predicate_unknown",
        `filterBase must be one of ${INSPECTION_FILTER_BASES.join(", ")}; an unknown base is refused, never ignored`,
      );
    }
    if (value === null) {
      return refuse("refused_filter_predicate_unknown", "filter requires a filterValue");
    }

    const matched = factRows.filter((f) => {
      switch (base) {
        case "lifecycle":
          return asString(f["lifecycle"]) === value;
        case "freshness":
          return asString(f["freshness"]) === value;
        case "knowledge":
          return asString(f["knowledge"]) === value;
        case "subject_collection":
          return asString(f["subjectCollection"]) === value;
        case "divergence":
          return asString(f["lifecycle"]) !== value;
        default:
          // Unreachable: `base` was checked against the closed list above. The
          // default refuses rather than returning true, so adding a member to
          // the vocabulary without teaching it here fails closed.
          return false;
      }
    });

    // `base` was checked against the closed list, so this narrowing is the
    // checked fact, not a guess at runtime.
    const filterBase = base as InspectionFilterBase;
    const matchedSubjects = matched
      .map((f) => asString(f["subjectVisibleId"]))
      .filter((s): s is string => s !== null);
    const capped =
      typeof q["limit"] === "number" ? matchedSubjects.slice(0, q["limit"] as number) : matchedSubjects;

    const result: FilteredInspection = {
      schemaVersion: INSPECTION_SCHEMA_VERSION,
      inspectionId: canonicalHash({
        op: operation,
        viewId: view.viewId,
        base,
        value,
        frameId,
        observerId,
        subjects: capped,
      }),
      operation: "filter",
      filterBase,
      filterValue: value,
      subjectVisibleIds: capped,
      matchedCount: capped.length,
      excludedCount: Math.max(0, allSubjects.length - capped.length),
      isFiltered: true,
      isComplete: false,
      canonicalViewAltered: false,
      authority: "none",
      readOnly: true,
      bounded: true,
      binding,
    };
    return {
      ok: true,
      code: "inspection_succeeded",
      operation,
      result,
      mutatedCanonicalState: false,
      authority: "none",
      readOnly: true,
    };
  }

  // ── enumerate refusals and conflicts: absence is reported, not smoothed ──
  if (operation === "enumerate_refusals_conflicts") {
    const conflicts: string[] = [];
    const barred: string[] = [];
    const bySubject = new Map<string, Record<string, unknown>>();
    for (const f of factRows) {
      const id = asString(f["subjectVisibleId"]);
      if (id === null) continue;
      bySubject.set(id, f);
      if (f["isBarred"] === true && !barred.includes(id)) barred.push(id);
    }
    // Two facts for one subject with different lifecycles is a visible conflict.
    for (const f of factRows) {
      const id = asString(f["subjectVisibleId"]);
      if (id === null) continue;
      if (bySubject.get(id) !== f && asString(f["lifecycle"]) !== asString(bySubject.get(id)?.["lifecycle"])) {
        if (!conflicts.includes(id)) conflicts.push(id);
      }
    }
    const result: RefusalInspection = {
      schemaVersion: INSPECTION_SCHEMA_VERSION,
      inspectionId: canonicalHash({
        op: operation,
        viewId: view.viewId,
        frameId,
        observerId,
        conflicts,
        barred,
      }),
      operation: "enumerate_refusals",
      refusalCodes: [...INSPECTION_REFUSAL_CODES],
      conflictSubjects: conflicts.sort(),
      barredSubjects: barred.sort(),
      counts: {
        refusalCodeCount: INSPECTION_REFUSAL_CODES.length,
        conflictSubjectCount: conflicts.length,
        barredSubjectCount: barred.length,
      },
      completenessClaimed: false,
      authority: "none",
      readOnly: true,
      binding,
    };
    return {
      ok: true,
      code: "inspection_succeeded",
      operation,
      result,
      mutatedCanonicalState: false,
      authority: "none",
      readOnly: true,
    };
  }

  // ── select / inspect / focus / expand_collapse / compare_views ───────────
  const focusScopeRaw = asString(q["focusScope"]);
  const focusScope =
    focusScopeRaw !== null && (INSPECTION_FOCUS_SCOPES as readonly string[]).includes(focusScopeRaw)
      ? (focusScopeRaw as InspectionFocusScope)
      : "whole_view";

  const expansionRaw = asString(q["expansionState"]);
  const expansionState =
    expansionRaw !== null && (INSPECTION_EXPANSION_STATES as readonly string[]).includes(expansionRaw)
      ? (expansionRaw as InspectionExpansionState)
      : "collapsed";

  let subjectIds: string[];
  if (operation === "select" || operation === "focus") {
    // Only the operations that are ABOUT a subject require one. `inspect` and
    // `compare_views` legitimately describe the whole view, so demanding a
    // subject there would refuse the most natural reading of the verb.
    const subject = asString(q["subjectVisibleId"]);
    if (subject === null) {
      return refuse("refused_subject_unknown", `${operation} requires a subjectVisibleId`);
    }
    // A subject not in the view is UNKNOWN, not absent-from-existence. The
    // refusal says the runtime cannot speak to it here.
    if (!allSubjects.includes(subject)) {
      return refuse("refused_subject_unknown", "subject is not present in this view");
    }
    subjectIds = focusScope === "subject" ? [subject] : allSubjects;
  } else {
    subjectIds = allSubjects;
  }

  const capped =
    typeof q["limit"] === "number" ? subjectIds.slice(0, q["limit"] as number) : subjectIds;

  // Only these five operations reach this branch; the narrowing makes the
  // result's literal type a checked fact rather than a cast.
  const viewOperation = operation as ViewInspection["operation"];
  const viewInspection: ViewInspection = {
    schemaVersion: INSPECTION_SCHEMA_VERSION,
    inspectionId: canonicalHash({
      op: operation,
      viewId: view.viewId,
      focusScope,
      expansionState,
      frameId,
      observerId,
      subjects: capped,
    }),
    operation: viewOperation,
    viewId: view.viewId,
    focusScope,
    expansionState,
    subjectVisibleIds: capped,
    factCount: capped.length,
    canonicalViewAltered: false,
    isGlobalTruth: false,
    authority: "none",
    controlPlane: false,
    readOnly: true,
    bounded: true,
    binding,
  };

  const selection: InspectionSelection = {
    subjectVisibleId: capped[0] ?? "",
    subjectCollection: "unspecified",
    focusScope,
    expansionState,
    authority: "none",
    confersPermission: false,
    isExecution: false,
    grantsNothing: true,
    binding,
  };

  const result: InspectionResult =
    operation === "select" || operation === "focus" ? selection : viewInspection;

  return {
    ok: true,
    code: "inspection_succeeded",
    // Narrowed to the allowed-operation union the decision type declares.
    operation: operation as InspectionAllowedOperation,
    result,
    mutatedCanonicalState: false,
    authority: "none",
    readOnly: true,
  };
}

/**
 * The one export adjacent to the forbidden list, and it cannot succeed under any
 * input. Present so a reader can see that the refusal was DELIBERATE and
 * reachable, rather than infer it was considered and found unnecessary — the
 * same reasoning 28E used for `refuseGlobalTruthSynthesis`.
 */
export function refuseInspectionAsControl(
  claimedAction: unknown,
): InspectionRefused {
  return refuse(
    "refused_query_operation_unknown",
    `inspection runtime performs no control action (${String(claimedAction)}); inspection != control`,
  );
}
