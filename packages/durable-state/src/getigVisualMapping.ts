/**
 * PHASE 28D — EVIDENCE-TO-VISUAL SEMANTIC MAPPING
 * (SEMANTIC TOKENS ONLY / NO GRAPHICS BACKEND / RENDERER-NEUTRAL)
 *
 * CENTRAL LAW: GEOMETRIC OR STYLISTIC SIMPLIFICATION MUST NOT STRENGTHEN
 * SEMANTIC CLAIMS.
 *
 * This module turns a 28A GETIG frame into renderer-neutral SEMANTIC TOKENS.
 * It draws nothing, imports no graphics library, and has no idea what a pixel
 * is. What it produces is the answer to the only question a renderer is allowed
 * to ask: "what claim may I make about this visible thing, and how strongly?"
 *
 * ── WHY THIS IS DATA AND NOT PROSE ──────────────────────────────────────────
 *
 * "A renderer may simplify" is true in one direction only. Simplifying
 * `quarantined` and `retired` into one look is honest coarsening: the viewer
 * still learns "something is wrong here". Simplifying `unknown` into `current`
 * is not simplification, it is a false statement. The two look identical to a
 * reader and mean opposite things.
 *
 * So this module refuses to describe the problem and instead makes the strong
 * version UNREPRESENTABLE, in two independent layers:
 *
 *   LAYER 1 — THE STRONGER VALUE DOES NOT EXIST.
 *   There is no `trusted` beside `unknown`, no `granted` beside `claim`, no
 *   `authorized` beside `planned`, no `global_truth` beside an observer view. A
 *   renderer cannot promote a fact to a claim it has no token for, because the
 *   token does not exist. This layer does NOT cover every promotion — a route
 *   really does have an `origin` and a fresh fact really is `current` — so
 *   `GETIG_VISUAL_FORBIDDEN_PROMOTIONS` records per row which layer actually
 *   does the work, and this comment does not overclaim on its behalf.
 *
 *   LAYER 2 — WEAKENING IS ALLOWED, STRENGTHENING IS ARITHMETICALLY IMPOSSIBLE.
 *   Every axis is an ORDERED list running weakest claim -> strongest claim, so
 *   each value carries a rank. Each token therefore publishes
 *   `permittedPresentationTiers`: the tiers it may legally be drawn at, which
 *   are exactly the tiers at or BELOW its own rank. An `unknown` fact can only
 *   ever be presented as `withheld`. There is no code path that produces a tier
 *   above a token's rank, because the list does not contain one.
 *
 * ── THE COARSENING GATE ─────────────────────────────────────────────────────
 *
 * `planGetigPresentationCoarsening()` is where a renderer declares "I am
 * drawing this whole axis the same way". That is legal, and it is checked two
 * ways:
 *
 *   · the chosen tier's rank must not exceed the MINIMUM semantic rank present
 *     on that axis. Collapsing a mixed `current`/`stale` axis to `declared`
 *     would draw the stale fact as current, so it is refused as STRENGTHENING.
 *     Collapsing the same axis to `withheld` is legal — it under-claims.
 *   · four axes may not be collapsed at all. Role, conflict, refusal and
 *     partition are the axes whose whole job is to be individually visible.
 *     Collapsing them is SUPPRESSION: the viewer can no longer tell a
 *     forwarder from an origin, or a conflicted fact from a settled one.
 *
 * ── COLOUR IS NOT THE CANONICAL MEANING ─────────────────────────────────────
 *
 * There is no colour, hue, saturation, size, shape or style field anywhere in
 * this module, and a test asserts that the emitted declarations contain no such
 * token. Presentation tiers are named for how much a drawing DISCLOSES
 * (`withheld` / `minimal` / `declared`), never for how it looks. A renderer may
 * pick any colour it likes; if colour carried the meaning, two renderers with
 * different palettes would disagree about what the system is claiming, which is
 * exactly the coupling this phase forbids.
 *
 * ── SELECTION IS NOT PERMISSION ─────────────────────────────────────────────
 *
 * `refuseVisualSelectionToPermission()` is the only interaction-adjacent export
 * and it cannot succeed under any input. Clicking a token is a read. It does
 * not select an authority, admit a peer, authorize a route or mutate anything,
 * and there is no code path here that could.
 */

import { canonicalHash } from "./canonical.js";

// ── closed vocabularies ──────────────────────────────────────────────────────

/** Every semantic axis a renderer is allowed to speak about. */
export const GETIG_VISUAL_AXES = Object.freeze([
  "knowledge",
  "freshness",
  "lifecycle",
  "grant",
  "route_state",
  "admission",
  "route_role",
  "refusal",
  "partition",
  "conflict",
  "authority",
] as const);
export type GetigVisualAxis = (typeof GETIG_VISUAL_AXES)[number];

/**
 * Each axis is ORDERED from the weakest claim to the strongest. A value's rank
 * is its index, and a presentation may never exceed it.
 *
 * Reading a few of these:
 *   · `freshness`: unknown < stale < current. "current" is the strong claim.
 *   · `lifecycle`:  retired < quarantined < observed. "observed" is the normal
 *     state; coarsening it down to either negative state under-claims.
 *   · `route_role` and the four anomaly axes are single-claim or uncomparable,
 *     which is exactly why they are marked non-collapsible below.
 */
export const GETIG_VISUAL_VALUES: Readonly<Record<GetigVisualAxis, readonly string[]>> = Object.freeze({
  knowledge: Object.freeze(["unknown", "known"]),
  freshness: Object.freeze(["unknown", "stale", "current"]),
  lifecycle: Object.freeze(["retired", "quarantined", "observed"]),
  grant: Object.freeze(["grant_none", "claim"]),
  route_state: Object.freeze(["unknown", "unavailable", "planned"]),
  admission: Object.freeze(["not_admitted", "admitted_explicit_evidence"]),
  route_role: Object.freeze(["origin", "forwarder", "destination"]),
  refusal: Object.freeze(["refused"]),
  partition: Object.freeze(["partitioned"]),
  conflict: Object.freeze(["conflict_visible"]),
  authority: Object.freeze(["read_only_zero_authority"]),
});

/**
 * Axes whose value MUST stay individually visible. Collapsing them does not
 * weaken a claim, it deletes one — which is a different and forbidden thing.
 */
export const GETIG_VISUAL_NON_COLLAPSIBLE_AXES = Object.freeze([
  "route_role",
  "refusal",
  "partition",
  "conflict",
] as const);
export type GetigVisualNonCollapsibleAxis = (typeof GETIG_VISUAL_NON_COLLAPSIBLE_AXES)[number];

/**
 * Presentation tiers, named for how much a drawing DISCLOSES — never for how it
 * looks. A tier's rank is the ceiling on what may be claimed while drawing at
 * it, and a token may only use tiers at or below its own semantic rank.
 */
export const GETIG_VISUAL_PRESENTATION_TIERS = Object.freeze(["withheld", "minimal", "declared"] as const);
export type GetigVisualPresentationTier = (typeof GETIG_VISUAL_PRESENTATION_TIERS)[number];

export const GETIG_VISUAL_PRESENTATION_TIER_RANK: Readonly<Record<GetigVisualPresentationTier, number>> = Object.freeze({
  withheld: 0,
  minimal: 1,
  declared: 2,
});

/**
 * The eight promotions the prompt requires be structurally prevented.
 *
 * Every row names the value a renderer would need in order to make the
 * promotion, and — importantly — WHICH LAYER ACTUALLY PREVENTS IT. That column
 * is not decoration. An earlier draft of this gate asserted that every
 * `strengthened_value` was simply absent from every vocabulary, and a test
 * disproved it: `origin` and `current` are both legitimate values that a route
 * and a fresh fact really do have. Absence is the prevention for four of these
 * promotions and NOT for the others:
 *
 *   · `value_absent`                     — the strengthened value exists nowhere.
 *   · `axis_non_collapsible`             — the value exists, but its axis may
 *                                          never be collapsed, so a forwarder
 *                                          can never be drawn as an origin.
 *   · `permitted_tier_ceiling`           — the value exists but ranks higher,
 *                                          and a lower-ranked fact's permitted
 *                                          tiers do not include it.
 *   · `structural_zero`                  — the mapping itself pins the
 *                                          contradicting field to a zero.
 *
 * Stating the real mechanism per row is the whole point: a reader should be
 * able to check each claim instead of taking a blanket assurance on trust.
 */
export const GETIG_VISUAL_FORBIDDEN_PROMOTIONS = Object.freeze([
  Object.freeze({ id: "unknown_to_trusted", axis: "knowledge", from: "unknown", strengthened_value: "trusted", prevented_by: "value_absent" }),
  Object.freeze({ id: "claim_to_granted", axis: "grant", from: "claim", strengthened_value: "granted", prevented_by: "value_absent" }),
  Object.freeze({ id: "observed_edge_to_admitted", axis: "admission", from: "not_admitted", strengthened_value: "admitted_by_inference", prevented_by: "value_absent" }),
  Object.freeze({ id: "route_to_authorized", axis: "route_state", from: "planned", strengthened_value: "authorized", prevented_by: "value_absent" }),
  Object.freeze({ id: "forwarder_to_origin", axis: "route_role", from: "forwarder", strengthened_value: "origin", prevented_by: "axis_non_collapsible" }),
  Object.freeze({ id: "stale_to_current", axis: "freshness", from: "stale", strengthened_value: "current", prevented_by: "permitted_tier_ceiling" }),
  Object.freeze({ id: "conflict_to_hidden", axis: "conflict", from: "conflict_visible", strengthened_value: "conflict_suppressed", prevented_by: "value_absent_and_axis_non_collapsible" }),
  Object.freeze({ id: "observer_view_to_global_truth", axis: "knowledge", from: "known", strengthened_value: "global_truth", prevented_by: "value_absent_and_structural_zero" }),
] as const);
export type GetigVisualForbiddenPromotion = (typeof GETIG_VISUAL_FORBIDDEN_PROMOTIONS)[number];

/** 28D's own refusals. Every code is driven by a real input in the suite. */
export const GETIG_VISUAL_REFUSAL_CODES = Object.freeze([
  "refused_mapping_frame_invalid",
  "refused_mapping_unknown_axis",
  "refused_mapping_unknown_value",
  "refused_mapping_unknown_subject",
  "refused_mapping_tier_unknown",
  "refused_mapping_strengthening",
  "refused_mapping_suppression",
  "refused_mapping_selection_not_permission",
] as const);
export type GetigVisualRefusalCode = (typeof GETIG_VISUAL_REFUSAL_CODES)[number];

/** Bounded output. A visible world cannot be unbounded to draw. */
export const GETIG_VISUAL_BOUNDS = Object.freeze({
  maxTokensPerMapping: 4_096,
  maxIdChars: 128,
});

export const GETIG_VISUAL_SCHEMA_VERSION = "menog-getig-visual/v0" as const;

// ── the shapes ───────────────────────────────────────────────────────────────

/** One renderer-neutral statement about one visible thing. */
export interface VisualSemanticToken {
  /** Deterministic and readable: `<collection>:<subjectId>:<axis>:<value>`. */
  readonly tokenId: string;
  readonly axis: GetigVisualAxis;
  /** The strongest claim this fact supports. */
  readonly semanticValue: string;
  /** That claim's rank within its axis. */
  readonly semanticRank: number;
  /**
   * The ONLY tiers this token may legally be drawn at. A renderer picking from
   * this list cannot strengthen the claim, because the stronger tiers are not
   * in the list. An `unknown` fact lists `["withheld"]` and nothing else.
   */
  readonly permittedPresentationTiers: readonly GetigVisualPresentationTier[];
  readonly subjectVisibleId: string;
  readonly subjectCollection: string;
  /** Structural: a token is a statement about evidence, never a grant. */
  readonly claim: "descriptive_only";
  readonly authority: "none";
  readonly mutation: "none";
  readonly executable: false;
  /** Law 9: provenance is metadata and confers nothing. */
  readonly provenanceRefIds: readonly string[];
}

export interface GetigVisualMapping {
  readonly schemaVersion: typeof GETIG_VISUAL_SCHEMA_VERSION;
  readonly frameId: string;
  readonly observerId: string;
  readonly epochId: string;
  /** Deterministic over the whole token set. */
  readonly mappingHash: string;
  readonly tokens: readonly VisualSemanticToken[];
  readonly tokenCount: number;
  /** Structural: this gate renders nothing and names no colour. */
  readonly rendererNeutral: true;
  readonly colorIsCanonicalMeaning: false;
  readonly graphicsBackend: "none";
  readonly readOnly: true;
  readonly authority: "none";
  readonly globalTruth: false;
  /** The central law, restated as a structural zero. */
  readonly strengthensSemanticClaims: false;
}

export type VisualMappingBuilt = {
  readonly ok: true;
  readonly code: "visual_mapping_built";
  readonly mapping: GetigVisualMapping;
};
export type VisualMappingRefused = {
  readonly ok: false;
  readonly code: "visual_mapping_refused";
  readonly refusal: GetigVisualRefusalCode;
  readonly explanation: string;
  readonly mapping: null;
};
export type VisualMappingDecision = VisualMappingBuilt | VisualMappingRefused;

/** One subject's planned presentation, after a legal coarsening. */
export interface PresentationPlanEntry {
  readonly tokenId: string;
  readonly axis: GetigVisualAxis;
  readonly fromValue: string;
  /** Always at or below `fromValue`'s rank — that is what legality means here. */
  readonly toTier: GetigVisualPresentationTier;
}

export interface PresentationCoarseningPlan {
  readonly axis: GetigVisualAxis;
  readonly tier: GetigVisualPresentationTier;
  readonly tierRank: number;
  readonly entries: readonly PresentationPlanEntry[];
  /** The lowest semantic rank present on this axis; the tier ceiling. */
  readonly ceilingRank: number;
  readonly underclaimsOnly: true;
}

export type CoarseningApproved = {
  readonly ok: true;
  readonly code: "presentation_coarsening_approved";
  readonly plan: PresentationCoarseningPlan;
};
export type CoarseningRefused = {
  readonly ok: false;
  readonly code: "presentation_coarsening_refused";
  readonly refusal: GetigVisualRefusalCode;
  readonly explanation: string;
  readonly plan: null;
};
export type CoarseningDecision = CoarseningApproved | CoarseningRefused;

// ── helpers ──────────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= GETIG_VISUAL_BOUNDS.maxIdChars;
}

/** Code-unit comparison, never `localeCompare`: a locale-dependent ordering
 *  would make `mappingHash` machine-dependent. */
function byKey<T>(items: readonly T[], key: (item: T) => string): T[] {
  return [...items].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
  });
}

function isAxis(value: unknown): value is GetigVisualAxis {
  return typeof value === "string" && (GETIG_VISUAL_AXES as readonly string[]).includes(value);
}

function isNonCollapsible(axis: GetigVisualAxis): axis is GetigVisualNonCollapsibleAxis {
  return (GETIG_VISUAL_NON_COLLAPSIBLE_AXES as readonly string[]).includes(axis);
}

function isTier(value: unknown): value is GetigVisualPresentationTier {
  return typeof value === "string" && (GETIG_VISUAL_PRESENTATION_TIERS as readonly string[]).includes(value);
}

/** Rank within the axis, or -1 when the value is not in the vocabulary. */
export function getigVisualSemanticRank(axis: GetigVisualAxis, value: string): number {
  const values = GETIG_VISUAL_VALUES[axis];
  if (!values) return -1;
  return values.indexOf(value);
}

/** The tiers a value may be drawn at: every tier at or below its own rank. */
export function getigVisualPermittedTiers(rank: number): readonly GetigVisualPresentationTier[] {
  return GETIG_VISUAL_PRESENTATION_TIERS.filter((t) => GETIG_VISUAL_PRESENTATION_TIER_RANK[t] <= rank);
}

// ── the ONE mapping builder ──────────────────────────────────────────────────

/**
 * Build the renderer-neutral semantic tokens for a 28A frame.
 *
 * `routeStates` and `admissionEvidence` are the ONLY places a caller may add
 * information, and both default to the honest answer:
 *
 *   · a route with no supplied state maps to `unknown`, never to `planned` —
 *     28A's visible route carries no planned/unavailable state, and inventing
 *     one would be exactly the kind of strengthening this gate exists to stop;
 *   · a route with no explicit admission evidence maps to `not_admitted`,
 *     because the prompt admits a peer only when explicitly evidenced.
 */
export function buildGetigVisualMapping(input: {
  readonly frameId: string;
  readonly frame: unknown;
  readonly routeStates?: Readonly<Record<string, string>>;
  readonly admissionEvidence?: Readonly<Record<string, string>>;
  /**
   * Observed partitions.
   *
   * These are supplied rather than read from the frame because 28A's
   * `GetigFrame` has NO partition collection — its members are entities,
   * relations, events, conflicts, refusals, routes and proposal flows only. A
   * partition is 27H reconciliation content, so 28D takes it as evidence.
   *
   * Absent input means "no partitions were observed". It does NOT mean
   * "partitions exist and are hidden", and this module never represents the
   * latter: there is no way to pass one in and have it silently dropped.
   *
   * Each record is identified by `partitionId`, falling back to
   * `reconciliationId` — the field name 27H actually uses.
   */
  readonly partitions?: readonly unknown[];
}): VisualMappingDecision {
  const refuse = (refusal: GetigVisualRefusalCode, detail: string): VisualMappingRefused => ({
    ok: false,
    code: "visual_mapping_refused",
    refusal,
    explanation: `the mapping was refused and no partial mapping was produced: ${detail}`,
    mapping: null,
  });

  if (!isRecord(input)) return refuse("refused_mapping_frame_invalid", "the builder input must be an object");
  if (!isId(input.frameId)) return refuse("refused_mapping_frame_invalid", "frameId is missing or over-long");
  const frame = input.frame;
  if (!isRecord(frame)) return refuse("refused_mapping_frame_invalid", "the frame must be an object");
  if (!isRecord(frame.observer) || !isId(frame.observer.observerId)) {
    return refuse("refused_mapping_frame_invalid", "frame.observer.observerId is required");
  }
  if (!isId(frame.epochId)) return refuse("refused_mapping_frame_invalid", "frame.epochId is required");

  const routeStates = input.routeStates ?? {};
  const admissionEvidence = input.admissionEvidence ?? {};
  if (!isRecord(routeStates)) return refuse("refused_mapping_frame_invalid", "routeStates must be an object");
  if (!isRecord(admissionEvidence)) return refuse("refused_mapping_frame_invalid", "admissionEvidence must be an object");

  const tokens: VisualSemanticToken[] = [];

  const emit = (
    collection: string,
    subjectVisibleId: string,
    axis: GetigVisualAxis,
    value: string,
    provenanceRefIds: readonly string[],
  ): void => {
    const rank = getigVisualSemanticRank(axis, value);
    if (rank < 0) {
      // An axis value that is not in the closed vocabulary is never coerced or
      // approximated; the whole mapping is refused rather than partly produced.
      throw new MappingValueError(axis, value);
    }
    tokens.push(
      Object.freeze({
        tokenId: `${collection}:${subjectVisibleId}:${axis}:${value}`,
        axis,
        semanticValue: value,
        semanticRank: rank,
        permittedPresentationTiers: Object.freeze(getigVisualPermittedTiers(rank)),
        subjectVisibleId,
        subjectCollection: collection,
        claim: "descriptive_only",
        authority: "none",
        mutation: "none",
        executable: false,
        provenanceRefIds: Object.freeze([...provenanceRefIds]),
      }),
    );
  };

  const refsOf = (item: Record<string, unknown>): readonly string[] => {
    const refs = item.provenanceRefs;
    if (!Array.isArray(refs)) return [];
    return refs
      .filter((r): r is Record<string, unknown> => isRecord(r))
      .map((r) => r.refId)
      .filter((id): id is string => isId(id));
  };

  const itemsOf = (key: string): readonly Record<string, unknown>[] => {
    const raw = frame[key];
    if (!Array.isArray(raw)) return [];
    return raw.filter(isRecord);
  };

  try {
    // ── entities: knowledge, freshness, lifecycle, grant, authority ──────────
    for (const e of itemsOf("entities")) {
      const id = e.visibleId;
      if (!isId(id)) return refuse("refused_mapping_unknown_subject", "an entity has no usable visibleId");
      const refs = refsOf(e);
      emit("entities", id, "knowledge", "known", refs);
      emit("entities", id, "freshness", typeof e.freshness === "string" ? e.freshness : "unknown", refs);
      emit("entities", id, "lifecycle", typeof e.lifecycle === "string" ? e.lifecycle : "unknown", refs);
      // The frame's `grant:"none"` is a structural zero. There is no value in
      // this axis that could say "granted", so nothing can promote a claim.
      emit("entities", id, "grant", "grant_none", refs);
      emit("entities", id, "authority", "read_only_zero_authority", refs);
    }

    // ── relations: a drawn line is not trust ────────────────────────────────
    for (const r of itemsOf("relations")) {
      const id = r.relationId;
      if (!isId(id)) return refuse("refused_mapping_unknown_subject", "a relation has no usable relationId");
      const refs = refsOf(r);
      emit("relations", id, "knowledge", "known", refs);
      emit("relations", id, "grant", "grant_none", refs);
      emit("relations", id, "authority", "read_only_zero_authority", refs);
    }

    // ── events: shown in a timeline, never performed by being shown ─────────
    for (const ev of itemsOf("events")) {
      const id = ev.eventId;
      if (!isId(id)) return refuse("refused_mapping_unknown_subject", "an event has no usable eventId");
      const refs = refsOf(ev);
      emit("events", id, "knowledge", "known", refs);
      emit("events", id, "freshness", typeof ev.freshness === "string" ? ev.freshness : "unknown", refs);
      emit("events", id, "grant", "grant_none", refs);
      emit("events", id, "authority", "read_only_zero_authority", refs);
    }

    // ── refusals: content, not errors to hide ───────────────────────────────
    for (const rf of itemsOf("refusals")) {
      const id = rf.refusalId;
      if (!isId(id)) return refuse("refused_mapping_unknown_subject", "a refusal has no usable refusalId");
      const refs = refsOf(rf);
      emit("refusals", id, "knowledge", "known", refs);
      emit("refusals", id, "refusal", "refused", refs);
    }

    // ── conflicts: emitted ALWAYS, and non-collapsible downstream ───────────
    for (const c of itemsOf("conflicts")) {
      const id = c.conflictId;
      if (!isId(id)) return refuse("refused_mapping_unknown_subject", "a conflict has no usable conflictId");
      const refs = refsOf(c);
      emit("conflicts", id, "knowledge", "known", refs);
      emit("conflicts", id, "conflict", "conflict_visible", refs);
    }

    // ── routes: state, roles, admission, freshness ──────────────────────────
    for (const rt of itemsOf("routes")) {
      const id = rt.routeId;
      if (!isId(id)) return refuse("refused_mapping_unknown_subject", "a route has no usable routeId");
      const refs = refsOf(rt);

      // Absent evidence means `unknown`. It never means `planned`.
      const suppliedState = routeStates[id];
      if (suppliedState !== undefined && getigVisualSemanticRank("route_state", suppliedState) < 0) {
        return refuse("refused_mapping_unknown_value", `route ${id} was given route_state "${suppliedState}"`);
      }
      emit("routes", id, "route_state", suppliedState ?? "unknown", refs);

      // Admission ONLY on explicit evidence. Absent evidence is not admission.
      const evidenceId = admissionEvidence[id];
      emit(
        "routes",
        id,
        "admission",
        evidenceId === undefined ? "not_admitted" : "admitted_explicit_evidence",
        evidenceId === undefined ? refs : [evidenceId],
      );

      emit("routes", id, "freshness", typeof rt.freshness === "string" ? rt.freshness : "unknown", refs);
      emit("routes", id, "grant", "grant_none", refs);

      // ROLE. Origin, every forwarder and the destination are separate tokens on
      // a non-collapsible axis, so a renderer cannot draw a forwarder as the
      // origin even by accident.
      const origin = rt.originVisibleId;
      if (!isId(origin)) return refuse("refused_mapping_unknown_subject", `route ${id} has no usable originVisibleId`);
      emit("routes", `${id}#origin`, "route_role", "origin", refs);
      if (Array.isArray(rt.forwarderVisibleIds)) {
        for (const f of rt.forwarderVisibleIds) {
          if (!isId(f)) return refuse("refused_mapping_unknown_subject", `route ${id} has an unusable forwarder id`);
          emit("routes", `${id}#forwarder:${f}`, "route_role", "forwarder", refs);
        }
      }
      const destination = rt.destinationVisibleId;
      if (!isId(destination)) {
        return refuse("refused_mapping_unknown_subject", `route ${id} has no usable destinationVisibleId`);
      }
      emit("routes", `${id}#destination`, "route_role", "destination", refs);
    }

    // ── proposal flows: forwarding an inert proposal endorses nothing ───────
    for (const p of itemsOf("proposalFlows")) {
      const id = p.proposalId;
      if (!isId(id)) return refuse("refused_mapping_unknown_subject", "a proposal flow has no usable proposalId");
      const refs = refsOf(p);
      emit("proposalFlows", id, "knowledge", "known", refs);
      emit("proposalFlows", id, "grant", "grant_none", refs);
    }

    // ── partitions: a partition is visible content, never silently merged ───
    const observedPartitions = input.partitions ?? [];
    if (!Array.isArray(observedPartitions)) {
      return refuse("refused_mapping_frame_invalid", "partitions must be an array when supplied");
    }
    for (const p of observedPartitions) {
      if (!isRecord(p)) return refuse("refused_mapping_unknown_subject", "a partition record is not an object");
      const id = p.partitionId ?? p.reconciliationId;
      if (!isId(id)) {
        return refuse("refused_mapping_unknown_subject", "a partition record has no usable partitionId or reconciliationId");
      }
      emit("partitions", id, "partition", "partitioned", refsOf(p));
    }
  } catch (error) {
    if (error instanceof MappingValueError) {
      return refuse("refused_mapping_unknown_value", `axis "${error.axis}" has no value "${error.value}"`);
    }
    return refuse("refused_mapping_frame_invalid", "the frame could not be read as visible content");
  }

  const ordered = byKey(tokens, (t) => t.tokenId);
  if (ordered.length > GETIG_VISUAL_BOUNDS.maxTokensPerMapping) {
    return refuse(
      "refused_mapping_frame_invalid",
      `${ordered.length} tokens exceeds the bound of ${GETIG_VISUAL_BOUNDS.maxTokensPerMapping}`,
    );
  }

  const observerId = frame.observer.observerId;
  const epochId = frame.epochId;

  return {
    ok: true,
    code: "visual_mapping_built",
    mapping: Object.freeze({
      schemaVersion: GETIG_VISUAL_SCHEMA_VERSION,
      frameId: input.frameId,
      observerId,
      epochId,
      mappingHash: canonicalHash({
        schemaVersion: GETIG_VISUAL_SCHEMA_VERSION,
        frameId: input.frameId,
        observerId,
        epochId,
        tokens: ordered.map((t) => t.tokenId),
      }),
      tokens: Object.freeze(ordered),
      tokenCount: ordered.length,
      rendererNeutral: true,
      colorIsCanonicalMeaning: false,
      graphicsBackend: "none",
      readOnly: true,
      authority: "none",
      globalTruth: false,
      strengthensSemanticClaims: false,
    }),
  };
}

/** Internal signal: an axis value outside the closed vocabulary. */
class MappingValueError extends Error {
  readonly axis: string;
  readonly value: string;
  constructor(axis: string, value: string) {
    super(`"${value}" is not a value of axis "${axis}"`);
    this.name = "MappingValueError";
    this.axis = axis;
    this.value = value;
  }
}

// ── the coarsening gate ──────────────────────────────────────────────────────

/**
 * Decide whether a renderer may draw one whole axis the same way.
 *
 * This is where "may simplify, must not strengthen" stops being a sentence and
 * becomes a decision with an exit code.
 */
export function planGetigPresentationCoarsening(
  mapping: unknown,
  request: { readonly axis: unknown; readonly tier: unknown },
): CoarseningDecision {
  const refuse = (refusal: GetigVisualRefusalCode, detail: string): CoarseningRefused => ({
    ok: false,
    code: "presentation_coarsening_refused",
    refusal,
    explanation: `the coarsening was refused and no partial plan was produced: ${detail}`,
    plan: null,
  });

  if (!isRecord(mapping) || !Array.isArray(mapping.tokens)) {
    return refuse("refused_mapping_frame_invalid", "the mapping must be a built GetigVisualMapping");
  }
  if (!isRecord(request)) {
    return refuse("refused_mapping_frame_invalid", "the coarsening request must be an object");
  }
  const axis = request.axis;
  if (!isAxis(axis)) return refuse("refused_mapping_unknown_axis", `"${String(axis)}" is not a visual axis`);
  const tier = request.tier;
  if (!isTier(tier)) return refuse("refused_mapping_tier_unknown", `"${String(tier)}" is not a presentation tier`);

  // Suppression is checked before rank, because it does not depend on the tier:
  // collapsing these axes deletes a distinction no tier can restore.
  if (isNonCollapsible(axis)) {
    return refuse(
      "refused_mapping_suppression",
      `the "${axis}" axis may not be collapsed: doing so would make its members indistinguishable, which hides a role, a refusal, a partition or a conflict rather than weakening its claim`,
    );
  }

  const onAxis = mapping.tokens.filter((t): t is Record<string, unknown> => isRecord(t) && t.axis === axis);
  if (onAxis.length === 0) {
    return refuse("refused_mapping_unknown_axis", `this mapping carries no "${axis}" tokens to coarsen`);
  }

  const ranks = onAxis.map((t) => (typeof t.semanticRank === "number" ? t.semanticRank : -1));
  const ceilingRank = Math.min(...ranks);
  if (ceilingRank < 0) {
    return refuse("refused_mapping_unknown_value", `a "${axis}" token carries no usable semantic rank`);
  }

  const tierRank = GETIG_VISUAL_PRESENTATION_TIER_RANK[tier];
  if (tierRank > ceilingRank) {
    return refuse(
      "refused_mapping_strengthening",
      `drawing the "${axis}" axis at "${tier}" (rank ${tierRank}) would present a value whose strongest legal claim is rank ${ceilingRank}; simplification may weaken a claim but never strengthen one`,
    );
  }

  const entries: PresentationPlanEntry[] = byKey(onAxis, (t) => String(t.tokenId)).map((t) => ({
    tokenId: String(t.tokenId),
    axis,
    fromValue: String(t.semanticValue),
    toTier: tier,
  }));

  return {
    ok: true,
    code: "presentation_coarsening_approved",
    plan: Object.freeze({
      axis,
      tier,
      tierRank,
      entries: Object.freeze(entries.map((e) => Object.freeze(e))),
      ceilingRank,
      underclaimsOnly: true,
    }),
  };
}

// ── the selection guard ──────────────────────────────────────────────────────

/**
 * Selecting a visible token is a READ. It never confers anything.
 *
 * This is the only interaction-adjacent export, and it cannot succeed under any
 * input. It exists so the law is testable rather than merely absent: a reader
 * can require that it is the sole such export and that it always refuses.
 */
export function refuseVisualSelectionToPermission(
  tokenId: string,
  _intent?: string,
): {
  readonly ok: false;
  readonly code: "selection_refused";
  readonly refusal: "refused_mapping_selection_not_permission";
  readonly explanation: string;
  readonly lookedAtTokenId: string;
  readonly conferredAuthority: false;
  readonly admittedPeer: false;
  readonly authorizedRoute: false;
  readonly mutatedRuntimeState: false;
} {
  return {
    ok: false,
    code: "selection_refused",
    refusal: "refused_mapping_selection_not_permission",
    explanation:
      "selecting a visible token reads what is already visible; it confers no authority, admits no peer, authorizes no route and mutates nothing. VISIBILITY != AUTHORITY.",
    lookedAtTokenId: typeof tokenId === "string" ? tokenId : "",
    conferredAuthority: false,
    admittedPeer: false,
    authorizedRoute: false,
    mutatedRuntimeState: false,
  };
}