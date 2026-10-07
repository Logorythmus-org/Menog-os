/**
 * PHASE 28A — GETIG REPRESENTATION CONTRACT
 * (CONTRACT-FIRST / RENDERER-NEUTRAL / READ-ONLY / ZERO AUTHORITY)
 *
 * MOTHER INVARIANT: THE VISIBLE WORLD IS A PROJECTION OF EVIDENCE, NOT A
 * SOURCE OF TRUTH OR AUTHORITY.  SHORT LAW: VISIBILITY != AUTHORITY.
 *
 * This module defines the closed, readonly shapes a GETIG frame may contain and
 * the ONE function that assembles such a frame. It is the foundation every later
 * Phase-28 gate links to, so it is deliberately small, pure and inert.
 *
 * WHAT THIS MODULE IS NOT — each of these is a STRUCTURAL guarantee, not a
 * comment. Every one of them is a literal in a type, so a caller cannot widen it
 * without a type error:
 *
 *   · VISIBLE ENTITY != RUNTIME ENTITY
 *       Every VisibleEntity carries `isRuntimeObject: false`. There is no field
 *       by which a visible object could become the thing it depicts.
 *   · RELATION != TRUST
 *       Every VisibleRelation carries `trust: "none"`.
 *   · VISUAL ROUTE != AUTHORIZATION
 *       Every VisibleRoute carries `admission: "none"`, `authorization: "none"`
 *       and `executionAuthorized: false`.
 *   · VISIBLE CAPABILITY CLAIM != GRANT
 *       Every VisibleEntity carries `grant: "none"`.
 *   · VISIBLE EVENT != EXECUTABLE ACTION
 *       Every VisibleEvent carries `executable: false` and `action: "none"`.
 *   · VISUAL REPLAY != RUNTIME REPLAY
 *       Every GetigFrame carries `replaySemantics: "visual_only_not_executable"`.
 *   · OBSERVER VIEW != GLOBAL TRUTH
 *       Every GetigFrame carries `globalTruth: false` and every observer context
 *       carries `isGlobalTruth: false`.
 *
 * The frame additionally binds `authority: "none"`, `controlPlane: false` and
 * `readOnly: true` as structural literals — VISUALIZATION != CONTROL PLANE.
 *
 * RENDERER-NEUTRAL: this module imports nothing but the canonical hasher and
 * touches no graphics, DOM, canvas or GPU surface. WebGPU belongs to Phase 29.
 *
 * READ-ONLY: there is no mutation API, no action API and no execution path here.
 * The only exported function that produces anything is `buildGetigFrame`, which
 * is a pure projection of its input — it opens no socket, binds no listener,
 * spawns no process, reads no store, and calls no Policy and no tool.
 *
 * UNKNOWN FAILS CLOSED: every enumerated field is checked against a closed
 * vocabulary. An unrecognized kind is REFUSED, never coerced, defaulted or
 * dropped. UNKNOWN IS NOT A DEFAULT VALUE.
 *
 * DETERMINISTIC: `canonicalVisibleHash` is computed over the assembled frame
 * content via the frozen canonical hasher, so identical input yields an
 * identical hash and the order of the collections is canonicalized.
 */

// ── canonical hasher (frozen, Phase-20) ──────────────────────────────────────

import { canonicalHash } from "./canonical.js";

export const GETIG_SCHEMA_VERSION = "menog-getig-frame/v0" as const;

// ── closed vocabularies (fail closed; unknown refuses) ───────────────────────

/**
 * The closed set of things a GETIG frame may show. This is the Phase-28 answer
 * to "model visible representations of runtime …" — every entry is a
 * REPRESENTATION, never the runtime object itself.
 */
export const GETIG_ENTITY_KINDS = Object.freeze([
  "runtime_node",
  "agent",
  "goal",
  "task",
  "tool_reference",
  "memory_reference",
  "policy_gate",
  "execution_boundary",
  "proposal",
  "route",
  "evidence",
  "refusal",
  "partition",
] as const);
export type GetigEntityKind = (typeof GETIG_ENTITY_KINDS)[number];

/** The closed set of relation shapes. A relation is a drawn line, never trust. */
export const GETIG_RELATION_KINDS = Object.freeze([
  "observed_edge",
  "forwarded_proposal",
  "routes_over",
  "partitions_from",
  "reconciles_with",
  "references",
  "contradicts",
] as const);
export type GetigRelationKind = (typeof GETIG_RELATION_KINDS)[number];

/** The closed set of visible event shapes. An event is shown, never performed. */
export const GETIG_EVENT_KINDS = Object.freeze([
  "node_observed",
  "state_changed",
  "edge_observed",
  "route_planned",
  "proposal_forwarded",
  "evidence_recorded",
  "refusal_recorded",
  "partition_detected",
] as const);
export type GetigEventKind = (typeof GETIG_EVENT_KINDS)[number];

/** Freshness is METADATA and is never upgraded by being drawn. */
export const GETIG_FRESHNESS_STATES = Object.freeze([
  "current",
  "stale",
  "unknown",
] as const);
export type GetigFreshness = (typeof GETIG_FRESHNESS_STATES)[number];

/** Lifecycle is METADATA. A retired fact is never visually resurrected. */
export const GETIG_LIFECYCLE_STATES = Object.freeze([
  "observed",
  "quarantined",
  "retired",
  "unknown",
] as const);
export type GetigLifecycleState = (typeof GETIG_LIFECYCLE_STATES)[number];

/** The closed set of ways two observer views can disagree. */
export const GETIG_CONFLICT_KINDS = Object.freeze([
  "value_disagreement",
  "state_disagreement",
  "freshness_disagreement",
  "absence_disagreement",
] as const);
export type GetigConflictKind = (typeof GETIG_CONFLICT_KINDS)[number];

/** Closed refusal vocabulary. No silent handling, no unknown branch. */
export const GETIG_REFUSAL_CODES = Object.freeze([
  "refused_invalid_input",
  "refused_unknown_entity_kind",
  "refused_unknown_relation_kind",
  "refused_unknown_event_kind",
  "refused_unknown_freshness",
  "refused_unknown_lifecycle_state",
  "refused_unknown_conflict_kind",
  "refused_unknown_authority_claim",
  "refused_missing_frame_id",
  "refused_missing_observer_context",
  "refused_missing_projection_hash",
  "refused_field_bound",
  "refused_collection_bound",
  "refused_duplicate_visible_id",
  "refused_non_deterministic_hash",
] as const);
export type GetigRefusalCode = (typeof GETIG_REFUSAL_CODES)[number];

export const GETIG_REFUSAL_EXPLANATIONS: Readonly<Record<GetigRefusalCode, string>> =
  Object.freeze({
    refused_invalid_input:
      "the frame input is not a well-formed object — refusing (fail closed). GETIG never repairs or coerces caller input.",
    refused_unknown_entity_kind:
      "a visible entity carried a kind outside the closed GETIG vocabulary — refusing. An unnamed entity must never be drawn, because a renderer would have to guess what it is, and a guess is a semantic claim.",
    refused_unknown_relation_kind:
      "a visible relation carried a kind outside the closed GETIG vocabulary — refusing. An unnamed relation is not a harmless line; it is an unstated claim about two objects.",
    refused_unknown_event_kind:
      "a visible event carried a kind outside the closed GETIG vocabulary — refusing.",
    refused_unknown_freshness:
      "freshness was not one of current/stale/unknown — refusing. Unknown stays unknown; it is never coerced to current.",
    refused_unknown_lifecycle_state:
      "lifecycle was not one of observed/quarantined/retired/unknown — refusing. An unrecognized lifecycle is never treated as live.",
    refused_unknown_conflict_kind:
      "a visible conflict carried a kind outside the closed GETIG vocabulary — refusing. Conflict stays visible and named; an unnamed conflict invites a renderer to hide it.",
    refused_unknown_authority_claim:
      "an input carried a field that claims authority the evidence cannot support — either a field this contract does not have (a Policy verdict, a tool call, a raw transcript, a secret, an allocation, a capability list), or a contract field carrying anything other than its structural zero. VISIBILITY != AUTHORITY, and a visible object may never assert what it cannot have.",
    refused_missing_frame_id:
      "the frame carried no frameId — refusing. An unidentified frame cannot be cited, compared or replayed.",
    refused_missing_observer_context:
      "the frame carried no observer context — refusing. A visible world with no stated observer is a claim of global truth, which is exactly the law this module forbids.",
    refused_missing_projection_hash:
      "the frame carried no sourceProjectionHash — refusing. A visible world not derived from an upstream projection has no evidence to stand on.",
    refused_field_bound:
      "a scalar field exceeded its declared bound — refusing (bounded, fail closed).",
    refused_collection_bound:
      "a visible collection exceeded its declared bound — refusing. A visible world is bounded so it can never become an unbounded dump of raw runtime state.",
    refused_duplicate_visible_id:
      "two visible objects shared an id within the same namespace — refusing. Ambiguous identity in a visible world is a correctness defect, not a display detail.",
    refused_non_deterministic_hash:
      "the canonical visible hash did not reproduce — refusing. GETIG canonical visible content must be deterministic; a frame that cannot reproduce its own hash is not admissible.",
  });

/** Bounds. A visible world is small, named and finite by construction. */
export const GETIG_BOUNDS = Object.freeze({
  maxEntities: 256,
  maxRelations: 512,
  maxEvents: 256,
  maxConflicts: 128,
  maxRefusals: 128,
  maxRoutes: 64,
  maxHopsPerRoute: 16,
  maxProposalFlows: 64,
  maxHopsPerProposalFlow: 32,
  maxProvenanceRefs: 64,
  maxIdChars: 128,
  maxObserverIdChars: 128,
  maxEpochIdChars: 128,
});

/** The closed authority literal. There is no other value in the system. */
export type GetigAuthority = "none";
/** The closed control-plane literal. */
export type GetigControlPlane = false;
/** The closed read-only literal. */
export type GetigReadOnly = true;

// ── closed readonly contracts ───────────────────────────────────────────────

/**
 * WHO IS LOOKING. Observer context is mandatory on every frame: a visible
 * world without a stated observer silently claims to be the global truth.
 */
export interface VisibleObserverContext {
  readonly observerId: string;
  readonly observerKind: "local_runtime" | "local_operator" | "offline_reader";
  readonly epochId: string;
  /**
   * Structural. An observer context may never declare itself global — that is
   * the fake-global-truth failure this whole phase exists to prevent.
   */
  readonly isGlobalTruth: false;
}

/**
 * WHERE A VISIBLE FACT CAME FROM — as METADATA ONLY (Law 9).
 *
 * This is a REFERENCE, never evidence content and never trust. A provenance ref
 * says "some governed record backs this"; it does not carry the record, does not
 * vouch for the fact, and does not authorize anything.
 */
export interface VisibleProvenanceRef {
  readonly refId: string;
  /** Metadata about the record. The record itself is never inlined here. */
  readonly recordedAtEpochMs: number;
  readonly sourceKind:
    | "local_configuration"
    | "governed_evidence"
    | "upstream_projection";
  /**
   * `null` when the source cannot cite an evidence id (local configuration must
   * not pretend to). Explicitly `null`, never "" and never invented.
   */
  readonly evidenceId: string | null;
  /** Structural: a provenance reference is metadata and confers nothing. */
  readonly confersTrust: false;
}

/**
 * A VISIBLE OBJECT. It is a representation of a runtime thing. It is never that
 * runtime thing, it grants nothing, and it cannot be acted upon.
 */
export interface VisibleEntity {
  readonly visibleId: string;
  readonly kind: GetigEntityKind;
  readonly label: string;
  /** Structural: a visible entity is not the runtime object it depicts. */
  readonly isRuntimeObject: false;
  /** Structural: VISIBLE CAPABILITY CLAIM != GRANT. */
  readonly grant: "none";
  readonly freshness: GetigFreshness;
  readonly lifecycle: GetigLifecycleState;
  readonly provenanceRefs: readonly VisibleProvenanceRef[];
  /** The id of the runtime thing this depicts — an identifier, never a handle. */
  readonly representsRuntimeId: string | null;
}

/** A VISIBLE RELATION. A drawn line is not trust, admission or authorization. */
export interface VisibleRelation {
  readonly relationId: string;
  readonly kind: GetigRelationKind;
  readonly fromVisibleId: string;
  readonly toVisibleId: string;
  /** Structural: RELATION != TRUST. */
  readonly trust: "none";
  readonly provenanceRefs: readonly VisibleProvenanceRef[];
}

/** A VISIBLE EVENT. Shown in a timeline. Never performed by being shown. */
export interface VisibleEvent {
  readonly eventId: string;
  readonly kind: GetigEventKind;
  readonly atEpochMs: number;
  readonly subjectVisibleId: string;
  /** Structural: VISIBLE EVENT != EXECUTABLE ACTION. */
  readonly executable: false;
  readonly action: "none";
  readonly freshness: GetigFreshness;
}

/** A VISIBLE CONFLICT. Conflict stays visible; it is never reconciled away. */
export interface VisibleConflict {
  readonly conflictId: string;
  readonly kind: GetigConflictKind;
  /** Which observer reported this view. Conflicts are ATTRIBUTED. */
  readonly attributedToObserverId: string;
  readonly subjectVisibleId: string;
  /** The competing claims, as displayed. Resolving them is NOT this gate's job. */
  readonly claims: readonly { readonly observerId: string; readonly stated: string }[];
  /** Structural: presenting a conflict never resolves it and never picks a winner. */
  readonly resolved: false;
}

/** A VISIBLE REFUSAL. Refusals are content, not errors to hide. */
export interface VisibleRefusal {
  readonly refusalId: string;
  readonly code: GetigRefusalCode;
  readonly subjectVisibleId: string | null;
  readonly explanation: string;
}

/** A VISIBLE ROUTE — the route as drawn. Never an authorization. */
export interface VisibleRoute {
  readonly routeId: string;
  /** The origin is the node the route starts at. A forwarder is never promoted. */
  readonly originVisibleId: string;
  /** Structural: the origin is fixed by the evidence and is never reassigned. */
  readonly originFixed: true;
  /** Forwarders are grouped and are NEVER folded into the origin. */
  readonly forwarderVisibleIds: readonly string[];
  readonly destinationVisibleId: string;
  readonly freshness: GetigFreshness;
  readonly provenanceRefs: readonly VisibleProvenanceRef[];
  /** Structural: VISUAL ROUTE != AUTHORIZATION. */
  readonly admission: "none";
  readonly authorization: "none";
  readonly executionAuthorized: false;
}

/** A VISIBLE PROPOSAL FLOW — multi-hop, inert, endorsed by nobody. */
export interface VisibleProposalFlow {
  readonly proposalId: string;
  readonly originVisibleId: string;
  readonly forwarderVisibleIds: readonly string[];
  readonly destinationVisibleId: string;
  readonly hopCount: number;
  /** Structural: FORWARDING AN INERT PROPOSAL ENDORSES NOTHING. */
  readonly endorsement: "none";
  readonly state: "proposed" | "forwarded" | "refused" | "unknown";
  readonly provenanceRefs: readonly VisibleProvenanceRef[];
}

/**
 * A GETIG FRAME — the complete, bounded, deterministic visible world for ONE
 * observer at ONE instant.
 *
 * `sourceProjectionHash` is the upstream evidence projection this frame was
 * derived from. `canonicalVisibleHash` is this frame's own deterministic
 * content hash. They are DISTINCT FIELDS on purpose: the first names where the
 * view came from, the second proves what is being shown. Keeping them separate
 * is what lets a later gate tell "the evidence changed" apart from "the view
 * changed".
 */
export interface GetigFrame {
  readonly schemaVersion: typeof GETIG_SCHEMA_VERSION;
  readonly frameId: string;
  readonly observer: VisibleObserverContext;
  readonly epochId: string;
  readonly asOfEpochMs: number;
  readonly sourceProjectionHash: string;
  readonly canonicalVisibleHash: string;
  readonly entities: readonly VisibleEntity[];
  readonly relations: readonly VisibleRelation[];
  readonly events: readonly VisibleEvent[];
  readonly conflicts: readonly VisibleConflict[];
  readonly refusals: readonly VisibleRefusal[];
  readonly routes: readonly VisibleRoute[];
  readonly proposalFlows: readonly VisibleProposalFlow[];
  /** Structural: VISUALIZATION != CONTROL PLANE. */
  readonly authority: GetigAuthority;
  readonly controlPlane: GetigControlPlane;
  readonly readOnly: GetigReadOnly;
  /** Structural: VISUAL REPLAY != RUNTIME REPLAY. */
  readonly replaySemantics: "visual_only_not_executable";
  /** Structural: OBSERVER VIEW != GLOBAL TRUTH. */
  readonly globalTruth: false;
  /** The structural zeros, named once so a renderer cannot miss them. */
  readonly visibleCapabilities: readonly string[];
}

// ── the builder input ────────────────────────────────────────────────────────

export interface GetigFrameInput {
  readonly frameId: string;
  readonly observer: VisibleObserverContext;
  readonly epochId: string;
  readonly asOfEpochMs: number;
  /** The upstream projection this view derives from. Required, never optional. */
  readonly sourceProjectionHash: string;
  readonly entities?: readonly VisibleEntity[];
  readonly relations?: readonly VisibleRelation[];
  readonly events?: readonly VisibleEvent[];
  readonly conflicts?: readonly VisibleConflict[];
  readonly refusals?: readonly VisibleRefusal[];
  readonly routes?: readonly VisibleRoute[];
  readonly proposalFlows?: readonly VisibleProposalFlow[];
}

export interface GetigFrameBuilt {
  readonly ok: true;
  readonly code: "frame_built";
  readonly frame: GetigFrame;
}

export interface GetigFrameRefused {
  readonly ok: false;
  readonly code: "frame_refused";
  readonly refusal: GetigRefusalCode;
  readonly explanation: string;
  /** Present when the frame could be identified; helps a caller report, never acts. */
  readonly frameId: string;
}

export type GetigFrameDecision = GetigFrameBuilt | GetigFrameRefused;

// ── internal helpers ─────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown, maxChars: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxChars;
}

function isHex64(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isFiniteNonNegative(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

/**
 * The structural zeros. These fields APPEAR in the contract — that is the whole
 * point of pinning them — so they are not forbidden. What is forbidden is
 * carrying them with any value other than the zero. A caller that writes
 * `authority: "admin"` is refused; a caller that omits the field is fine,
 * because the builder imposes the zero itself.
 */
export const GETIG_STRUCTURAL_ZERO_FIELDS = Object.freeze({
  authority: "none",
  controlPlane: false,
  readOnly: true,
  globalTruth: false,
  isGlobalTruth: false,
  isRuntimeObject: false,
  grant: "none",
  trust: "none",
  admission: "none",
  authorization: "none",
  executionAuthorized: false,
  executable: false,
  action: "none",
  endorsement: "none",
  resolved: false,
  confersTrust: false,
  originFixed: true,
  replaySemantics: "visual_only_not_executable",
} as const);

/**
 * Authority-shaped fields that are NOT part of this contract at all. Their mere
 * PRESENCE in caller input is the refusal, whatever the value: a visible object
 * has no business carrying a Policy verdict, a tool invocation, an allocation,
 * an escalation or a capability list. These are the fields a renderer would be
 * tempted to draw as if they meant something.
 */
export const GETIG_FORBIDDEN_CLAIM_FIELDS = Object.freeze([
  "policy",
  "policyDecision",
  "policyText",
  "hiddenPolicy",
  "toolCall",
  "toolResult",
  "toolOutput",
  "rawPrompt",
  "prompt",
  "transcript",
  "memoryContent",
  "storeContent",
  "secret",
  "privateKey",
  "credential",
  "env",
  "environment",
  "localPath",
  "invoke",
  "execute",
  "allocate",
  "escalate",
  "override",
  "sudo",
  "permission",
  "capability",
  "capabilities",
  "consent",
  "approved",
] as const);

/**
 * Walk caller input looking for a claim the evidence cannot support.
 *
 * Returns a description of the FIRST violation found, or null when the input is
 * clean. Two distinct violations, one refusal code:
 *   · a forbidden field that is not part of the contract at all;
 *   · a contract field carrying anything other than its structural zero.
 */
function findAuthorityClaimViolation(value: unknown, depth = 0): string | null {
  if (depth > 12 || value === null || typeof value !== "object") return null;
  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = findAuthorityClaimViolation(item, depth + 1);
      if (hit) return hit;
    }
    return null;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if ((GETIG_FORBIDDEN_CLAIM_FIELDS as readonly string[]).includes(key)) {
      return `forbidden field '${key}'`;
    }
    if (Object.prototype.hasOwnProperty.call(GETIG_STRUCTURAL_ZERO_FIELDS, key)) {
      const expected = (GETIG_STRUCTURAL_ZERO_FIELDS as Record<string, unknown>)[key];
      if (child !== expected) {
        return `field '${key}' must be ${JSON.stringify(expected)}, got ${JSON.stringify(child)}`;
      }
      continue;
    }
    if (key === "visibleCapabilities") {
      if (!Array.isArray(child) || child.length !== 0) {
        return "field 'visibleCapabilities' must be an empty list";
      }
      continue;
    }
    const hit = findAuthorityClaimViolation(child, depth + 1);
    if (hit) return hit;
  }
  return null;
}

/** Deduplicate-free id check within one namespace; ambiguity refuses. */
function hasDuplicateIds(items: readonly { readonly [k: string]: unknown }[], key: string): boolean {
  const seen = new Set<string>();
  for (const item of items) {
    const id = item[key];
    if (typeof id !== "string") continue;
    if (seen.has(id)) return true;
    seen.add(id);
  }
  return false;
}

function withinBound(items: unknown, max: number): boolean {
  return Array.isArray(items) && items.length <= max;
}

// ── the ONE builder ──────────────────────────────────────────────────────────

/**
 * Build a GETIG frame. Pure projection of `input` — it reads nothing, opens
 * nothing, calls nothing, and cannot act.
 *
 * Fail-closed by construction: an unknown vocabulary value, an authority-shaped
 * field, an over-bound collection, a duplicate visible id, or a missing observer
 * all produce a REFUSAL with no frame at all. A refusal exposes no partial world.
 */
export function buildGetigFrame(input: GetigFrameInput): GetigFrameDecision {
  const refuse = (refusal: GetigRefusalCode, detail?: string): GetigFrameRefused => ({
    ok: false,
    code: "frame_refused",
    refusal,
    explanation: detail ? `${GETIG_REFUSAL_EXPLANATIONS[refusal]} (${detail})` : GETIG_REFUSAL_EXPLANATIONS[refusal],
    frameId: isRecord(input) && typeof (input as Record<string, unknown>).frameId === "string" ? String((input as Record<string, unknown>).frameId) : "",
  });

  if (!isRecord(input)) {
    return refuse("refused_invalid_input");
  }

  // Identity and provenance anchors come first: without them there is nothing
  // meaningful to show, and a frame that exists but cannot be cited is worse
  // than a refusal.
  if (!isNonEmptyString(input.frameId, GETIG_BOUNDS.maxIdChars)) {
    return refuse("refused_missing_frame_id");
  }
  const observer = input.observer as unknown;
  if (
    !isRecord(observer) ||
    !isNonEmptyString(observer.observerId, GETIG_BOUNDS.maxObserverIdChars) ||
    !isNonEmptyString(observer.epochId, GETIG_BOUNDS.maxEpochIdChars) ||
    !["local_runtime", "local_operator", "offline_reader"].includes(String(observer.observerKind))
  ) {
    return refuse("refused_missing_observer_context");
  }
  if (!isNonEmptyString(input.epochId, GETIG_BOUNDS.maxEpochIdChars)) {
    return refuse("refused_invalid_input", "epochId");
  }
  if (!isFiniteNonNegative(input.asOfEpochMs)) {
    return refuse("refused_invalid_input", "asOfEpochMs");
  }
  if (!isHex64(input.sourceProjectionHash)) {
    return refuse("refused_missing_projection_hash");
  }

  // A visible contract may never CARRY a claim the evidence cannot support.
  // Checked before vocabulary so the most dangerous input gets the most
  // specific refusal.
  const claimViolation = findAuthorityClaimViolation(input);
  if (claimViolation !== null) {
    return refuse("refused_unknown_authority_claim", claimViolation);
  }

  const collections = {
    entities: input.entities ?? [],
    relations: input.relations ?? [],
    events: input.events ?? [],
    conflicts: input.conflicts ?? [],
    refusals: input.refusals ?? [],
    routes: input.routes ?? [],
    proposalFlows: input.proposalFlows ?? [],
  };

  const boundErrors: [keyof typeof collections, number][] = [
    ["entities", GETIG_BOUNDS.maxEntities],
    ["relations", GETIG_BOUNDS.maxRelations],
    ["events", GETIG_BOUNDS.maxEvents],
    ["conflicts", GETIG_BOUNDS.maxConflicts],
    ["refusals", GETIG_BOUNDS.maxRefusals],
    ["routes", GETIG_BOUNDS.maxRoutes],
    ["proposalFlows", GETIG_BOUNDS.maxProposalFlows],
  ];
  for (const [name, max] of boundErrors) {
    if (!withinBound(collections[name], max)) {
      return refuse("refused_collection_bound", `${name} > ${max}`);
    }
  }

  // ── closed vocabulary, fail closed ────────────────────────────────────────
  for (const entity of collections.entities) {
    if (!isRecord(entity)) return refuse("refused_invalid_input", "entity");
    if (!isNonEmptyString(entity.visibleId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "entity.visibleId");
    }
    if (!(GETIG_ENTITY_KINDS as readonly string[]).includes(String(entity.kind))) {
      return refuse("refused_unknown_entity_kind", String(entity.kind));
    }
    if (!(GETIG_FRESHNESS_STATES as readonly string[]).includes(String(entity.freshness))) {
      return refuse("refused_unknown_freshness", String(entity.freshness));
    }
    if (!(GETIG_LIFECYCLE_STATES as readonly string[]).includes(String(entity.lifecycle))) {
      return refuse("refused_unknown_lifecycle_state", String(entity.lifecycle));
    }
    if (!withinBound(entity.provenanceRefs, GETIG_BOUNDS.maxProvenanceRefs)) {
      return refuse("refused_collection_bound", "entity.provenanceRefs");
    }
  }
  for (const relation of collections.relations) {
    if (!isRecord(relation)) return refuse("refused_invalid_input", "relation");
    if (!isNonEmptyString(relation.relationId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "relation.relationId");
    }
    if (!(GETIG_RELATION_KINDS as readonly string[]).includes(String(relation.kind))) {
      return refuse("refused_unknown_relation_kind", String(relation.kind));
    }
    if (
      !isNonEmptyString(relation.fromVisibleId, GETIG_BOUNDS.maxIdChars) ||
      !isNonEmptyString(relation.toVisibleId, GETIG_BOUNDS.maxIdChars)
    ) {
      return refuse("refused_invalid_input", "relation endpoints");
    }
    if (!withinBound(relation.provenanceRefs, GETIG_BOUNDS.maxProvenanceRefs)) {
      return refuse("refused_collection_bound", "relation.provenanceRefs");
    }
  }
  for (const event of collections.events) {
    if (!isRecord(event)) return refuse("refused_invalid_input", "event");
    if (!isNonEmptyString(event.eventId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "event.eventId");
    }
    if (!(GETIG_EVENT_KINDS as readonly string[]).includes(String(event.kind))) {
      return refuse("refused_unknown_event_kind", String(event.kind));
    }
    if (!isFiniteNonNegative(event.atEpochMs)) {
      return refuse("refused_invalid_input", "event.atEpochMs");
    }
    if (!isNonEmptyString(event.subjectVisibleId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "event.subjectVisibleId");
    }
    if (!(GETIG_FRESHNESS_STATES as readonly string[]).includes(String(event.freshness))) {
      return refuse("refused_unknown_freshness", String(event.freshness));
    }
  }
  for (const conflict of collections.conflicts) {
    if (!isRecord(conflict)) return refuse("refused_invalid_input", "conflict");
    if (!isNonEmptyString(conflict.conflictId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "conflict.conflictId");
    }
    if (!(GETIG_CONFLICT_KINDS as readonly string[]).includes(String(conflict.kind))) {
      return refuse("refused_unknown_conflict_kind", String(conflict.kind));
    }
    if (!isNonEmptyString(conflict.attributedToObserverId, GETIG_BOUNDS.maxObserverIdChars)) {
      return refuse("refused_invalid_input", "conflict.attributedToObserverId");
    }
    if (!isNonEmptyString(conflict.subjectVisibleId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "conflict.subjectVisibleId");
    }
    if (!Array.isArray(conflict.claims)) {
      return refuse("refused_invalid_input", "conflict.claims");
    }
  }
  for (const visibleRefusal of collections.refusals) {
    if (!isRecord(visibleRefusal)) return refuse("refused_invalid_input", "refusal");
    if (!isNonEmptyString(visibleRefusal.refusalId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "refusal.refusalId");
    }
    if (!(GETIG_REFUSAL_CODES as readonly string[]).includes(String(visibleRefusal.code))) {
      return refuse("refused_unknown_conflict_kind", String(visibleRefusal.code));
    }
    if (typeof visibleRefusal.explanation !== "string") {
      return refuse("refused_invalid_input", "refusal.explanation");
    }
  }
  for (const route of collections.routes) {
    if (!isRecord(route)) return refuse("refused_invalid_input", "route");
    if (!isNonEmptyString(route.routeId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "route.routeId");
    }
    if (!isNonEmptyString(route.originVisibleId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "route.originVisibleId");
    }
    if (!isNonEmptyString(route.destinationVisibleId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "route.destinationVisibleId");
    }
    if (!withinBound(route.forwarderVisibleIds, GETIG_BOUNDS.maxHopsPerRoute)) {
      return refuse("refused_collection_bound", "route.forwarderVisibleIds");
    }
    if (!(GETIG_FRESHNESS_STATES as readonly string[]).includes(String(route.freshness))) {
      return refuse("refused_unknown_freshness", String(route.freshness));
    }
    if (!withinBound(route.provenanceRefs, GETIG_BOUNDS.maxProvenanceRefs)) {
      return refuse("refused_collection_bound", "route.provenanceRefs");
    }
  }
  for (const flow of collections.proposalFlows) {
    if (!isRecord(flow)) return refuse("refused_invalid_input", "proposalFlow");
    if (!isNonEmptyString(flow.proposalId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "proposalFlow.proposalId");
    }
    if (!isNonEmptyString(flow.originVisibleId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "proposalFlow.originVisibleId");
    }
    if (!isNonEmptyString(flow.destinationVisibleId, GETIG_BOUNDS.maxIdChars)) {
      return refuse("refused_invalid_input", "proposalFlow.destinationVisibleId");
    }
    if (!withinBound(flow.forwarderVisibleIds, GETIG_BOUNDS.maxHopsPerProposalFlow)) {
      return refuse("refused_collection_bound", "proposalFlow.forwarderVisibleIds");
    }
    if (!["proposed", "forwarded", "refused", "unknown"].includes(String(flow.state))) {
      return refuse("refused_invalid_input", "proposalFlow.state");
    }
    if (!withinBound(flow.provenanceRefs, GETIG_BOUNDS.maxProvenanceRefs)) {
      return refuse("refused_collection_bound", "proposalFlow.provenanceRefs");
    }
  }

  // ── ambiguous identity refuses ─────────────────────────────────────────────
  const idChecks: [readonly unknown[], string][] = [
    [collections.entities, "visibleId"],
    [collections.relations, "relationId"],
    [collections.events, "eventId"],
    [collections.conflicts, "conflictId"],
    [collections.refusals, "refusalId"],
    [collections.routes, "routeId"],
    [collections.proposalFlows, "proposalId"],
  ];
  for (const [items, key] of idChecks) {
    if (hasDuplicateIds(items as readonly { readonly [k: string]: unknown }[], key)) {
      return refuse("refused_duplicate_visible_id", key);
    }
  }

  // ── assemble the frame ─────────────────────────────────────────────────────
  const content = {
    schemaVersion: GETIG_SCHEMA_VERSION,
    frameId: input.frameId,
    observer: {
      observerId: (observer as Record<string, unknown>).observerId as string,
      observerKind: (observer as Record<string, unknown>).observerKind as VisibleObserverContext["observerKind"],
      epochId: (observer as Record<string, unknown>).epochId as string,
      isGlobalTruth: false as const,
    },
    epochId: input.epochId,
    asOfEpochMs: input.asOfEpochMs,
    sourceProjectionHash: input.sourceProjectionHash,
    entities: collections.entities,
    relations: collections.relations,
    events: collections.events,
    conflicts: collections.conflicts,
    refusals: collections.refusals,
    routes: collections.routes,
    proposalFlows: collections.proposalFlows,
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    replaySemantics: "visual_only_not_executable" as const,
    globalTruth: false as const,
    visibleCapabilities: Object.freeze([]) as readonly string[],
  };

  const canonicalVisibleHash = canonicalHash(content);

  // Determinism is a REQUIREMENT, not an assumption: recompute and compare. A
  // frame that cannot reproduce its own hash is not admissible, because a
  // renderer would then be drawing something whose content it cannot name.
  if (canonicalHash(content) !== canonicalVisibleHash) {
    return refuse("refused_non_deterministic_hash");
  }

  const frame: GetigFrame = { ...content, canonicalVisibleHash };
  return { ok: true, code: "frame_built", frame };
}

/**
 * The structural-zero report for a frame: the claims a renderer must never
 * infer. Exported so a later gate can ASSERT these rather than re-derive them.
 */
export function readGetigStructuralZeros(frame: GetigFrame): {
  readonly authority: GetigAuthority;
  readonly controlPlane: GetigControlPlane;
  readonly readOnly: GetigReadOnly;
  readonly replaySemantics: GetigFrame["replaySemantics"];
  readonly globalTruth: false;
  readonly observableCapabilities: 0;
} {
  return {
    authority: frame.authority,
    controlPlane: frame.controlPlane,
    readOnly: frame.readOnly,
    replaySemantics: frame.replaySemantics,
    globalTruth: frame.globalTruth,
    observableCapabilities: 0,
  };
}