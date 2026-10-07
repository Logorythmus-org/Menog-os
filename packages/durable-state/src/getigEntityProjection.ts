/**
 * PHASE 28B — RUNTIME ENTITY PROJECTION
 * (PURE DETERMINISTIC PROJECTION / READ-ONLY / NO INVENTED INFORMATION)
 *
 * MOTHER INVARIANT: THE VISIBLE WORLD IS A PROJECTION OF EVIDENCE, NOT A
 * SOURCE OF TRUTH OR AUTHORITY.  VISIBILITY != AUTHORITY.
 *
 * This module maps a FROZEN Phase-27 observability snapshot into a 28A GETIG
 * frame. It is a projection and nothing else:
 *
 *   · it READS the upstream snapshot and never mutates, extends or repairs it;
 *   · it INVENTS NOTHING — every visible field is copied from an upstream field
 *     or is an explicit structural zero;
 *   · it carries no authority across, because 28A's structural zeros make that
 *     impossible to express, not merely discouraged;
 *   · it calls no network, store, Policy, tool, spawn or rendering API.
 *
 * THE ORDERING DECISION — the one that makes determinism real:
 *
 * `canonicalDurableJson` (frozen Phase-20) sorts object KEYS but preserves
 * ARRAY ORDER. So if this module emitted collections in upstream order, a
 * shuffled input would produce a different `canonicalVisibleHash`, which the
 * 28B law forbids outright. Therefore:
 *
 *   · COLLECTION ORDER IS CANONICALIZED — every visible collection is sorted by
 *     a stable natural key, so shuffled input yields byte-identical content.
 *   · HOP ORDER IS SEMANTIC AND IS PRESERVED — a route's forwarder sequence is
 *     meaning, not presentation. Sorting it would destroy the very thing the
 *     route asserts, so it is never sorted.
 *
 * Getting this backwards in either direction would be a silent correctness bug:
 * not sorting invents instability; sorting hops invents a false path.
 *
 * THE LAWS THIS PROJECTION MUST NOT BREAK, and how each is preserved:
 *   edge != trust/admission      → relations carry `trust: "none"` (28A pin)
 *   advertisement != grant       → entities carry `grant: "none"` (28A pin)
 *   route != authorization       → routes carry admission/authorization none
 *   forwarder != origin          → origin is copied from `originNodeId` and the
 *                                  forwarder sequence is kept SEPARATE
 *   reconciliation != consensus  → every upstream conflict is emitted VISIBLE
 *                                  and `resolved: false`; agreement counts are
 *                                  never turned into a winner
 *   unknown stays unknown        → `unknown_freshness` and `unknown_observation`
 *                                  map to `unknown`, never to current/observed
 *   stale stays stale            → `outside_window` maps to `stale`
 *   retired stays retired        → `retired_observation` maps to `retired`
 */

import {
  buildGetigFrame,
  GETIG_BOUNDS,
  type GetigFrame,
  type GetigFrameDecision,
  type GetigRefusalCode,
  type VisibleConflict,
  type VisibleEntity,
  type VisibleObserverContext,
  type VisibleProvenanceRef,
  type VisibleRefusal,
  type VisibleRelation,
  type VisibleRoute,
} from "./getigRepresentation.js";

export const GETIG_PROJECTION_SCHEMA_VERSION = "menog-getig-entity-projection/v0" as const;

// ── upstream vocabulary (copied from the frozen Phase-27 surfaces) ────────────

/** 27H freshness vocabulary, as measured. */
const UPSTREAM_FRESHNESS = ["within_window", "outside_window", "unknown_freshness"] as const;
/** 27C/27H observation-state vocabulary. */
const UPSTREAM_OBSERVATION_STATES = [
  "observed",
  "stale",
  "quarantined_observation",
  "retired_observation",
  "unknown_observation",
] as const;
/** 27G reconciliation resolution classes. */
const UPSTREAM_CONFLICT_RESOLUTIONS = [
  "terminal_retained",
  "quarantine_retained",
  "no_consensus_unknown",
] as const;

// ── mapping tables (explicit; nothing is guessed) ────────────────────────────

/**
 * Freshness. `unknown_freshness` maps to `unknown` and NOT to `current`: an
 * upstream that could not determine freshness must not be drawn as fresh.
 */
export const PROJECTION_FRESHNESS_MAP: Readonly<Record<(typeof UPSTREAM_FRESHNESS)[number], "current" | "stale" | "unknown">> =
  Object.freeze({
    within_window: "current",
    outside_window: "stale",
    unknown_freshness: "unknown",
  });

/**
 * Lifecycle. Note `stale` is NOT a lifecycle value — a stale observation is
 * still an observed fact that has aged, and conflating the two dimensions would
 * let a renderer draw a stale node as though it had never been seen. Staleness
 * lives in `freshness`; lifecycle stays `observed`.
 */
export const PROJECTION_LIFECYCLE_MAP: Readonly<Record<(typeof UPSTREAM_OBSERVATION_STATES)[number], "observed" | "quarantined" | "retired" | "unknown">> =
  Object.freeze({
    observed: "observed",
    stale: "observed",
    quarantined_observation: "quarantined",
    retired_observation: "retired",
    unknown_observation: "unknown",
  });

/**
 * Upstream mesh refusal codes that may appear inside a 27H snapshot, mapped to
 * their GETIG classification.
 *
 * This table is CLOSED and EXPLICIT. An upstream code that is not listed makes
 * the whole projection REFUSE rather than being approximated — because guessing
 * a classification would be inventing information, which is the one thing this
 * gate exists to prevent. Widening this table is a deliberate act, not a
 * fallback.
 */
export const PROJECTION_UPSTREAM_REFUSAL_MAP: Readonly<Record<string, GetigRefusalCode>> =
  Object.freeze({
    refused_invalid_input: "refused_invalid_input",
    refused_field_bound: "refused_field_bound",
    refused_epoch_mismatch: "refused_invalid_input",
    refused_unknown_vocabulary: "refused_unknown_entity_kind",
    refused_invalid_provenance: "refused_invalid_input",
    refused_non_finite_time: "refused_invalid_input",
    refused_duplicate_entry: "refused_duplicate_visible_id",
    refused_unknown: "refused_unknown_entity_kind",
  });

/** 28B-specific refusals, when the projection itself cannot proceed. */
export const PROJECTION_REFUSAL_CODES = Object.freeze([
  "refused_projection_invalid_input",
  "refused_projection_not_a_snapshot",
  "refused_projection_upstream_shape",
  "refused_projection_unmapped_refusal_code",
  "refused_projection_unknown_vocabulary",
  "refused_projection_oversize",
] as const);
export type ProjectionRefusalCode = (typeof PROJECTION_REFUSAL_CODES)[number];

// ── the projection input ─────────────────────────────────────────────────────

export interface GetigProjectionInput {
  readonly frameId: string;
  readonly observer: VisibleObserverContext;
  /** The FROZEN upstream snapshot, consumed read-only. */
  readonly snapshot: unknown;
}

export interface GetigProjectionBuilt {
  readonly ok: true;
  readonly code: "projection_built";
  readonly frame: GetigFrame;
  /**
   * Statistics about the projection itself — how many upstream records became
   * visible records. Metadata for a caller; confers nothing.
   */
  readonly summary: ProjectionSummary;
}

export interface ProjectionSummary {
  readonly nodesProjected: number;
  readonly edgesProjected: number;
  readonly routesProjected: number;
  readonly refusalsProjected: number;
  readonly conflictsProjected: number;
  readonly collectionsCanonicalized: boolean;
  readonly hopOrderPreserved: true;
}

export interface GetigProjectionRefused {
  readonly ok: false;
  readonly code: "projection_refused";
  readonly refusal: ProjectionRefusalCode;
  readonly explanation: string;
  readonly frameId: string;
}

export type GetigProjectionDecision = GetigProjectionBuilt | GetigProjectionRefused;

const PROJECTION_REFUSAL_EXPLANATIONS: Readonly<Record<ProjectionRefusalCode, string>> =
  Object.freeze({
    refused_projection_invalid_input:
      "the projection input is not a well-formed object — refusing (fail closed). The projection never repairs its caller.",
    refused_projection_not_a_snapshot:
      "the supplied upstream value is not a Phase-27 observability snapshot — refusing. A projection may only read what its upstream actually produced; projecting an arbitrary object would be inventing a world.",
    refused_projection_upstream_shape:
      "the upstream snapshot is missing a required section or a record is malformed — refusing. Nothing partial is ever projected.",
    refused_projection_unmapped_refusal_code:
      "an upstream refusal code has no explicit GETIG classification — refusing the whole projection. Approximating the code would invent a meaning the evidence never supplied.",
    refused_projection_unknown_vocabulary:
      "an upstream vocabulary value is outside the frozen Phase-27 set — refusing. An unrecognized value is unknown, never defaulted.",
    refused_projection_oversize:
      "the upstream snapshot exceeds the GETIG visible bounds — refusing. A visible world is bounded by construction.",
  });

// ── internal helpers ─────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function arr(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? (value as readonly unknown[]) : [];
}

/**
 * Deterministic ordering by a natural key. String comparison is code-unit
 * order, which is stable across runs and platforms — `localeCompare` is not,
 * and would make the hash locale-dependent.
 */
function byKey<T>(items: readonly T[], key: (item: T) => string): T[] {
  return [...items].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
  });
}

/** Map an upstream provenance record to a 28A metadata-only reference. */
function toProvenanceRef(provenance: unknown, subjectId: string): VisibleProvenanceRef | null {
  if (!isRecord(provenance)) return null;
  const source = provenance.source;
  // 27B's rule, preserved: local configuration must NOT pretend to cite an
  // evidence id. An explicit null is the honest value; inventing one is not.
  const evidenceId =
    source === "local_configuration"
      ? null
      : typeof provenance.evidenceId === "string" && provenance.evidenceId.length > 0
        ? provenance.evidenceId
        : null;
  const recordedAtEpochMs = provenance.recordedAtEpochMs;
  return {
    refId: `${subjectId}:provenance`,
    recordedAtEpochMs: typeof recordedAtEpochMs === "number" && Number.isFinite(recordedAtEpochMs) ? recordedAtEpochMs : 0,
    sourceKind:
      source === "local_configuration" || source === "governed_evidence"
        ? source
        : "upstream_projection",
    evidenceId,
    confersTrust: false,
  };
}

// ── the projection ───────────────────────────────────────────────────────────

/**
 * Project a frozen Phase-27 observability snapshot into a 28A GETIG frame.
 *
 * Pure: reads its input, returns a new frame, mutates nothing, calls nothing.
 * A refusal exposes no partial frame — exactly as in 28A.
 */
export function projectObservabilitySnapshot(input: GetigProjectionInput): GetigProjectionDecision {
  const refuse = (refusal: ProjectionRefusalCode, detail?: string): GetigProjectionRefused => ({
    ok: false,
    code: "projection_refused",
    refusal,
    explanation: detail ? `${PROJECTION_REFUSAL_EXPLANATIONS[refusal]} (${detail})` : PROJECTION_REFUSAL_EXPLANATIONS[refusal],
    frameId: isRecord(input) && typeof (input as Record<string, unknown>).frameId === "string" ? String((input as Record<string, unknown>).frameId) : "",
  });

  if (!isRecord(input)) return refuse("refused_projection_invalid_input");

  const snapshot = input.snapshot;
  if (!isRecord(snapshot)) return refuse("refused_projection_not_a_snapshot");

  // The upstream snapshot carries its own zero-authority literals. If they are
  // anything else, we are not looking at a frozen 27H snapshot and must not
  // pretend otherwise.
  if (snapshot.authority !== "none" || snapshot.controlPlane !== false || snapshot.readOnly !== true) {
    return refuse("refused_projection_not_a_snapshot", "upstream structural zeros are not intact");
  }
  if (typeof snapshot.projectionHash !== "string" || !/^[0-9a-f]{64}$/.test(snapshot.projectionHash)) {
    return refuse("refused_projection_upstream_shape", "projectionHash");
  }
  // Epoch and as-of time are COPIED or refused. Substituting a placeholder would
  // be inventing the one field that tells a reader WHEN the view was taken.
  if (typeof snapshot.epochId !== "string" || snapshot.epochId.length === 0) {
    return refuse("refused_projection_upstream_shape", "epochId");
  }
  if (typeof snapshot.asOfEpochMs !== "number" || !Number.isFinite(snapshot.asOfEpochMs) || snapshot.asOfEpochMs < 0) {
    return refuse("refused_projection_upstream_shape", "asOfEpochMs");
  }

  for (const key of ["nodes", "edges", "routes", "refusals", "partitions"]) {
    if (!Array.isArray(snapshot[key])) return refuse("refused_projection_upstream_shape", key);
  }

  // ── bounds, checked before any work is done ────────────────────────────────
  if (
    arr(snapshot.nodes).length > GETIG_BOUNDS.maxEntities ||
    arr(snapshot.edges).length > GETIG_BOUNDS.maxRelations ||
    arr(snapshot.routes).length > GETIG_BOUNDS.maxRoutes ||
    arr(snapshot.refusals).length > GETIG_BOUNDS.maxRefusals
  ) {
    return refuse("refused_projection_oversize");
  }

  // ── entities: one per upstream node ────────────────────────────────────────
  const entities: VisibleEntity[] = [];
  for (const node of arr(snapshot.nodes)) {
    if (!isRecord(node) || typeof node.nodeId !== "string" || node.nodeId.length === 0) {
      return refuse("refused_projection_upstream_shape", "node");
    }
    const observationState = node.observationState;
    const freshness = node.freshness;
    if (!(UPSTREAM_OBSERVATION_STATES as readonly string[]).includes(String(observationState))) {
      return refuse("refused_projection_unknown_vocabulary", `observationState ${String(observationState)}`);
    }
    if (!(UPSTREAM_FRESHNESS as readonly string[]).includes(String(freshness))) {
      return refuse("refused_projection_unknown_vocabulary", `freshness ${String(freshness)}`);
    }
    const ref = toProvenanceRef(node.provenance, node.nodeId);
    entities.push({
      visibleId: node.nodeId,
      // Both upstream node kinds are runtime nodes as far as the visible world
      // is concerned; the trust distinction is upstream metadata, not a visible
      // entity class, and inventing a "trusted node" kind would be an overclaim.
      kind: "runtime_node",
      label: node.nodeId,
      isRuntimeObject: false,
      grant: "none",
      freshness: PROJECTION_FRESHNESS_MAP[projectionFreshness(freshness)],
      lifecycle: PROJECTION_LIFECYCLE_MAP[projectionLifecycle(observationState)],
      provenanceRefs: ref ? [ref] : [],
      // An IDENTIFIER, never a handle to the live node.
      representsRuntimeId: node.nodeId,
    });
  }

  // ── relations: one per upstream edge ───────────────────────────────────────
  const relations: VisibleRelation[] = [];
  for (const edge of arr(snapshot.edges)) {
    if (
      !isRecord(edge) ||
      typeof edge.edgeId !== "string" ||
      typeof edge.fromNodeId !== "string" ||
      typeof edge.toNodeId !== "string"
    ) {
      return refuse("refused_projection_upstream_shape", "edge");
    }
    const freshness = edge.freshness;
    if (!(UPSTREAM_FRESHNESS as readonly string[]).includes(String(freshness))) {
      return refuse("refused_projection_unknown_vocabulary", `edge freshness ${String(freshness)}`);
    }
    const ref = toProvenanceRef(edge.provenance, edge.edgeId);
    relations.push({
      relationId: edge.edgeId,
      kind: "observed_edge",
      fromVisibleId: edge.fromNodeId,
      toVisibleId: edge.toNodeId,
      // EDGE != TRUST. An observed edge is an observation of adjacency and
      // nothing more; the visible world never asserts the peer is admitted.
      trust: "none",
      provenanceRefs: ref ? [ref] : [],
    });
  }

  // ── routes: origin copied, forwarders kept separate ────────────────────────
  const routes: VisibleRoute[] = [];
  for (const route of arr(snapshot.routes)) {
    if (
      !isRecord(route) ||
      typeof route.routeId !== "string" ||
      typeof route.originNodeId !== "string" ||
      typeof route.destinationNodeId !== "string" ||
      route.originFixed !== true
    ) {
      return refuse("refused_projection_upstream_shape", "route");
    }
    const freshness = route.freshness;
    if (!(UPSTREAM_FRESHNESS as readonly string[]).includes(String(freshness))) {
      return refuse("refused_projection_unknown_vocabulary", `route freshness ${String(freshness)}`);
    }
    const forwarders = arr(route.forwarderNodeIds).filter((f): f is string => typeof f === "string");
    if (forwarders.length > GETIG_BOUNDS.maxHopsPerRoute) {
      return refuse("refused_projection_oversize", "route.forwarderNodeIds");
    }
    routes.push({
      routeId: route.routeId,
      // ORIGIN IS COPIED, NEVER DERIVED. The forwarder sequence is preserved in
      // its own field and is never merged into the origin.
      originVisibleId: route.originNodeId,
      originFixed: true,
      // Hop order is SEMANTIC and is preserved exactly as upstream gave it.
      forwarderVisibleIds: forwarders,
      destinationVisibleId: route.destinationNodeId,
      freshness: PROJECTION_FRESHNESS_MAP[projectionFreshness(freshness)],
      provenanceRefs: [],
      admission: "none",
      authorization: "none",
      executionAuthorized: false,
    });
    // A route is also visible as an entity, so a renderer can select it.
    entities.push({
      visibleId: `route:${route.routeId}`,
      kind: "route",
      label: route.routeId,
      isRuntimeObject: false,
      grant: "none",
      freshness: PROJECTION_FRESHNESS_MAP[projectionFreshness(freshness)],
      lifecycle: "observed",
      provenanceRefs: [],
      representsRuntimeId: typeof route.routeId === "string" ? route.routeId : null,
    });
  }

  // ── refusals: mapped through the closed table, never approximated ──────────
  const visibleRefusals: VisibleRefusal[] = [];
  for (const refusal of arr(snapshot.refusals)) {
    if (!isRecord(refusal) || typeof refusal.subjectId !== "string" || typeof refusal.code !== "string") {
      return refuse("refused_projection_upstream_shape", "refusal");
    }
    const mapped = PROJECTION_UPSTREAM_REFUSAL_MAP[refusal.code];
    if (mapped === undefined) {
      // Fail closed. Approximating would invent a classification.
      return refuse("refused_projection_unmapped_refusal_code", refusal.code);
    }
    visibleRefusals.push({
      refusalId: `refusal:${refusal.subjectId}:${refusal.code}`,
      code: mapped,
      subjectVisibleId: refusal.subjectId,
      // Upstream refusals carry NO free text, so neither does this. There is no
      // channel through which a secret or a prompt could ride into the frame.
      explanation: `upstream refused this record (${mapped})`,
    });
  }

  // ── conflicts: visible, attributed, and never resolved ─────────────────────
  const conflicts: VisibleConflict[] = [];
  for (const partition of arr(snapshot.partitions)) {
    if (!isRecord(partition) || typeof partition.reconciliationId !== "string") {
      return refuse("refused_projection_upstream_shape", "partition");
    }
    for (const conflict of arr(partition.conflicts)) {
      if (!isRecord(conflict) || typeof conflict.subjectNodeId !== "string") {
        return refuse("refused_projection_upstream_shape", "conflict");
      }
      const resolution = conflict.resolution;
      if (!(UPSTREAM_CONFLICT_RESOLUTIONS as readonly string[]).includes(String(resolution))) {
        return refuse("refused_projection_unknown_vocabulary", `conflict resolution ${String(resolution)}`);
      }
      const localState = String(conflict.localState);
      const remoteState = String(conflict.remoteState);
      if (!(UPSTREAM_OBSERVATION_STATES as readonly string[]).includes(localState) ||
          !(UPSTREAM_OBSERVATION_STATES as readonly string[]).includes(remoteState)) {
        return refuse("refused_projection_unknown_vocabulary", "conflict state");
      }
      conflicts.push({
        conflictId: `conflict:${partition.reconciliationId}:${conflict.subjectNodeId}`,
        kind: "state_disagreement",
        // ATTRIBUTED: the observer sees WHO disagrees, so no side looks like
        // the truth simply by being drawn first.
        attributedToObserverId: input.observer.observerId,
        subjectVisibleId: conflict.subjectNodeId,
        claims: byKey(
          [
            { observerId: `${input.observer.observerId}:local`, stated: localState },
            { observerId: `${input.observer.observerId}:remote`, stated: remoteState },
          ],
          (c) => `${c.observerId}\u0000${c.stated}`,
        ),
        // RECONCILIATION != CONSENSUS. Upstream reported a reconciliation class;
        // the visible world records the disagreement and stops. Even
        // `terminal_retained` does NOT resolve the conflict here — that would be
        // a consensus claim the observer-relative law forbids.
        resolved: false,
      });
    }
  }

  // ── canonical ordering ─────────────────────────────────────────────────────
  // Collection order is canonicalized so shuffled upstream input produces
  // byte-identical visible content. Hop order is NOT touched.
  const canonicalEntities = byKey(entities, (e) => e.visibleId);
  const canonicalRelations = byKey(relations, (r) => r.relationId);
  const canonicalRoutes = byKey(routes, (r) => r.routeId);
  const canonicalRefusals = byKey(visibleRefusals, (r) => r.refusalId);
  const canonicalConflicts = byKey(conflicts, (c) => c.conflictId);

  const decision: GetigFrameDecision = buildGetigFrame({
    frameId: input.frameId,
    observer: input.observer,
    // Epoch and as-of time are COPIED from upstream, never invented locally.
    epochId: snapshot.epochId,
    asOfEpochMs: snapshot.asOfEpochMs,
    // The upstream projection hash is carried VERBATIM. It is 28A's job to hash
    // the visible content; this module must never recompute or replace it.
    sourceProjectionHash: snapshot.projectionHash,
    entities: canonicalEntities,
    relations: canonicalRelations,
    events: [],
    conflicts: canonicalConflicts,
    refusals: canonicalRefusals,
    routes: canonicalRoutes,
    proposalFlows: [],
  });

  if (!decision.ok) {
    // 28A refused the projected frame. Report 28A's own reason rather than
    // inventing a parallel failure path.
    return {
      ok: false,
      code: "projection_refused",
      refusal: "refused_projection_upstream_shape",
      explanation: `the projected frame was refused by the 28A contract: ${decision.explanation}`,
      frameId: decision.frameId,
    };
  }

  return {
    ok: true,
    code: "projection_built",
    frame: decision.frame,
    summary: {
      nodesProjected: arr(snapshot.nodes).length,
      edgesProjected: arr(snapshot.edges).length,
      routesProjected: arr(snapshot.routes).length,
      refusalsProjected: canonicalRefusals.length,
      conflictsProjected: canonicalConflicts.length,
      collectionsCanonicalized: true,
      hopOrderPreserved: true,
    },
  };
}

// Narrowing helpers keep the map lookups total without an `as` cast.
function projectionFreshness(value: unknown): (typeof UPSTREAM_FRESHNESS)[number] {
  return value as (typeof UPSTREAM_FRESHNESS)[number];
}
function projectionLifecycle(value: unknown): (typeof UPSTREAM_OBSERVATION_STATES)[number] {
  return value as (typeof UPSTREAM_OBSERVATION_STATES)[number];
}