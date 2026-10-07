/**
 * PHASE 27H — Mesh Observability (DETERMINISTIC REDACTED READ-ONLY
 * PROJECTION / VISUALIZATION != CONTROL PLANE).
 *
 * This module exposes ONE pure function that projects local
 * topology/runtime KNOWLEDGE into a deterministic, redacted,
 * read-only snapshot for later GETIG visualization work: nodes, edges,
 * routes (with origin/forwarders/destination roles), lifecycle state
 * distinctions, freshness, provenance METADATA, recorded refusals,
 * partition/reconciliation summaries, and the zero-authority state of
 * the projection itself. The snapshot is display knowledge: it is
 * never an input to any decision, never a control signal, never a
 * source of authority.
 *
 * THE LAWS IT ENFORCES
 *   · VISUALIZATION != CONTROL PLANE — the export surface is exactly
 *     ONE pure builder function: no mutation method, no action API,
 *     no apply/set/update/execute surface of any kind. Every snapshot
 *     carries the structural literals authority: "none",
 *     controlPlane: false, readOnly: true.
 *   · DETERMINISTIC — same input, byte-identical snapshot: every
 *     section is canonically sorted (UTF-16 code-unit order, no
 *     locale), everything returned is Object.freeze'd, and
 *     projectionHash = canonicalHash over schema version + input.
 *     The builder reads NO clock: asOfEpochMs is caller-supplied like
 *     every epoch time in this phase.
 *   · REDACTED — the input schema has NO free-text, payload, or store-
 *     content channel: every string is a bounded identifier (<=128), a
 *     bounded refusal-code token (<=64, shape-checked), or a frozen
 *     vocabulary member; provenance is projected as METADATA ONLY
 *     (source, evidence id, recorded time) — evidence content itself
 *     is never accepted, never stored, never rendered.
 *   · UNKNOWN STAYS UNKNOWN — unknown_node, unknown_edge,
 *     unknown_route, unknown_role, unknown_source and
 *     unknown_observation project exactly as recorded; missing
 *     sections project as explicit empty arrays and zero lifecycle
 *     counts; nothing is inferred, promoted, averaged, or invented. A
 *     record that cannot be classified under the frozen 27A/27B/27C
 *     vocabularies REFUSES (fail closed) instead of rendering.
 *   · FRESHNESS IS CLASSIFIED, NOT DECIDED — ageMs = asOfEpochMs
 *     minus recordedAtEpochMs; a negative age (record after asOf)
 *     cannot be ordered, so it projects as unknown_freshness; the
 *     frozen window (300000 ms) separates within_window from
 *     outside_window. No freshness value ever authorizes anything.
 *   · FAIL-CLOSED INPUT — bounded sections, one epoch across every
 *     section, closed vocabularies, finite non-negative times,
 *     sequential hop indexes, non-negative integer counts, unique
 *     identifiers per section; every refusal carries an explanation
 *     matching /refus/ and a projectionHash. Refusal exposes NO
 *     snapshot (nothing partial ever escapes).
 *
 * SCOPE LAW: LOCAL-ONLY. No discovery/scanning/mDNS/broadcast/gossip
 * membership/WAN/Internet/cloud relay/NAT traversal/UPnP/tunnel/
 * consensus/global authority; no socket, no listener, no spawn, no
 * clock, no store access; no alternate listener/spawn/persist/control
 * path; no tool or Policy surface. Observability is read-only, never
 * control; recovery/reconnect/reconciliation grants nothing and never
 * auto-resumes. This module CONSUMES 27A/27B/27C/27G vocabularies
 * read-only and never advances any of them.
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 * Separation law: PEER != PATH != TOPOLOGY != TRUST != AUTHORITY != EXECUTION.
 */

import { canonicalHash } from "./canonical.js";
import {
  MESH_EDGE_KINDS,
  MESH_HOP_ROLES,
  MESH_NODE_KINDS,
  MESH_ROUTE_STATES,
  type MeshRoute,
} from "./meshTopologyTrust.js";
import {
  TOPOLOGY_PROVENANCE_SOURCES,
  type TopologyProvenance,
} from "./meshTopologyGraph.js";
import {
  TOPOLOGY_OBSERVATION_STATES,
  type TopologyObservationState,
} from "./meshTopologyLifecycle.js";
import type { ConflictResolution } from "./meshPartitionReconciliation.js";

/** Observability schema version (27H). */
export const OBSERVABILITY_SCHEMA_VERSION =
  "menog-mesh-observability/v0" as const;

/**
 * VISUALIZATION != CONTROL PLANE — exported so every consumer can pin
 * the law text next to the rendered snapshot.
 */
export const OBSERVABILITY_SCOPE_TEXT =
  "VISUALIZATION != CONTROL PLANE: a deterministic, redacted, read-only projection of local topology/runtime knowledge for display — it never mutates, never acts, never executes; authority is none, unknown stays unknown, and recovery/reconnect/reconciliation grants nothing and never auto-resumes. Every execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21.";

// ── frozen bounds (callers may exceed, never redefine) ───────────────────────

/** Hard caps on one projection. Refusal, never truncation, past a bound. */
export const OBSERVABILITY_BOUNDS = Object.freeze({
  maxNodes: 64,
  maxEdges: 256,
  maxRoutes: 64,
  maxHopsPerRoute: 16,
  maxRefusals: 64,
  maxPartitions: 64,
  maxConflictsPerPartition: 64,
  maxIdChars: 128,
  maxCodeChars: 64,
  freshnessWindowMs: 300_000,
});

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Closed projection refusal codes (fail-closed; no silent handling). */
export const OBSERVABILITY_REFUSAL_CODES = Object.freeze([
  "refused_invalid_input",
  "refused_field_bound",
  "refused_epoch_mismatch",
  "refused_unknown_vocabulary",
  "refused_invalid_provenance",
  "refused_non_finite_time",
  "refused_duplicate_entry",
  "refused_unknown",
] as const);
export type ObservabilityRefusalCode =
  (typeof OBSERVABILITY_REFUSAL_CODES)[number];

// ── freshness vocabulary (closed) ────────────────────────────────────────────

/**
 * Freshness classes. A recorded time AFTER asOfEpochMs cannot be
 * ordered, so it stays unknown_freshness (unknown stays unknown).
 */
export const OBSERVABILITY_FRESHNESS = Object.freeze([
  "within_window",
  "outside_window",
  "unknown_freshness",
] as const);
export type ObservabilityFreshness = (typeof OBSERVABILITY_FRESHNESS)[number];

/** Conflict resolution classes a partition may project (27G vocabulary). */
export const OBSERVABILITY_CONFLICT_RESOLUTIONS: readonly ConflictResolution[] =
  Object.freeze([
    "terminal_retained",
    "quarantine_retained",
    "no_consensus_unknown",
  ]);

/** Refusal-code token shape: lowercase identifier, bounded by maxCodeChars. */
export const OBSERVABILITY_CODE_PATTERN = /^[a-z][a-z0-9_]*$/;

// ── projection input (caller-supplied knowledge; NO free-text channel) ───────

/** One node's projected line: identity, kind, lifecycle state, provenance meta. */
export interface ObservabilityNodeInput {
  readonly nodeId: string;
  readonly kind: string;
  readonly epochId: string;
  readonly observationState: TopologyObservationState;
  readonly provenance: TopologyProvenance;
}

/** One edge's projected line: identity, endpoints, kind, provenance meta. */
export interface ObservabilityEdgeInput {
  readonly edgeId: string;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly kind: string;
  readonly epochId: string;
  readonly provenance: TopologyProvenance;
}

/** One route (27A) scoped to the projection's epoch. */
export interface ObservabilityRouteInput {
  readonly epochId: string;
  readonly route: MeshRoute;
}

/** One recorded refusal: a bounded subject id and a token-shaped code. */
export interface ObservabilityRefusalInput {
  readonly subjectId: string;
  readonly code: string;
  readonly epochId: string;
}

/** One conflict as recorded by a reconciliation (27G), scoped by epoch. */
export interface ObservabilityConflictInput {
  readonly subjectNodeId: string;
  readonly localState: TopologyObservationState;
  readonly remoteState: TopologyObservationState;
  readonly resolution: ConflictResolution;
  readonly localRecordedAtEpochMs: number;
  readonly remoteRecordedAtEpochMs: number;
}

/** One reconciliation summary (27G counts + attributed conflicts). */
export interface ObservabilityPartitionInput {
  readonly reconciliationId: string;
  readonly epochId: string;
  readonly agreementCount: number;
  readonly localExclusiveCount: number;
  readonly remoteExclusiveCount: number;
  readonly conflicts: readonly ObservabilityConflictInput[];
}

/** Caller-supplied projection input: one epoch, six sections, pure. */
export interface ObservabilityInput {
  readonly snapshotId: string;
  readonly epochId: string;
  readonly asOfEpochMs: number;
  readonly nodes: readonly ObservabilityNodeInput[];
  readonly edges: readonly ObservabilityEdgeInput[];
  readonly routes: readonly ObservabilityRouteInput[];
  readonly refusals: readonly ObservabilityRefusalInput[];
  readonly partitions: readonly ObservabilityPartitionInput[];
}

// ── snapshot (the read-only projection) ──────────────────────────────────────

/** Provenance METADATA only — never evidence content. */
export interface ObservabilityProvenance {
  readonly source: TopologyProvenance["source"];
  readonly evidenceId: string | null;
  readonly recordedAtEpochMs: number;
}

/** One projected node. */
export interface ObservabilityNode {
  readonly nodeId: string;
  readonly kind: string;
  readonly observationState: TopologyObservationState;
  readonly provenance: ObservabilityProvenance;
  readonly ageMs: number;
  readonly freshness: ObservabilityFreshness;
}

/** One projected edge. */
export interface ObservabilityEdge {
  readonly edgeId: string;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly kind: string;
  readonly provenance: ObservabilityProvenance;
  readonly ageMs: number;
  readonly freshness: ObservabilityFreshness;
}

/** One projected hop inside a route. */
export interface ObservabilityHop {
  readonly hopIndex: number;
  readonly nodeId: string;
  readonly role: string;
}

/** One projected route: origin/forwarders/destination exposed as knowledge. */
export interface ObservabilityRoute {
  readonly routeId: string;
  readonly state: string;
  readonly originNodeId: string;
  readonly originFixed: true;
  readonly forwarderNodeIds: readonly string[];
  readonly destinationNodeId: string;
  readonly hops: readonly ObservabilityHop[];
  readonly observedAtEpochMs: number;
  readonly ageMs: number;
  readonly freshness: ObservabilityFreshness;
}

/** Lifecycle distinction counts over the frozen 27C vocabulary. */
export interface ObservabilityLifecycle {
  readonly observed: number;
  readonly stale: number;
  readonly quarantined_observation: number;
  readonly retired_observation: number;
  readonly unknown_observation: number;
}

/** One projected refusal record (code only — no explanation channel). */
export interface ObservabilityRefusal {
  readonly subjectId: string;
  readonly code: string;
}

/** One projected conflict: both states, both times, resolution class. */
export interface ObservabilityConflict {
  readonly subjectNodeId: string;
  readonly localState: TopologyObservationState;
  readonly remoteState: TopologyObservationState;
  readonly resolution: ConflictResolution;
  readonly localRecordedAtEpochMs: number;
  readonly remoteRecordedAtEpochMs: number;
}

/** One projected reconciliation summary. */
export interface ObservabilityPartition {
  readonly reconciliationId: string;
  readonly agreementCount: number;
  readonly localExclusiveCount: number;
  readonly remoteExclusiveCount: number;
  readonly conflictCount: number;
  readonly conflicts: readonly ObservabilityConflict[];
}

/**
 * THE SNAPSHOT — deterministic, redacted, frozen. The three literals
 * at the bottom are structural: visualization carries authority none.
 */
export interface ObservabilitySnapshot {
  readonly schemaVersion: typeof OBSERVABILITY_SCHEMA_VERSION;
  readonly snapshotId: string;
  readonly epochId: string;
  readonly asOfEpochMs: number;
  readonly nodes: readonly ObservabilityNode[];
  readonly edges: readonly ObservabilityEdge[];
  readonly routes: readonly ObservabilityRoute[];
  readonly lifecycle: ObservabilityLifecycle;
  readonly refusals: readonly ObservabilityRefusal[];
  readonly partitions: readonly ObservabilityPartition[];
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly projectionHash: string;
}

// ── decision ─────────────────────────────────────────────────────────────────

/**
 * Outcome of one projection. Success = the frozen snapshot plus a
 * scope-pinned explanation; refusal = no snapshot at all (nothing
 * partial ever escapes) and no authority surface.
 */
export type ObservabilityDecision =
  | {
      readonly ok: true;
      readonly code: "snapshot_built";
      readonly snapshot: ObservabilitySnapshot;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "snapshot_refused";
      readonly snapshotId: string;
      readonly refusal: ObservabilityRefusalCode;
      readonly explanation: string;
      readonly projectionHash: string;
    };

// ── refusal explanations (every refusal is explained; no silent handling) ────

const REFUSAL_EXPLANATIONS: Readonly<
  Record<ObservabilityRefusalCode, string>
> = Object.freeze({
  refused_invalid_input:
    "malformed projection input — refusing (fail closed); every section must be a well-formed array of structured records with typed identifiers, sequential hop indexes, non-negative integer counts, and token-shaped refusal codes — there is no free-text channel in this schema",
  refused_field_bound:
    "field over frozen bound — refusing (fail closed); a caller may exceed a bound, never redefine one — identifiers, section sizes, hop counts, conflict counts, and code lengths are hard-capped, never truncated, never evicted",
  refused_epoch_mismatch:
    "epoch mismatch — refusing (fail closed); a projection mixes only records from ITS OWN epoch — cross-epoch display would fabricate a world the evidence never described (epoch substitution refused)",
  refused_unknown_vocabulary:
    "unknown vocabulary — refusing (fail closed) under the frozen 27A/27B/27C vocabularies; an unnamed kind, state, role, source, or resolution class never rides through a projection as if it were knowledge (unknown stays unknown)",
  refused_invalid_provenance:
    "invalid provenance — refusing (fail closed); provenance must be an object with a sanctioned source, an evidence id (string or null), and a recorded time — projection displays provenance metadata, never the evidence itself",
  refused_non_finite_time:
    "non-finite or negative time — refusing (fail closed); projection reads caller-supplied epoch times only (no clock) — a NaN, infinite, or negative time can never be rendered as freshness",
  refused_duplicate_entry:
    "duplicate entry — refusing (fail closed); a section that repeats an identifier (or a partition that repeats a conflict subject) is incoherent and cannot be projected",
  refused_unknown: "unmapped projection condition — refusing (fail closed)",
});

// ── shared guards ────────────────────────────────────────────────────────────

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function inVocab(vocab: readonly string[], value: string): boolean {
  return vocab.includes(value);
}

/**
 * Runtime array check that does NOT act as a type guard: the declared
 * readonly section types stay intact after the check (Array.isArray
 * would narrow them to a mutable any[] and erase element typing).
 */
function isArrayValue(value: unknown): boolean {
  return Array.isArray(value);
}

/** UTF-16 code-unit ordering — deterministic, locale-independent. */
function byString<T>(key: (item: T) => string): (a: T, b: T) => number {
  return (a, b) => {
    const ka = key(a);
    const kb = key(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  };
}

/**
 * Freshness classification (pure; no clock): a recorded time after
 * asOfEpochMs cannot be ordered and stays unknown_freshness.
 */
function classifyFreshness(ageMs: number): ObservabilityFreshness {
  if (ageMs < 0) {
    return "unknown_freshness";
  }
  return ageMs <= OBSERVABILITY_BOUNDS.freshnessWindowMs
    ? "within_window"
    : "outside_window";
}

/**
 * Validate ONE provenance object (pinned inner order: shape → field
 * bounds → source vocabulary → time validity). Metadata only.
 */
function validateProvenance(
  prov: TopologyProvenance,
): ObservabilityRefusalCode | null {
  if (prov === null || typeof prov !== "object") {
    return "refused_invalid_input";
  }
  if (
    typeof prov.source !== "string" ||
    (prov.evidenceId !== null && typeof prov.evidenceId !== "string") ||
    typeof prov.recordedAtEpochMs !== "number"
  ) {
    return "refused_invalid_provenance";
  }
  if (
    typeof prov.evidenceId === "string" &&
    prov.evidenceId.length > OBSERVABILITY_BOUNDS.maxIdChars
  ) {
    return "refused_field_bound";
  }
  if (!inVocab(TOPOLOGY_PROVENANCE_SOURCES as readonly string[], prov.source)) {
    return "refused_unknown_vocabulary";
  }
  if (!Number.isFinite(prov.recordedAtEpochMs) || prov.recordedAtEpochMs < 0) {
    return "refused_non_finite_time";
  }
  return null;
}

// ── build the deterministic read-only projection ─────────────────────────────

/**
 * Build ONE deterministic, redacted, read-only snapshot from caller-
 * supplied knowledge. Pinned validation order (first match wins):
 *   1. input shape: object with non-empty snapshot/epoch ids, a
 *      numeric asOfEpochMs, and six arrays (`refused_invalid_input`)
 *   2. field bounds: ids and section sizes (`refused_field_bound`)
 *   3. asOfEpochMs finite and >= 0 (`refused_non_finite_time`)
 *   4. per section, pinned order nodes → edges → routes → refusals →
 *      partitions; per item, array order: inner shape → field bounds →
 *      epoch match (snapshot epoch only; `refused_epoch_mismatch`) →
 *      frozen vocabulary (`refused_unknown_vocabulary`) → provenance
 *      rules (`refused_invalid_provenance` / `refused_non_finite_
 *      time`) → unique identifier (`refused_duplicate_entry`)
 *   5. build: canonically sort every section, classify freshness,
 *      count lifecycle states, freeze everything, attach the
 *      structural authority-none literals, hash the input
 * The builder mutates NOTHING, reads NO clock, reaches NO network,
 * creates NO store: the snapshot is display knowledge with authority
 * "none" — visualization is not a control plane.
 */
export function buildMeshObservabilitySnapshot(
  input: ObservabilityInput,
): ObservabilityDecision {
  const projectionHash = canonicalHash({
    schemaVersion: OBSERVABILITY_SCHEMA_VERSION,
    input,
  });
  const raw: Partial<ObservabilityInput> =
    input !== null && typeof input === "object" ? input : {};
  const refuse = (
    refusal: ObservabilityRefusalCode,
    explanation?: string,
  ): ObservabilityDecision => ({
    ok: false,
    code: "snapshot_refused",
    snapshotId: typeof raw.snapshotId === "string" ? raw.snapshotId : "",
    refusal,
    explanation: explanation ?? REFUSAL_EXPLANATIONS[refusal],
    projectionHash,
  });

  // 1. input shape
  if (input === null || typeof input !== "object") {
    return refuse("refused_invalid_input");
  }
  if (
    !isNonEmptyString(input.snapshotId) ||
    !isNonEmptyString(input.epochId) ||
    typeof input.asOfEpochMs !== "number" ||
    !isArrayValue(input.nodes) ||
    !isArrayValue(input.edges) ||
    !isArrayValue(input.routes) ||
    !isArrayValue(input.refusals) ||
    !isArrayValue(input.partitions)
  ) {
    return refuse("refused_invalid_input");
  }
  // 2. field bounds
  if (
    input.snapshotId.length > OBSERVABILITY_BOUNDS.maxIdChars ||
    input.epochId.length > OBSERVABILITY_BOUNDS.maxIdChars ||
    input.nodes.length > OBSERVABILITY_BOUNDS.maxNodes ||
    input.edges.length > OBSERVABILITY_BOUNDS.maxEdges ||
    input.routes.length > OBSERVABILITY_BOUNDS.maxRoutes ||
    input.refusals.length > OBSERVABILITY_BOUNDS.maxRefusals ||
    input.partitions.length > OBSERVABILITY_BOUNDS.maxPartitions
  ) {
    return refuse("refused_field_bound");
  }
  // 3. asOf time validity (no clock — caller-supplied only)
  if (!Number.isFinite(input.asOfEpochMs) || input.asOfEpochMs < 0) {
    return refuse("refused_non_finite_time");
  }

  const epochId = input.epochId;
  const asOfEpochMs = input.asOfEpochMs;
  const idBound = (value: string): boolean =>
    value.length <= OBSERVABILITY_BOUNDS.maxIdChars;

  // 4. per-section validation (pinned section order), projected in pass

  // nodes: shape → bounds → epoch → vocabulary → provenance → unique
  const projectedNodes: ObservabilityNode[] = [];
  const nodeSeen = new Set<string>();
  for (const node of input.nodes) {
    if (node === null || typeof node !== "object") {
      return refuse("refused_invalid_input");
    }
    if (
      !isNonEmptyString(node.nodeId) ||
      typeof node.kind !== "string" ||
      !isNonEmptyString(node.epochId) ||
      typeof node.observationState !== "string"
    ) {
      return refuse("refused_invalid_input");
    }
    if (!idBound(node.nodeId)) {
      return refuse("refused_field_bound");
    }
    if (node.epochId !== epochId) {
      return refuse("refused_epoch_mismatch");
    }
    if (
      !inVocab(MESH_NODE_KINDS as readonly string[], node.kind) ||
      !inVocab(
        TOPOLOGY_OBSERVATION_STATES as readonly string[],
        node.observationState,
      )
    ) {
      return refuse("refused_unknown_vocabulary");
    }
    const provFailure = validateProvenance(node.provenance);
    if (provFailure !== null) {
      return refuse(provFailure);
    }
    if (nodeSeen.has(node.nodeId)) {
      return refuse("refused_duplicate_entry");
    }
    nodeSeen.add(node.nodeId);
    const nodeAge = asOfEpochMs - node.provenance.recordedAtEpochMs;
    projectedNodes.push(
      Object.freeze({
        nodeId: node.nodeId,
        kind: node.kind,
        observationState: node.observationState,
        provenance: Object.freeze({
          source: node.provenance.source,
          evidenceId: node.provenance.evidenceId,
          recordedAtEpochMs: node.provenance.recordedAtEpochMs,
        }),
        ageMs: nodeAge,
        freshness: classifyFreshness(nodeAge),
      }),
    );
  }

  // edges: shape → bounds → epoch → vocabulary → provenance → unique
  const projectedEdges: ObservabilityEdge[] = [];
  const edgeSeen = new Set<string>();
  for (const edge of input.edges) {
    if (edge === null || typeof edge !== "object") {
      return refuse("refused_invalid_input");
    }
    if (
      !isNonEmptyString(edge.edgeId) ||
      !isNonEmptyString(edge.fromNodeId) ||
      !isNonEmptyString(edge.toNodeId) ||
      typeof edge.kind !== "string" ||
      !isNonEmptyString(edge.epochId)
    ) {
      return refuse("refused_invalid_input");
    }
    if (
      !idBound(edge.edgeId) ||
      !idBound(edge.fromNodeId) ||
      !idBound(edge.toNodeId)
    ) {
      return refuse("refused_field_bound");
    }
    if (edge.epochId !== epochId) {
      return refuse("refused_epoch_mismatch");
    }
    if (!inVocab(MESH_EDGE_KINDS as readonly string[], edge.kind)) {
      return refuse("refused_unknown_vocabulary");
    }
    const provFailure = validateProvenance(edge.provenance);
    if (provFailure !== null) {
      return refuse(provFailure);
    }
    if (edgeSeen.has(edge.edgeId)) {
      return refuse("refused_duplicate_entry");
    }
    edgeSeen.add(edge.edgeId);
    const edgeAge = asOfEpochMs - edge.provenance.recordedAtEpochMs;
    projectedEdges.push(
      Object.freeze({
        edgeId: edge.edgeId,
        fromNodeId: edge.fromNodeId,
        toNodeId: edge.toNodeId,
        kind: edge.kind,
        provenance: Object.freeze({
          source: edge.provenance.source,
          evidenceId: edge.provenance.evidenceId,
          recordedAtEpochMs: edge.provenance.recordedAtEpochMs,
        }),
        ageMs: edgeAge,
        freshness: classifyFreshness(edgeAge),
      }),
    );
  }

  // routes: shape (incl. origin/destination/hop structure) → bounds →
  // epoch → vocabulary (state, hop roles) → time → unique
  const projectedRoutes: ObservabilityRoute[] = [];
  const routeSeen = new Set<string>();
  for (const entry of input.routes) {
    if (entry === null || typeof entry !== "object") {
      return refuse("refused_invalid_input");
    }
    if (
      !isNonEmptyString(entry.epochId) ||
      entry.route === null ||
      typeof entry.route !== "object"
    ) {
      return refuse("refused_invalid_input");
    }
    const route = entry.route;
    if (
      !isNonEmptyString(route.routeId) ||
      typeof route.state !== "string" ||
      route.origin === null ||
      typeof route.origin !== "object" ||
      !isNonEmptyString(route.origin.nodeId) ||
      route.origin.originFixed !== true ||
      route.destination === null ||
      typeof route.destination !== "object" ||
      !isNonEmptyString(route.destination.nodeId) ||
      route.destination.role !== "destination" ||
      !isArrayValue(route.hops) ||
      typeof route.observedAtEpochMs !== "number"
    ) {
      return refuse("refused_invalid_input");
    }
    if (
      !idBound(route.routeId) ||
      !idBound(route.origin.nodeId) ||
      !idBound(route.destination.nodeId)
    ) {
      return refuse("refused_field_bound");
    }
    if (route.hops.length > OBSERVABILITY_BOUNDS.maxHopsPerRoute) {
      return refuse("refused_field_bound");
    }
    let hopIndex = 0;
    for (const hop of route.hops) {
      if (hop === null || typeof hop !== "object") {
        return refuse("refused_invalid_input");
      }
      if (
        !Number.isInteger(hop.hopIndex) ||
        !isNonEmptyString(hop.nodeId) ||
        typeof hop.role !== "string"
      ) {
        return refuse("refused_invalid_input");
      }
      if (hop.hopIndex !== hopIndex) {
        return refuse("refused_invalid_input");
      }
      if (!idBound(hop.nodeId)) {
        return refuse("refused_field_bound");
      }
      hopIndex += 1;
    }
    if (entry.epochId !== epochId) {
      return refuse("refused_epoch_mismatch");
    }
    if (!inVocab(MESH_ROUTE_STATES as readonly string[], route.state)) {
      return refuse("refused_unknown_vocabulary");
    }
    for (const hop of route.hops) {
      if (!inVocab(MESH_HOP_ROLES as readonly string[], hop.role)) {
        return refuse("refused_unknown_vocabulary");
      }
    }
    if (
      !Number.isFinite(route.observedAtEpochMs) ||
      route.observedAtEpochMs < 0
    ) {
      return refuse("refused_non_finite_time");
    }
    if (routeSeen.has(route.routeId)) {
      return refuse("refused_duplicate_entry");
    }
    routeSeen.add(route.routeId);
    const routeAge = asOfEpochMs - route.observedAtEpochMs;
    projectedRoutes.push(
      Object.freeze({
        routeId: route.routeId,
        state: route.state,
        originNodeId: route.origin.nodeId,
        originFixed: true as const,
        forwarderNodeIds: Object.freeze(
          route.hops
            .filter((hop) => hop.role === "forwarder")
            .map((hop) => hop.nodeId),
        ),
        destinationNodeId: route.destination.nodeId,
        hops: Object.freeze(
          route.hops.map((hop) =>
            Object.freeze({
              hopIndex: hop.hopIndex,
              nodeId: hop.nodeId,
              role: hop.role,
            }),
          ),
        ),
        observedAtEpochMs: route.observedAtEpochMs,
        ageMs: routeAge,
        freshness: classifyFreshness(routeAge),
      }),
    );
  }

  // refusals: shape → bounds → epoch → code token → unique pair
  const projectedRefusals: ObservabilityRefusal[] = [];
  const refusalSeen = new Set<string>();
  for (const refusal of input.refusals) {
    if (refusal === null || typeof refusal !== "object") {
      return refuse("refused_invalid_input");
    }
    if (
      !isNonEmptyString(refusal.subjectId) ||
      typeof refusal.code !== "string" ||
      refusal.code.length === 0 ||
      !isNonEmptyString(refusal.epochId)
    ) {
      return refuse("refused_invalid_input");
    }
    if (
      refusal.subjectId.length > OBSERVABILITY_BOUNDS.maxIdChars ||
      refusal.code.length > OBSERVABILITY_BOUNDS.maxCodeChars
    ) {
      return refuse("refused_field_bound");
    }
    if (refusal.epochId !== epochId) {
      return refuse("refused_epoch_mismatch");
    }
    if (!OBSERVABILITY_CODE_PATTERN.test(refusal.code)) {
      return refuse("refused_invalid_input");
    }
    const refusalKey = refusal.subjectId + "\u0000" + refusal.code;
    if (refusalSeen.has(refusalKey)) {
      return refuse("refused_duplicate_entry");
    }
    refusalSeen.add(refusalKey);
    projectedRefusals.push(
      Object.freeze({ subjectId: refusal.subjectId, code: refusal.code }),
    );
  }

  // partitions: shape (counts) → bounds → epoch → per conflict
  // (shape → vocabulary → time → unique subject) → unique id
  const projectedPartitions: ObservabilityPartition[] = [];
  const partitionSeen = new Set<string>();
  for (const partition of input.partitions) {
    if (partition === null || typeof partition !== "object") {
      return refuse("refused_invalid_input");
    }
    if (
      !isNonEmptyString(partition.reconciliationId) ||
      !isNonEmptyString(partition.epochId) ||
      !Number.isInteger(partition.agreementCount) ||
      partition.agreementCount < 0 ||
      !Number.isInteger(partition.localExclusiveCount) ||
      partition.localExclusiveCount < 0 ||
      !Number.isInteger(partition.remoteExclusiveCount) ||
      partition.remoteExclusiveCount < 0 ||
      !isArrayValue(partition.conflicts)
    ) {
      return refuse("refused_invalid_input");
    }
    if (!idBound(partition.reconciliationId)) {
      return refuse("refused_field_bound");
    }
    if (
      partition.conflicts.length >
      OBSERVABILITY_BOUNDS.maxConflictsPerPartition
    ) {
      return refuse("refused_field_bound");
    }
    if (partition.epochId !== epochId) {
      return refuse("refused_epoch_mismatch");
    }
    const conflictSeen = new Set<string>();
    const projectedConflicts: ObservabilityConflict[] = [];
    for (const conflict of partition.conflicts) {
      if (conflict === null || typeof conflict !== "object") {
        return refuse("refused_invalid_input");
      }
      if (
        !isNonEmptyString(conflict.subjectNodeId) ||
        typeof conflict.localState !== "string" ||
        typeof conflict.remoteState !== "string" ||
        typeof conflict.resolution !== "string" ||
        typeof conflict.localRecordedAtEpochMs !== "number" ||
        typeof conflict.remoteRecordedAtEpochMs !== "number"
      ) {
        return refuse("refused_invalid_input");
      }
      if (!idBound(conflict.subjectNodeId)) {
        return refuse("refused_field_bound");
      }
      if (
        !inVocab(
          TOPOLOGY_OBSERVATION_STATES as readonly string[],
          conflict.localState,
        ) ||
        !inVocab(
          TOPOLOGY_OBSERVATION_STATES as readonly string[],
          conflict.remoteState,
        ) ||
        !OBSERVABILITY_CONFLICT_RESOLUTIONS.includes(conflict.resolution)
      ) {
        return refuse("refused_unknown_vocabulary");
      }
      if (
        !Number.isFinite(conflict.localRecordedAtEpochMs) ||
        conflict.localRecordedAtEpochMs < 0 ||
        !Number.isFinite(conflict.remoteRecordedAtEpochMs) ||
        conflict.remoteRecordedAtEpochMs < 0
      ) {
        return refuse("refused_non_finite_time");
      }
      if (conflictSeen.has(conflict.subjectNodeId)) {
        return refuse("refused_duplicate_entry");
      }
      conflictSeen.add(conflict.subjectNodeId);
      projectedConflicts.push(
        Object.freeze({
          subjectNodeId: conflict.subjectNodeId,
          localState: conflict.localState,
          remoteState: conflict.remoteState,
          resolution: conflict.resolution,
          localRecordedAtEpochMs: conflict.localRecordedAtEpochMs,
          remoteRecordedAtEpochMs: conflict.remoteRecordedAtEpochMs,
        }),
      );
    }
    if (partitionSeen.has(partition.reconciliationId)) {
      return refuse("refused_duplicate_entry");
    }
    partitionSeen.add(partition.reconciliationId);
    projectedConflicts.sort(byString((conflict) => conflict.subjectNodeId));
    projectedPartitions.push(
      Object.freeze({
        reconciliationId: partition.reconciliationId,
        agreementCount: partition.agreementCount,
        localExclusiveCount: partition.localExclusiveCount,
        remoteExclusiveCount: partition.remoteExclusiveCount,
        conflictCount: projectedConflicts.length,
        conflicts: Object.freeze(projectedConflicts),
      }),
    );
  }

  // 5. build — canonical order, lifecycle counts, frozen, structural
  //    authority-none literals, input hash
  projectedNodes.sort(byString((node) => node.nodeId));
  projectedEdges.sort(byString((edge) => edge.edgeId));
  projectedRoutes.sort(byString((route) => route.routeId));
  projectedRefusals.sort(
    byString((refusal) => refusal.subjectId + "\u0000" + refusal.code),
  );
  projectedPartitions.sort(
    byString((partition) => partition.reconciliationId),
  );
  for (const node of projectedNodes) {
    Object.freeze(node.provenance);
    Object.freeze(node);
  }
  for (const edge of projectedEdges) {
    Object.freeze(edge.provenance);
    Object.freeze(edge);
  }
  for (const route of projectedRoutes) {
    Object.freeze(route.forwarderNodeIds);
    Object.freeze(route.hops);
    Object.freeze(route);
  }
  for (const refusal of projectedRefusals) {
    Object.freeze(refusal);
  }
  for (const partition of projectedPartitions) {
    Object.freeze(partition.conflicts);
    Object.freeze(partition);
  }

  const lifecycle: Record<TopologyObservationState, number> =
    Object.fromEntries(
      TOPOLOGY_OBSERVATION_STATES.map((state) => [state, 0]),
    ) as Record<TopologyObservationState, number>;
  for (const node of projectedNodes) {
    lifecycle[node.observationState] += 1;
  }

  const snapshot: ObservabilitySnapshot = Object.freeze({
    schemaVersion: OBSERVABILITY_SCHEMA_VERSION,
    snapshotId: input.snapshotId,
    epochId,
    asOfEpochMs,
    nodes: Object.freeze(projectedNodes),
    edges: Object.freeze(projectedEdges),
    routes: Object.freeze(projectedRoutes),
    lifecycle: Object.freeze(lifecycle),
    refusals: Object.freeze(projectedRefusals),
    partitions: Object.freeze(projectedPartitions),
    authority: "none" as const,
    controlPlane: false as const,
    readOnly: true as const,
    projectionHash,
  });

  return {
    ok: true,
    code: "snapshot_built",
    snapshot,
    explanation:
      "snapshot '" +
      input.snapshotId +
      "' built over epoch '" +
      epochId +
      "' at " +
      projectedNodes.length +
      " node(s), " +
      projectedEdges.length +
      " edge(s), " +
      projectedRoutes.length +
      " route(s), " +
      projectedRefusals.length +
      " refusal record(s), " +
      projectedPartitions.length +
      " partition record(s) — VISUALIZATION != CONTROL PLANE: a deterministic redacted read-only projection with authority 'none', zero mutation surface, unknown stays unknown, and NO recovery or reconciliation granting anything or auto-resuming. Every execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21.",
  };
}
