/**
 * PHASE 27A — Governed Local Mesh: Mesh Trust Model
 * (CONTRACT-FIRST / NO SOCKET / NO LISTENER / NO DISCOVERY / NO ROUTING
 * EXECUTION / NO NEW AUTHORITY).
 *
 * This module defines the CLOSED vocabularies and deterministic, fail-closed
 * decisions for the Phase-27 mesh trust model before any topology store,
 * advertisement propagation, route computation, or forwarding code exists
 * (27B+). It implements no socket, no listener, no discovery, no crypto, no
 * store access, and no execution surface: every decision here is a pure
 * function of caller-supplied facts, and every decision embeds a
 * deterministic explanation. The module never reads the wall clock
 * (caller-supplied `observedAtEpochMs` only).
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 * Separation law: PEER != PATH != TOPOLOGY != TRUST != AUTHORITY != EXECUTION.
 *
 * The pack pins, each enforced structurally below and by the suite:
 *
 *  M1  EDGE != TRUST                    — an edge records that two nodes
 *                                          were observed in relation; it
 *                                          carries no trust of any kind.
 *  M2  PATH != ADMISSION                — a computed or observed path is
 *                                          topology knowledge; it never
 *                                          admits a peer (24C owns
 *                                          admission, unchanged).
 *  M3  ROUTE != AUTHORIZATION           — a route plans how bytes WOULD
 *                                          travel; it authorizes nothing.
 *  M4  FORWARDER != ORIGIN              — a node that forwards a proposal
 *                                          did not originate it; origin
 *                                          attribution never moves.
 *  M5  ADVERTISEMENT != GRANT           — a capability advertisement is
 *                                          remote DATA describing claimed
 *                                          capabilities; it grants none.
 *  M6  TOPOLOGY KNOWLEDGE != MEMBERSHIP — knowing the graph is not being
 *                                          a member; membership remains
 *                                          the frozen 24C registry's
 *                                          evidenced local decision.
 *
 * Remote claims are DATA with zero authority: an observation, advertisement,
 * or topology summary received from a peer is recorded as untrusted DATA
 * and can never allocate, authorize, admit, or execute. Every execution
 * still requires fresh LOCAL allocation + fresh LOCAL Policy for the
 * assigned actor + frozen Phase-20/21 (law carried verbatim on decisions).
 *
 * SCOPE LAW: LOCAL-ONLY. No discovery/scanning/mDNS/broadcast/gossip
 * membership/WAN/Internet/cloud relay/NAT traversal/UPnP/tunnel/consensus/
 * global authority is representable in this module's vocabularies (unknown
 * values refuse rather than guess). No network or topology path reaches a
 * tool here: this contract has no tool vocabulary at all.
 */

import { canonicalHash } from "./canonical.js";

// ── schema version ───────────────────────────────────────────────────────────

/** Mesh trust-model contract schema version (27A). */
export const MESH_TRUST_SCHEMA_VERSION = "menog-mesh-trust/v0" as const;
export type MeshTrustSchemaVersion = typeof MESH_TRUST_SCHEMA_VERSION;

// ── the six mesh pins (machine-checkable) ────────────────────────────────────

/** The six pins, as a closed, ordered vocabulary (M1..M6). */
export const MESH_TRUST_PINS = Object.freeze([
  "EDGE_NOT_TRUST",
  "PATH_NOT_ADMISSION",
  "ROUTE_NOT_AUTHORIZATION",
  "FORWARDER_NOT_ORIGIN",
  "ADVERTISEMENT_NOT_GRANT",
  "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
] as const);
export type MeshTrustPin = (typeof MESH_TRUST_PINS)[number];

/**
 * Deterministic, closed explanations for each pin. The SAME strings are
 * embedded in every decision this module emits, so explanations are
 * stable, greppable, and test-pinned (no free-form authority prose).
 */
export const MESH_TRUST_PIN_EXPLANATIONS: Readonly<
  Record<MeshTrustPin, string>
> = Object.freeze({
  EDGE_NOT_TRUST:
    "M1 EDGE != TRUST: an edge records only that two nodes were observed in relation; it carries no trust, grants nothing, and never mutates the frozen 24C registry.",
  PATH_NOT_ADMISSION:
    "M2 PATH != ADMISSION: a path is topology knowledge describing how bytes WOULD travel; it never admits a peer — admission remains the frozen 24C registry's evidenced local decision.",
  ROUTE_NOT_AUTHORIZATION:
    "M3 ROUTE != AUTHORIZATION: a route plans a sequence of hops; it authorizes no message, no peer action, no Policy, and no execution — every execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21.",
  FORWARDER_NOT_ORIGIN:
    "M4 FORWARDER != ORIGIN: forwarding a proposal never makes the forwarder its origin; origin attribution is fixed at creation and is not moved by any hop.",
  ADVERTISEMENT_NOT_GRANT:
    "M5 ADVERTISEMENT != GRANT: a capability advertisement is remote DATA describing claimed capabilities; it grants none of them and widens nothing.",
  TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP:
    "M6 TOPOLOGY KNOWLEDGE != MEMBERSHIP: knowing the graph — nodes, edges, paths, routes — is not being a member; membership remains the frozen 24C registry's evidenced local decision.",
});

// ── node vocabulary (closed) ─────────────────────────────────────────────────

/**
 * Node kinds observable in the topology graph. Nodes in the graph are
 * KNOWLEDGE about identifiers, never membership records: the graph may
 * contain a node the local registry has never admitted, and that is
 * knowledge, not admission (M6).
 */
export const MESH_NODE_KINDS = Object.freeze([
  "local_node",
  "admitted_node",
  "observed_node",
  "unknown_node",
] as const);
export type MeshNodeKind = (typeof MESH_NODE_KINDS)[number];

/** A topology node: pure knowledge, keyed by a caller-supplied identifier. */
export interface MeshNode {
  readonly nodeId: string;
  readonly kind: MeshNodeKind;
  /** Caller-supplied observation time; the module never reads a clock. */
  readonly observedAtEpochMs: number;
}

// ── edge vocabulary (closed) ─────────────────────────────────────────────────

/**
 * Edge kinds: how the relation between two nodes came to be known.
 * An edge is directed knowledge (from -> to). It never encodes trust,
 * admission, or authority of either endpoint (M1).
 */
export const MESH_EDGE_KINDS = Object.freeze([
  "configured_edge",
  "observed_edge",
  "advertised_edge",
  "unknown_edge",
] as const);
export type MeshEdgeKind = (typeof MESH_EDGE_KINDS)[number];

/** A topology edge: directed knowledge between two node ids, no trust (M1). */
export interface MeshEdge {
  readonly edgeId: string;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly kind: MeshEdgeKind;
  readonly observedAtEpochMs: number;
}

// ── path vocabulary (closed) ─────────────────────────────────────────────────

/** Path states: what the graph believes about a node sequence (knowledge). */
export const MESH_PATH_STATES = Object.freeze([
  "path_open",
  "path_unverified",
  "path_blocked",
  "unknown_path",
] as const);
export type MeshPathState = (typeof MESH_PATH_STATES)[number];

/**
 * A path: an ordered node-id sequence with a state. It is topology
 * knowledge only — never an admission, never an authorization (M2).
 */
export interface MeshPath {
  readonly pathId: string;
  readonly nodeIds: readonly string[];
  readonly state: MeshPathState;
  readonly observedAtEpochMs: number;
}

// ── observation vocabulary (closed) ──────────────────────────────────────────

/**
 * Observation kinds: the closed set of topology facts a local node may
 * record. Observations are read-only knowledge; there is no observation
 * that controls anything (observability is read-only, never control).
 */
export const MESH_OBSERVATION_KINDS = Object.freeze([
  "node_observed",
  "edge_observed",
  "path_observed",
  "route_observed",
  "origin_observed",
  "forwarder_observed",
  "destination_observed",
  "unknown_observation",
] as const);
export type MeshObservationKind = (typeof MESH_OBSERVATION_KINDS)[number];

/** A topology observation: read-only recorded knowledge, zero authority. */
export interface MeshObservation {
  readonly observationId: string;
  readonly kind: MeshObservationKind;
  readonly subjectNodeId: string;
  readonly observedAtEpochMs: number;
}

// ── advertisement vocabulary (closed) ────────────────────────────────────────

/** Advertisement kinds: what a remote node CLAIMS about itself (M5). */
export const MESH_ADVERTISEMENT_KINDS = Object.freeze([
  "capability_advertisement",
  "topology_advertisement",
  "route_advertisement",
  "unknown_advertisement",
] as const);
export type MeshAdvertisementKind =
  (typeof MESH_ADVERTISEMENT_KINDS)[number];

/**
 * Advertised capability claims: the closed set a peer may CLAIM. Each is
 * received as DATA and grants nothing (M5); the closed MAY-NOT set below
 * names the capabilities that refuse even as claims.
 */
export const MESH_ADVERTISED_CAPABILITY_CLAIMS = Object.freeze([
  "claim_can_forward_proposals",
  "claim_reachable_on_local_lan",
  "claim_supports_framed_transport",
  "claim_topology_summary",
  "unknown_capability_claim",
] as const);
export type MeshCapabilityClaim = (typeof MESH_ADVERTISED_CAPABILITY_CLAIMS)[number];

/** A remote capability advertisement: remote DATA, zero grant (M5). */
export interface MeshAdvertisement {
  readonly advertisementId: string;
  readonly kind: MeshAdvertisementKind;
  readonly claimingNodeId: string;
  readonly capabilityClaims: readonly MeshCapabilityClaim[];
  readonly observedAtEpochMs: number;
}

// ── route / hop vocabulary (closed) ──────────────────────────────────────────

/**
 * Route states: what the planner believes about a computed route.
 * A route is a PLAN over topology knowledge; it authorizes nothing (M3).
 */
export const MESH_ROUTE_STATES = Object.freeze([
  "route_planned",
  "route_unverified",
  "route_unavailable",
  "unknown_route",
] as const);
export type MeshRouteState = (typeof MESH_ROUTE_STATES)[number];

/**
 * Hop roles. Origin, Forwarder and Destination are DISTINCT roles: the
 * forwarder is never the origin (M4), and destination is a knowledge label
 * for the terminus of a plan, not an execution target.
 */
export const MESH_HOP_ROLES = Object.freeze([
  "origin",
  "forwarder",
  "destination",
  "unknown_role",
] as const);
export type MeshHopRole = (typeof MESH_HOP_ROLES)[number];

/** One hop in a planned route. Role is descriptive knowledge only. */
export interface MeshHop {
  readonly hopIndex: number;
  readonly nodeId: string;
  readonly role: MeshHopRole;
}

/** Origin of a proposal: fixed attribution, never moved by forwarding (M4). */
export interface MeshOrigin {
  readonly nodeId: string;
  readonly originFixed: true;
}

/** Forwarder of a proposal: relays knowledge, originates nothing (M4). */
export interface MeshForwarder {
  readonly nodeId: string;
  readonly role: "forwarder";
}

/** Destination of a proposal: the terminus of a plan, no execution implied. */
export interface MeshDestination {
  readonly nodeId: string;
  readonly role: "destination";
}

/** A route: origin + ordered hops + destination. A PLAN, not authority (M3). */
export interface MeshRoute {
  readonly routeId: string;
  readonly state: MeshRouteState;
  readonly origin: MeshOrigin;
  readonly hops: readonly MeshHop[];
  readonly destination: MeshDestination;
  readonly observedAtEpochMs: number;
}

// ── topology vocabulary (closed) ─────────────────────────────────────────────

/**
 * A topology: the graph as knowledge — nodes, edges, paths, routes —
 * plus its provenance. Knowing it is not membership (M6), and it grants
 * no authority of any kind.
 */
export interface MeshTopology {
  readonly topologyId: string;
  readonly nodes: readonly MeshNode[];
  readonly edges: readonly MeshEdge[];
  readonly paths: readonly MeshPath[];
  readonly routes: readonly MeshRoute[];
  readonly observedAtEpochMs: number;
}

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Closed mesh refusal codes (fail-closed; no silent handling exists). */
export const MESH_REFUSAL_CODES = Object.freeze([
  "refused_unknown_node_kind",
  "refused_unknown_edge_kind",
  "refused_unknown_path_state",
  "refused_unknown_observation_kind",
  "refused_unknown_advertisement_kind",
  "refused_unknown_capability_claim",
  "refused_capability_claim_grant",
  "refused_unknown_route_state",
  "refused_unknown_hop_role",
  "refused_forwarder_as_origin",
  "refused_claim_crosses_boundary",
  "refused_out_of_mesh_scope",
  "refused_unknown_mesh_scope",
  "refused_anonymous_claim",
  "refused_unknown",
] as const);
export type MeshRefusalCode = (typeof MESH_REFUSAL_CODES)[number];

// ── mesh scope vocabulary (closed MAY / MAY-NOT) ─────────────────────────────

/** What the mesh topology layer is ALLOWED to do (closed MAY set). */
export const MESH_SCOPES = Object.freeze([
  "record_observation",
  "record_node",
  "record_edge",
  "record_path",
  "record_route",
  "receive_advertisement_as_data",
  "plan_route_over_recorded_topology",
  "summarize_topology_knowledge",
] as const);
export type MeshScope = (typeof MESH_SCOPES)[number];

/**
 * Capabilities the mesh topology layer MUST NEVER hold (closed MAY-NOT
 * set). Each maps to the pin that refuses it; unknown capabilities refuse
 * too (fail closed).
 */
export const MESH_NON_SCOPES = Object.freeze([
  "execute_tool",
  "choose_policy",
  "admit_peer",
  "grant_authority",
  "grant_capability",
  "persist_record",
  "administer_peer",
  "discover_peers",
  "bind_public",
  "traverse_nat",
  "relay_cloud",
  "reach_internet",
  "gossip_membership",
  "consensus_join",
  "forward_as_origin",
] as const);
export type MeshNonScope = (typeof MESH_NON_SCOPES)[number];

const NON_SCOPE_PINS: Readonly<Record<MeshNonScope, MeshTrustPin>> =
  Object.freeze({
    execute_tool: "ROUTE_NOT_AUTHORIZATION",
    choose_policy: "ROUTE_NOT_AUTHORIZATION",
    admit_peer: "PATH_NOT_ADMISSION",
    grant_authority: "ROUTE_NOT_AUTHORIZATION",
    grant_capability: "ADVERTISEMENT_NOT_GRANT",
    persist_record: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
    administer_peer: "ROUTE_NOT_AUTHORIZATION",
    discover_peers: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
    bind_public: "EDGE_NOT_TRUST",
    traverse_nat: "EDGE_NOT_TRUST",
    relay_cloud: "EDGE_NOT_TRUST",
    reach_internet: "EDGE_NOT_TRUST",
    gossip_membership: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
    consensus_join: "ROUTE_NOT_AUTHORIZATION",
    forward_as_origin: "FORWARDER_NOT_ORIGIN",
  });

export type MeshScopeDecision =
  | {
      readonly ok: true;
      readonly code: "within_mesh_scope";
      readonly scope: MeshScope;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "outside_mesh_scope";
      readonly refusal: MeshRefusalCode;
      readonly violatedPin: MeshTrustPin | null;
      readonly explanation: string;
    };

/**
 * Decide a requested mesh-topology capability. Closed MAY set passes;
 * the closed MAY-NOT set refuses naming its pin; anything unknown refuses
 * with null pin (fail closed — an unnamed capability cannot ride through).
 */
export function decideMeshScope(request: {
  readonly capability: string;
}): MeshScopeDecision {
  if ((MESH_SCOPES as readonly string[]).includes(request.capability)) {
    const scope = request.capability as MeshScope;
    return {
      ok: true,
      code: "within_mesh_scope",
      scope,
      explanation:
        "capability '" +
        scope +
        "' is within the closed mesh MAY set — knowledge recording and planning only; it opens nothing, discovers nothing, and grants nothing (M1/M2/M3)",
    };
  }
  if ((MESH_NON_SCOPES as readonly string[]).includes(request.capability)) {
    const nonScope = request.capability as MeshNonScope;
    return {
      ok: false,
      code: "outside_mesh_scope",
      refusal: "refused_out_of_mesh_scope",
      violatedPin: NON_SCOPE_PINS[nonScope],
      explanation:
        "capability '" +
        nonScope +
        "' is in the closed mesh MAY-NOT set — refused by " +
        NON_SCOPE_PINS[nonScope] +
        "; the mesh topology layer never holds this capability at all",
    };
  }
  return {
    ok: false,
    code: "outside_mesh_scope",
    refusal: "refused_unknown_mesh_scope",
    violatedPin: null,
    explanation:
      "capability '" +
      request.capability +
      "' is not in the closed mesh vocabulary — refusing (fail closed); only the pinned MAY set is representable",
  };
}

// ── node decisions ───────────────────────────────────────────────────────────

export type MeshNodeDecision =
  | {
      readonly ok: true;
      readonly code: "node_recorded_as_knowledge";
      readonly kind: MeshNodeKind;
      readonly membership: "none";
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "node_refused";
      readonly refusal: MeshRefusalCode;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Decide a topology node record. Nodes are recorded as KNOWLEDGE with
 * membership structurally "none" (M6): the graph never admits, never
 * grants authority, and never substitutes for the frozen 24C registry.
 * Unknown kinds refuse (fail closed).
 */
export function decideMeshNode(input: {
  readonly node: MeshNode;
  readonly observedAtEpochMs: number;
}): MeshNodeDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: MESH_TRUST_SCHEMA_VERSION,
    nodeId: input.node.nodeId,
    kind: input.node.kind,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  switch (input.node.kind) {
    case "local_node":
    case "admitted_node":
    case "observed_node":
      return {
        ok: true,
        code: "node_recorded_as_knowledge",
        kind: input.node.kind,
        membership: "none",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP +
          " Node '" +
          input.node.kind +
          "' is recorded as graph knowledge only; membership stays 'none' by construction and no authority attaches.",
        provenanceHash,
      };
    case "unknown_node":
      return {
        ok: false,
        code: "node_refused",
        refusal: "refused_unknown_node_kind",
        explanation:
          "unknown node kind — refusing (fail closed); an unnamed kind cannot ride through as knowledge",
        provenanceHash,
      };
    default: {
      const unknown: never = input.node.kind;
      void unknown;
      return {
        ok: false,
        code: "node_refused",
        refusal: "refused_unknown",
        explanation: "unmapped node kind — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
}

// ── edge decisions ───────────────────────────────────────────────────────────

export type MeshEdgeDecision =
  | {
      readonly ok: true;
      readonly code: "edge_recorded_as_knowledge";
      readonly kind: MeshEdgeKind;
      readonly trust: "none";
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "edge_refused";
      readonly refusal: MeshRefusalCode;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Decide a topology edge record. Edges are recorded as KNOWLEDGE with
 * trust structurally "none" (M1): a relation between two node ids never
 * carries trust, never mutates the 24C registry, and never admits.
 * Unknown kinds refuse (fail closed).
 */
export function decideMeshEdge(input: {
  readonly edge: MeshEdge;
  readonly observedAtEpochMs: number;
}): MeshEdgeDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: MESH_TRUST_SCHEMA_VERSION,
    edgeId: input.edge.edgeId,
    fromNodeId: input.edge.fromNodeId,
    toNodeId: input.edge.toNodeId,
    kind: input.edge.kind,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  switch (input.edge.kind) {
    case "configured_edge":
    case "observed_edge":
    case "advertised_edge":
      return {
        ok: true,
        code: "edge_recorded_as_knowledge",
        kind: input.edge.kind,
        trust: "none",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.EDGE_NOT_TRUST +
          " Edge '" +
          input.edge.kind +
          "' is recorded as directed knowledge only; trust stays 'none' by construction.",
        provenanceHash,
      };
    case "unknown_edge":
      return {
        ok: false,
        code: "edge_refused",
        refusal: "refused_unknown_edge_kind",
        explanation:
          "unknown edge kind — refusing (fail closed); an unnamed kind cannot ride through as knowledge",
        provenanceHash,
      };
    default: {
      const unknown: never = input.edge.kind;
      void unknown;
      return {
        ok: false,
        code: "edge_refused",
        refusal: "refused_unknown",
        explanation: "unmapped edge kind — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
}

// ── path decisions ───────────────────────────────────────────────────────────

export type MeshPathDecision =
  | {
      readonly ok: true;
      readonly code: "path_recorded_as_knowledge";
      readonly state: MeshPathState;
      readonly admission: "none";
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "path_refused";
      readonly refusal: MeshRefusalCode;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Decide a topology path record. Paths are recorded as KNOWLEDGE with
 * admission structurally "none" (M2): how bytes WOULD travel never admits
 * a peer — admission remains the frozen 24C registry's evidenced local
 * decision. Unknown states refuse (fail closed).
 */
export function decideMeshPath(input: {
  readonly path: MeshPath;
  readonly observedAtEpochMs: number;
}): MeshPathDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: MESH_TRUST_SCHEMA_VERSION,
    pathId: input.path.pathId,
    nodeIds: input.path.nodeIds,
    state: input.path.state,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  switch (input.path.state) {
    case "path_open":
    case "path_unverified":
    case "path_blocked":
      return {
        ok: true,
        code: "path_recorded_as_knowledge",
        state: input.path.state,
        admission: "none",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.PATH_NOT_ADMISSION +
          " Path state '" +
          input.path.state +
          "' is topology knowledge only; admission stays 'none' by construction.",
        provenanceHash,
      };
    case "unknown_path":
      return {
        ok: false,
        code: "path_refused",
        refusal: "refused_unknown_path_state",
        explanation:
          "unknown path state — refusing (fail closed); an unnamed state cannot ride through as knowledge",
        provenanceHash,
      };
    default: {
      const unknown: never = input.path.state;
      void unknown;
      return {
        ok: false,
        code: "path_refused",
        refusal: "refused_unknown",
        explanation: "unmapped path state — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
}

// ── observation decisions ────────────────────────────────────────────────────

export type MeshObservationDecision =
  | {
      readonly ok: true;
      readonly code: "observation_recorded_read_only";
      readonly kind: MeshObservationKind;
      readonly authority: "none";
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "observation_refused";
      readonly refusal: MeshRefusalCode;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Decide a topology observation. Observations are read-only knowledge with
 * authority structurally "none": observability is read-only, never control.
 * Unknown kinds refuse (fail closed).
 */
export function decideMeshObservation(input: {
  readonly observation: MeshObservation;
  readonly observedAtEpochMs: number;
}): MeshObservationDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: MESH_TRUST_SCHEMA_VERSION,
    observationId: input.observation.observationId,
    kind: input.observation.kind,
    subjectNodeId: input.observation.subjectNodeId,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  switch (input.observation.kind) {
    case "node_observed":
    case "edge_observed":
    case "path_observed":
    case "route_observed":
    case "origin_observed":
    case "forwarder_observed":
    case "destination_observed":
      return {
        ok: true,
        code: "observation_recorded_read_only",
        kind: input.observation.kind,
        authority: "none",
        explanation:
          "observation '" +
          input.observation.kind +
          "' is recorded read-only as knowledge; authority stays 'none' by construction — observability is read-only, never control",
        provenanceHash,
      };
    case "unknown_observation":
      return {
        ok: false,
        code: "observation_refused",
        refusal: "refused_unknown_observation_kind",
        explanation:
          "unknown observation kind — refusing (fail closed); an unnamed kind cannot ride through as knowledge",
        provenanceHash,
      };
    default: {
      const unknown: never = input.observation.kind;
      void unknown;
      return {
        ok: false,
        code: "observation_refused",
        refusal: "refused_unknown",
        explanation: "unmapped observation kind — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
}

// ── advertisement decisions (remote claims are DATA, zero authority) ─────────

export type MeshAdvertisementDecision =
  | {
      readonly ok: true;
      readonly code: "advertisement_received_as_data";
      readonly grant: "none";
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "advertisement_refused";
      readonly refusal: MeshRefusalCode;
      readonly violatedPin: MeshTrustPin | null;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Decide a remote capability advertisement. Advertisements are remote DATA
 * with grant structurally "none" (M5): a peer CLAIMING a capability grants
 * itself nothing and widens nothing. Claims outside the closed vocabulary
 * refuse (fail closed); the advertisement as a whole is never a grant.
 */
export function decideMeshAdvertisement(input: {
  readonly advertisement: MeshAdvertisement;
  readonly observedAtEpochMs: number;
}): MeshAdvertisementDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: MESH_TRUST_SCHEMA_VERSION,
    advertisementId: input.advertisement.advertisementId,
    kind: input.advertisement.kind,
    claimingNodeId: input.advertisement.claimingNodeId,
    capabilityClaims: input.advertisement.capabilityClaims,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  if (typeof input.advertisement.claimingNodeId !== "string" || input.advertisement.claimingNodeId.length === 0) {
    return {
      ok: false,
      code: "advertisement_refused",
      refusal: "refused_anonymous_claim",
      violatedPin: "ADVERTISEMENT_NOT_GRANT",
      explanation:
        "advertisement carries no claiming node — an anonymous claim cannot even be evaluated as DATA (fail closed)",
      provenanceHash,
    };
  }
  switch (input.advertisement.kind) {
    case "capability_advertisement":
    case "topology_advertisement":
    case "route_advertisement":
      break;
    case "unknown_advertisement":
      return {
        ok: false,
        code: "advertisement_refused",
        refusal: "refused_unknown_advertisement_kind",
        violatedPin: "ADVERTISEMENT_NOT_GRANT",
        explanation:
          "unknown advertisement kind — refusing (fail closed); an unnamed kind cannot ride through as DATA",
        provenanceHash,
      };
    default: {
      const unknown: never = input.advertisement.kind;
      void unknown;
      return {
        ok: false,
        code: "advertisement_refused",
        refusal: "refused_unknown",
        violatedPin: "ADVERTISEMENT_NOT_GRANT",
        explanation: "unmapped advertisement kind — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
  for (const claim of input.advertisement.capabilityClaims) {
    if (claim === "unknown_capability_claim") {
      return {
        ok: false,
        code: "advertisement_refused",
        refusal: "refused_unknown_capability_claim",
        violatedPin: "ADVERTISEMENT_NOT_GRANT",
        explanation:
          "advertisement contains an unknown capability claim — refusing (fail closed); an unnamed claim cannot ride through even as DATA",
        provenanceHash,
      };
    }
    if (!((MESH_ADVERTISED_CAPABILITY_CLAIMS as readonly string[]).includes(claim))) {
      return {
        ok: false,
        code: "advertisement_refused",
        refusal: "refused_unknown_capability_claim",
        violatedPin: "ADVERTISEMENT_NOT_GRANT",
        explanation:
          "advertisement contains a capability claim outside the closed vocabulary — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
  return {
    ok: true,
    code: "advertisement_received_as_data",
    grant: "none",
    explanation:
      MESH_TRUST_PIN_EXPLANATIONS.ADVERTISEMENT_NOT_GRANT +
      " Claims [" +
      input.advertisement.capabilityClaims.join(", ") +
      "] are recorded as remote DATA; grant stays 'none' by construction — no claim is ever executed or honored as a grant.",
    provenanceHash,
  };
}

// ── route / hop decisions ────────────────────────────────────────────────────

export type MeshRouteDecision =
  | {
      readonly ok: true;
      readonly code: "route_recorded_as_plan";
      readonly state: MeshRouteState;
      readonly authorization: "none";
      readonly executionAuthorized: false;
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "route_refused";
      readonly refusal: MeshRefusalCode;
      readonly violatedPin: MeshTrustPin | null;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Decide a planned route. Routes are PLANS over topology knowledge with
 * authorization structurally "none" and executionAuthorized structurally
 * false (M3): planning how bytes WOULD travel authorizes no message and
 * no execution. Hop roles are validated fail-closed: an unknown role
 * refuses, and a forwarder occupying the origin position refuses naming
 * M4 (forwarder != origin) — origin attribution never moves.
 */
export function decideMeshRoute(input: {
  readonly route: MeshRoute;
  readonly observedAtEpochMs: number;
}): MeshRouteDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: MESH_TRUST_SCHEMA_VERSION,
    routeId: input.route.routeId,
    state: input.route.state,
    origin: input.route.origin.nodeId,
    hops: input.route.hops,
    destination: input.route.destination.nodeId,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  switch (input.route.state) {
    case "route_planned":
    case "route_unverified":
    case "route_unavailable":
      break;
    case "unknown_route":
      return {
        ok: false,
        code: "route_refused",
        refusal: "refused_unknown_route_state",
        violatedPin: "ROUTE_NOT_AUTHORIZATION",
        explanation:
          "unknown route state — refusing (fail closed); an unnamed state cannot ride through as a plan",
        provenanceHash,
      };
    default: {
      const unknown: never = input.route.state;
      void unknown;
      return {
        ok: false,
        code: "route_refused",
        refusal: "refused_unknown",
        violatedPin: "ROUTE_NOT_AUTHORIZATION",
        explanation: "unmapped route state — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
  for (const hop of input.route.hops) {
    if (hop.role === "unknown_role") {
      return {
        ok: false,
        code: "route_refused",
        refusal: "refused_unknown_hop_role",
        violatedPin: "ROUTE_NOT_AUTHORIZATION",
        explanation:
          "route contains an unknown hop role — refusing (fail closed); an unnamed role cannot ride through as knowledge",
        provenanceHash,
      };
    }
    if (!((MESH_HOP_ROLES as readonly string[]).includes(hop.role))) {
      return {
        ok: false,
        code: "route_refused",
        refusal: "refused_unknown_hop_role",
        violatedPin: "ROUTE_NOT_AUTHORIZATION",
        explanation:
          "route contains a hop role outside the closed vocabulary — refusing (fail closed)",
        provenanceHash,
      };
    }
    if (hop.role === "forwarder" && hop.nodeId === input.route.origin.nodeId) {
      return {
        ok: false,
        code: "route_refused",
        refusal: "refused_forwarder_as_origin",
        violatedPin: "FORWARDER_NOT_ORIGIN",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.FORWARDER_NOT_ORIGIN +
          " The origin node is recorded as its own forwarder — origin attribution would move, so the route refuses.",
        provenanceHash,
      };
    }
  }
  return {
    ok: true,
    code: "route_recorded_as_plan",
    state: input.route.state,
    authorization: "none",
    executionAuthorized: false,
    explanation:
      MESH_TRUST_PIN_EXPLANATIONS.ROUTE_NOT_AUTHORIZATION +
      " Route state '" +
      input.route.state +
      "' is a PLAN over topology knowledge; authorization stays 'none' and executionAuthorized stays false by construction — every execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21.",
    provenanceHash,
  };
}

// ── mesh claim decisions (the six pins over one claim) ───────────────────────

/** Claims presented AT the mesh topology boundary (by a peer or process). */
export type MeshClaimKind =
  | "node_kind_fact"
  | "edge_relation_fact"
  | "path_state_fact"
  | "observation_fact"
  | "route_plan_fact"
  | "capability_advertisement_fact"
  | "edge_trust_claim"
  | "path_admission_claim"
  | "route_authorization_claim"
  | "forwarder_origin_claim"
  | "advertisement_grant_claim"
  | "topology_membership_claim";

export type MeshClaimDecision =
  | {
      readonly ok: true;
      readonly code: "claim_received_as_data";
      readonly authority: "none";
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "claim_crosses_boundary";
      readonly violatedPin: MeshTrustPin;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Decide a claim presented at the mesh topology boundary. Fact claims
 * (node kinds, edge relations, path states, observations, route plans,
 * capability advertisements) are receivable precisely because they grant
 * nothing (M1–M6): authority stays structurally "none". Claims that ASSERT
 * a conflation — trust from an edge, admission from a path, authorization
 * from a route, origin from a forwarder, a grant from an advertisement,
 * membership from topology knowledge — cross the boundary and are refused,
 * naming the violated pin. Remote claims are DATA with zero authority.
 * Deterministic: the provenance hash binds (kind, subject, observedAt).
 */
export function decideMeshClaim(input: {
  readonly claimKind: MeshClaimKind;
  readonly subject: string;
  readonly observedAtEpochMs: number;
}): MeshClaimDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: MESH_TRUST_SCHEMA_VERSION,
    claimKind: input.claimKind,
    subject: input.subject,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  if (typeof input.subject !== "string" || input.subject.length === 0) {
    return {
      ok: false,
      code: "claim_crosses_boundary",
      violatedPin: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
      explanation:
        "mesh claim carries no subject — an anonymous claim cannot even be evaluated as DATA (fail closed)",
      provenanceHash,
    };
  }
  switch (input.claimKind) {
    case "node_kind_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        authority: "none",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP +
          " The fact is receivable as DATA and confers no membership.",
        provenanceHash,
      };
    case "edge_relation_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        authority: "none",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.EDGE_NOT_TRUST +
          " The fact is receivable as DATA and trusts nothing.",
        provenanceHash,
      };
    case "path_state_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        authority: "none",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.PATH_NOT_ADMISSION +
          " The fact is receivable as DATA and admits nothing.",
        provenanceHash,
      };
    case "observation_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        authority: "none",
        explanation:
          "M0 OBSERVATION READ-ONLY: an observation is read-only knowledge with authority 'none' — observability is read-only, never control; the fact is receivable as DATA.",
        provenanceHash,
      };
    case "route_plan_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        authority: "none",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.ROUTE_NOT_AUTHORIZATION +
          " The plan is receivable as DATA and authorizes nothing.",
        provenanceHash,
      };
    case "capability_advertisement_fact":
      return {
        ok: true,
        code: "claim_received_as_data",
        authority: "none",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.ADVERTISEMENT_NOT_GRANT +
          " The advertisement is receivable as DATA and grants nothing.",
        provenanceHash,
      };
    case "edge_trust_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "EDGE_NOT_TRUST",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.EDGE_NOT_TRUST +
          " A claim that an edge carries trust crosses the boundary and is refused.",
        provenanceHash,
      };
    case "path_admission_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "PATH_NOT_ADMISSION",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.PATH_NOT_ADMISSION +
          " A claim that a path admits a peer crosses the boundary and is refused.",
        provenanceHash,
      };
    case "route_authorization_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "ROUTE_NOT_AUTHORIZATION",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.ROUTE_NOT_AUTHORIZATION +
          " A claim that a route authorizes action crosses the boundary and is refused.",
        provenanceHash,
      };
    case "forwarder_origin_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "FORWARDER_NOT_ORIGIN",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.FORWARDER_NOT_ORIGIN +
          " A claim that a forwarder is (or becomes) the origin crosses the boundary and is refused.",
        provenanceHash,
      };
    case "advertisement_grant_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "ADVERTISEMENT_NOT_GRANT",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.ADVERTISEMENT_NOT_GRANT +
          " A claim that an advertisement grants capability crosses the boundary and is refused.",
        provenanceHash,
      };
    case "topology_membership_claim":
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
        explanation:
          MESH_TRUST_PIN_EXPLANATIONS.TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP +
          " A claim that topology knowledge confers membership crosses the boundary and is refused.",
        provenanceHash,
      };
    default: {
      const unknown: never = input.claimKind;
      void unknown;
      return {
        ok: false,
        code: "claim_crosses_boundary",
        violatedPin: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
        explanation: "unknown mesh claim kind — refusing (fail closed)",
        provenanceHash,
      };
    }
  }
}

// ── mesh self-description (pure) ─────────────────────────────────────────────

/**
 * Deterministic, canonical description of the mesh trust model for
 * provenance bindings (no I/O; pure function of the supplied facts).
 */
export function meshTrustFingerprint(input: {
  readonly localNodeId: string | null;
  readonly observedAtEpochMs: number;
}): string {
  return canonicalHash({
    schemaVersion: MESH_TRUST_SCHEMA_VERSION,
    localNodeId: input.localNodeId,
    observedAtEpochMs: input.observedAtEpochMs,
    pins: MESH_TRUST_PINS,
    nodeKinds: MESH_NODE_KINDS,
    edgeKinds: MESH_EDGE_KINDS,
    pathStates: MESH_PATH_STATES,
    observationKinds: MESH_OBSERVATION_KINDS,
    advertisementKinds: MESH_ADVERTISEMENT_KINDS,
    capabilityClaims: MESH_ADVERTISED_CAPABILITY_CLAIMS,
    routeStates: MESH_ROUTE_STATES,
    hopRoles: MESH_HOP_ROLES,
    scopes: MESH_SCOPES,
  });
}
