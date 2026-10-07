/**
 * PHASE 27E — Route & Path Planning (DETERMINISTIC / BOUNDED / ROUTE !=
 * AUTHORIZATION / PATH != ADMISSION / NO TRUST / NO TOOL / NO CLOCK).
 *
 * Deterministic bounded path computation over EXPLICIT topology knowledge
 * (the 27B graph snapshot) with an explicit observation-state overlay (the
 * 27C vocabulary). The planner computes HOW bytes WOULD travel — it
 * decides nothing about WHO may travel:
 *   · ROUTE != AUTHORIZATION (27A M3) — every successful decision carries
 *     authorization: "none" and executionAuthorized: false as STRUCTURAL
 *     LITERALS, composed by calling the frozen 27A `decideMeshRoute`; the
 *     module has no authority/approve/authorize surface, no Policy call,
 *     and no execution path.
 *   · PATH != ADMISSION (27A M2) — every successful decision carries
 *     admission: "none", composed by calling the frozen 27A
 *     `decideMeshPath`; a route can never bypass admission, and the
 *     frozen 24C registry remains the only admission decision.
 *   · NO TRANSITIVE TRUST, NO CAPABILITY UNION — transitiveTrust and
 *     capabilityUnion are structural false literals; walking knowledge
 *     through a node grants nothing and accumulates nothing.
 *   · EVERY EXECUTION STILL REQUIRES fresh LOCAL allocation + fresh LOCAL
 *     Policy for the assigned actor + frozen Phase-20/21 (propagated in
 *     the composed 27A explanation text).
 *
 * DETERMINISM: one algorithm, no ties left to chance — shortest-hop
 * paths only, and among equal-length candidates the LEXICOGRAPHICALLY
 * SMALLEST node sequence wins (greedy over a BFS layering); parallel
 * edges resolve to the lexicographically smallest edge id. Identical
 * input => byte-identical decision (hash-bound).
 *
 * BOUNDEDNESS (graph explosion is REFUSED, never searched):
 *   · the input graph is refused BEFORE any search if it exceeds the
 *     frozen bounds (64 nodes / 256 edges);
 *   · candidate paths are hop-capped (63 = max nodes - 1);
 *   · the search is a BFS with a visited set: each node expands at most
 *     once and each edge is scanned at most twice (forward + reverse
 *     passes) — suite-pinned counters on a dense adversarial graph.
 *
 * LOOPS: the planned path is loop-free BY CONSTRUCTION (BFS distances
 * strictly increase along it; self-loops and revisits are pruned at
 * subgraph construction); a candidate path that repeats a node refuses
 * `refused_route_loop`. A cycle in the graph is knowledge, not a trap —
 * it never appears in a result.
 *
 * OBSERVATION OVERLAY (fail closed): an element is traversable ONLY if
 * its explicit state is `observed` AND its record epoch matches the
 * snapshot epoch. Absent state is NOT observed. `stale`,
 * `quarantined_observation`, `retired_observation`, and
 * `unknown_observation` states are never traversed (mirrors 27C: quarantine
 * never returns; terminal never resurrects). Quarantine or staleness on
 * the only corridor fails closed as `refused_no_route`.
 *
 * SCOPE LAW: LOCAL-ONLY. No discovery/scanning/mDNS/broadcast/gossip
 * membership/WAN/Internet/cloud relay/NAT traversal/UPnP/tunnel/
 * consensus/global authority; no socket, no listener, no spawn, no
 * clock (caller-supplied epochs only), no store access; no alternate
 * listener/spawn/persist/control path. Planning is pure knowledge —
 * observability read-only, never control.
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 * Separation law: PEER != PATH != TOPOLOGY != TRUST != AUTHORITY != EXECUTION.
 */

import { canonicalHash } from "./canonical.js";
import {
  decideMeshPath,
  decideMeshRoute,
  type MeshPath,
  type MeshRefusalCode,
  type MeshRoute,
} from "./meshTopologyTrust.js";
import type {
  TopologyGraphSnapshot,
  TopologyNodeRecord,
} from "./meshTopologyGraph.js";
import type { TopologyObservationState } from "./meshTopologyLifecycle.js";

/** Route-planning schema version (27E). */
export const ROUTE_PLANNING_SCHEMA_VERSION = "menog-mesh-route-planning/v0" as const;
export type RoutePlanningSchemaVersion = typeof ROUTE_PLANNING_SCHEMA_VERSION;

// ── frozen bounds (callers may exceed, never redefine) ───────────────────────

/**
 * Hard caps on route planning. The input graph over a bound is refused
 * BEFORE any search (graph explosion fails closed); a planned path is a
 * simple path over at most `maxInputNodes` nodes, so `maxPathHops` is
 * exactly `maxInputNodes - 1`.
 */
export const ROUTE_BOUNDS = Object.freeze({
  maxInputNodes: 64,
  maxInputEdges: 256,
  maxPathHops: 63,
});
export type RouteBoundName = keyof typeof ROUTE_BOUNDS;

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Closed route-planning refusal codes (fail-closed; no silent handling). */
export const ROUTE_REFUSAL_CODES = Object.freeze([
  "refused_invalid_request",
  "refused_epoch_mismatch",
  "refused_same_endpoint",
  "refused_unknown_node",
  "refused_endpoint_not_observed",
  "refused_route_bound",
  "refused_route_loop",
  "refused_route_gap",
  "refused_hop_not_observed",
  "refused_no_route",
  "refused_unknown",
] as const);
export type RouteRefusalCode = (typeof ROUTE_REFUSAL_CODES)[number];

// ── inputs ───────────────────────────────────────────────────────────────────

/**
 * Caller-supplied route plan input. `nodeStates`/`edgeStates` are the
 * explicit 27C observation overlay: ONLY an element explicitly marked
 * `observed` is traversable — an absent key is NOT observed (fail
 * closed). The graph is a 27B snapshot (read-only knowledge).
 */
export interface RoutePlanInput {
  readonly routeId: string;
  readonly epochId: string;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly observedAtEpochMs: number;
  readonly graph: TopologyGraphSnapshot;
  readonly nodeStates: Readonly<Record<string, TopologyObservationState>>;
  readonly edgeStates: Readonly<Record<string, TopologyObservationState>>;
}

/**
 * Caller-supplied candidate-path validation input: the candidate is an
 * ordered node-id sequence the caller asserts ALREADY holds; the planner
 * checks it against the same explicit knowledge and overlay.
 */
export interface RouteValidationInput {
  readonly routeId: string;
  readonly epochId: string;
  readonly observedAtEpochMs: number;
  readonly path: readonly string[];
  readonly graph: TopologyGraphSnapshot;
  readonly nodeStates: Readonly<Record<string, TopologyObservationState>>;
  readonly edgeStates: Readonly<Record<string, TopologyObservationState>>;
}

// ── decisions ────────────────────────────────────────────────────────────────

/**
 * Outcome of planning one route. Every SUCCESS carries the zero-authority
 * structural literals: `admission: "none"` (composed 27A M2),
 * `authorization: "none"` + `executionAuthorized: false` (composed 27A
 * M3), `transitiveTrust: false`, `capabilityUnion: false` (27E). Every
 * refusal explains itself, reports search counters, and grants nothing.
 */
export type RoutePlanDecision =
  | {
      readonly ok: true;
      readonly code: "route_planned";
      readonly routeId: string;
      readonly path: readonly string[];
      readonly edgePath: readonly string[];
      readonly hopCount: number;
      readonly admission: "none";
      readonly authorization: "none";
      readonly executionAuthorized: false;
      readonly transitiveTrust: false;
      readonly capabilityUnion: false;
      readonly expandedNodes: number;
      readonly scannedEdges: number;
      readonly excludedNodes: number;
      readonly excludedEdges: number;
      readonly explanation: string;
      readonly routeHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "route_refused";
      readonly routeId: string;
      readonly refusal: RouteRefusalCode;
      readonly expandedNodes: number;
      readonly scannedEdges: number;
      readonly explanation: string;
      readonly routeHash: string;
    };

/** Outcome of validating one candidate path (same literals, no search). */
export type RouteValidationDecision =
  | {
      readonly ok: true;
      readonly code: "candidate_route_valid";
      readonly routeId: string;
      readonly path: readonly string[];
      readonly edgePath: readonly string[];
      readonly hopCount: number;
      readonly admission: "none";
      readonly authorization: "none";
      readonly executionAuthorized: false;
      readonly transitiveTrust: false;
      readonly capabilityUnion: false;
      readonly explanation: string;
      readonly routeHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "route_refused";
      readonly routeId: string;
      readonly refusal: RouteRefusalCode;
      readonly explanation: string;
      readonly routeHash: string;
    };

// ── refusal explanations (every refusal is explained; no silent handling) ────

const REFUSAL_EXPLANATIONS: Readonly<Record<RouteRefusalCode, string>> =
  Object.freeze({
    refused_invalid_request:
      "malformed route input — refusing (fail closed); an unbounded or un-epoch'd input cannot be searched, hashed, or audited",
    refused_epoch_mismatch:
      "epoch mismatch — refusing (fail closed); a route may only be planned over knowledge from the SAME epoch it claims, so cross-epoch plans never ride through",
    refused_same_endpoint:
      "origin equals destination — refusing (fail closed); a route from a node to itself is trivial knowledge, never a plan over the mesh",
    refused_unknown_node:
      "unknown node — refusing (fail closed); an endpoint outside the explicit topology graph has no knowledge to plan over",
    refused_endpoint_not_observed:
      "endpoint not observed — refusing (fail closed); only an EXPLICITLY observed endpoint of the current epoch is plannable — absent, stale, quarantined, retired, or unknown state never routes",
    refused_route_bound:
      "route bound exceeded — refusing (fail closed); the input graph over the frozen bounds is graph explosion and is refused BEFORE any search, and a candidate path over the frozen hop cap is never walked (a caller may exceed a bound, never redefine one)",
    refused_route_loop:
      "route contains a loop — refusing (fail closed); a path that revisits a node is cycle knowledge, never a plan, so loops are detected and refused rather than walked",
    refused_route_gap:
      "route gap — refusing (fail closed); consecutive nodes are not joined by a directed edge in the explicit graph, so no such hop exists",
    refused_hop_not_observed:
      "hop not observed — refusing (fail closed); a directed edge exists between the nodes but it, or an endpoint, is not explicitly observed for this epoch — stale or quarantined corridors never route",
    refused_no_route:
      "no route exists — refusing (fail closed); the destination is unreachable over explicitly observed knowledge (disconnected, direction-only, or blocked by non-observed elements) — absence of a route never widens anything",
    refused_unknown:
      "unmapped route condition — refusing (fail closed)",
  });

/**
 * Map a frozen 27A mesh refusal onto this planner's closed vocabulary.
 * The planner BUILDS its route from closed vocabularies, so any 27A
 * route/path refusal indicates vocabulary corruption upstream — fail
 * closed to `refused_unknown` (never silently dropped: the composed
 * 27A explanation is carried through).
 */
function mapMeshRouteRefusal(refusal: MeshRefusalCode): RouteRefusalCode {
  void refusal;
  return "refused_unknown";
}

// ── shared guards ────────────────────────────────────────────────────────────

/** The ONLY traversable observation state (27C closed vocabulary). */
const OBSERVED: TopologyObservationState = "observed";

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isStateMap(
  value: unknown,
): value is Readonly<Record<string, TopologyObservationState>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isGraphShape(value: unknown): value is TopologyGraphSnapshot {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const candidate = value as Partial<TopologyGraphSnapshot>;
  return (
    isNonEmptyString(candidate.epochId) &&
    Array.isArray(candidate.nodes) &&
    Array.isArray(candidate.edges)
  );
}

/** An element of the snapshot is traversable only when EXPLICITLY observed. */
function isObservedAt(
  states: Readonly<Record<string, TopologyObservationState>>,
  elementId: string,
): boolean {
  return states[elementId] === OBSERVED;
}

/**
 * Index the snapshot's node records (first record wins on a duplicate
 * id — idempotent knowledge, same rule as the 27B graph). Malformed
 * entries are skipped: they can never be planned over (fail closed).
 */
function buildNodeIndex(
  nodes: readonly TopologyNodeRecord[],
): Map<string, TopologyNodeRecord> {
  const index = new Map<string, TopologyNodeRecord>();
  for (const record of nodes) {
    if (record === null || typeof record !== "object") continue;
    if (!isNonEmptyString(record.nodeId)) continue;
    if (index.has(record.nodeId)) continue;
    index.set(record.nodeId, record);
  }
  return index;
}

/**
 * A node participates in routing only when its record is from the
 * snapshot's epoch AND its explicit overlay state is `observed`.
 */
function observedNodeChecker(
  nodeIndex: ReadonlyMap<string, TopologyNodeRecord>,
  graphEpochId: string,
  nodeStates: Readonly<Record<string, TopologyObservationState>>,
): (nodeId: string) => boolean {
  return (nodeId: string): boolean => {
    const record = nodeIndex.get(nodeId);
    if (record === undefined) return false;
    if (record.epochId !== graphEpochId) return false;
    return isObservedAt(nodeStates, nodeId);
  };
}

// ── shared composition with the frozen 27A contract ─────────────────────────

interface ComposedMeshTrust {
  readonly admission: "none";
  readonly authorization: "none";
  readonly executionAuthorized: false;
  readonly composedExplanation: string;
}
type ComposeDecision =
  | { readonly ok: true; readonly value: ComposedMeshTrust }
  | {
      readonly ok: false;
      readonly refusal: RouteRefusalCode;
      readonly explanation: string;
    };

/**
 * Compose a node sequence with the FROZEN 27A decisions:
 * `decideMeshPath` (M2 PATH != ADMISSION) over the path, and
 * `decideMeshRoute` (M3 ROUTE != AUTHORIZATION) over the constructed
 * route with closed hop roles (origin → forwarder* → destination).
 * Any 27A refusal maps fail-closed onto this planner's vocabulary; on
 * success the composed structural literals and both 27A explanations
 * are carried into the planner's decision verbatim.
 */
function composeWithMeshTrust(input: {
  readonly routeId: string;
  readonly path: readonly string[];
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly observedAtEpochMs: number;
}): ComposeDecision {
  const meshPath: MeshPath = {
    pathId: input.routeId,
    nodeIds: input.path,
    state: "path_open",
    observedAtEpochMs: input.observedAtEpochMs,
  };
  const pathDecision = decideMeshPath({
    path: meshPath,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  if (!pathDecision.ok) {
    return {
      ok: false,
      refusal: mapMeshRouteRefusal(pathDecision.refusal),
      explanation: pathDecision.explanation,
    };
  }
  const lastIndex = input.path.length - 1;
  const hops = input.path.map((nodeId, index) => ({
    hopIndex: index,
    nodeId,
    role:
      index === 0
        ? ("origin" as const)
        : index === lastIndex
          ? ("destination" as const)
          : ("forwarder" as const),
  }));
  const meshRoute: MeshRoute = {
    routeId: input.routeId,
    state: "route_planned",
    origin: { nodeId: input.fromNodeId, originFixed: true },
    hops,
    destination: { nodeId: input.toNodeId, role: "destination" },
    observedAtEpochMs: input.observedAtEpochMs,
  };
  const routeDecision = decideMeshRoute({
    route: meshRoute,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  if (!routeDecision.ok) {
    return {
      ok: false,
      refusal: mapMeshRouteRefusal(routeDecision.refusal),
      explanation: routeDecision.explanation,
    };
  }
  return {
    ok: true,
    value: {
      admission: pathDecision.admission,
      authorization: routeDecision.authorization,
      executionAuthorized: routeDecision.executionAuthorized,
      composedExplanation:
        pathDecision.explanation + " " + routeDecision.explanation,
    },
  };
}

// ── plan a route ───────────────────────────────────────────────────────────

/**
 * Plan ONE deterministic bounded route over explicit observed topology.
 * Pinned validation order (first match wins):
 *   1. input shape (ids, time, graph shape, overlay shape)
 *   2. input graph bounds (graph explosion refused BEFORE any search)
 *   3. epoch agreement (one epoch's knowledge, one epoch's plan)
 *   4. origin != destination (trivial routes are never plans)
 *   5. endpoints exist in the explicit graph
 *   6. endpoints EXPLICITLY observed for this epoch
 *   7. observed subgraph construction (excluded elements counted)
 *   8. forward BFS — visited set makes loops impossible, sorted
 *      adjacency makes the traversal deterministic; unreachable =>
 *      `refused_no_route` (with search counters)
 *   9. reverse BFS (distance-to-destination layering)
 *  10. reconstruction of the LEXICOGRAPHICALLY SMALLEST shortest path
 *      (invariant guard refuses a partial path — never returned)
 *  11. composition with the frozen 27A path + route decisions
 * Any refusal leaves the caller's knowledge untouched (planning is
 * read-only; this function mutates NOTHING).
 */
export function planRoute(input: RoutePlanInput): RoutePlanDecision {
  const routeHash = canonicalHash({
    schemaVersion: ROUTE_PLANNING_SCHEMA_VERSION,
    routeId: input.routeId,
    epochId: input.epochId,
    fromNodeId: input.fromNodeId,
    toNodeId: input.toNodeId,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  let expandedNodes = 0;
  let scannedEdges = 0;
  const refuse = (
    refusal: RouteRefusalCode,
    explanation?: string,
  ): RoutePlanDecision => ({
    ok: false,
    code: "route_refused",
    routeId: typeof input.routeId === "string" ? input.routeId : "",
    refusal,
    expandedNodes,
    scannedEdges,
    explanation: explanation ?? REFUSAL_EXPLANATIONS[refusal],
    routeHash,
  });

  // 1. shape — fail closed before anything is read
  if (
    !isNonEmptyString(input.routeId) ||
    !isNonEmptyString(input.epochId) ||
    !isNonEmptyString(input.fromNodeId) ||
    !isNonEmptyString(input.toNodeId) ||
    typeof input.observedAtEpochMs !== "number" ||
    !Number.isFinite(input.observedAtEpochMs) ||
    input.observedAtEpochMs < 0 ||
    !isGraphShape(input.graph) ||
    !isStateMap(input.nodeStates) ||
    !isStateMap(input.edgeStates)
  ) {
    return refuse("refused_invalid_request");
  }
  // 2. bounds — an input graph over a frozen bound is graph explosion and
  // is refused before a single edge is touched
  if (
    input.graph.nodes.length > ROUTE_BOUNDS.maxInputNodes ||
    input.graph.edges.length > ROUTE_BOUNDS.maxInputEdges
  ) {
    return refuse("refused_route_bound");
  }
  // 3. epoch agreement
  if (input.epochId !== input.graph.epochId) {
    return refuse("refused_epoch_mismatch");
  }
  // 4. trivial route
  if (input.fromNodeId === input.toNodeId) {
    return refuse("refused_same_endpoint");
  }
  // 5. endpoints in the explicit graph
  const nodeIndex = buildNodeIndex(input.graph.nodes);
  if (!nodeIndex.has(input.fromNodeId) || !nodeIndex.has(input.toNodeId)) {
    return refuse("refused_unknown_node");
  }
  // 6. endpoints EXPLICITLY observed
  const nodeObserved = observedNodeChecker(
    nodeIndex,
    input.graph.epochId,
    input.nodeStates,
  );
  if (!nodeObserved(input.fromNodeId) || !nodeObserved(input.toNodeId)) {
    return refuse("refused_endpoint_not_observed");
  }

  // 7. observed subgraph — excluded elements are COUNTED, never silent
  let excludedNodes = 0;
  for (const [nodeId, record] of nodeIndex) {
    if (record.epochId !== input.graph.epochId || !isObservedAt(input.nodeStates, nodeId)) {
      excludedNodes += 1;
    }
  }
  let excludedEdges = 0;
  const seenEdgeIds = new Set<string>();
  const adjacency = new Map<string, { to: string; edgeId: string }[]>();
  for (const edge of input.graph.edges) {
    if (edge === null || typeof edge !== "object") {
      excludedEdges += 1;
      continue;
    }
    if (
      !isNonEmptyString(edge.edgeId) ||
      !isNonEmptyString(edge.fromNodeId) ||
      !isNonEmptyString(edge.toNodeId)
    ) {
      excludedEdges += 1;
      continue;
    }
    if (seenEdgeIds.has(edge.edgeId)) {
      excludedEdges += 1; // duplicate edge id: first record wins
      continue;
    }
    seenEdgeIds.add(edge.edgeId);
    if (edge.fromNodeId === edge.toNodeId) {
      excludedEdges += 1; // self-loop: never traversable (loop detection)
      continue;
    }
    if (edge.epochId !== input.graph.epochId) {
      excludedEdges += 1;
      continue;
    }
    if (!isObservedAt(input.edgeStates, edge.edgeId)) {
      excludedEdges += 1;
      continue;
    }
    if (!nodeObserved(edge.fromNodeId) || !nodeObserved(edge.toNodeId)) {
      excludedEdges += 1;
      continue;
    }
    const bucket = adjacency.get(edge.fromNodeId);
    const entry = { to: edge.toNodeId, edgeId: edge.edgeId };
    if (bucket === undefined) {
      adjacency.set(edge.fromNodeId, [entry]);
    } else {
      bucket.push(entry);
    }
  }
  for (const bucket of adjacency.values()) {
    bucket.sort((a, b) =>
      a.to < b.to
        ? -1
        : a.to > b.to
          ? 1
          : a.edgeId < b.edgeId
            ? -1
            : a.edgeId > b.edgeId
              ? 1
              : 0,
    );
  }

  // 8. forward BFS (visited set => loop-free; sorted => deterministic)
  const forwardDist = new Map<string, number>();
  forwardDist.set(input.fromNodeId, 0);
  const forwardQueue: string[] = [input.fromNodeId];
  for (const current of forwardQueue) {
    const depth = forwardDist.get(current) ?? 0;
    const bucket = adjacency.get(current);
    if (bucket === undefined) continue;
    for (const edge of bucket) {
      scannedEdges += 1;
      if (!forwardDist.has(edge.to)) {
        forwardDist.set(edge.to, depth + 1);
        forwardQueue.push(edge.to);
      }
    }
  }
  expandedNodes = forwardDist.size;
  const distance = forwardDist.get(input.toNodeId);
  if (distance === undefined) {
    return refuse("refused_no_route");
  }

  // 9. reverse BFS (distance TO the destination)
  const reverse = new Map<string, string[]>();
  for (const [fromId, bucket] of adjacency) {
    for (const edge of bucket) {
      const reverseBucket = reverse.get(edge.to);
      if (reverseBucket === undefined) {
        reverse.set(edge.to, [fromId]);
      } else {
        reverseBucket.push(fromId);
      }
    }
  }
  const reverseDist = new Map<string, number>();
  reverseDist.set(input.toNodeId, 0);
  const reverseQueue: string[] = [input.toNodeId];
  for (const current of reverseQueue) {
    const depth = reverseDist.get(current) ?? 0;
    const bucket = reverse.get(current);
    if (bucket === undefined) continue;
    for (const predecessor of bucket) {
      scannedEdges += 1;
      if (!reverseDist.has(predecessor)) {
        reverseDist.set(predecessor, depth + 1);
        reverseQueue.push(predecessor);
      }
    }
  }

  // 10. reconstruction: lexicographically smallest among shortest paths
  const path: string[] = [input.fromNodeId];
  const edgePath: string[] = [];
  let current = input.fromNodeId;
  for (let step = 0; step < distance; step += 1) {
    const depth = forwardDist.get(current) ?? 0;
    const bucket = adjacency.get(current);
    let chosen: { to: string; edgeId: string } | undefined;
    if (bucket !== undefined) {
      for (const candidate of bucket) {
        const forward = forwardDist.get(candidate.to);
        const backward = reverseDist.get(candidate.to);
        if (
          forward !== undefined &&
          backward !== undefined &&
          forward === depth + 1 &&
          forward + backward === distance
        ) {
          chosen = candidate;
          break;
        }
      }
    }
    if (chosen === undefined) break; // invariant guard below refuses
    path.push(chosen.to);
    edgePath.push(chosen.edgeId);
    current = chosen.to;
  }
  if (path.length !== distance + 1) {
    return refuse(
      "refused_unknown",
      "shortest-path reconstruction invariant broken — refusing (fail closed); a partial path is never returned as a plan",
    );
  }

  // 11. compose with the frozen 27A path + route decisions (M2 + M3)
  const composed = composeWithMeshTrust({
    routeId: input.routeId,
    path,
    fromNodeId: input.fromNodeId,
    toNodeId: input.toNodeId,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  if (!composed.ok) {
    return refuse(composed.refusal, composed.explanation);
  }
  return {
    ok: true,
    code: "route_planned",
    routeId: input.routeId,
    path: Object.freeze([...path]),
    edgePath: Object.freeze([...edgePath]),
    hopCount: distance,
    admission: composed.value.admission,
    authorization: composed.value.authorization,
    executionAuthorized: composed.value.executionAuthorized,
    transitiveTrust: false,
    capabilityUnion: false,
    expandedNodes,
    scannedEdges,
    excludedNodes,
    excludedEdges,
    explanation:
      "route '" +
      input.routeId +
      "' planned from '" +
      input.fromNodeId +
      "' to '" +
      input.toNodeId +
      "' over " +
      distance +
      " hop(s) of EXPLICITLY observed topology knowledge — a PLAN over knowledge, not an authorization: admission/authorization stay 'none', executionAuthorized stays false, no transitive trust, no capability union (every execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21). " +
      composed.value.composedExplanation,
    routeHash,
  };
}

// ── validate a candidate route ─────────────────────────────────────────────────────────────────

/**
 * Validate ONE caller-supplied candidate path (an ordered node-id
 * sequence) against the same explicit knowledge and overlay. Pinned
 * validation order (first match wins):
 *   1. input shape (ids, time, non-empty string path, graph shape,
 *      overlay shape)
 *   2. input graph bounds (graph explosion refused before any walk)
 *   3. epoch agreement
 *   4. single-node path (origin == destination)
 *   5. hop cap (a walk over the frozen bound is refused BEFORE
 *      membership — a huge adversarial path never gets searched)
 *   6. every member exists in the explicit graph
 *   7. LOOP detection: a repeated node refuses `refused_route_loop`
 *   8. endpoints EXPLICITLY observed for this epoch
 *   9. per-hop resolution IN ORDER: the lexicographically smallest
 *      OBSERVED directed edge resolves the hop; a pair with edges that
 *      none of them (or their endpoints) are observed for this epoch
 *      refuses `refused_hop_not_observed`; a pair with NO directed edge
 *      refuses `refused_route_gap` (direction matters — the reverse
 *      edge is not this edge)
 *  10. composition with the frozen 27A path + route decisions
 * Validation is pure and read-only: it mutates NOTHING and grants
 * nothing — a valid candidate is knowledge, never permission.
 */
export function validateRoutePath(
  input: RouteValidationInput,
): RouteValidationDecision {
  const routeHash = canonicalHash({
    schemaVersion: ROUTE_PLANNING_SCHEMA_VERSION,
    routeId: input.routeId,
    epochId: input.epochId,
    path: input.path,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  const refuse = (
    refusal: RouteRefusalCode,
    explanation?: string,
  ): RouteValidationDecision => ({
    ok: false,
    code: "route_refused",
    routeId: typeof input.routeId === "string" ? input.routeId : "",
    refusal,
    explanation: explanation ?? REFUSAL_EXPLANATIONS[refusal],
    routeHash,
  });

  // 1. shape
  if (
    !isNonEmptyString(input.routeId) ||
    !isNonEmptyString(input.epochId) ||
    typeof input.observedAtEpochMs !== "number" ||
    !Number.isFinite(input.observedAtEpochMs) ||
    input.observedAtEpochMs < 0 ||
    !Array.isArray(input.path) ||
    input.path.length === 0 ||
    !input.path.every((nodeId) => isNonEmptyString(nodeId)) ||
    !isGraphShape(input.graph) ||
    !isStateMap(input.nodeStates) ||
    !isStateMap(input.edgeStates)
  ) {
    return refuse("refused_invalid_request");
  }
  // 2. bounds
  if (
    input.graph.nodes.length > ROUTE_BOUNDS.maxInputNodes ||
    input.graph.edges.length > ROUTE_BOUNDS.maxInputEdges
  ) {
    return refuse("refused_route_bound");
  }
  // 3. epoch agreement
  if (input.epochId !== input.graph.epochId) {
    return refuse("refused_epoch_mismatch");
  }
  const candidatePath: string[] = [...input.path];
  // 4. single-node path
  if (candidatePath.length === 1) {
    return refuse("refused_same_endpoint");
  }
  // 5. hop cap before membership
  if (candidatePath.length - 1 > ROUTE_BOUNDS.maxPathHops) {
    return refuse("refused_route_bound");
  }
  // 6. membership
  const nodeIndex = buildNodeIndex(input.graph.nodes);
  for (const nodeId of candidatePath) {
    if (!nodeIndex.has(nodeId)) {
      return refuse("refused_unknown_node");
    }
  }
  // 7. loop detection
  const seen = new Set<string>();
  for (const nodeId of candidatePath) {
    if (seen.has(nodeId)) {
      return refuse("refused_route_loop");
    }
    seen.add(nodeId);
  }
  // 8. endpoints observed
  const nodeObserved = observedNodeChecker(
    nodeIndex,
    input.graph.epochId,
    input.nodeStates,
  );
  const originId = candidatePath[0] as string;
  const destinationId = candidatePath[candidatePath.length - 1] as string;
  if (!nodeObserved(originId) || !nodeObserved(destinationId)) {
    return refuse("refused_endpoint_not_observed");
  }
  // 9. per-hop resolution (in order; smallest observed edge id wins)
  const edgePath: string[] = [];
  for (let index = 0; index + 1 < candidatePath.length; index += 1) {
    const fromId = candidatePath[index] as string;
    const toId = candidatePath[index + 1] as string;
    let chosenEdgeId: string | undefined;
    let pairHasDirectedEdge = false;
    for (const edge of input.graph.edges) {
      if (edge === null || typeof edge !== "object") continue;
      if (
        !isNonEmptyString(edge.edgeId) ||
        edge.fromNodeId !== fromId ||
        edge.toNodeId !== toId
      ) {
        continue;
      }
      pairHasDirectedEdge = true;
      if (chosenEdgeId !== undefined && edge.edgeId >= chosenEdgeId) continue;
      if (edge.epochId !== input.graph.epochId) continue;
      if (!isObservedAt(input.edgeStates, edge.edgeId)) continue;
      if (!nodeObserved(fromId) || !nodeObserved(toId)) continue;
      chosenEdgeId = edge.edgeId;
    }
    if (chosenEdgeId === undefined) {
      if (pairHasDirectedEdge) {
        return refuse("refused_hop_not_observed");
      }
      return refuse("refused_route_gap");
    }
    edgePath.push(chosenEdgeId);
  }
  // 10. compose with the frozen 27A path + route decisions (M2 + M3)
  const composed = composeWithMeshTrust({
    routeId: input.routeId,
    path: candidatePath,
    fromNodeId: originId,
    toNodeId: destinationId,
    observedAtEpochMs: input.observedAtEpochMs,
  });
  if (!composed.ok) {
    return refuse(composed.refusal, composed.explanation);
  }
  return {
    ok: true,
    code: "candidate_route_valid",
    routeId: input.routeId,
    path: Object.freeze([...candidatePath]),
    edgePath: Object.freeze([...edgePath]),
    hopCount: candidatePath.length - 1,
    admission: composed.value.admission,
    authorization: composed.value.authorization,
    executionAuthorized: composed.value.executionAuthorized,
    transitiveTrust: false,
    capabilityUnion: false,
    explanation:
      "candidate route '" +
      input.routeId +
      "' validated over " +
      (candidatePath.length - 1) +
      " hop(s) of EXPLICITLY observed topology knowledge — a valid candidate is knowledge, never permission: admission/authorization stay 'none', executionAuthorized stays false, no transitive trust, no capability union (every execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21). " +
      composed.value.composedExplanation,
    routeHash,
  };
}
