/**
 * PHASE 27E — Route & Path Planning Tests (DETERMINISTIC / BOUNDED /
 * ROUTE != AUTHORIZATION / PATH != ADMISSION / LOOPS + EXPLOSION
 * REFUSED / STALE + QUARANTINED NEVER ROUTE).
 *
 * Pins the planner's laws structurally and behaviorally:
 *   · closed vocabularies + frozen bounds (pinned exact values);
 *   · structural zero-authority literals on EVERY success (admission
 *     "none", authorization "none", executionAuthorized false,
 *     transitiveTrust false, capabilityUnion false) and the composed
 *     frozen 27A M2/M3 explanation text;
 *   · no authorize/approve/admit export surface, no trust/Policy token
 *     in module source (no network/store/clock either);
 *   · planning: deterministic shortest-hop paths with lexicographic
 *     tie-breaks, deterministic edge resolution, byte-identical reruns;
 *   · refusals in pinned order: shape → bounds (graph explosion BEFORE
 *     search) → epoch → same endpoint → unknown → endpoint observed →
 *     search (no route);
 *   · stale / quarantined / retired / unknown observation states never
 *     traverse (interior blocks as no-route, endpoints refuse directly);
 *   · loops: cyclic graphs never repeat a node in a result, self-loops
 *     are excluded, candidate paths that revisit a node refuse;
 *   · dense adversarial graph at the frozen bounds routes within the
 *     pinned search counters (64 nodes / 256 edges / ≤512 scans);
 *   · candidate validation: bound before membership, unknown before
 *     loop, loop before endpoint state, gap vs not-observed distinction
 *     with directed-edge semantics;
 *   · integration with a real 27B LocalTopologyGraph snapshot;
 *   · no I/O, no clock, no mutation (graph snapshots untouched).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  ROUTE_PLANNING_SCHEMA_VERSION,
  ROUTE_BOUNDS,
  ROUTE_REFUSAL_CODES,
  planRoute,
  validateRoutePath,
  LocalTopologyGraph,
  type RoutePlanDecision,
  type RoutePlanInput,
  type RouteValidationDecision,
  type RouteValidationInput,
  type TopologyGraphSnapshot,
  type TopologyObservationState,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 27E module must NEVER contain (structural no-socket pin). */
const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:dns",
  "node:crypto",
  "WebSocket",
  "fetch(",
  "spawn(",
  "listen(",
  "createServer",
  "connect(",
  "createSocket",
  "createHash",
  "DatabaseSync",
  "acceptMutation",
  "setInterval",
  "setTimeout",
  "Date.now",
  "performance.now",
  ".persist(",
  "DurableStore",
  "PeerRegistry",
  "executeToolRun",
  "runIsolated",
  "toolJunction",
  "requireTool",
]);

/** The ONLY modules the 27E module may import (pinned). */
const ALLOWED_IMPORTS = Object.freeze([
  "./canonical.js",
  "./meshTopologyGraph.js",
  "./meshTopologyLifecycle.js",
  "./meshTopologyTrust.js",
]);

/** Law tokens that must never appear in the planner's source. */
const FORBIDDEN_LAW_TOKENS: readonly string[] = Object.freeze([
  "isPeerTrustTransition",
  "PEER_TRUST_TRANSITIONS",
  "trustState",
  "policyEngine",
  "evaluatePolicy",
  "authorize(",
  "admit(",
  "granted",
]);

const NOW = 1_700_000_000_000;
const EPOCH = "epoch-27e";
const PROVENANCE = {
  source: "governed_evidence",
  evidenceId: "ev-1",
  recordedAtEpochMs: NOW,
} as const;

/**
 * Hand-crafted snapshot builder: nodes + directed [from, to, edgeId?]
 * edges, all in one epoch. Edge ids default to edge-000, edge-001, ...
 */
const snap = (
  nodeIds: readonly string[],
  edges: readonly (readonly [string, string] | readonly [string, string, string])[],
  over: Partial<TopologyGraphSnapshot> = {},
): TopologyGraphSnapshot => ({
  epochId: EPOCH,
  nodes: nodeIds.map((id) => ({
    nodeId: id,
    kind: "observed_node",
    epochId: EPOCH,
    provenance: PROVENANCE,
  })),
  edges: edges.map((spec, index) => ({
    edgeId: spec[2] ?? "edge-" + String(index).padStart(3, "0"),
    fromNodeId: spec[0],
    toNodeId: spec[1],
    kind: "observed_edge",
    epochId: EPOCH,
    provenance: PROVENANCE,
  })),
  ...over,
});

const observedNodes = (
  g: TopologyGraphSnapshot,
): Record<string, TopologyObservationState> => {
  const states: Record<string, TopologyObservationState> = {};
  for (const node of g.nodes) {
    if (node !== null && typeof node === "object" && typeof node.nodeId === "string") {
      states[node.nodeId] = "observed";
    }
  }
  return states;
};

const observedEdges = (
  g: TopologyGraphSnapshot,
): Record<string, TopologyObservationState> => {
  const states: Record<string, TopologyObservationState> = {};
  for (const edge of g.edges) {
    if (edge !== null && typeof edge === "object" && typeof edge.edgeId === "string") {
      states[edge.edgeId] = "observed";
    }
  }
  return states;
};

const allObserved = (
  g: TopologyGraphSnapshot,
): {
  nodeStates: Record<string, TopologyObservationState>;
  edgeStates: Record<string, TopologyObservationState>;
} => ({ nodeStates: observedNodes(g), edgeStates: observedEdges(g) });

/** Plan input over a snapshot; `over` may replace overlay/maps/ids. */
const planInput = (
  g: TopologyGraphSnapshot,
  fromNodeId: string,
  toNodeId: string,
  over: Partial<RoutePlanInput> = {},
): RoutePlanInput => ({
  routeId: "route-1",
  epochId: EPOCH,
  fromNodeId,
  toNodeId,
  observedAtEpochMs: NOW,
  graph: g,
  ...allObserved(g),
  ...over,
});

/** Validation input over a snapshot; `over` may replace overlay/maps/ids. */
const validationInput = (
  g: TopologyGraphSnapshot,
  path: readonly string[],
  over: Partial<RouteValidationInput> = {},
): RouteValidationInput => ({
  routeId: "route-1",
  epochId: EPOCH,
  observedAtEpochMs: NOW,
  path,
  graph: g,
  ...allObserved(g),
  ...over,
});

/** Every success (plan or valid candidate) carries the zero-authority literals. */
function expectZeroAuthority(d: RoutePlanDecision | RouteValidationDecision): void {
  expect(d.ok).toBe(true);
  if (d.ok) {
    expect(d.admission).toBe("none");
    expect(d.authorization).toBe("none");
    expect(d.executionAuthorized).toBe(false);
    expect(d.transitiveTrust).toBe(false);
    expect(d.capabilityUnion).toBe(false);
    expect(d.routeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(d.path)).toBe(true);
    expect(Object.isFrozen(d.edgePath)).toBe(true);
    expect(d.explanation).toContain("PATH != ADMISSION");
    expect(d.explanation).toContain("ROUTE != AUTHORIZATION");
    expect(d.explanation).toContain("fresh LOCAL allocation");
  }
}

function expectPlanRefusal(d: RoutePlanDecision, refusal: string): void {
  expect(d.ok).toBe(false);
  if (!d.ok) {
    expect(d.code).toBe("route_refused");
    expect(d.refusal).toBe(refusal);
    expect(d.explanation.length).toBeGreaterThan(20);
    expect(d.explanation).toMatch(/refus/);
    expect(d.routeHash).toMatch(/^[0-9a-f]{64}$/);
    expect("admission" in d).toBe(false);
    expect("authorization" in d).toBe(false);
    expect("executionAuthorized" in d).toBe(false);
  }
}

function expectValidationRefusal(d: RouteValidationDecision, refusal: string): void {
  expect(d.ok).toBe(false);
  if (!d.ok) {
    expect(d.code).toBe("route_refused");
    expect(d.refusal).toBe(refusal);
    expect(d.explanation.length).toBeGreaterThan(20);
    expect(d.explanation).toMatch(/refus/);
    expect(d.routeHash).toMatch(/^[0-9a-f]{64}$/);
    expect("admission" in d).toBe(false);
    expect("authorization" in d).toBe(false);
  }
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("27E structure — closed vocabulary, frozen bounds, zero-authority source", () => {
  it("forbidden surfaces list is pinned and the module contains none of them", () => {
    expect(FORBIDDEN_SURFACES).toEqual([
      "child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dgram",
      "node:tls",
      "node:dns",
      "node:crypto",
      "WebSocket",
      "fetch(",
      "spawn(",
      "listen(",
      "createServer",
      "connect(",
      "createSocket",
      "createHash",
      "DatabaseSync",
      "acceptMutation",
      "setInterval",
      "setTimeout",
      "Date.now",
      "performance.now",
      ".persist(",
      "DurableStore",
      "PeerRegistry",
      "executeToolRun",
      "runIsolated",
      "toolJunction",
      "requireTool",
    ]);
    const code = codeOnly(SRC("meshRoutePlanning.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
  });

  it("module imports ONLY the pinned local modules (no network, no store, no clock)", () => {
    const src = SRC("meshRoutePlanning.ts");
    const imports = [
      ...[...src.matchAll(/^import [^\n]* from "([^"]+)"/gm)].map((m) => m[1] as string),
      ...[...src.matchAll(/^\} from "([^"]+)"/gm)].map((m) => m[1] as string),
    ].sort();
    expect(imports).toEqual([...ALLOWED_IMPORTS].sort());
  });

  it("schema version and route bounds are pinned frozen constants", () => {
    expect(ROUTE_PLANNING_SCHEMA_VERSION).toBe("menog-mesh-route-planning/v0");
    expect(ROUTE_BOUNDS).toEqual({
      maxInputNodes: 64,
      maxInputEdges: 256,
      maxPathHops: 63,
    });
    expect(Object.isFrozen(ROUTE_BOUNDS)).toBe(true);
    expect(ROUTE_BOUNDS.maxPathHops).toBe(ROUTE_BOUNDS.maxInputNodes - 1);
  });

  it("refusal vocabulary is a pinned frozen closed set (fail-closed, no silent handling)", () => {
    expect([...ROUTE_REFUSAL_CODES]).toEqual([
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
    ]);
    expect(Object.isFrozen(ROUTE_REFUSAL_CODES)).toBe(true);
  });

  it("every authority/admission literal in source is the structural 'none'/false (no trust, no Policy token)", () => {
    const code = codeOnly(SRC("meshRoutePlanning.ts"));
    for (const match of code.matchAll(/admission:\s*"[^"]*"/g)) {
      expect(match[0]).toBe('admission: "none"');
    }
    for (const match of code.matchAll(/authorization:\s*"[^"]*"/g)) {
      expect(match[0]).toBe('authorization: "none"');
    }
    expect(code).not.toContain("executionAuthorized: true");
    expect(code).not.toContain("transitiveTrust: true");
    expect(code).not.toContain("capabilityUnion: true");
    for (const token of FORBIDDEN_LAW_TOKENS) {
      expect(code).not.toContain(token);
    }
  });

  it("export surface: ONLY planRoute + validateRoutePath functions, no class, no authorize/approve export", () => {
    const code = codeOnly(SRC("meshRoutePlanning.ts"));
    const functions = [...code.matchAll(/^export function (\w+)/gm)].map((m) => m[1] as string).sort();
    expect(functions).toEqual(["planRoute", "validateRoutePath"]);
    expect(code).not.toContain("export class");
    const exportNames = [...code.matchAll(/^export (?:const|type|interface) (\w+)/gm)].map(
      (m) => m[1] as string,
    );
    for (const name of exportNames) {
      expect(name).not.toMatch(/authoriz|approv|admit|grant/i);
    }
    expect(typeof planRoute).toBe("function");
    expect(typeof validateRoutePath).toBe("function");
  });
});

// ── planning ────────────────────────────────────────────────────────────────

describe("27E planning — deterministic bounded shortest-hop routes", () => {
  const LINE = snap(["a", "b", "c", "d"], [
    ["a", "b"],
    ["b", "c"],
    ["c", "d"],
  ]);

  it("a line graph routes origin → destination hop by hop (zero-authority literals)", () => {
    const d = planRoute(planInput(LINE, "a", "d"));
    expectZeroAuthority(d);
    if (d.ok) {
      expect(d.code).toBe("route_planned");
      expect([...d.path]).toEqual(["a", "b", "c", "d"]);
      expect([...d.edgePath]).toEqual(["edge-000", "edge-001", "edge-002"]);
      expect(d.hopCount).toBe(3);
      expect(d.expandedNodes).toBe(4);
      expect(d.excludedNodes).toBe(0);
      expect(d.excludedEdges).toBe(0);
      expect(d.expandedNodes).toBeLessThanOrEqual(ROUTE_BOUNDS.maxInputNodes);
      expect(d.scannedEdges).toBeLessThanOrEqual(2 * ROUTE_BOUNDS.maxInputEdges);
      expect(d.routeId).toBe("route-1");
    }
  });

  it("identical input yields byte-identical decisions (pure, no clock)", () => {
    const first = planRoute(planInput(LINE, "a", "d"));
    const second = planRoute(planInput(LINE, "a", "d"));
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it("equal-length candidates resolve lexicographically (no tie left to chance)", () => {
    const g = snap(["a", "b", "c", "d", "e"], [
      ["a", "b"],
      ["a", "c"],
      ["b", "d"],
      ["c", "d"],
      ["d", "e"],
    ]);
    const d = planRoute(planInput(g, "a", "e"));
    expectZeroAuthority(d);
    if (d.ok) {
      expect([...d.path]).toEqual(["a", "b", "d", "e"]); // b < c at the first fork
      expect(d.hopCount).toBe(3);
    }
  });

  it("parallel edges resolve to the lexicographically smallest edge id", () => {
    const g = snap(["a", "b", "c"], [
      ["a", "b", "edge-z"],
      ["a", "b", "edge-a"],
      ["b", "c"],
    ]);
    const d = planRoute(planInput(g, "a", "c"));
    expectZeroAuthority(d);
    if (d.ok) {
      expect([...d.path]).toEqual(["a", "b", "c"]);
      expect([...d.edgePath]).toEqual(["edge-a", "edge-002"]);
    }
  });

  it("graph construction order does not change the route (determinism over knowledge)", () => {
    const g1 = snap(["a", "b", "c"], [
      ["a", "b"],
      ["b", "c"],
    ]);
    const g2 = snap(["c", "b", "a"], [
      ["b", "c", "edge-001"],
      ["a", "b", "edge-000"],
    ]);
    const d1 = planRoute(planInput(g1, "a", "c"));
    const d2 = planRoute(planInput(g2, "a", "c"));
    expectZeroAuthority(d1);
    expectZeroAuthority(d2);
    if (d1.ok && d2.ok) {
      expect([...d2.path]).toEqual([...d1.path]);
      expect([...d2.edgePath]).toEqual([...d1.edgePath]);
      expect(d2.hopCount).toBe(d1.hopCount);
      expect(d2.expandedNodes).toBe(d1.expandedNodes);
    }
  });
});

// ── planning refusals ───────────────────────────────────────────────────────

describe("27E planning refusals — pinned order, fail closed, nothing searched", () => {
  const LINE = snap(["a", "b", "c", "d"], [
    ["a", "b"],
    ["b", "c"],
    ["c", "d"],
  ]);

  it("malformed input refuses (empty ids, non-finite time, bad graph shape, bad overlay)", () => {
    expectPlanRefusal(planRoute(planInput(LINE, "a", "d", { routeId: "" })), "refused_invalid_request");
    expectPlanRefusal(
      planRoute(planInput(LINE, "a", "d", { observedAtEpochMs: Number.POSITIVE_INFINITY })),
      "refused_invalid_request",
    );
    expectPlanRefusal(planRoute(planInput(LINE, "a", "d", { fromNodeId: "" })), "refused_invalid_request");
    expectPlanRefusal(
      planRoute(
        planInput(LINE, "a", "d", {
          graph: { ...LINE, nodes: "not-an-array" } as unknown as TopologyGraphSnapshot,
        }),
      ),
      "refused_invalid_request",
    );
    expectPlanRefusal(
      planRoute(
        planInput(LINE, "a", "d", {
          nodeStates: null as unknown as Record<string, TopologyObservationState>,
        }),
      ),
      "refused_invalid_request",
    );
  });

  it("an oversized input graph is graph explosion — refused BEFORE any search (counters stay 0)", () => {
    const nodes65 = Array.from({ length: 65 }, (_, index) => "n" + index);
    const overNodes = planRoute(planInput(snap(nodes65, []), "n0", "n64"));
    expectPlanRefusal(overNodes, "refused_route_bound");
    if (!overNodes.ok) {
      expect(overNodes.expandedNodes).toBe(0);
      expect(overNodes.scannedEdges).toBe(0);
    }
    const ringNodes = Array.from({ length: 32 }, (_, index) => "n" + index);
    const manyEdges = Array.from({ length: 257 }, (_, index) =>
      ["n" + (index % 32), "n" + ((index + 1) % 32), "e" + index] as readonly [string, string, string],
    );
    const overEdges = planRoute(planInput(snap(ringNodes, manyEdges), "n0", "n5"));
    expectPlanRefusal(overEdges, "refused_route_bound");
    if (!overEdges.ok) {
      expect(overEdges.expandedNodes).toBe(0);
      expect(overEdges.scannedEdges).toBe(0);
    }
  });

  it("epoch mismatch refuses (one epoch's knowledge, one epoch's plan)", () => {
    expectPlanRefusal(planRoute(planInput(LINE, "a", "d", { epochId: "epoch-other" })), "refused_epoch_mismatch");
  });

  it("origin == destination refuses — even for an UNKNOWN node (pinned order: trivial before knowledge)", () => {
    expectPlanRefusal(planRoute(planInput(LINE, "a", "a")), "refused_same_endpoint");
    expectPlanRefusal(planRoute(planInput(LINE, "ghost", "ghost")), "refused_same_endpoint");
  });

  it("an endpoint outside the explicit graph refuses", () => {
    expectPlanRefusal(planRoute(planInput(LINE, "a", "ghost")), "refused_unknown_node");
    expectPlanRefusal(planRoute(planInput(LINE, "ghost", "d")), "refused_unknown_node");
  });

  it("an endpoint not EXPLICITLY observed refuses (absent, stale, quarantined, retired, unknown)", () => {
    const absent = allObserved(LINE).nodeStates;
    delete absent["d"];
    expectPlanRefusal(planRoute(planInput(LINE, "a", "d", { nodeStates: absent })), "refused_endpoint_not_observed");
    for (const state of [
      "stale",
      "quarantined_observation",
      "retired_observation",
      "unknown_observation",
    ] as const) {
      expectPlanRefusal(
        planRoute(planInput(LINE, "a", "d", { nodeStates: { ...observedNodes(LINE), d: state } })),
        "refused_endpoint_not_observed",
      );
    }
  });

  it("a node record from ANOTHER epoch never routes (record epoch must match the snapshot)", () => {
    const g = snap(["a", "b"], [["a", "b"]]);
    const foreign = {
      ...g,
      nodes: g.nodes.map((node) =>
        node.nodeId === "b" ? { ...node, epochId: "epoch-old" } : node,
      ),
    };
    expectPlanRefusal(planRoute(planInput(foreign, "a", "b")), "refused_endpoint_not_observed");
  });

  it("disconnected and direction-only destinations refuse no_route (search counters observable)", () => {
    const g = snap(["a", "b", "c"], [["a", "b"]]); // c is isolated
    const disconnected = planRoute(planInput(g, "a", "c"));
    expectPlanRefusal(disconnected, "refused_no_route");
    if (!disconnected.ok) {
      expect(disconnected.expandedNodes).toBeGreaterThan(0);
      expect(disconnected.scannedEdges).toBeGreaterThanOrEqual(1);
    }
    const reversedOnly = snap(["a", "b"], [["b", "a"]]); // only b → a exists
    expectPlanRefusal(planRoute(planInput(reversedOnly, "a", "b")), "refused_no_route");
  });
});

// ── observation overlay ──────────────────────────────────────────────────────

describe("27E observation overlay — stale/quarantined corridors never route", () => {
  const CHAIN = snap(["a", "b", "c", "d"], [
    ["a", "b"],
    ["b", "c"],
    ["c", "d"],
  ]);
  const FORK = snap(["a", "b", "d", "x", "y"], [
    ["a", "b"],
    ["b", "d"],
    ["a", "x"],
    ["x", "y"],
    ["y", "d"],
  ]);

  it("a stale INTERIOR node blocks the ONLY corridor as no_route", () => {
    expectPlanRefusal(
      planRoute(planInput(CHAIN, "a", "d", { nodeStates: { ...observedNodes(CHAIN), b: "stale" } })),
      "refused_no_route",
    );
  });

  it("a stale EDGE blocks the corridor (edges observe their own state)", () => {
    const g = snap(["a", "b", "c"], [
      ["a", "b"],
      ["b", "c"],
    ]);
    expectPlanRefusal(
      planRoute(planInput(g, "a", "c", { edgeStates: { ...observedEdges(g), "edge-000": "stale" } })),
      "refused_no_route",
    );
  });

  it("a quarantined ENDPOINT refuses directly (distinct from interior blocking)", () => {
    expectPlanRefusal(
      planRoute(planInput(CHAIN, "a", "d", { nodeStates: { ...observedNodes(CHAIN), d: "quarantined_observation" } })),
      "refused_endpoint_not_observed",
    );
  });

  it("quarantine with an observed DETOUR still routes — excluded elements are counted, never silent", () => {
    const d = planRoute(
      planInput(FORK, "a", "d", { nodeStates: { ...observedNodes(FORK), b: "quarantined_observation" } }),
    );
    expectZeroAuthority(d);
    if (d.ok) {
      expect([...d.path]).toEqual(["a", "x", "y", "d"]);
      expect(d.hopCount).toBe(3);
      expect(d.excludedNodes).toBe(1);
      expect(d.excludedEdges).toBe(2); // a→b and b→d lose an endpoint
    }
  });

  it("control: the same graph routes its SHORTEST corridor when everything is observed", () => {
    const d = planRoute(planInput(FORK, "a", "d"));
    expectZeroAuthority(d);
    if (d.ok) {
      expect([...d.path]).toEqual(["a", "b", "d"]);
      expect(d.hopCount).toBe(2);
      expect(d.excludedNodes).toBe(0);
      expect(d.excludedEdges).toBe(0);
    }
  });
});

// ── loops and graph explosion ──────────────────────────────────────────────────────────

describe("27E loops and explosion — cycles pruned, bounds enforced, dense graphs tamed", () => {
  it("a cyclic graph routes loop-free (the result never repeats a node)", () => {
    const g = snap(["a", "b", "c", "d"], [
      ["a", "b"],
      ["b", "c"],
      ["c", "a"],
      ["c", "d"],
    ]);
    const d = planRoute(planInput(g, "a", "d"));
    expectZeroAuthority(d);
    if (d.ok) {
      expect([...d.path]).toEqual(["a", "b", "c", "d"]);
      expect(new Set(d.path).size).toBe(d.path.length);
      expect(d.hopCount).toBe(3);
    }
    // and a route back ALONG the cycle still never repeats a node
    const back = planRoute(planInput(g, "b", "a"));
    expectZeroAuthority(back);
    if (back.ok) {
      expect([...back.path]).toEqual(["b", "c", "a"]);
      expect(new Set(back.path).size).toBe(back.path.length);
    }
    // the sink node d has no outbound corridor: unreachable refuses
    expectPlanRefusal(planRoute(planInput(g, "d", "a")), "refused_no_route");
  });

  it("a self-loop edge is excluded from traversal and counted (never in a result)", () => {
    const g = snap(["a", "b"], [
      ["a", "a"],
      ["a", "b"],
    ]);
    const d = planRoute(planInput(g, "a", "b"));
    expectZeroAuthority(d);
    if (d.ok) {
      expect([...d.path]).toEqual(["a", "b"]);
      expect([...d.edgePath]).toEqual(["edge-001"]);
      expect(d.excludedEdges).toBe(1);
    }
  });

  it("duplicate edge records resolve first-wins deterministically (idempotent knowledge)", () => {
    const g: TopologyGraphSnapshot = {
      epochId: EPOCH,
      nodes: ["a", "b", "c"].map((id) => ({
        nodeId: id,
        kind: "observed_node",
        epochId: EPOCH,
        provenance: PROVENANCE,
      })),
      edges: [
        { edgeId: "edge-dup", fromNodeId: "a", toNodeId: "b", kind: "observed_edge", epochId: EPOCH, provenance: PROVENANCE },
        { edgeId: "edge-dup", fromNodeId: "a", toNodeId: "c", kind: "observed_edge", epochId: EPOCH, provenance: PROVENANCE },
      ],
    };
    const first = planRoute(planInput(g, "a", "b"));
    expectZeroAuthority(first);
    if (first.ok) {
      expect([...first.edgePath]).toEqual(["edge-dup"]); // first record wins
      expect(first.excludedEdges).toBe(1); // the duplicate was counted, not silent
    }
    // the duplicate's target was never linked: reaching it refuses
    expectPlanRefusal(planRoute(planInput(g, "a", "c")), "refused_no_route");
  });

  it("a dense graph AT the frozen bounds routes within the pinned search counters", () => {
    const pad2 = (i: number): string => "node-" + String(i).padStart(2, "0");
    const nodeIds = Array.from({ length: 64 }, (_, index) => pad2(index));
    const edges: (readonly [string, string, string])[] = [];
    let edgeNumber = 0;
    for (let index = 0; index < 64; index += 1) {
      for (const offset of [1, 2, 4, 8]) {
        edges.push([
          pad2(index),
          pad2((index + offset) % 64),
          "edge-" + String(edgeNumber).padStart(3, "0"),
        ]);
        edgeNumber += 1;
      }
    }
    expect(edges.length).toBe(ROUTE_BOUNDS.maxInputEdges);
    const g = snap(nodeIds, edges);
    expect(g.nodes.length).toBe(ROUTE_BOUNDS.maxInputNodes);
    const d = planRoute(planInput(g, pad2(0), pad2(32)));
    expectZeroAuthority(d);
    if (d.ok) {
      expect([...d.path]).toEqual([pad2(0), pad2(8), pad2(16), pad2(24), pad2(32)]);
      expect(d.hopCount).toBe(4);
      expect(d.expandedNodes).toBeLessThanOrEqual(ROUTE_BOUNDS.maxInputNodes);
      expect(d.scannedEdges).toBeLessThanOrEqual(2 * ROUTE_BOUNDS.maxInputEdges);
      expect(d.excludedNodes).toBe(0);
      expect(d.excludedEdges).toBe(0);
    }
    const rerun = planRoute(planInput(g, pad2(0), pad2(32)));
    expect(JSON.stringify(rerun)).toBe(JSON.stringify(d));
  });
});

// ── candidate validation ──────────────────────────────────────────────────────

describe("27E candidate validation — loops, gaps, observation, pinned order", () => {
  const CHAIN = snap(["a", "b", "c"], [
    ["a", "b"],
    ["b", "c"],
  ]);

  it("a valid candidate validates with resolved edges and zero-authority literals", () => {
    const d = validateRoutePath(validationInput(CHAIN, ["a", "b", "c"]));
    expectZeroAuthority(d);
    if (d.ok) {
      expect(d.code).toBe("candidate_route_valid");
      expect([...d.path]).toEqual(["a", "b", "c"]);
      expect([...d.edgePath]).toEqual(["edge-000", "edge-001"]);
      expect(d.hopCount).toBe(2);
      expect(d.routeId).toBe("route-1");
    }
    const rerun = validateRoutePath(validationInput(CHAIN, ["a", "b", "c"]));
    expect(JSON.stringify(rerun)).toBe(JSON.stringify(d));
  });

  it("empty, non-string, and non-array candidates refuse invalid_request", () => {
    expectValidationRefusal(validateRoutePath(validationInput(CHAIN, [])), "refused_invalid_request");
    expectValidationRefusal(
      validateRoutePath(validationInput(CHAIN, ["a", 7 as unknown as string])),
      "refused_invalid_request",
    );
    expectValidationRefusal(
      validateRoutePath(validationInput(CHAIN, ["a", "b"], { routeId: "" })),
      "refused_invalid_request",
    );
    expectValidationRefusal(
      validateRoutePath(
        validationInput(CHAIN, ["a", "b"], {
          path: "a>b" as unknown as readonly string[],
        }),
      ),
      "refused_invalid_request",
    );
  });

  it("a single-node path refuses same_endpoint", () => {
    expectValidationRefusal(validateRoutePath(validationInput(CHAIN, ["a"])), "refused_same_endpoint");
  });

  it("a walk over the frozen hop cap refuses bound BEFORE membership (huge candidates never searched)", () => {
    const huge = Array.from({ length: 65 }, (_, index) => "ghost-" + index);
    expectValidationRefusal(validateRoutePath(validationInput(CHAIN, huge)), "refused_route_bound");
  });

  it("an unknown member refuses unknown_node — even when the path also loops (pinned order)", () => {
    expectValidationRefusal(validateRoutePath(validationInput(CHAIN, ["a", "x", "a"])), "refused_unknown_node");
    expectValidationRefusal(validateRoutePath(validationInput(CHAIN, ["a", "b", "ghost"])), "refused_unknown_node");
  });

  it("a repeated node refuses route_loop (candidate loops are detected, never walked)", () => {
    const cyclic = snap(["a", "b", "c"], [
      ["a", "b"],
      ["b", "c"],
      ["c", "a"],
    ]);
    expectValidationRefusal(validateRoutePath(validationInput(cyclic, ["a", "b", "c", "a"])), "refused_route_loop");
    expectValidationRefusal(validateRoutePath(validationInput(CHAIN, ["a", "a"])), "refused_route_loop");
  });

  it("loop detection beats endpoint state (pinned order: structure before overlay)", () => {
    const g = snap(["a", "b"], [["a", "b"]]);
    expectValidationRefusal(
      validateRoutePath(validationInput(g, ["a", "b", "a"], { nodeStates: { ...observedNodes(g), a: "stale" } })),
      "refused_route_loop",
    );
  });

  it("a stale or quarantined ENDPOINT refuses endpoint_not_observed", () => {
    const g = snap(["a", "b"], [["a", "b"]]);
    for (const state of ["stale", "quarantined_observation", "retired_observation"] as const) {
      expectValidationRefusal(
        validateRoutePath(validationInput(g, ["a", "b"], { nodeStates: { ...observedNodes(g), a: state } })),
        "refused_endpoint_not_observed",
      );
    }
    expectValidationRefusal(
      validateRoutePath(validationInput(g, ["a", "b"], { nodeStates: { ...observedNodes(g), b: "stale" } })),
      "refused_endpoint_not_observed",
    );
  });

  it("a non-adjacent pair refuses route_gap — the reverse edge is not this edge", () => {
    expectValidationRefusal(validateRoutePath(validationInput(CHAIN, ["a", "c"])), "refused_route_gap");
    expectValidationRefusal(validateRoutePath(validationInput(CHAIN, ["c", "a"])), "refused_route_gap");
    const reversedOnly = snap(["a", "b"], [["b", "a"]]);
    expectValidationRefusal(validateRoutePath(validationInput(reversedOnly, ["a", "b"])), "refused_route_gap");
  });

  it("an unobserved edge or interior node refuses hop_not_observed (the corridor exists but never routes)", () => {
    expectValidationRefusal(
      validateRoutePath(
        validationInput(CHAIN, ["a", "b", "c"], {
          edgeStates: { ...observedEdges(CHAIN), "edge-000": "stale" },
        }),
      ),
      "refused_hop_not_observed",
    );
    expectValidationRefusal(
      validateRoutePath(
        validationInput(CHAIN, ["a", "b", "c"], {
          nodeStates: { ...observedNodes(CHAIN), b: "stale" },
        }),
      ),
      "refused_hop_not_observed",
    );
    expectValidationRefusal(
      validateRoutePath(
        validationInput(CHAIN, ["a", "b", "c"], {
          edgeStates: { ...observedEdges(CHAIN), "edge-001": "quarantined_observation" },
        }),
      ),
      "refused_hop_not_observed",
    );
  });

  it("epoch mismatch refuses (one epoch's knowledge, one epoch's candidate)", () => {
    expectValidationRefusal(
      validateRoutePath(validationInput(CHAIN, ["a", "b"], { epochId: "epoch-other" })),
      "refused_epoch_mismatch",
    );
  });

  it("an oversized input graph refuses bound before any hop is walked (counters: no search exists)", () => {
    const nodes65 = Array.from({ length: 65 }, (_, index) => "n" + index);
    expectValidationRefusal(
      validateRoutePath(validationInput(snap(nodes65, []), ["n0", "n1"])),
      "refused_route_bound",
    );
  });

  it("a malformed graph refuses invalid_request", () => {
    expectValidationRefusal(
      validateRoutePath(
        validationInput(CHAIN, ["a", "b"], {
          graph: { ...CHAIN, edges: 7 } as unknown as TopologyGraphSnapshot,
        }),
      ),
      "refused_invalid_request",
    );
  });
});

// ── integration with the real 27B graph ───────────────────────────────────────

describe("27E integration — a real 27B LocalTopologyGraph snapshot plans routes", () => {
  it("plans and validates over real 27B records, and planning mutates NOTHING", () => {
    const opened = LocalTopologyGraph.open({ epochId: EPOCH });
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    const graph = opened.graph;
    const nodeA = graph.addNode({ nodeId: "a", kind: "observed_node", epochId: EPOCH, provenance: PROVENANCE });
    const nodeB = graph.addNode({ nodeId: "b", kind: "observed_node", epochId: EPOCH, provenance: PROVENANCE });
    const nodeC = graph.addNode({ nodeId: "c", kind: "observed_node", epochId: EPOCH, provenance: PROVENANCE });
    const edgeAB = graph.addEdge({ edgeId: "ab", fromNodeId: "a", toNodeId: "b", kind: "observed_edge", epochId: EPOCH, provenance: PROVENANCE });
    const edgeBC = graph.addEdge({ edgeId: "bc", fromNodeId: "b", toNodeId: "c", kind: "observed_edge", epochId: EPOCH, provenance: PROVENANCE });
    expect(nodeA.ok && nodeB.ok && nodeC.ok).toBe(true);
    expect(edgeAB.ok && edgeBC.ok).toBe(true);
    const snapshot = graph.snapshot();
    const fingerprintBefore = graph.fingerprint();

    const planned = planRoute(planInput(snapshot, "a", "c"));
    expectZeroAuthority(planned);
    if (planned.ok) {
      expect([...planned.path]).toEqual(["a", "b", "c"]);
      expect([...planned.edgePath]).toEqual(["ab", "bc"]);
      expect(planned.hopCount).toBe(2);
    }
    const validated = validateRoutePath(validationInput(snapshot, ["a", "b", "c"]));
    expectZeroAuthority(validated);
    if (validated.ok) {
      expect([...validated.edgePath]).toEqual(["ab", "bc"]);
      expect(validated.hopCount).toBe(2);
    }
    expectPlanRefusal(planRoute(planInput(snapshot, "a", "ghost")), "refused_unknown_node");

    // read-only: the graph is untouched by planning and validation
    expect(graph.nodeCount).toBe(3);
    expect(graph.edgeCount).toBe(2);
    expect(graph.fingerprint()).toBe(fingerprintBefore);
  });
});
